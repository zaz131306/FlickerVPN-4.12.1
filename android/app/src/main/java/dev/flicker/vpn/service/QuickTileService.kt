// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn.service

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.util.Log
import androidx.annotation.RequiresApi
import dev.flicker.vpn.FlickerApp
import dev.flicker.vpn.MainActivity
import dev.flicker.vpn.Native
import dev.flicker.vpn.R
import dev.flicker.vpn.Repository
import dev.flicker.vpn.TunnelService
import dev.flicker.vpn.data.AppState
import dev.flicker.vpn.data.ServiceStatus
import dev.flicker.vpn.util.Battery

/**
 * Плитка в шторке быстрых настроек: включить/выключить VPN без открытия приложения.
 *
 * ТРИ ВЕЩИ, НА КОТОРЫХ ПЛИТКА ОБЫЧНО И ЛОМАЕТСЯ (все закрыты):
 *
 *  1. TileService живёт в ОТДЕЛЬНОЙ привязке и сам ничего не знает про наш
 *     сервис. Поэтому [updateTile] статический и вызывается из TunnelService при
 *     каждой смене статуса — через requestListeningState система перечитывает
 *     плитку. Без этого она залипает в прошлом состоянии.
 *
 *  2. `qsTile` бывает null (плитка не добавлена пользователем, привязка ещё не
 *     установилась). Любое обращение — только через `?.`, иначе NPE валит
 *     системный процесс настроек, а не наше приложение.
 *
 *  3. На Android 14 (U) `startActivityAndCollapse(Intent)` заменена на версию с
 *     PendingIntent; старая на 14+ кидает. Развилка обязательна.
 *
 *  ПЛЮС: VpnService.prepare() требует, чтобы пользователь увидел системный диалог
 *  согласия. Из плитки его нельзя показать, пока экран заблокирован, поэтому
 *  используем unlockAndRun — иначе тап по плитке молча ничего не делает.
 */
@RequiresApi(Build.VERSION_CODES.N)
class QuickTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        render()
    }

    override fun onClick() {
        super.onClick()
        qsTile ?: return

        when (effectiveStatus()) {
            ServiceStatus.Connected -> {
                Log.i(TAG, "плитка: отключаю")
                TunnelService.stop(this)
            }

            ServiceStatus.Connecting -> {
                // Игнорируем: двойной тап не должен порождать два параллельных старта.
                Log.i(TAG, "плитка: идёт подключение, тап проигнорирован")
            }

            ServiceStatus.Disconnected, ServiceStatus.Failed -> {
                Log.i(TAG, "плитка: включаю")
                try {
                    unlockAndRun { startFromTile() }
                } catch (e: Exception) {
                    Log.w(TAG, "unlockAndRun не сработал, стартую напрямую", e)
                    startFromTile()
                }
            }
        }
        render()
    }

    private fun startFromTile() {
        // v4.8.1: в режиме «Обход DPI» внешнего узла НЕТ — трафик идёт
        // напрямую с искажением пакетов. Требовать выбранный сервер здесь
        // нельзя, иначе плитка в этом режиме просто открывает приложение
        // и ничего не включает.
        val bypass = dev.flicker.vpn.util.Prefs.mode(this) ==
            dev.flicker.vpn.util.Prefs.MODE_BYPASS
        val json = if (bypass) TunnelService.BYPASS_NO_SERVER
                   else Repository.selectedServerJson()
        if (json == null) {
            Log.w(TAG, "нет выбранного узла — открываю приложение")
            openApp()
            return
        }
        // v4.12.0: обход DPI не использует Go-ядро (byedpi + hev-socks5-tunnel
        // живут в :bypass) — требовать libflickerbox.so нужно только для
        // серверных режимов.
        if (!bypass && !FlickerApp.nativeReady) {
            Log.e(TAG, "ядро не готово: ${Native.userVisibleError}")
            openApp()
            return
        }
        TunnelService.start(this, json)

        // Один раз предлагаем снять ограничение батареи: без него OEM убьёт туннель
        if (Battery.shouldAsk(this) && !dev.flicker.vpn.util.Prefs.batteryAsked(this)) {
            dev.flicker.vpn.util.Prefs.setBatteryAsked(this)
            openApp()
        }
    }

    private fun openApp() {
        try {
            val intent = Intent(this, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startActivityAndCollapse(
                    android.app.PendingIntent.getActivity(
                        this, 0, intent,
                        android.app.PendingIntent.FLAG_UPDATE_CURRENT or
                            android.app.PendingIntent.FLAG_IMMUTABLE,
                    )
                )
            } else {
                @Suppress("DEPRECATION", "StartActivityAndCollapseDeprecated")
                startActivityAndCollapse(intent)
            }
        } catch (e: Exception) {
            Log.w(TAG, "не удалось открыть приложение", e)
        }
    }

    /**
     * v4.6.0: статус с проверкой, что сервис действительно жив.
     *
     * Плитка живёт в отдельной привязке и читает глобальный [AppState]. Если
     * путь обновления состояния не выполнился (отменённая корутина остановки,
     * гонка, смерть процесса), [AppState.status] застревает в `Connected`, и
     * плитка показывает «включено» при мёртвом туннеле — а тап по ней уходит в
     * ветку «отключаю» и не делает ничего видимого. Пользователь видит ровно
     * «приложение не отключается, ключик висит».
     *
     * Сверяем с [TunnelService.isLive]: состояние должно ВЫЧИСЛЯТЬСЯ из живого
     * сервиса (принцип Intra `VpnController.getState()` и v2rayNG
     * `CoreServiceManager.isRunning()`), а не только храниться.
     *
     * v4.12.0: ОБХОД DPI — исключение. Он работает в процессе :bypass, и
     * `isLive` (статик своего процесса) про него не знает ничего. Источник
     * правды здесь — наличие VPN-интерфейса в системе
     * ([TunnelService.isVpnInterfaceUp]); раньше плитка в режиме обхода всегда
     * сбрасывала Connected → Disconnected («нет подключения»).
     */
    private fun effectiveStatus(): ServiceStatus {
        val status = AppState.status
        val bypass = dev.flicker.vpn.util.Prefs.mode(this) ==
            dev.flicker.vpn.util.Prefs.MODE_BYPASS
        if (bypass) {
            return when {
                TunnelService.isVpnInterfaceUp(this) -> ServiceStatus.Connected
                status == ServiceStatus.Connecting -> status
                else -> {
                    if (status == ServiceStatus.Connected) AppState.reset()
                    if (status == ServiceStatus.Failed) status else ServiceStatus.Disconnected
                }
            }
        }
        if (status == ServiceStatus.Connected && !TunnelService.isLive) {
            Log.w(TAG, "AppState=Connected, а живого сервиса нет — считаю Disconnected")
            AppState.reset()
            return ServiceStatus.Disconnected
        }
        return status
    }

    private fun render() {
        val tile = qsTile ?: return
        val status = effectiveStatus()

        tile.state = when (status) {
            ServiceStatus.Connected -> Tile.STATE_ACTIVE
            ServiceStatus.Connecting -> Tile.STATE_UNAVAILABLE
            ServiceStatus.Disconnected, ServiceStatus.Failed -> Tile.STATE_INACTIVE
        }

        tile.label = when (status) {
            ServiceStatus.Connected -> getString(R.string.tile_on)
            ServiceStatus.Connecting -> getString(R.string.tile_connecting)
            ServiceStatus.Failed -> getString(R.string.tile_failed)
            ServiceStatus.Disconnected -> getString(R.string.app_name)
        }
        tile.contentDescription = tile.label

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            try {
                tile.subtitle = when (status) {
                    ServiceStatus.Connected -> AppState.serverName.ifBlank {
                        // v4.12.0: в режиме обхода имя может не доехать до этого
                        // процесса — показываем хотя бы метку режима.
                        if (dev.flicker.vpn.util.Prefs.mode(this@QuickTileService) ==
                            dev.flicker.vpn.util.Prefs.MODE_BYPASS
                        ) getString(R.string.mode_bypass) else getString(R.string.mode_vpn)
                    }
                    ServiceStatus.Failed -> AppState.lastError?.take(40) ?: getString(R.string.tile_failed)
                    else -> null
                }
            } catch (e: Exception) {
                Log.w(TAG, "subtitle недоступен", e)
            }
        }

        try {
            tile.updateTile()
        } catch (e: Exception) {
            Log.w(TAG, "updateTile()", e)
        }
    }

    companion object {
        private const val TAG = "FlickerTile"

        /**
         * Просит систему перечитать плитку. Вызывать из TunnelService при каждой
         * смене статуса. Безопасно: на API < 24 просто выходит.
         */
        fun updateTile(context: Context) {
            refreshListeningState(context)
        }

        /**
         * Отдельный вход для FlickerApp.onCreate — вызывается рефлексией, чтобы
         * проект собирался и без плитки.
         */
        @JvmStatic
        fun refreshListeningState(context: Context) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) return
            try {
                requestListeningState(context, ComponentName(context, QuickTileService::class.java))
            } catch (e: Exception) {
                Log.w(TAG, "requestListeningState", e)
            }
        }
    }
}
