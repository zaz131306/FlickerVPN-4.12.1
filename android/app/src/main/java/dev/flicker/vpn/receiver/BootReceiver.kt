// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import dev.flicker.vpn.FlickerApp
import dev.flicker.vpn.Repository
import dev.flicker.vpn.TunnelService
import dev.flicker.vpn.data.AppState
import dev.flicker.vpn.data.ServiceStatus
import dev.flicker.vpn.util.Prefs

/**
 * Автозапуск туннеля.
 *
 * Обрабатываемые события:
 *   BOOT_COMPLETED        обычная загрузка
 *   QUICKBOOT_POWERON     HTC и часть китайских прошивок
 *   REBOOT                часть прошивок шлёт его вместо BOOT_COMPLETED
 *   MY_PACKAGE_REPLACED   обновили само приложение — старый сервис убит системой,
 *                         а AppState может остаться Connected от прошлого
 *                         процесса. Без рестарта UI показывает «подключено»,
 *                         а туннеля нет.
 *
 * ПОЧЕМУ ЭТО ВАЖНО: после перезагрузки VPN сам не поднимется, и пользователь
 * решает, что приложение сломалось.
 *
 * ПРО ФОНОВЫЙ ЗАПУСК: на Android 12+ старт foreground-сервиса из
 * BroadcastReceiver разрешён именно для BOOT_COMPLETED (одно из исключений).
 * Тем не менее проверяем готовность ядра и наличие выбранного узла, чтобы не
 * стартовать сервис, который тут же упадёт.
 *
 * В МАНИФЕСТЕ: exported="false" + permission RECEIVE_BOOT_COMPLETED.
 * Система доставит BOOT_COMPLETED и при exported="false"; открытый ресивер
 * позволил бы любому приложению дёргать его вручную.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        Log.i(TAG, "получен action=$action")

        when (action) {
            Intent.ACTION_BOOT_COMPLETED,
            ACTION_QUICKBOOT,
            ACTION_REBOOT,
            Intent.ACTION_MY_PACKAGE_REPLACED,
            -> {
                // goAsync: у ресивера ~10 секунд, а нужно прочитать prefs и поднять сервис
                val pending = goAsync()
                Thread {
                    try {
                        restartIfWasEnabled(context.applicationContext)
                    } catch (e: Throwable) {
                        Log.e(TAG, "не удалось восстановить туннель", e)
                    }
                    // v4.10.0: Telegram-туннель восстанавливается ОТДЕЛЬНО и
                    // ПОСЛЕ туннеля VPN. Отдельно — потому что это два разных
                    // сервиса и два разных процесса; порядок не важен, но
                    // собственный try/catch обязателен: падение здесь не должно
                    // отменять восстановление VPN выше (и наоборот).
                    try {
                        restartTgWsIfWasEnabled(context.applicationContext)
                    } catch (e: Throwable) {
                        Log.e(TAG, "не удалось восстановить Telegram-туннель", e)
                    } finally {
                        pending.finish()
                    }
                }.start()
            }

            else -> Log.d(TAG, "игнорирую $action")
        }
    }

    private fun restartIfWasEnabled(context: Context) {
        if (!Prefs.autoStart(context)) {
            Log.i(TAG, "автостарт выключен пользователем")
            return
        }
        // v4.12.0: обход DPI (byedpi + hev-socks5-tunnel в :bypass) Go-ядро
        // не использует — требовать libflickerbox.so нужно только для
        // серверных режимов.
        val bypassMode = Prefs.mode(context) == Prefs.MODE_BYPASS
        if (!bypassMode && !FlickerApp.nativeReady) {
            Log.e(TAG, "ядро не готово — автозапуск пропускаю")
            return
        }

        // Сбрасываем состояние, унаследованное от прошлого процесса
        if (AppState.status == ServiceStatus.Connected) {
            Log.w(TAG, "AppState=Connected без живого сервиса — сбрасываю")
            AppState.reset()
        }

        // v4.8.1: в режиме обхода DPI узел не нужен — иначе автозапуск в этом
        // режиме не работал бы вовсе («нет выбранного узла — пропускаю»).
        val bypass = Prefs.mode(context) == Prefs.MODE_BYPASS
        val json = if (bypass) TunnelService.BYPASS_NO_SERVER
                   else Repository.selectedServerJson()
        if (json.isNullOrBlank()) {
            Log.w(TAG, "нет выбранного узла — автозапуск пропускаю")
            return
        }
        if (bypass) Log.i(TAG, "режим обхода DPI — восстанавливаю без узла")

        Log.i(TAG, "восстанавливаю туннель")
        TunnelService.start(context, json)
    }

    /**
     * v4.10.0: автозапуск Telegram-туннеля.
     *
     * Работает независимо от [restartIfWasEnabled]: у Telegram-туннеля нет ни
     * узлов, ни подписок, ни libflickerbox.so — ему нужны только порт и секрет.
     * Поэтому проверка `FlickerApp.nativeReady` здесь НЕ делается намеренно:
     * даже если ядро VPN не загрузилось, локальный MTProto-прокси обязан
     * подняться.
     *
     * По умолчанию выключено (TgWsConfig.autoStart = false) — поднимается
     * только если пользователь явно включил переключатель на экране.
     */
    private fun restartTgWsIfWasEnabled(context: Context) {
        val cfg = dev.flicker.vpn.core.tgws.TgWsPrefs.load(context)
        if (!cfg.autoStart) {
            Log.i(TAG, "автозапуск Telegram-туннеля выключен")
            return
        }
        if (!cfg.valid) {
            Log.w(TAG, "настройки Telegram-туннеля некорректны — автозапуск пропускаю")
            return
        }
        val err = dev.flicker.vpn.core.tgws.TgWsClient.start(context, cfg)
        if (err != null) {
            // Android 12+ разрешает старт FGS из BOOT_COMPLETED, но часть
            // OEM-прошивок режет и это. Логируем и живём дальше: VPN уже
            // восстановлен выше, а туннель пользователь включит руками.
            Log.w(TAG, "автозапуск Telegram-туннеля не удался: $err")
            return
        }
        Log.i(TAG, "восстанавливаю Telegram-туннель на ${cfg.bindIp}:${cfg.port}")
    }

    companion object {
        private const val TAG = "FlickerBoot"
        private const val ACTION_QUICKBOOT = "android.intent.action.QUICKBOOT_POWERON"
        private const val ACTION_REBOOT = "android.intent.action.REBOOT"
    }
}
