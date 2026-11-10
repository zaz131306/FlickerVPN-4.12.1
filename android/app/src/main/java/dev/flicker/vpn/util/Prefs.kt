// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn.util

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit

/**
 * Настройки, которые нужны фоновым компонентам: BootReceiver, QuickTileService.
 *
 * ПОЧЕМУ ОТДЕЛЬНО ОТ Repository: Repository хранит серверы/источники/настройки
 * в JSON-файлах и инициализируется из FlickerApp.onCreate. BootReceiver же
 * стартует в момент, когда Application ещё может быть не создан, и ему нужен
 * синхронный ответ «включать ли туннель». SharedPreferences для этого надёжнее:
 * чтение не требует ни инициализации, ни suspend-контекста.
 *
 * apply() везде вместо commit(): commit() пишет на диск синхронно и на медленной
 * флешке даёт видимый лаг, если вызвать из UI-потока.
 */
object Prefs {

    private const val FILE = "flicker_prefs"

    private const val KEY_AUTOSTART = "auto_start"
    private const val KEY_MODE = "tunnel_mode"
    private const val KEY_AUTO_RECONNECT = "auto_reconnect"
    private const val KEY_BATTERY_ASKED = "battery_asked"

    // v4.7.0: режим «Обход DPI» (byedpi, без внешнего сервера).
    private const val KEY_BYEDPI_PRESET = "byedpi_preset"
    private const val KEY_BYEDPI_COMMAND = "byedpi_command"
    // v4.12.0: DNS обхода DPI (эталонный дефолт 8.8.8.8).
    private const val KEY_BYPASS_DNS = "bypass_dns"

    /** Значения [mode]. */
    const val MODE_VPN = "vpn"
    const val MODE_PROXY = "proxy"
    const val MODE_BYPASS = "bypass"

    private fun prefs(context: Context): SharedPreferences =
        context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    /** Поднимать ли туннель после перезагрузки устройства. По умолчанию выключено. */
    fun autoStart(context: Context): Boolean = prefs(context).getBoolean(KEY_AUTOSTART, false)

    fun setAutoStart(context: Context, value: Boolean) =
        prefs(context).edit { putBoolean(KEY_AUTOSTART, value) }

    /** Текущий режим: [MODE_VPN] | [MODE_PROXY] | [MODE_BYPASS]. */
    fun mode(context: Context): String = prefs(context).getString(KEY_MODE, MODE_VPN) ?: MODE_VPN

    fun setMode(context: Context, value: String) =
        prefs(context).edit { putString(KEY_MODE, value) }

    /**
     * ID пресета byedpi (см. `ByeDpiArgs.PRESETS`).
     *
     * v4.10.1: значение по умолчанию БЫЛО ЗАХАРДКОЖЕНО здесь как "oob" и
     * расходилось с `ByeDpiArgs.DEFAULT_PRESET_ID`. Из-за этого смена дефолта
     * в самих пресетах ни на что не влияла: пользователь, ни разу не
     * открывавший выбор пресета, всегда получал "oob".
     *
     * Теперь источник истины один — [dev.flicker.vpn.core.ByeDpiArgs.DEFAULT_PRESET_ID]
     * (с v4.10.1 это "ref", дословная командная строка ByeByeDPI-x-tg).
     * Важно: если пресет уже выбран вручную и сохранён, хранится именно он —
     * миграция не делается намеренно, чужой явный выбор перезаписывать нельзя.
     */
    fun byedpiPreset(context: Context): String =
        prefs(context).getString(
            KEY_BYEDPI_PRESET,
            dev.flicker.vpn.core.ByeDpiArgs.DEFAULT_PRESET_ID
        ) ?: dev.flicker.vpn.core.ByeDpiArgs.DEFAULT_PRESET_ID

    fun setByedpiPreset(context: Context, value: String) =
        prefs(context).edit { putString(KEY_BYEDPI_PRESET, value) }

    /**
     * Своя командная строка byedpi. Если непустая — имеет приоритет над
     * пресетом (режим «свои параметры», как CMD-настройки в ByeByeDPI-x-tg).
     *
     * argv[0], --ip и --port указывать не нужно: их подставит
     * `ByeDpiArgs.build()`. --help/--version/-D отфильтровываются.
     */
    fun byedpiCommand(context: Context): String =
        prefs(context).getString(KEY_BYEDPI_COMMAND, "") ?: ""

    fun setByedpiCommand(context: Context, value: String) =
        prefs(context).edit { putString(KEY_BYEDPI_COMMAND, value) }

    /**
     * v4.12.0: DNS для режима «Обход DPI».
     *
     * Эталон ByeByeDPI-x-tg кладёт этот адрес в VpnService.Builder
     * (ByeDpiVpnService.startTun2Socks: prefs "dns_ip", default "8.8.8.8"),
     * и DNS-трафик уходит через TUN → tun2socks → SOCKS5(byedpi) → интернет,
     * то есть резолвинг тоже защищён обходом. Значение по умолчанию —
     * ровно эталонное.
     */
    fun bypassDns(context: Context): String =
        prefs(context).getString(KEY_BYPASS_DNS, "8.8.8.8")?.trim() ?: "8.8.8.8"

    fun setBypassDns(context: Context, value: String) =
        prefs(context).edit { putString(KEY_BYPASS_DNS, value.trim()) }

    /** Переподключаться ли автоматически при обрыве. По умолчанию включено. */
    fun autoReconnect(context: Context): Boolean =
        prefs(context).getBoolean(KEY_AUTO_RECONNECT, true)

    fun setAutoReconnect(context: Context, value: Boolean) =
        prefs(context).edit { putBoolean(KEY_AUTO_RECONNECT, value) }

    /**
     * Показывали ли уже диалог про оптимизацию батареи.
     * Без этого флага диалог вылезает при каждом запуске и раздражает.
     */
    fun batteryAsked(context: Context): Boolean = prefs(context).getBoolean(KEY_BATTERY_ASKED, false)

    fun setBatteryAsked(context: Context) =
        prefs(context).edit { putBoolean(KEY_BATTERY_ASKED, true) }
}
