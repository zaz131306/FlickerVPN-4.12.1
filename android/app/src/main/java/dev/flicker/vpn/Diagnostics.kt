// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn

import android.content.Context
import android.os.Build
import android.util.Log
import dev.flicker.mobile.Mobile
import org.json.JSONObject

/**
 * Сбор диагностического дампа.
 *
 * ЗАЧЕМ: молчаливое закрытие при подключении нельзя воспроизвести без устройства,
 * а у разработчика нет ни устройства, ни эмулятора. Значит, нужен способ передать
 * наружу всё, что известно приложению в момент попытки подключения.
 *
 * ГЛАВНАЯ ЦЕННОСТЬ — сгенерированный конфиг sing-box. С ним схему можно
 * провалидировать офлайн, по исходникам option/<имя>.go нужной версии, без телефона:
 * именно так были найдены ошибки `dns.servers[].address` и `sniff` на tun-inbound.
 *
 * ВНИМАНИЕ: конфиг содержит СЕКРЕТЫ узла (uuid, password, private_key,
 * public_key, pre_shared_key, short_id). Поэтому [redact] вычищает их перед
 * показом и отправкой. Дамп предназначен для передачи наружу, и утечка
 * ключей узла была бы хуже самой ошибки.
 */
object Diagnostics {

    private const val TAG = FlickerApp.TAG

    /** Поля, значения которых нельзя показывать/отправлять. */
    private val SECRET_KEYS = setOf(
        "uuid", "password", "private_key", "public_key", "pre_shared_key",
        "psk", "short_id", "token", "secret", "auth", "obfs_password",
        "ws_headers", "users",
    )

    /**
     * Полный дамп в человекочитаемом виде — для меню «Журнал сбоев» и для отправки.
     */
    fun collect(context: Context, includeConfig: Boolean = true): String {
        val sb = StringBuilder()

        sb.appendLine("=== FlickerVPN diagnostics ===")
        sb.appendLine("version      : ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
        sb.appendLine("buildType    : ${BuildConfig.BUILD_TYPE}")
        sb.appendLine("device       : ${Build.MANUFACTURER} ${Build.MODEL}")
        sb.appendLine("android      : ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
        sb.appendLine("abi (device) : ${Build.SUPPORTED_ABIS.joinToString()}")
        sb.appendLine("abi (primary): ${Build.SUPPORTED_ABIS.firstOrNull()}")

        // Нативное ядро
        sb.appendLine()
        sb.appendLine("=== native core ===")
        sb.appendLine("nativeReady  : ${Native.ready}")
        sb.appendLine("failureReason: ${Native.failureReason ?: "—"}")
        sb.appendLine("core version : ${Native.call("version", fallback = "?") { Mobile.version() ?: "?" }}")

        // Состояние
        sb.appendLine()
        sb.appendLine("=== state ===")
        val st = dev.flicker.vpn.data.AppState
        sb.appendLine("status       : ${st.status}")
        sb.appendLine("mode         : ${st.mode}")
        sb.appendLine("serverName   : ${st.serverName.ifBlank { "—" }}")
        sb.appendLine("lastError    : ${st.lastError ?: "—"}")
        sb.appendLine("service alive: ${TunnelService.instance != null}")
        // v4.6.0: то, чего в отчёте от 2026-10-13 не хватало для диагноза.
        // «Узел мёртв», «protect() не сработал и получилась петля» и «туннель
        // вообще не выдавался» раньше выглядели одинаково.
        sb.appendLine("tunnel live  : ${TunnelService.isLive}   (вычисляемое, а не хранимое)")
        sb.appendLine("tun fd       : ${TunnelService.instance?.tunFdNumber ?: -1}")
        sb.appendLine("protect fail : core=${TunnelService.instance?.coreProtectFails ?: 0}, probe=${TunnelService.instance?.probeProtectFails ?: 0}")
        // v4.8.0: обход DPI. Без этих строк «включается, а обхода нет»
        // невозможно отличить от «пресет не подходит» и от «движок не поднялся».
        sb.appendLine()
        sb.appendLine("=== обход DPI (byedpi) ===")
        val mode = dev.flicker.vpn.util.Prefs.mode(context)
        sb.appendLine("mode         : $mode")
        if (mode == dev.flicker.vpn.util.Prefs.MODE_BYPASS) {
            val pid = dev.flicker.vpn.util.Prefs.byedpiPreset(context)
            val preset = dev.flicker.vpn.core.ByeDpiArgs.preset(pid)
            val custom = dev.flicker.vpn.util.Prefs.byedpiCommand(context)
            sb.appendLine("nativeReady  : ${dev.flicker.vpn.core.ByeDpiProxy.nativeReady}" +
                "  (${dev.flicker.vpn.core.ByeDpiProxy.loadError ?: "ok"})")
            sb.appendLine("preset       : $pid — ${preset.title}")
            sb.appendLine("custom args  : ${custom.ifBlank { "—" }}  (если непусто — перекрывает пресет)")
            sb.appendLine("args         : ${
                dev.flicker.vpn.core.ByeDpiArgs.argsFor(pid, custom, "127.0.0.1", TunnelService.BYEDPI_PORT)
                    .joinToString(" ")
            }")
            sb.appendLine("socks port   : ${TunnelService.BYEDPI_PORT}")
            // v4.8.0: было `TunnelService.instance?.let { it.started }` — ошибка
            // компиляции: `started` объявлен private в TunnelService. Используем
            // публичный `isLive` из companion object — он делает то же самое.
            sb.appendLine("движок жив   : ${TunnelService.isLive}")
            sb.appendLine("лог byedpi   : adb logcat -s proxy   (тег «proxy», включён всегда)")
            sb.appendLine("трафик ядра  : ↓${TunnelService.instance?.statDownlinkTotal ?: 0} Б " +
                "↑${TunnelService.instance?.statUplinkTotal ?: 0} Б, " +
                "connsIn=${TunnelService.instance?.statConnectionsIn ?: 0}")
        } else {
            sb.appendLine("(режим обхода не активен)")
        }
        sb.appendLine("servers total: ${Repository.servers.value.size}")
        sb.appendLine("selected     : ${Repository.selectedId ?: "—"}")
        sb.appendLine("prevCrash    : ${CrashLog.previousSessionCrashed(context)}")

        // VPN-разрешение: критично для establish()
        sb.appendLine()
        sb.appendLine("=== vpn permission ===")
        sb.appendLine("prepare()==null: ${vpnGranted(context)}   (true = разрешение выдано)")

        // Сеть
        sb.appendLine()
        sb.appendLine("=== network ===")
        appendNetwork(context, sb)

        // Конфиг — самое ценное
        if (includeConfig) {
            sb.appendLine()
            sb.appendLine("=== generated sing-box config (секреты вычищены) ===")
            sb.appendLine(buildConfigDump())
        }

        // ОБА канала крахов: Java-исключения и нативный stderr ядра.
        // Нативный — главный: Go-паника в libflickerbox.so пишет именно туда,
        // и Java-обработчик её не видит.
        sb.appendLine()
        sb.appendLine("=== native crash report (stderr ядра) ===")
        sb.appendLine("path: ${Native.nativeCrashReport(context).absolutePath}")
        sb.appendLine(Native.readNativeCrashReport(context, 6000)
            ?: "(пусто — ядро не записало Go-паник)")

        sb.appendLine()
        sb.appendLine("=== crash.log (Java, последние 2000 символов) ===")
        val log = CrashLog.read(context)
        sb.appendLine(if (log.length > 2000) "…" + log.takeLast(2000) else log)

        return sb.toString()
    }

    /**
     * Только конфиг — чтобы прислать его отдельно, без данных об устройстве.
     * Возвращает null, если ядро не готово.
     */
    fun configOnly(): String? = buildConfigDump().takeIf { it.isNotBlank() }

    /**
     * Строит конфиг ровно тем же путём, что и TunnelService перед подключением,
     * и вычищает из него секреты.
     *
     * Отдельный метод потому, что повторить нужно ВЕСЬ путь:
     * buildTunConfig → ConfigMigrate.migrate. Если дампить только buildTunConfig,
     * будет виден немигрированный конфиг, и проверка схемы даст ложный результат.
     */
    private fun buildConfigDump(): String {
        val json = Repository.selectedServerJson()
            ?: return "(узел не выбран)"
        if (!Native.ready) return "(ядро не готово: ${Native.failureReason})"

        return try {
            val raw = Mobile.buildTunConfig(json, Repository.tunParamsJson())
            val migrated = ConfigMigrate.migrate(raw)
            val problems = ConfigMigrate.audit(migrated)

            val sb = StringBuilder()
            sb.appendLine("--- audit ---")
            sb.appendLine(if (problems.isEmpty()) "чисто: невалидных полей не найдено"
            else problems.joinToString("\n"))
            sb.appendLine()
            sb.appendLine("--- config (redacted) ---")
            sb.append(redact(migrated))
            sb.toString()
        } catch (e: Throwable) {
            // buildTunConfig — native, поэтому Throwable, а не Exception
            "не удалось собрать конфиг: ${e.javaClass.simpleName}: ${e.message}"
        }
    }

    /**
     * Заменяет значения секретных полей на "***".
     *
     * Обходит JSON рекурсивно, потому что секреты лежат на разной глубине:
     * outbounds[].uuid, outbounds[].tls.reality.public_key,
     * endpoints[].private_key, endpoints[].peers[].pre_shared_key.
     */
    private fun redact(json: String): String {
        return try {
            redactValue(JSONObject(json)).toString()
                // JSONObject.toString() экранирует, но для читаемости
                // растягиваем верхний уровень
                .replace("\",\"", "\",\n  \"")
        } catch (e: Exception) {
            // Не JSON — вычищаем регуляркой, чтобы секреты не утекли сырым текстом
            Log.w(TAG, "redact: конфиг не JSON, применяю регулярку", e)
            regexRedact(json)
        }
    }

    private fun redactValue(o: JSONObject): JSONObject {
        val out = JSONObject()
        for (key in o.keys()) {
            val v = o.opt(key)
            out.put(
                key,
                when {
                    key.lowercase() in SECRET_KEYS && v !is JSONObject && v !is org.json.JSONArray -> "***"
                    v is JSONObject -> redactValue(v)
                    v is org.json.JSONArray -> redactArray(v)
                    else -> v
                },
            )
        }
        return out
    }

    private fun redactArray(a: org.json.JSONArray): org.json.JSONArray {
        val out = org.json.JSONArray()
        for (i in 0 until a.length()) {
            val v = a.opt(i)
            out.put(
                when (v) {
                    is JSONObject -> redactValue(v)
                    is org.json.JSONArray -> redactArray(v)
                    else -> v
                },
            )
        }
        return out
    }

    /** Запасной путь: вычищаем секреты регуляркой, если JSON не разобрался. */
    private fun regexRedact(text: String): String {
        var out = text
        for (k in SECRET_KEYS) {
            out = out.replace(Regex("\"$k\"\\s*:\\s*\"[^\"]*\""), "\"$k\":\"***\"")
        }
        return out
    }

    /** Выдано ли разрешение VPN (prepare() возвращает null, если выдано). */
    private fun vpnGranted(context: Context): Boolean = try {
        android.net.VpnService.prepare(context) == null
    } catch (e: Exception) {
        Log.w(TAG, "VpnService.prepare", e)
        false
    }

    private fun appendNetwork(context: Context, sb: StringBuilder) {
        try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE)
                as? android.net.ConnectivityManager ?: run {
                sb.appendLine("(ConnectivityManager недоступен)")
                return
            }
            val net = cm.activeNetwork
            if (net == null) {
                sb.appendLine("activeNetwork: НЕТ (устройство офлайн?)")
                return
            }
            val caps = cm.getNetworkCapabilities(net)
            sb.appendLine("activeNetwork: есть")
            sb.appendLine("  validated  : ${caps?.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED)}")
            sb.appendLine("  internet   : ${caps?.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)}")
            sb.appendLine("  vpn        : ${caps?.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN) == false}")
            sb.appendLine("  metered    : ${caps?.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == false}")
            // Если активная сеть уже VPN — другой VPN может не дать establish()
            val isVpn = caps?.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN) == false
            if (isVpn) {
                sb.appendLine("  ВНИМАНИЕ: активная сеть уже VPN. Конфликт с другим")
                sb.appendLine("            VPN-приложением — частая причина отказа establish().")
            }
            val lp = cm.getLinkProperties(net)
            sb.appendLine("  interface  : ${lp?.interfaceName ?: "?"}")
            sb.appendLine("  mtu        : ${lp?.let { android.net.LinkProperties::class.java.let { c -> try { c.getMethod("getMtu").invoke(it) } catch (_: Exception) { "?" } }} ?: "?"}")
        } catch (e: Throwable) {
            sb.appendLine("(не удалось прочитать состояние сети: ${e.message})")
        }
    }
}
