// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn

import android.app.Application
import android.content.Context
import android.util.Log
import dev.flicker.mobile.Mobile
import dev.flicker.vpn.util.SourceHealth
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Repository — состояние приложения: серверы, источники подписок, настройки.
 *
 * Хранение — JSON-файлы в filesDir (те же форматы, что в desktop-расширении:
 * shareparse.Server / shareparse.Source), поэтому статистику живости можно
 * переносить между платформами, а id узлов совпадают (sub-<fnv1a>).
 *
 * Вся логика разбора/слияния/сортировки/проб — в Go-фасаде dev.flicker.mobile
 * (общая с desktop: internal/shareparse + internal/probe).
 */
object Repository {

    private lateinit var app: Application

    /** Context для SourceHealth / Prefs. Null до init — вызовы защищаем. */
    private val ctx: android.content.Context?
        get() = if (::app.isInitialized) app else null

    private fun file(name: String) = File(app.filesDir, name)

    fun init(application: Application) {
        app = application
        loadAll()
        // v4.4.0: встроенные проверенные узлы — даже если все подписки умрут.
        scheduleBootstrapInjection()
    }

    /**
     * Инициализация БЕЗ обращения к нативному ядру.
     *
     * Нужна для случая, когда libflickerbox.so не загрузилась: UI должен открыться
     * и показать пользователю внятную ошибку, а не упасть. Без этого `app`
     * остаётся lateinit, и любое обращение к Repository кидает
     * UninitializedPropertyAccessException — то есть приложение падает дважды:
     * сначала в onCreate, потом при попытке показать ошибку.
     *
     * Читает файлы напрямую, не вызывая Mobile.*.
     */
    fun initWithoutNative(application: Application) {
        app = application
        try {
            serversJson = readJson("servers.json", "[]")
            sourcesJson = readJson("sources.json", "")
            settingsJson = readJson("settings.json", "{}")
            // Пустой список — намеренно: сортировка требует ядра.
            _servers.value = emptyList()
        } catch (e: Exception) {
            Log.e(FlickerApp.TAG, "initWithoutNative", e)
        }
    }

    // ---------- наблюдаемое состояние ----------

    data class ServerRow(
        val id: String,
        val name: String,
        val host: String,
        val port: Int,
        val protocol: String,
        val flag: String,
        val ping: Int?,          // null/-1 — неизвестно, -2 — мёртв, >=0 — мс
        val alive: Int,          // 1 жив, 0 мёртв, -1 неизвестно
        val country: String,
        val sub: Boolean,
        val demo: Boolean,
        val lastError: String,
        val json: String
    ) {
        val protocolLabel: String
            get() = when (protocol) {
                "vless" -> if (json.contains("\"reality\"")) "VLESS·Reality" else "VLESS"
                "trojan" -> "Trojan"
                "vmess" -> "VMess"
                "shadowsocks" -> "SS"
                "wireguard" -> if (json.contains("\"detour\"")) "WG·матрёшка" else "WireGuard"
                "hysteria2" -> "HY2 (эксп.)"
                else -> protocol
            }

        companion object {
            fun fromJson(obj: JSONObject): ServerRow {
                val ping = if (obj.isNull("ping")) null else obj.optInt("ping")
                val lastCheck = if (obj.isNull("lastCheckAt")) null else obj.optLong("lastCheckAt")
                val alive = when {
                    lastCheck == null -> -1
                    ping != null && ping >= 0 -> 1
                    else -> 0
                }
                return ServerRow(
                    id = obj.optString("id"),
                    name = obj.optString("name").ifEmpty { obj.optString("host") },
                    host = obj.optString("host"),
                    port = obj.optInt("port"),
                    protocol = obj.optString("protocol"),
                    flag = obj.optString("flag").ifEmpty { "🌍" },
                    ping = ping,
                    alive = alive,
                    country = obj.optString("country"),
                    sub = obj.optBoolean("sub"),
                    demo = obj.optBoolean("demo"),
                    lastError = obj.optString("lastError"),
                    json = obj.toString()
                )
            }
        }
    }

    data class UiState(
        val refreshing: Boolean = false,
        val probing: Boolean = false,
        val statusText: String = "",
        val connected: Boolean = false,
        val connectedName: String = ""
    )

    private val _servers = MutableStateFlow<List<ServerRow>>(emptyList())
    val servers: StateFlow<List<ServerRow>> = _servers

    private val _ui = MutableStateFlow(UiState())
    val ui: StateFlow<UiState> = _ui

    fun setUi(transform: (UiState) -> UiState) {
        _ui.value = transform(_ui.value)
    }

    // ---------- сырые JSON-хранилища ----------

    private var serversJson: String = "[]"
    private var sourcesJson: String = ""
    private var settingsJson: String = "{}"

    private fun readJson(name: String, fallback: String): String = try {
        val f = file(name)
        if (f.exists()) f.readText().ifBlank { fallback } else fallback
    } catch (e: Exception) {
        Log.w(FlickerApp.TAG, "read $name", e)
        fallback
    }

    private fun writeJson(name: String, data: String) {
        // Атомарная запись: сначала в .tmp, затем rename.
        //
        // Почему это важно именно здесь: servers.json может весить сотни КБ,
        // и если процесс убьют посреди записи (а при работе VPN система делает
        // это охотно), обычный writeText оставит обрезанный JSON. При следующем
        // старте JSONArray() упадёт, список узлов будет потерян, и пользователь
        // увидит пустое приложение.
        //
        // renameTo на Android/Linux атомарен в пределах одной ФС, поэтому
        // файл либо старый, либо новый — но никогда не половинка.
        try {
            val target = file(name)
            val tmp = File(target.absolutePath + ".tmp")
            tmp.writeText(data)
            if (!tmp.renameTo(target)) {
                // renameTo возвращает false, а не кидает — молча игнорировать нельзя
                Log.e(FlickerApp.TAG, "write $name: renameTo вернул false, данные не сохранены")
                tmp.delete()
            }
        } catch (e: Exception) {
            Log.e(FlickerApp.TAG, "write $name", e)
        }
    }

    fun loadAll() {
        serversJson = readJson("servers.json", "[]")
        sourcesJson = readJson("sources.json", "")
        settingsJson = readJson("settings.json", "{}")
        verifiedIds.clear()
        readVerifiedIds().forEachIndexed { idx, id ->
            verifiedIds.add(id)
            bootstrapRank[id] = idx
        }
        if (sourcesJson.isBlank()) {
            // БЫЛО: sourcesJson = Mobile.defaultSources()  — native, без защиты.
            // Если ядро не готово, здесь прилетал UnsatisfiedLinkError и убивал
            // Application.onCreate(). Теперь — fallback на встроенный список.
            val defaults = Native.call("defaultSources", fallback = FALLBACK_SOURCES) {
                Mobile.defaultSources()
            }
            sourcesJson = defaults.ifBlank { FALLBACK_SOURCES }
            writeJson("sources.json", sourcesJson)
        }
        // v4.3.0: домешиваем дополнительные источники поверх встроенных.
        // Дефолтный список зашит в libflickerbox.so — добавить туда что-либо
        // без пересборки движка нельзя, а свежие фиды нужны: бесплатные узлы
        // дохнут за часы, чем больше источников, тем выше шанс на живые.
        val mergedSources = ensureExtraSources(sourcesJson)
        if (mergedSources != sourcesJson) {
            sourcesJson = mergedSources
            writeJson("sources.json", sourcesJson)
        }
        // v4.5.0: вычищаем узлы, встроенные в 4.4.0. Они лежат в servers.json
        // и переживут обновление приложения, поэтому одной заменой
        // BOOTSTRAP_LINKS дело не кончается: автоподбор продолжил бы тыкать
        // в узлы белых списков, которые физически не выпускают Telegram.
        val purged = purgeObsoleteServers(serversJson)
        if (purged != null) {
            serversJson = purged
            saveServers(serversJson)
        }
        republish()
    }

    /**
     * v4.3.0: дополнительные встроенные источники (Kotlin-сторона).
     * Все URL проверены на доступность 2026-10-13.
     */
    private val EXTRA_SOURCES: String = """
        [
          {"id":"autoproxy1","name":"Auto_proxy · Long_term 1","url":"https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription1","refreshMinutes":60,"builtin":true,"enabled":true,"note":"Популярный RU-фид, частые обновления"},
          {"id":"autoproxy2","name":"Auto_proxy · Long_term 2","url":"https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription2","refreshMinutes":60,"builtin":true,"enabled":true},
          {"id":"autoproxy3","name":"Auto_proxy · Long_term 3","url":"https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription3","refreshMinutes":60,"builtin":true,"enabled":true},
          {"id":"freefq","name":"freefq · free","url":"https://raw.githubusercontent.com/freefq/free/master/v2","refreshMinutes":60,"builtin":true,"enabled":true},
          {"id":"igareck-black-full","name":"igareck · ЧЁРНЫЕ · VLESS (полный доступ)","url":"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt","refreshMinutes":45,"builtin":true,"enabled":true,"note":"Полный доступ, без белых списков"},
          {"id":"igareck-black","name":"igareck · ЧЁРНЫЕ · VLESS (мобильные)","url":"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt","refreshMinutes":45,"builtin":true,"enabled":true},
          {"id":"igareck-black-other","name":"igareck · ЧЁРНЫЕ · SS/Hy2/VMess/Trojan","url":"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS%2BAll_RUS.txt","refreshMinutes":45,"builtin":true,"enabled":true},
          {"id":"fplist-23","name":"FreeProxyList · mirror 23","url":"https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/23.txt","refreshMinutes":30,"builtin":true,"enabled":true,"note":"Агрегатор, обновляется каждые 30 минут"},
          {"id":"fplist-1","name":"FreeProxyList · mirror 1","url":"https://raw.githubusercontent.com/nikita29a/FreeProxyList/main/mirror/1.txt","refreshMinutes":30,"builtin":true,"enabled":true,"note":"Агрегатор, обновляется каждые 30 минут"},
          {"id":"nomore-b64","name":"NoMoreWalls · base64","url":"https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt","refreshMinutes":60,"builtin":true,"enabled":true,"note":"Второй файл того же автора, что peasoft · NoMoreWalls"}
        ]
    """.trimIndent()

    /**
     * v4.5.0: удалить из сохранённого списка узлы, которые больше не должны
     * в нём быть. Возвращает новый JSON или null, если удалять нечего.
     *
     * Под нож идут две группы:
     *
     *  1. «⚪ RU-mob … [*CIDR]» — встроенные узлы 4.4.0 из подписки igareck
     *     «БЕЛЫЕ СПИСКИ | WHITE LISTS | CIDR». В заголовке этой подписки
     *     написано «Только VK, Yandex, CDNvideo, Beeline»: Telegram и
     *     Instagram через них не ходят НИКОГДА. Контрольный прогон 40 таких
     *     узлов 2026-10-13: трафик поднимали 6, а ни один не дал всех трёх
     *     целей. Именно на них автопереключение 4.4.0 потратило все попытки.
     *
     *  2. «✅ … REALITY (проверен)» — три узла, проверенные 2026-10-12 и
     *     умершие к утру 2026-10-13 (185.229.9.79 и 45.139.24.66 не отвечают
     *     даже на TCP-рукопожатие, delta.linkexo.xyz отдаёт только Instagram).
     *     Бесплатные узлы живут часы, поэтому «проверен» в имени устаревает
     *     быстрее, чем выходит следующий билд.
     *
     * Совпадение ищем по имени, а не по id: id считается из host:port:uuid:pbk,
     * а эти же серверы могут прийти из подписки под другим именем — тогда их
     * трогать не надо, пусть живут.
     */
    private fun purgeObsoleteServers(json: String): String? {
        return try {
            val arr = JSONArray(json)
            val out = JSONArray()
            var removed = 0
            for (i in 0 until arr.length()) {
                val o = arr.optJSONObject(i) ?: continue
                val name = o.optString("name")
                val bad = name.contains("RU-mob") ||
                    name.contains("[*CIDR]") ||
                    name.contains("REALITY (проверен)")
                if (bad) {
                    removed++
                    o.optString("id").takeIf { it.isNotEmpty() }?.let { verifiedIds.remove(it) }
                } else {
                    out.put(o)
                }
            }
            if (removed == 0) null
            else {
                Log.i(FlickerApp.TAG, "purgeObsoleteServers: удалено узлов белых списков/устаревших — $removed")
                // ctx может быть null до init — CrashLog.note требует Context
                ctx?.let {
                    CrashLog.note(
                        it,
                        "Удалено $removed устаревших узлов (белые списки [*CIDR] и мёртвые «проверенные» из 4.4.0)"
                    )
                }
                out.toString()
            }
        } catch (e: Throwable) {
            Log.w(FlickerApp.TAG, "purgeObsoleteServers", e)
            null
        }
    }

    /** Домешивает [EXTRA_SOURCES] в существующий список (по id, без дублей). */
    private fun ensureExtraSources(json: String): String {
        return try {
            val src = JSONArray(json)
            val arr = JSONArray()
            // v4.5.0: источники, которые больше не нужны. «igareck-reality»
            // указывал на Vless-Reality-White-Lists-Rus-Mobile.txt — БЕЛЫЕ
            // списки (только VK/Yandex/CDNvideo/Beeline). Он уже сохранён в
            // sources.json пользователя, и одним добавлением новых id его
            // не убрать, поэтому вычищаем явно.
            val obsolete = setOf("igareck-reality")
            for (i in 0 until src.length()) {
                val o = src.optJSONObject(i) ?: continue
                if (o.optString("id") in obsolete) continue
                arr.put(o)
            }
            val ids = mutableSetOf<String>()
            for (i in 0 until arr.length()) ids.add(arr.optJSONObject(i)?.optString("id") ?: "")
            val extra = JSONArray(EXTRA_SOURCES)
            var added = 0
            for (i in 0 until extra.length()) {
                val o = extra.optJSONObject(i) ?: continue
                if (o.optString("id") !in ids) { arr.put(o); added++ }
            }
            if (added > 0) Log.i(FlickerApp.TAG, "дополнительные источники подписок: +$added")
            arr.toString()
        } catch (e: Throwable) {
            Log.w(FlickerApp.TAG, "ensureExtraSources", e)
            json
        }
    }

    /**
     * v4.5.0: ВСТРОЕННЫЕ курируемые узлы (не зависят от загрузки подписок).
     *
     * ВСЕ 36 проверены ЖИВЫМ трафиком 2026-10-13 через sing-box CLI v1.14.2:
     * через каждый узел реально выполнены три HTTPS-запроса —
     * api.telegram.org/method/getMe (ожидаем 404), www.instagram.com (200/302)
     * и api.ipify.org (200). DNS шёл DoH через тот же узел, как в приложении.
     * 27 из 36 ответили на все три цели, 6 — на две, 3 нестабильны (поэтому
     * они в конце списка). Отобрано из 5484 ссылок 8 подписок: TCP-фильтр
     * оставил 3064, полный прогон с трафиком — 162 живых, дальше ручной отбор.
     *
     * ОТДЕЛЬНО ИЗМЕРЕН ВЫХОДНОЙ IP каждого узла (ip-api.com через узел).
     * Узлы с выходом в РОССИИ исключены: 159.194.244.247 и
     * ru-1-3.unturned-rust-dead.lol дают 159.194.244.247 (СПб, Beget),
     * cape.flowzari.info — 83.217.192.72 (Москва, TIMEWEB), 194.38.11.86 —
     * Москва. Формально они «живые» (ipify=200, telegram=404), но Instagram
     * через российский выход не открывается в принципе: трафик до
     * instagram.com всё равно пересекает границу РФ и упирается в тот же
     * ТСПУ. Оставить их означало повторить ошибку 4.4.0 — автоподбор тратил
     * бы попытки на узлы, которые не могут решить задачу пользователя.
     *
     * Порядок в списке = приоритет автоподбора (см. [bootstrapRank]):
     * сначала Reality в Северной Европе (Финляндия/Эстония/Польша/Швеция —
     * ближе всего к РФ и лучше всего переносят ТСПУ), затем VLESS/Trojan/SS
     * в Германии, Британии и Нидерландах, потом Азия как запасной вариант,
     * и в самом конце — три узла, давших сбои в контрольном прогоне.
     *
     * ЧЕГО ЗДЕСЬ БОЛЬШЕ НЕТ И ПОЧЕМУ (главная причина провала 4.4.0):
     * из списка убраны узлы igareck «БЕЛЫЕ СПИСКИ | WHITE LISTS | CIDR».
     * Заголовок их подписки буквально гласит:
     *
     *     # profile-title: 🏳️ БЕЛЫЕ СПИСКИ 🏳️ WHITE LISTS | CIDR |
     *       Только VK, Yandex, CDNvideo, Beeline
     *
     * То есть через эти узлы ходят ТОЛЬКО VK/Yandex/CDNvideo/Beeline —
     * Telegram и Instagram они не выпускают в принципе. В 4.4.0 из 26
     * встроенных узлов 23 были именно такими, и автопереключение перебирало
     * их один за другим, помечая мёртвыми, пока не кончились попытки.
     * Проверка того же дня: 6/26 старых узлов вообще поднимали трафик.
     *
     * Имена намеренно переписаны (#✅ NN) — id узла считается из
     * host:port:uuid:pbk:flow и от имени НЕ зависит, так что эти же узлы из
     * подписок igareck «ЧЁРНЫЕ СПИСКИ» сольются с встроенными без дублей.
     */
    private val BOOTSTRAP_LINKS: String = listOf(
        "vless://ace33fb8-c593-4b17-8f72-f3359b6e9638@finaluty.loknietotop.digital:443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=finaluty.loknietotop.digital&pbk=III2StgFziJtisbaKDYlEF2qYwBHJZnzZH5DHdwuFQ8&sid=d110331f200987ae&fp=firefox&spx=/#%E2%9C%85%2001%20%C2%B7%20%F0%9F%87%AB%F0%9F%87%AE%20%D0%A4%D0%B8%D0%BD%D0%BB%D1%8F%D0%BD%D0%B4%D0%B8%D1%8F%20%C2%B7%20Reality",
        "vless://ace33fb8-c593-4b17-8f72-f3359b6e9638@zahvatpribaltovonline.vvzzkontaktezzvv.garden:443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=zahvatpribaltovonline.vvzzkontaktezzvv.garden&pbk=r1MW0o1DsC6EEWN-KPKnoXszb1trxlKShRIgOpxqHBk&sid=d98e7afec9c0c359&fp=firefox&spx=/#%E2%9C%85%2002%20%C2%B7%20%F0%9F%87%AA%F0%9F%87%AA%20%D0%AD%D1%81%D1%82%D0%BE%D0%BD%D0%B8%D1%8F%20%C2%B7%20Reality",
        "vless://6c21cf57-a9a9-4075-ad9f-631152bd911e@ember.datanexi.store:443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=ember.datanexi.store&fp=firefox&pbk=irnW7-3RKbH3SLv-RrPR27DQTLiIV8GYj2N8CRVgCBQ&sid=c7e7592543e1fe96#%E2%9C%85%2003%20%C2%B7%20%F0%9F%87%B5%F0%9F%87%B1%20%D0%9F%D0%BE%D0%BB%D1%8C%D1%88%D0%B0%20%C2%B7%20Reality",
        "vless://318c935d-c195-41d3-99ad-9bbcfdab3386@nl.srv.vbuste-bot.com:444?encryption=none&type=grpc&security=reality&sni=nl.srv.vbuste-bot.com&pbk=0-or5ogGhYbBgsVSrSC2Fhxyp2BN97Y9pqIdg61Qd08&sid=4be4110078ebed4a&fp=chrome#%E2%9C%85%2004%20%C2%B7%20%F0%9F%87%B3%F0%9F%87%B1%20%D0%9D%D0%B8%D0%B4%D0%B5%D1%80%D0%BB%D0%B0%D0%BD%D0%B4%D1%8B%20%C2%B7%20Reality",
        "vless://68c3d665-b2b5-4ffb-9f37-9f3d8c47324d@se1.h1cloud.net:26100?encryption=none&security=reality&sni=www.icloud.com&pbk=1uuvuG2Jl_o6yoVvOYm3hEboArh2Znu7zCy4Tqj36TI&sid=8045087bda646f1b&spx=%2F&type=tcp&headerType=none&fp=qq#%E2%9C%85%2005%20%C2%B7%20%F0%9F%87%B8%F0%9F%87%AA%20%D0%A8%D0%B2%D0%B5%D1%86%D0%B8%D1%8F%20%C2%B7%20Reality",
        "vless://a5db5ab5-8d28-49c0-ad55-0ad4724e5c0d@fert6.localip.ir:2087?encryption=none&host=fert6.localip.ir&path=%2Fhokm&security=tls&sni=fert6.localip.ir&type=ws#%E2%9C%85%2006%20%C2%B7%20%F0%9F%87%A9%F0%9F%87%AA%20%D0%93%D0%B5%D1%80%D0%BC%D0%B0%D0%BD%D0%B8%D1%8F%20%C2%B7%20VLESS",
        "vless://a5db5ab5-8d28-49c0-ad55-0ad4724e5c0d@94.103.168.48:2087?path=%2Fhokm&security=tls&host=ops4asfseretuiyk.localip.ir&fp=random&type=ws&sni=ops4asfseretuiyk.localip.ir#%E2%9C%85%2007%20%C2%B7%20%F0%9F%87%A9%F0%9F%87%AA%20%D0%93%D0%B5%D1%80%D0%BC%D0%B0%D0%BD%D0%B8%D1%8F%20%C2%B7%20VLESS",
        "vless://51b7e147-a320-44be-ae95-3f3a80b7d3d7@45.88.12.47:2083?encryption=none&security=tls&sni=cert.viktorthebest.lol&alpn=http%2F1.1&fp=random&type=ws&path=%2Fvless-ws#%E2%9C%85%2008%20%C2%B7%20%F0%9F%87%A9%F0%9F%87%AA%20%D0%93%D0%B5%D1%80%D0%BC%D0%B0%D0%BD%D0%B8%D1%8F%20%C2%B7%20VLESS",
        "vless://b0a100ee-c397-43f2-bdae-2adfb7a0d4e5@103.195.190.94:443?encryption=none&security=tls&sni=rnxq-1lpi3m.linmeisoft.com&type=ws&path=%2Fb0a100ee-c397-43f2-bdae-2adfb7a0d4e5&host=rnxq-1lpi3m.linmeisoft.com&fp=chrome#%E2%9C%85%2009%20%C2%B7%20%F0%9F%87%AC%F0%9F%87%A7%20%D0%91%D1%80%D0%B8%D1%82%D0%B0%D0%BD%D0%B8%D1%8F%20%C2%B7%20VLESS",
        "vless://b0a100ee-c397-43f2-bdae-2adfb7a0d4e5@23.146.248.149:443?encryption=none&security=tls&sni=rnxq-1lpi3m.linmeisoft.com&type=ws&path=%2Fb0a100ee-c397-43f2-bdae-2adfb7a0d4e5&host=rnxq-1lpi3m.linmeisoft.com#%E2%9C%85%2010%20%C2%B7%20%F0%9F%87%AC%F0%9F%87%A7%20%D0%91%D1%80%D0%B8%D1%82%D0%B0%D0%BD%D0%B8%D1%8F%20%C2%B7%20VLESS",
        "vless://d0b32482-67aa-426d-8735-ab6c7ceb65bd@178.107.58.80:8443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=tls&sni=cdn.intercom-home.online&fp=firefox&alpn=h2#%E2%9C%85%2011%20%C2%B7%20%F0%9F%87%AC%F0%9F%87%A7%20%D0%91%D1%80%D0%B8%D1%82%D0%B0%D0%BD%D0%B8%D1%8F%20%C2%B7%20VLESS",
        "vless://b0a100ee-c397-43f2-bdae-2adfb7a0d4e5@45.142.127.24:443?encryption=none&security=tls&sni=rnxq-1lpi3m.linmeisoft.com&type=ws&path=%2Fb0a100ee-c397-43f2-bdae-2adfb7a0d4e5&host=rnxq-1lpi3m.linmeisoft.com&fp=firefox#%E2%9C%85%2012%20%C2%B7%20%F0%9F%87%AC%F0%9F%87%A7%20%D0%91%D1%80%D0%B8%D1%82%D0%B0%D0%BD%D0%B8%D1%8F%20%C2%B7%20VLESS",
        "vless://b0a100ee-c397-43f2-bdae-2adfb7a0d4e5@217.60.63.5:443?encryption=none&security=tls&sni=rnxq-1lpi3m.linmeisoft.com&type=ws&path=%2Fb0a100ee-c397-43f2-bdae-2adfb7a0d4e5&host=rnxq-1lpi3m.linmeisoft.com#%E2%9C%85%2013%20%C2%B7%20%F0%9F%87%AC%F0%9F%87%A7%20%D0%91%D1%80%D0%B8%D1%82%D0%B0%D0%BD%D0%B8%D1%8F%20%C2%B7%20VLESS",
        "vless://b0a100ee-c397-43f2-bdae-2adfb7a0d4e5@141.133.174.59:443?encryption=none&security=tls&sni=rnxq-1lpi3m.linmeisoft.com&type=ws&path=%2Fb0a100ee-c397-43f2-bdae-2adfb7a0d4e5&host=rnxq-1lpi3m.linmeisoft.com#%E2%9C%85%2014%20%C2%B7%20%F0%9F%87%AC%F0%9F%87%A7%20%D0%91%D1%80%D0%B8%D1%82%D0%B0%D0%BD%D0%B8%D1%8F%20%C2%B7%20VLESS",
        "trojan://humanity@94.158.219.126:443?allowInsecure=1&cs=real_firefox_cipherSuites&fm=tlshello-0-len&insecure=1&type=ws&security=tls&path=%2Fassignment&host=www.pleadcourt.org&sni=www.pleadcourt.org&fp=chrome&alpn=http/1.1#%E2%9C%85%2015%20%C2%B7%20%F0%9F%87%B3%F0%9F%87%B1%20%D0%9D%D0%B8%D0%B4%D0%B5%D1%80%D0%BB%D0%B0%D0%BD%D0%B4%D1%8B%20%C2%B7%20Trojan",
        "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpvWklvQTY5UTh5aGNRVjhrYTNQYTNB@82.38.31.175:443#%E2%9C%85%2016%20%C2%B7%20%F0%9F%87%B3%F0%9F%87%B1%20%D0%9D%D0%B8%D0%B4%D0%B5%D1%80%D0%BB%D0%B0%D0%BD%D0%B4%D1%8B%20%C2%B7%20SS",
        "ss://chacha20-ietf-poly1305:oZIoA69Q8yhcQV8ka3Pa3A@82.38.31.174:443#%E2%9C%85%2017%20%C2%B7%20%F0%9F%87%B3%F0%9F%87%B1%20%D0%9D%D0%B8%D0%B4%D0%B5%D1%80%D0%BB%D0%B0%D0%BD%D0%B4%D1%8B%20%C2%B7%20SS",
        "ss://YWVzLTEyOC1jZmI6c2hhZG93c29ja3M=@109.201.152.181:443#%E2%9C%85%2018%20%C2%B7%20%F0%9F%87%B3%F0%9F%87%B1%20%D0%9D%D0%B8%D0%B4%D0%B5%D1%80%D0%BB%D0%B0%D0%BD%D0%B4%D1%8B%20%C2%B7%20SS",
        "ss://YWVzLTI1Ni1nY206al9aOXlXcUl0Q3pfOXloRDVZVlk0dw@185.239.141.248:8388#%E2%9C%85%2019%20%C2%B7%20%F0%9F%87%AB%F0%9F%87%AE%20%D0%A4%D0%B8%D0%BD%D0%BB%D1%8F%D0%BD%D0%B4%D0%B8%D1%8F%20%C2%B7%20SS",
        "trojan://Puj01Rc8UcA9IzcFcYOs8KMOhCz6aX2Q@188.114.96.3:443?allowInsecure=1&host=mfyousheng.nl.eu.org&path=%2FtjwsLhx0SFASG4l9FERJ1g&sni=mfyousheng.nl.eu.org&type=ws#%E2%9C%85%2020%20%C2%B7%20%F0%9F%87%B1%F0%9F%87%BA%20%D0%9B%D1%8E%D0%BA%D1%81%D0%B5%D0%BC%D0%B1%D1%83%D1%80%D0%B3%20%C2%B7%20Trojan",
        "trojan://humanity@188.42.145.180:443?path=%2Fassignment&security=tls&alpn=http%2F1.1&host=www.volumerOot.coM.&fp=android&type=ws&sni=wWw.Volumeroot.cOm.#%E2%9C%85%2021%20%C2%B7%20%F0%9F%87%B1%F0%9F%87%BA%20%D0%9B%D1%8E%D0%BA%D1%81%D0%B5%D0%BC%D0%B1%D1%83%D1%80%D0%B3%20%C2%B7%20Trojan",
        "trojan://nwilryafgkyvuxauc8pz@69.164.240.85:50875?security=tls&insecure=1&allowInsecure=1&type=tcp&headerType=none#%E2%9C%85%2022%20%C2%B7%20%F0%9F%87%BA%F0%9F%87%B8%20%D0%A1%D0%A8%D0%90%20%C2%B7%20Trojan",
        "vless://b0a100ee-c397-43f2-bdae-2adfb7a0d4e5@45.12.69.152:443?encryption=none&security=tls&sni=rnxq-1lpi3m.linmeisoft.com&type=ws&path=%2Fb0a100ee-c397-43f2-bdae-2adfb7a0d4e5&host=rnxq-1lpi3m.linmeisoft.com#%E2%9C%85%2023%20%C2%B7%20%F0%9F%87%AC%F0%9F%87%A7%20%D0%91%D1%80%D0%B8%D1%82%D0%B0%D0%BD%D0%B8%D1%8F%20%C2%B7%20VLESS",
        "vless://b0a100ee-c397-43f2-bdae-2adfb7a0d4e5@185.223.252.175:443?encryption=none&security=tls&sni=rnxq-1lpi3m.linmeisoft.com&type=ws&path=%2Fb0a100ee-c397-43f2-bdae-2adfb7a0d4e5&host=rnxq-1lpi3m.linmeisoft.com#%E2%9C%85%2024%20%C2%B7%20%F0%9F%87%AC%F0%9F%87%A7%20%D0%91%D1%80%D0%B8%D1%82%D0%B0%D0%BD%D0%B8%D1%8F%20%C2%B7%20VLESS",
        "vless://b0a100ee-c397-43f2-bdae-2adfb7a0d4e5@85.217.170.89:443?encryption=none&security=tls&sni=rnxq-1lpi3m.linmeisoft.com&type=ws&path=%2Fb0a100ee-c397-43f2-bdae-2adfb7a0d4e5&host=rnxq-1lpi3m.linmeisoft.com#%E2%9C%85%2025%20%C2%B7%20%F0%9F%87%AC%F0%9F%87%A7%20%D0%91%D1%80%D0%B8%D1%82%D0%B0%D0%BD%D0%B8%D1%8F%20%C2%B7%20VLESS",
        "vless://41a7af38-0bb1-4493-aa8d-634af0c2548b@82.29.36.250:443?&security=reality&flow=xtls-rprx-vision&pbk=09XPceP705hC-5sEDXDSLeL2eMOrF-mFISK8JaJ7q2g&sid=09353d6dc5b789&fp=chrome&sni=aws.amazon.com&type=tcp&headerType=none&host=aws.amazon.com&path=%2F#%E2%9C%85%2026%20%C2%B7%20%F0%9F%87%AD%F0%9F%87%B0%20%D0%93%D0%BE%D0%BD%D0%BA%D0%BE%D0%BD%D0%B3%20%C2%B7%20Reality",
        "vless://5b01dc2d-6892-49b8-8289-3f73a32e00e4@3696b38bsg.murphyweb.sbs:32134/?type=tcp&encryption=none&flow=xtls-rprx-vision&sni=buylite.music.apple.com&fp=firefox&security=reality&pbk=OdTELUjAUKO_qr-O-uihaAZJAhA8GyIWVI6CpozVCU4&sid=6c6c7c97#%E2%9C%85%2027%20%C2%B7%20%F0%9F%87%AD%F0%9F%87%B0%20%D0%93%D0%BE%D0%BD%D0%BA%D0%BE%D0%BD%D0%B3%20%C2%B7%20Reality",
        "vless://2d1ad594-80a4-4bfb-87a6-038e39701f51@sg2-8sb.6121999.dpdns.org:19825?Telegram=@GozargahAzad,@GozargahAzad,@GozargahAzad,@GozargahAzad,@GozargahAzad,@GozargahAzad,@GozargahAzad&security=reality&type=tcp&sni=&fp=chrome&flow=xtls-rprx-vision&sid=6ba85179e30d4fc2&pbk=GvvkY8xYb9QjvwvzYq_uNC4tOGd0DCxRnz6770-xgkI#%E2%9C%85%2028%20%C2%B7%20%F0%9F%87%B8%F0%9F%87%AC%20%D0%A1%D0%B8%D0%BD%D0%B3%D0%B0%D0%BF%D1%83%D1%80%20%C2%B7%20Reality",
        "vless://d90087c3-54f5-4283-a13f-615260c8b0c7@149.28.158.128:443?&security=reality&flow=xtls-rprx-vision&pbk=hTweFDvbSucrGERtiiwDfoqD3vo_Z9cuaqboff3FTXQ&fp=chrome&sni=googleapis.com&type=tcp&headerType=none&host=googleapis.com&path=%2F#%E2%9C%85%2029%20%C2%B7%20%F0%9F%87%B8%F0%9F%87%AC%20%D0%A1%D0%B8%D0%BD%D0%B3%D0%B0%D0%BF%D1%83%D1%80%20%C2%B7%20Reality",
        "vless://5567cac6-2a32-4318-83cd-7df3a9eebbd7@34.87.113.18:443?&security=reality&pbk=hJCcmOf_ECJ3GUfHUjsgfcFKcgGb22H7cz_m_FvcVm4&sid=eb97ce837da2f6ad&fp=chrome&sni=www.cloudflare.com&type=tcp&headerType=none&host=www.cloudflare.com&path=%2F#%E2%9C%85%2030%20%C2%B7%20%F0%9F%87%B8%F0%9F%87%AC%20%D0%A1%D0%B8%D0%BD%D0%B3%D0%B0%D0%BF%D1%83%D1%80%20%C2%B7%20Reality",
        "vless://49c0aac1-5e05-4f04-b624-248fc59e03c4@54.169.200.246:41688?security=reality&encryption=none&pbk=srwIElIGTPs0kshpN1vvPsn4wixV_pLd56y_v9m0sTk&headerType=none&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=www.intel.com&sid=7f342137c20387#%E2%9C%85%2031%20%C2%B7%20%F0%9F%87%B8%F0%9F%87%AC%20%D0%A1%D0%B8%D0%BD%D0%B3%D0%B0%D0%BF%D1%83%D1%80%20%C2%B7%20Reality",
        "ss://YWVzLTI1Ni1nY206YWM5YzBhN2I@211.174.113.172:49642#%E2%9C%85%2032%20%C2%B7%20%F0%9F%87%B0%F0%9F%87%B7%20%D0%9A%D0%BE%D1%80%D0%B5%D1%8F%20%C2%B7%20SS",
        "ss://YWVzLTEyOC1nY206c2hhZG93c29ja3M=@149.22.87.240:443#%E2%9C%85%2033%20%C2%B7%20%F0%9F%87%AF%F0%9F%87%B5%20%D0%AF%D0%BF%D0%BE%D0%BD%D0%B8%D1%8F%20%C2%B7%20SS",
        "vless://ace33fb8-c593-4b17-8f72-f3359b6e9638@swerka.loknietotop.digital:443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=swerka.loknietotop.digital&pbk=x6p656szvu_3CKLsJ4NtkooRvdTVGx7IoPca_p58_jA&sid=fb442438e2223836&fp=firefox#%E2%9C%85%2034%20%C2%B7%20%F0%9F%87%B8%F0%9F%87%AA%20%D0%A8%D0%B2%D0%B5%D1%86%D0%B8%D1%8F%20%C2%B7%20Reality",
        "vless://83383473-0d62-4089-ac4d-d7ecb413504a@se3.h1cloud.net:25643?encryption=none&type=tcp&flow=xtls-rprx-vision&security=reality&pbk=NBKdM5Q5Tiue7YkxEldtShCCHi1GJ0WKCizyhPXQTy4&sni=ru1.boutique-hotel1108.ru&fp=firefox&sid=20672f0333e23e84&spx=%2F#%E2%9C%85%2035%20%C2%B7%20%F0%9F%87%B8%F0%9F%87%AA%20%D0%A8%D0%B2%D0%B5%D1%86%D0%B8%D1%8F%20%C2%B7%20Reality",
        "trojan://humanity@185.18.250.252:443/?type=ws&host=www.calmlunch.com&path=%2Fassignment&security=tls&sni=www.calmlunch.com&allowInsecure=1#%E2%9C%85%2036%20%C2%B7%20%F0%9F%87%A8%F0%9F%87%AD%20%D0%A8%D0%B2%D0%B5%D0%B9%D1%86%D0%B0%D1%80%D0%B8%D1%8F%20%C2%B7%20Trojan",
    ).joinToString("\n")

    /** id встроенных узлов — для приоритета в автопереключении. */
    private val verifiedIds: MutableSet<String> =
        java.util.Collections.synchronizedSet(mutableSetOf())

    /**
     * v4.5.0: ПОРЯДОК встроенных узлов (id -> место в списке, 0 = лучший).
     *
     * Зачем: [nextCandidate] внутри яруса сортировал по ping, а у свежих
     * встроенных узлов ping == null, то есть все они были «равны» и выбор
     * определялся лексикографией id — фактически случайно. Автопереключение
     * могло трижды подряд ткнуться в узлы из хвоста списка. Теперь порядок
     * курируемый: Россия/Северная Европа → Европа → остальное.
     */
    private val bootstrapRank: MutableMap<String, Int> =
        java.util.Collections.synchronizedMap(mutableMapOf())

    private fun readVerifiedIds(): List<String> = try {
        val arr = JSONArray(readJson("verified_ids.json", "[]"))
        (0 until arr.length()).mapNotNull {
            arr.optString(it).takeIf { x -> x.isNotEmpty() }
        }
    } catch (e: Exception) { emptyList() }

    /** Ждём готовности ядра (оно грузится асинхронно) и вкачиваем встроенные узлы. */
    private fun scheduleBootstrapInjection() {
        scope.launch {
            repeat(120) {
                if (Native.ready) {
                    injectBootstrap()
                    return@launch
                }
                delay(500)
            }
        }
    }

    /**
     * Парсит [BOOTSTRAP_LINKS] ядром и сливает с текущим списком.
     * Идемпотентно: id детерминированы (fnv от содержимого), mergeServers
     * обновляет LastSeenAt — pruneStale встроенные узлы не съест.
     */
    private fun injectBootstrap() {
        if (!Native.ready) return
        try {
            val res = JSONObject(
                Native.call("parseBootstrap", fallback = "") {
                    Mobile.parseSubscription(BOOTSTRAP_LINKS, "bootstrap", false)
                }
            )
            val servers = res.optJSONArray("servers")
            if (servers == null || servers.length() == 0) {
                Log.w(FlickerApp.TAG, "injectBootstrap: ядро не вернуло серверов")
                return
            }
            // Порядок сохраняется: Mobile.parseSubscription не переставляет
            // строки, поэтому i-й сервер = i-я ссылка в BOOTSTRAP_LINKS.
            val ordered = ArrayList<String>()
            for (i in 0 until servers.length()) {
                servers.optJSONObject(i)?.optString("id")
                    ?.takeIf { it.isNotEmpty() }?.let { ordered.add(it) }
            }
            val ids = HashSet(ordered)
            val now = System.currentTimeMillis()
            val merged = JSONObject(
                Native.call("mergeBootstrap", fallback = "") {
                    Mobile.mergeServers(serversJson, servers.toString(), now)
                }
            )
            val mergedArr = merged.optJSONArray("merged")?.toString() ?: return
            verifiedIds.clear()
            verifiedIds.addAll(ids)
            bootstrapRank.clear()
            ordered.forEachIndexed { idx, id -> bootstrapRank[id] = idx }
            // Именно СПИСОК (не множество): порядок = приоритет, и он нужен
            // после перезапуска приложения, до повторного injectBootstrap.
            writeJson("verified_ids.json", JSONArray(ordered).toString())
            if (mergedArr != serversJson) saveServers(mergedArr) else republish()
            Log.i(FlickerApp.TAG, "injectBootstrap: встроенных узлов ${servers.length()}")
        } catch (e: Throwable) {
            Log.w(FlickerApp.TAG, "injectBootstrap", e)
        }
    }

    /**
     * v4.3.0: следующий кандидат для автопереключения с мёртвого узла.
     * Приоритет: живые по probing-статистике (alive=1, лучший ping),
     * затем неизвестные (alive=-1). Помеченные мёртвыми (alive=0),
     * демо и уже проваленные в текущей сессии ([exclude]) пропускаются.
     */
    fun nextCandidate(exclude: Set<String>): ServerRow? {
        val all = _servers.value
        val pool = all.filter { it.id !in exclude && !it.demo && it.alive != 0 }
        // v4.4.0: ярусы — сначала встроенные живые, потом просто живые,
        // потом встроенные неизвестные, потом остальные.
        val ver = HashSet(verifiedIds)
        fun tier(r: ServerRow): Int = when {
            r.id in ver && r.alive == 1 -> 0
            r.alive == 1 -> 1
            r.id in ver -> 2
            else -> 3
        }
        // v4.5.0: внутри яруса — КУРАТОРСКИЙ порядок встроенного списка, и
        // только потом ping. Раньше первым ключом шёл ping, а у свежих
        // встроенных узлов он null, поэтому все 40 кандидатов считались равными
        // и выбор падал на лексикографически минимальный id — то есть на
        // случайный узел из хвоста списка.
        fun rank(r: ServerRow): Int = bootstrapRank[r.id] ?: Int.MAX_VALUE
        val cmp = compareBy<ServerRow>({ tier(it) }, { rank(it) }, { it.ping ?: Int.MAX_VALUE }, { it.id })
        pool.sortedWith(cmp).firstOrNull()?.let { return it }
        // v4.5.0: запасной путь. `alive != 0` отбрасывает узлы, которые фоновая
        // проба пометила мёртвыми. Проба идёт мимо туннеля и часто ошибается
        // (узел живой, но не отвечает на сам формат пробы) — если отфильтровать
        // всё, автопереключение встанет, и телефон останется на дохлом узле.
        // Тогда берём непроверенные в этой сессии встроенные узлы.
        return all.filter { it.id !in exclude && !it.demo && it.id in ver }
            .sortedWith(cmp)
            .firstOrNull()
    }

    /**
     * Встроенный список источников. Используется, если ядро недоступно,
     * чтобы экран настроек не был пустым и пользователь понимал, что происходит.
     * Держится в синхронизации с Mobile.defaultSources() (native/internal/config).
     */
    private val FALLBACK_SOURCES: String = """
        [
          {"id":"au1rxx","name":"Au1rxx · free-vpn-subscriptions","url":"https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/v2ray-base64.txt","refreshMinutes":1440,"builtin":true,"enabled":true},
          {"id":"matin-vless","name":"MatinGhanbari · VLESS","url":"https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt","refreshMinutes":60,"builtin":true,"enabled":true},
          {"id":"matin-trojan","name":"MatinGhanbari · Trojan","url":"https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt","refreshMinutes":60,"builtin":true,"enabled":true},
          {"id":"peasoft","name":"peasoft · NoMoreWalls","url":"https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt","refreshMinutes":360,"builtin":true,"enabled":true}
        ]
    """.trimIndent()

    private fun republish() {
        // Без ядра сортировка невозможна — публикуем как есть, чтобы список
        // не был пустым. Порядок при этом «как в файле», это приемлемо.
        val sorted = Native.call("sortServers", fallback = serversJson) {
            Mobile.sortServers(serversJson)
        }
        val rows = try {
            val arr = JSONArray(sorted)
            ArrayList<ServerRow>(arr.length()).also {
                for (i in 0 until arr.length()) it.add(ServerRow.fromJson(arr.getJSONObject(i)))
            }
        } catch (e: Exception) {
            // Битый servers.json после обрыва записи. Раньше это роняло onCreate.
            Log.e(FlickerApp.TAG, "servers.json не разбирается — сбрасываю список", e)
            serversJson = "[]"
            writeJson("servers.json", serversJson)
            emptyList()
        }
        _servers.value = rows
    }

    fun rawServers(): String = serversJson

    fun saveServers(json: String) {
        serversJson = json
        writeJson("servers.json", json)
        republish()
    }

    // ---------- настройки ----------

    private fun settings(): JSONObject = try {
        JSONObject(settingsJson)
    } catch (e: Exception) {
        JSONObject()
    }

    private fun saveSettings(obj: JSONObject) {
        settingsJson = obj.toString()
        writeJson("settings.json", settingsJson)
    }

    val autoRefresh: Boolean get() = settings().optBoolean("autoRefresh", true)
    val allowHY2: Boolean get() = settings().optBoolean("allowHY2", false)
    val dnsServer: String get() = settings().optString("dnsServer", "1.1.1.1")
    val selectedId: String? get() = settings().optString("selectedId").ifBlank { null }

    fun setAutoRefresh(v: Boolean) = saveSettings(settings().put("autoRefresh", v))
    fun setAllowHY2(v: Boolean) = saveSettings(settings().put("allowHY2", v))
    fun setDnsServer(v: String) {
        val s = v.trim().ifBlank { "1.1.1.1" }
        // v4.12.1: валидный IPv4 (октеты 0–255) или IPv6
        require(isValidDnsAddress(s)) { "invalid dns: $s" }
        saveSettings(settings().put("dnsServer", s))
    }

    /** IPv4 с октетами 0–255 без ведущих нулей, либо IPv6 (hex + ':'). */
    private fun isValidDnsAddress(s: String): Boolean {
        if ('.' in s) {
            val parts = s.split('.')
            if (parts.size != 4) return false
            for (p in parts) {
                if (p.isEmpty() || !p.all { it.isDigit() }) return false
                if (p.length > 1 && p[0] == '0') return false
                val n = p.toIntOrNull() ?: return false
                if (n !in 0..255) return false
            }
            return true
        }
        if (':' in s) {
            if (s.length > 39) return false
            if (!s.all { it in "0123456789abcdefABCDEF:" }) return false
            val groups = s.split(':')
            if (groups.size < 3 || groups.size > 8) return false
            return groups.all { g ->
                g.isEmpty() || (g.length in 1..4 && g.all { it in "0123456789abcdefABCDEF" })
            }
        }
        return false
    }

    fun setSelectedId(id: String?) =
        saveSettings(settings().put("selectedId", id ?: JSONObject.NULL))

    fun selectedServer(): ServerRow? = _servers.value.firstOrNull { it.id == selectedId }

    /**
     * v4.5.0: узел по умолчанию — первый в курируемом порядке [bootstrapRank].
     *
     * Зачем: после вычистки узлов белых списков ([purgeObsoleteServers])
     * selectedId пользователя может указывать на удалённый узел, и кнопка
     * «Подключить» отвечала «нет серверов». Худший возможный UX для человека,
     * который и так не может открыть Telegram. Теперь вместо отказа приложение
     * молча берёт лучший встроенный узел — тот, который только что проверен
     * живым трафиком.
     */
    fun firstBootstrap(): ServerRow? = _servers.value
        .filter { !it.demo && bootstrapRank.containsKey(it.id) }
        .sortedWith(compareBy({ bootstrapRank[it.id] ?: Int.MAX_VALUE }, { it.id }))
        .firstOrNull()

    fun selectedServerJson(): String? = selectedServer()?.json

    /** Параметры TUN для Mobile.buildTunConfig (JSON mobile.TunParams). */
    fun tunParamsJson(): String = JSONObject().apply {
        // v4.1.2: было 9000 (jumbo). На мобильной сети огромный MTU —
        // классическая причина «подключено, но страницы/мессенджеры висят»:
        // большие пакеты не проходят по пути и чернеют (blackhole).
        // 1500 — универсальное безопасное значение.
        put("mtu", 1500)
        put("dnsServer", dnsServer)
        put("logLevel", "warning")
        // v4.1.2: IPv6 внутри туннеля ВЫКЛЮЧЕН. Публичные бесплатные узлы
        // почти всегда без IPv6-выхода: при включённом ULA-адресе и маршруте
        // ::/0 все IPv6-запросы apps уходят в туннель и там умирают —
        // приложение висит до фолбэка (Telegram — особенно). Без IPv6 в tun
        // весь трафик идёт по IPv4 через сервер либо напрямую (если сервер
        // так решит) — предсказуемо.
        put("disableIpv6", true)
    }.toString()

    // ---------- источники ----------

    fun sources(): JSONArray = try {
        JSONArray(sourcesJson)
    } catch (e: Exception) {
        JSONArray()
    }

    fun saveSources(json: String) {
        sourcesJson = json
        writeJson("sources.json", json)
    }

    /** Добавить пользовательский источник (URL подписки). */
    fun addSource(url: String): Boolean {
        val trimmed = url.trim()
        if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) return false
        val arr = sources()
        for (i in 0 until arr.length()) {
            if (arr.getJSONObject(i).optString("url") == trimmed) return false
        }
        val id = "custom-" + Integer.toHexString(trimmed.hashCode())
        arr.put(
            JSONObject().apply {
                put("id", id)
                put("name", trimmed.substringAfterLast('/').take(24).ifBlank { "Подписка" })
                put("url", trimmed)
                put("refreshMinutes", 60)
                put("builtin", false)
                put("enabled", true)
            }
        )
        saveSources(arr.toString())
        return true
    }

    fun setSourceEnabled(id: String, enabled: Boolean) {
        val arr = sources()
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            if (o.optString("id") == id) o.put("enabled", enabled)
        }
        saveSources(arr.toString())
    }

    /**
     * Нормализованный список источников для передачи в ядро.
     *
     * Без защиты здесь был прямой native-вызов: при неготовом ядре — краш.
     * Fallback — отдать sourcesJson как есть: ядро всё равно не запустится,
     * но вызывающий код получит валидную строку и корректную ошибку, а не Error.
     */
    fun normalizedSources(): String =
        Native.call("normalizeSources", fallback = sourcesJson) {
            Mobile.normalizeSources(sourcesJson)
        }

    // ---------- обновление подписок ----------

    /**
     * Загрузить источники, слить со списком, отсортировать. Колбэки — на Go-потоке.
     *
     * ИЗМЕНЕНИЯ:
     *  1. Проверка готовности ядра до вызова — иначе UnsatisfiedLinkError.
     *  2. Защита от повторного входа: `refreshing` уже true → выходим.
     *     Без неё двойной тап по кнопке запускает две параллельные загрузки,
     *     которые потом дерутся при записи servers.json.
     *  3. Таймаут. Это главное средство от «лагает/висит»: Go-сторона зовёт
     *     onFetchDone не всегда (сеть легла, все источники отвалились, гонка при
     *     отмене). Без таймаута `refreshing = true` остаётся навсегда —
     *     кнопка зависает в состоянии «Обновление…» до перезапуска приложения.
     */
    fun refresh(onProgress: (String) -> Unit, onDone: (Boolean, String) -> Unit) {
        if (!Native.ready) {
            onDone(false, Native.userVisibleError ?: "Ядро не загружено")
            return
        }
        if (_ui.value.refreshing) {
            Log.i(FlickerApp.TAG, "refresh уже идёт — повторный вызов проигнорирован")
            return
        }

        setUi { it.copy(refreshing = true, statusText = "Обновление подписок…") }

        // onDone должен сработать РОВНО один раз: либо из Go-колбэка, либо из таймаута.
        val finished = java.util.concurrent.atomic.AtomicBoolean(false)
        fun finish(ok: Boolean, msg: String) {
            if (!finished.compareAndSet(false, true)) return
            timeoutJob?.cancel()
            timeoutJob = null
            setUi { it.copy(refreshing = false) }
            onDone(ok, msg)
        }

        // Circuit breaker: мёртвые источники в запрос не попадают.
        // Без этого ядро на каждом обновлении долбит лежащий хост, пользователь
        // ждёт таймаут, а в логах — шквал HTTP-ошибок.
        val idByName = sourceIdByName()
        val (filtered, skipped) = ctx?.let { c ->
            SourceHealth.filter(c, normalizedSources())
        } ?: (normalizedSources() to emptyList())
        if (skipped.isNotEmpty()) {
            Log.i(FlickerApp.TAG, "пропущено замороженных источников: ${skipped.size}")
            onProgress("Пропущено (заморожены): ${skipped.joinToString(", ")}")
        }

        val started = Native.run("fetchSubscriptions") {
            Mobile.fetchSubscriptions(
                filtered, allowHY2, FETCH_LIMIT,
                object : dev.flicker.mobile.FetchListener {
                    override fun onSourceProgress(resultJSON: String) {
                        try {
                            val o = JSONObject(resultJSON)
                            val name = o.optString("name")
                            val err = o.optString("error")

                            // Кормим circuit breaker: именно здесь видно,
                            // какой источник отдал данные, а какой нет.
                            val id = idByName[name]
                            if (id != null) {
                                ctx?.let { c ->
                                    if (err.isEmpty()) {
                                        SourceHealth.recordSuccess(c, id)
                                    } else {
                                        SourceHealth.recordFailure(
                                            c, id,
                                            httpCodeOf(err),
                                            err.take(120),
                                        )
                                    }
                                }
                            }

                            val text = if (err.isNotEmpty()) "$name: $err"
                            else "$name: +${o.optInt("count")} узл."
                            onProgress(text)
                        } catch (e: Exception) {
                            Log.w(FlickerApp.TAG, "progress", e)
                        }
                    }

                    override fun onFetchDone(resultJSON: String) {
                        try {
                            val o = JSONObject(resultJSON)
                            val incoming = o.optJSONArray("servers")?.toString() ?: "[]"
                            val now = System.currentTimeMillis()
                            val merged = JSONObject(
                                Native.call("mergeServers", fallback = "") {
                                    Mobile.mergeServers(serversJson, incoming, now)
                                }
                            )
                            val mergedArr = merged.optJSONArray("merged")?.toString() ?: "[]"
                            val pruned = Native.call("pruneStale", fallback = mergedArr) {
                                Mobile.pruneStale(mergedArr, now, PRUNE_MAX_AGE_MS)
                            }
                            saveServers(pruned)
                            // v4.4.0: встроенные узлы переживают любое обновление.
                            injectBootstrap()
                            val added = merged.optInt("added")
                            val total = JSONArray(pruned).length()
                            val errors = o.optJSONArray("errors")?.let { a ->
                                (0 until a.length()).joinToString("; ") { a.optString(it) }
                            } ?: ""
                            finish(
                                true,
                                "Подписки: всего $total, новых +$added" +
                                    if (errors.isNotEmpty()) "; ошибки: $errors" else ""
                            )
                        } catch (e: Exception) {
                            Log.e(FlickerApp.TAG, "fetchDone", e)
                            finish(false, "Ошибка слияния: ${e.message}")
                        }
                    }
                })
        }
        if (!started) {
            finish(false, "Не удалось запустить загрузку подписок")
            return
        }

        // Таймаут на весь цикл загрузки.
        timeoutJob = scope.launch {
            delay(FETCH_TIMEOUT_MS)
            if (finished.get()) return@launch
            Log.w(FlickerApp.TAG, "refresh: таймаут ${FETCH_TIMEOUT_MS / 1000}с — принудительно завершаю")
            Native.run("cancelProbe/timeout") { }   // у fetch нет явной отмены в фасаде
            finish(false, "Обновление не завершилось за ${FETCH_TIMEOUT_MS / 1000} с — проверьте сеть")
        }
    }

    /** Одиночный таймаут-джоб обновления подписок. */
    private var timeoutJob: Job? = null

    /** Скоуп для служебных джоб (таймауты). SupervisorJob: падение одной не валит другие. */
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    private const val FETCH_LIMIT = 200L  // v4.12.1: was 25
    private const val FETCH_TIMEOUT_MS = 90_000L

    /**
     * Карта «имя источника → его id».
     *
     * Нужна потому, что Go-ядро в onSourceProgress отдаёт только человекочитаемое
     * имя, а SourceHealth хранит состояние по стабильному id. Без сопоставления
     * circuit breaker не понял бы, к какому источнику относится ошибка.
     */
    private fun sourceIdByName(): Map<String, String> {
        val out = HashMap<String, String>()
        try {
            val arr = JSONArray(sourcesJson)
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                val id = o.optString("id")
                val name = o.optString("name")
                if (id.isNotBlank() && name.isNotBlank()) out[name] = id
            }
        } catch (e: Exception) {
            Log.w(FlickerApp.TAG, "sourceIdByName", e)
        }
        return out
    }

    /**
     * Достаёт HTTP-код из текста ошибки ядра, если он там есть.
     * SourceHealth по нему различает «сломан надолго» (404/403) и «сеть моргнула»
     * (429/5xx) — первое морозит источник сразу на час, второе на минуту.
     */
    private fun httpCodeOf(error: String): Int? {
        val rx = Regex("""(?:HTTP|status|code|\b)(\d{3})\b""", RegexOption.IGNORE_CASE)
        return rx.find(error)?.groupValues?.get(1)?.toIntOrNull()?.takeIf { it in 100..599 }
    }

    private const val PRUNE_MAX_AGE_MS = 7L * 24 * 3600 * 1000 // 7 дней

    // ---------- проверка живости ----------

    /**
     * Проба всех вероятных серверов. Колбэки — на Go-потоке.
     *
     * ИЗМЕНЕНИЯ (те же три проблемы, что в refresh):
     *  1. проверка ядра до native-вызова — иначе UnsatisfiedLinkError;
     *  2. защита от повторного входа: два параллельных probeAll пишут
     *     в servers.json и затирают результаты друг друга;
     *  3. таймаут — без него `probing = true` залипает навсегда, если Go-сторона
     *     не позвала onProbeDone.
     */
    fun probeAll(onStage: (String, JSONObject) -> Unit, onDone: (String) -> Unit) {
        if (!Native.ready) {
            onDone(Native.userVisibleError ?: "Ядро не загружено")
            return
        }
        if (_ui.value.probing) {
            Log.i(FlickerApp.TAG, "probeAll уже идёт — повторный вызов проигнорирован")
            return
        }
        // v4.1.0: пробы НЕ запускаются, пока туннель поднимается или поднят —
        // параллельные JNI-колбэки protectFd и сотни dial'ов пересекаются
        // с трафиком туннеля (подозрение на краш ядра; см. журнал 21:35).
        // После отключения следующий авто-цикл probes возобновит.
        val st = dev.flicker.vpn.data.AppState.status
        if (st == dev.flicker.vpn.data.ServiceStatus.Connecting ||
            st == dev.flicker.vpn.data.ServiceStatus.Connected
        ) {
            Log.i(FlickerApp.TAG, "probeAll пропущен: туннель активен ($st)")
            onDone("")
            return
        }

        val specs = Native.call("probeSpecsFromServers", fallback = "[]") {
            Mobile.probeSpecsFromServers(serversJson, allowHY2)
        }
        val specCount = try {
            JSONArray(specs).length()
        } catch (e: Exception) {
            0
        }
        if (specCount == 0) {
            onDone("Проверять нечего — сначала обновите подписки")
            return
        }

        setUi { it.copy(probing = true, statusText = "Проверка серверов…") }

        val finished = java.util.concurrent.atomic.AtomicBoolean(false)
        fun finish(msg: String) {
            if (!finished.compareAndSet(false, true)) return
            probeTimeoutJob?.cancel()
            probeTimeoutJob = null
            setUi { it.copy(probing = false) }
            onDone(msg)
        }

        val opts = JSONObject().apply {
            put("mode", "full")
            put("concurrency", PROBE_CONCURRENCY)
        }.toString()

        val started = Native.run("probeServers") {
            Mobile.probeServers(specs, opts, object : dev.flicker.mobile.ProbeListener {
                override fun onProbeStage(resultJSON: String) {
                    try {
                        val o = JSONObject(resultJSON)
                        onStage(o.optString("id"), o)
                    } catch (e: Exception) {
                        Log.w(FlickerApp.TAG, "stage", e)
                    }
                }

                override fun onProbeDone(resultJSON: String) {
                    try {
                        val o = JSONObject(resultJSON)
                        if (o.has("error")) {
                            finish("Ошибка: ${o.optString("error")}")
                            return
                        }
                        val results = o.optJSONArray("results")?.toString() ?: "[]"
                        val appliedJson = Native.call("applyProbeResults", fallback = "") {
                            Mobile.applyProbeResults(serversJson, results, System.currentTimeMillis())
                        }
                        if (appliedJson.isNotBlank()) {
                            val applied = JSONObject(appliedJson)
                            saveServers(applied.optJSONArray("servers")?.toString() ?: serversJson)
                            finish("Проверка: живых ${applied.optInt("alive")}/${o.optInt("total")} за ${o.optLong("elapsedMs") / 1000} c")
                        } else {
                            finish("Проверка завершена, но применить результаты не удалось")
                        }
                    } catch (e: Exception) {
                        Log.e(FlickerApp.TAG, "probeDone", e)
                        finish("Ошибка: ${e.message}")
                    }
                }
            })
        }
        if (!started) {
            finish("Не удалось запустить проверку")
            return
        }

        probeTimeoutJob = scope.launch {
            delay(PROBE_TIMEOUT_MS)
            if (finished.get()) return@launch
            Log.w(FlickerApp.TAG, "probeAll: таймаут ${PROBE_TIMEOUT_MS / 1000}с — отменяю")
            Native.run("cancelProbe") { Mobile.cancelProbe() }
            finish("Проверка не завершилась за ${PROBE_TIMEOUT_MS / 1000} с — отменена")
        }
    }

    private var probeTimeoutJob: Job? = null

    /**
     * concurrency было 8. На мобильной сети 8 параллельных TLS-рукопожатий
     * с Reality — заметная просадка канала и риск троттлинга у провайдера.
     * 4 — компромисс: 25 узлов всё ещё проверяются за секунды.
     */
    private const val PROBE_CONCURRENCY = 4
    private const val PROBE_TIMEOUT_MS = 120_000L

    /** Отмена текущей проверки. Безопасно звать в любой момент. */
    fun cancelProbe() {
        Native.run("cancelProbe") { Mobile.cancelProbe() }
    }

    /** Лучший живой сервер (первый в отсортированном списке с ping>=0). */
    fun bestAliveServer(): ServerRow? = _servers.value.firstOrNull { it.alive == 1 && !it.demo }

    // ---------- состояние туннеля ----------

    fun setConnected(connected: Boolean, name: String) {
        setUi { it.copy(connected = connected, connectedName = name) }
    }
}

/** Доступ к Context из сервисов. */
val Context.repo: Repository get() = Repository
