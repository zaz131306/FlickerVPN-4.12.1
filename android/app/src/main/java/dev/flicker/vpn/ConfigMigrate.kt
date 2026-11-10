// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn

import android.util.Log
import org.json.JSONArray
import org.json.JSONObject

/**
 * Миграция конфига sing-box к схеме v1.12+.
 *
 * ---------------------------------------------------------------------------
 *  ЗАЧЕМ ЭТОТ КЛАСС СУЩЕСТВУЕТ
 * ---------------------------------------------------------------------------
 *  Ошибка при подключении к ЛЮБОМУ узлу:
 *
 *      start or reload service: decode config:
 *      dns.servers(1).address: json: unknown field "address"
 *
 *  Причина: в sing-box v1.14.2 схема DNS-серверов переписана.
 *  option/dns.go:
 *
 *      type DNSServerAddressOptions struct {
 *          Server     string `json:"server"`          // БЫЛО "address"
 *          ServerPort uint16 `json:"server_port,omitempty"`
 *      }
 *
 *  Поля "address" больше нет, а парсер конфига собран с DisallowUnknownFields,
 *  поэтому неизвестное поле — это не предупреждение, а фатальная ошибка.
 *  Индекс (1) в сообщении — второй сервер в массиве: первый {"type":"hosts"}
 *  без адреса проходит, а на udp-сервере парсер и падает.
 *
 *  Генерирует этот JSON Go-фасад: native/mobile/mobile.go, BuildTunConfig():
 *
 *      {"type": "udp", "tag": "remote", "address": tun.DNSServer, "detour": ...}
 *
 *  В исходниках Go уже исправлено на "server". НО: libflickerbox.so собирается
 *  отдельно через gomobile (tools/build-libbox-aar.sh, 30–50 минут, нужен Go 1.26
 *  и ~16 ГБ диска). До её пересборки внутри .so остаётся старый генератор.
 *
 *  Поэтому миграция сделана и здесь тоже: конфиг правится ПОСЛЕ того, как его
 *  вернул Mobile.buildTunConfig(), и ДО передачи в libbox. Это чинит ошибку
 *  немедленно, с уже собранной .so, без перекомпиляции ядра.
 *
 * ---------------------------------------------------------------------------
 *  ЧТО СОЗНАТЕЛЬНО НЕ ТРОНУТО
 * ---------------------------------------------------------------------------
 *  В версии 4.0.3 был класс LegacyCfg, который дополнительно:
 *    * убирал sniff / sniff_override_destination / sniff_timeout /
 *      domain_strategy / udp_disable_domain_unmapping из inbounds;
 *    * добавлял в route.rules правила {action:"sniff"} и
 *      {protocol:"dns", action:"hijack-dns"};
 *    * переносил dns.rules[].outbound в route.default_domain_resolver.
 *
 *  В sing-box v1.14.2 всё это НЕ НУЖНО и местами вредно:
 *    * "sniff" на tun-inbound валиден — InboundOptions встроен в
 *      TunInboundOptions, поле объявлено как `json:"sniff,omitempty"`.
 *      Пометка schema:"omit" убирает его только из JSON-схемы для документации,
 *      парсер его по-прежнему принимает;
 *    * "hijack-dns" и "sniff" — действительно валидные RuleAction
 *      (constant/rule.go: RuleActionTypeHijackDNS, RuleActionTypeSniff),
 *      но добавлять их поверх работающего конфига — лишний риск;
 *    * route.default_domain_resolver имеет тип *DomainResolveOptions, то есть
 *      ОБЪЕКТ, а LegacyCfg писал туда СТРОКУ. На конфиге с dns.rules[].outbound
 *      это дало бы новую ошибку парсинга.
 *
 *  Правило: миграция чинит ровно то, что реально отвергает парсер.
 *  Проверено по исходникам option/<имя>.go тега v1.14.2:
 *      dns.servers[].address      — НЕВАЛИДНО  → правим
 *      tun.address                — валидно    → не трогаем
 *      wireguard peer.address     — валидно    → не трогаем
 *      wireguard endpoint.address — валидно    → не трогаем
 *      outbound server/server_port— валидно    → не трогаем
 *      inbound sniff              — валидно    → не трогаем
 */
object ConfigMigrate {

    private const val TAG = FlickerApp.TAG

    /**
     * Поля inbound, удалённые в sing-box 1.13.0. Любое из них, будучи непустым,
     * приводит к фатальной ошибке разбора конфига (см. migrateInbounds).
     */
    private val LEGACY_INBOUND_FIELDS = listOf(
        "sniff",
        "sniff_override_destination",
        "sniff_timeout",
        "domain_strategy",
        "udp_disable_domain_unmapping",
    )

    private const val ACTION_SNIFF = "sniff"
    private const val ACTION_HIJACK_DNS = "hijack-dns"

    /**
     * Приводит конфиг к схеме sing-box v1.14.2.
     *
     * Идемпотентна: повторный вызов на уже мигрированном конфиге ничего не меняет.
     * Никогда не бросает: при любой ошибке разбора возвращает входную строку
     * как есть — пусть libbox выдаст внятную ошибку схемы, а не молчаливый краш.
     */
    fun migrate(configJson: String, logFile: String? = null): String {
        return try {
            val root = JSONObject(configJson)
            var changed = false

            if (migrateDnsServers(root)) changed = true
            if (migrateInbounds(root)) changed = true
            // v4.2.0: auto_route — см. forceAutoRoute
            if (forceAutoRoute(root)) changed = true
            // v4.5.0: прямой резолвер + ipv4_only — см. ensureDirectResolver
            if (ensureDirectResolver(root)) changed = true
            // v4.5.0: журнал ядра в файл — см. applyCoreLog
            if (applyCoreLog(root, logFile)) changed = true

            if (changed) {
                val out = root.toString()
                Log.i(TAG, "ConfigMigrate: конфиг приведён к схеме sing-box 1.14")
                out
            } else {
                configJson
            }
        } catch (e: Throwable) {
            // Ловим Throwable: org.json на некоторых прошивках кидает Error.
            // Возвращаем исходник — лучше внятная ошибка от libbox, чем тишина.
            Log.w(TAG, "ConfigMigrate: не удалось разобрать конфиг, отдаю как есть", e)
            configJson
        }
    }

    /**
     * Убирает legacy-поля из inbounds[] и переносит их в route-правила.
     *
     * ЭТО ФАТАЛЬНАЯ ОШИБКА, А НЕ ПРЕДУПРЕЖДЕНИЕ. В sing-box v1.14.2
     * option/inbound.go при разборе каждого inbound выполняет:
     *
     *     if listenWrapper.TakeListenOptions().InboundOptions != (InboundOptions{}) {
     *         return E.New("legacy inbound fields are deprecated in sing-box 1.11.0
     *                       and removed in sing-box 1.13.0, checkout migration: ...")
     *     }
     *
     * Сравнение идёт со СТАНДАРТНЫМ значением структуры, поэтому достаточно
     * ЛЮБОГО одного непустого поля — и весь конфиг отвергается. Симптом на
     * устройстве: подключение не устанавливается ни к одному узлу.
     *
     * ЛОВУШКА, в которую легко попасть (и в которую я попал при первом разборе):
     * эти поля по-прежнему объявлены в InboundOptions с тегом
     * `json:"sniff,omitempty"` и помечены `schema:"omit"`. То есть по struct-тегам
     * они выглядят валидными, и `aapt`/парсер JSON их принимает. `schema:"omit"`
     * убирает их только из JSON-схемы для документации. Отдельная проверка в
     * UnmarshalJSONContext роняет разбор ПОСЛЕ успешного парсинга.
     *
     * Вывод: «поле есть в структуре» НЕ означает «поле можно передавать».
     * Единственный надёжный источник истины — сам код UnmarshalJSONContext.
     *
     * Сниффинг и перехват DNS переехали в route-правила:
     *     {"action":"sniff"}                      вместо inbound.sniff
     *     {"protocol":"dns","action":"hijack-dns"} вместо перехвата DNS в tun
     * Оба действия валидны (option/rule_action.go, enum:"...,hijack-dns,sniff,resolve"),
     * "protocol" — поле сопоставления из RawDefaultRule.
     *
     * @return true, если конфиг изменён
     */
    private fun migrateInbounds(root: JSONObject): Boolean {
        val inbounds = root.optJSONArray("inbounds") ?: return false

        var hadLegacy = false
        for (i in 0 until inbounds.length()) {
            val inb = inbounds.optJSONObject(i) ?: continue
            for (legacy in LEGACY_INBOUND_FIELDS) {
                if (inb.has(legacy)) {
                    inb.remove(legacy)
                    hadLegacy = true
                }
            }
        }
        if (!hadLegacy) return false

        // Поля убрали — значит сниффинг надо вернуть через route-правила,
        // иначе туннель поднимется, но домены перестанут определяться
        // (VLESS/Trojan с SNI по домену молча перестанут работать).
        ensureRouteRules(root)
        return true
    }

    /**
     * Добавляет в начало route.rules правила sniff и hijack-dns, если их там нет.
     *
     * Порядок важен: правила обходятся сверху вниз, поэтому sniff должен стоять
     * ДО hijack-dns — иначе DNS-пакеты уйдут на перехват не сниффингованными.
     * Существующие правила пользователя сохраняются после них.
     *
     * Идемпотентно: повторный вызов не дублирует правила.
     */
    private fun ensureRouteRules(root: JSONObject) {
        var route = root.optJSONObject("route")
        if (route == null) {
            route = JSONObject()
            root.put("route", route)
        }
        val existing = route.optJSONArray("rules")
        val out = JSONArray()

        var hasSniff = false
        var hasHijack = false
        val rest = JSONArray()
        if (existing != null) {
            for (i in 0 until existing.length()) {
                val r = existing.optJSONObject(i)
                if (r == null) { rest.put(existing.opt(i)); continue }
                when (r.optString("action")) {
                    ACTION_SNIFF -> hasSniff = true
                    ACTION_HIJACK_DNS -> hasHijack = true
                }
                rest.put(r)
            }
        }

        if (!hasSniff) out.put(JSONObject().put("action", ACTION_SNIFF))
        if (!hasHijack) out.put(JSONObject().put("protocol", "dns").put("action", ACTION_HIJACK_DNS))
        for (i in 0 until rest.length()) out.put(rest.get(i))

        route.put("rules", out)
    }

    /**
     * dns.servers[]: "address" → "server" (+ "server_port", если адрес с портом).
     *
     * @return true, если конфиг изменён
     */
    private fun migrateDnsServers(root: JSONObject): Boolean {
        val dns = root.optJSONObject("dns") ?: return false
        val servers = dns.optJSONArray("servers") ?: return false

        var changed = false
        for (i in 0 until servers.length()) {
            val s = servers.optJSONObject(i) ?: continue
            if (!s.has("address")) {
                // v4.4.0: сервер уже новой схемы — остаётся перевести удалённый udp/tcp → DoH
                if (dnsRemoteToDoh(s)) changed = true
                continue
            }

            val address = s.optString("address")
            s.remove("address")

            // Особые адреса без хоста: "local" и "fakeip" — это не транспорт
            // с адресом, а отдельные типы DNS-сервера.
            when (address) {
                "local" -> {
                    s.put("type", "local")
                }

                "fakeip" -> {
                    s.put("type", "fakeip")
                    if (!s.has("inet4_range")) s.put("inet4_range", "198.18.0.0/15")
                }

                else -> {
                    val (host, port) = splitHostPort(address)
                    // тип по умолчанию — udp, если не задан явно
                    if (!s.has("type") || s.optString("type").isBlank()) {
                        s.put("type", "udp")
                    }
                    s.put("server", host)
                    if (port > 0 && !s.has("server_port")) {
                        s.put("server_port", port)
                    }
                }
            }

            // Сопутствующие устаревшие поля из той же схемы DNS-транспорта.
            // "address_resolver" переименован в "domain_resolver"
            // (он есть в AbstractDialerOptions как *DomainResolveOptions).
            if (s.has("address_resolver")) {
                val resolver = s.opt("address_resolver")
                s.remove("address_resolver")
                if (resolver != null && !s.has("domain_resolver")) {
                    s.put("domain_resolver", resolver)
                }
            }
            // Эти два поля удалены из схемы вовсе — парсер их отвергнет.
            s.remove("address_strategy")
            s.remove("address_fallback_delay")

            // v4.4.0: udp → DoH и для мигрированных серверов
            if (dnsRemoteToDoh(s)) changed = true

            changed = true
        }
        return changed
    }

    /**
     * Разрезает "1.1.1.1:5353" на хост и порт.
     *
     * Нужно потому, что в v1.14.2 адрес DNS-сервера задаётся ДВУМЯ полями
     * (server + server_port), а не одной строкой "host:port".
     *
     * IPv6 в квадратных скобках ("[2001:4860:4860::8888]:53") обрабатывается
     * отдельно: наивный поиск последнего ":" порезал бы такой адрес пополам.
     * Голый IPv6 без скобок (несколько ":") НЕ режется — это адрес, а не порт.
     *
     * Порт 0 = «не задан»; тогда server_port не пишется, и sing-box берёт
     * дефолт транспорта (53 для udp/tcp, 853 для tls, 443 для https).
     */
    /**
     * v4.4.0: удалённый DNS-транспорт (udp/tcp ЧЕРЕЗ УЗЕЛ) → DoH на 443.
     *
     * ЭКСПЕРИМЕНТ 2026-10-13 (песочница, живой трафик через sing-box CLI):
     * бесплатные узлы массово блокируют исходящий порт 53, хотя HTTPS-реле
     * через них работает:
     *
     *   узел                реле   DNS-53   DoH-443
     *   185.229.9.79        ОК     ОК       ОК
     *   45.139.24.66        ОК     БЛОК     ОК
     *   delta.linkexo.xyz   ОК     БЛОК     БЛОК
     *
     * На устройстве это выглядит как «Подключено, всё зелёное, но во ВСЕХ
     * приложениях UnknownHostException» — трафик не идёт именно из-за DNS.
     * DoH (Cloudflare 1.1.1.1/dns-query, TCP 443) неотличим от обычного
     * HTTPS и режется только вместе с самим туннелем.
     *
     * Меняем ТОЛЬКО серверы с непустым "detour" (т.е. ходящие через узел);
     * локальные/прямые резолверы не трогаем. Схема v1.14.2 проверена на CLI:
     * type "https" + server + server_port + path + tls.server_name
     * (dns/transport/https.go, RemoteHTTPSDNSServerOptions).
     */
    private fun dnsRemoteToDoh(s: JSONObject): Boolean {
        val type = s.optString("type")
        if (type != "udp" && type != "tcp") return false
        val detour = s.optString("detour")
        if (detour.isEmpty()) return false   // прямой резолвер — не трогаем
        s.remove("server")
        s.remove("server_port")
        s.put("type", "https")
        s.put("server", "1.1.1.1")
        s.put("server_port", 443)
        s.put("path", "/dns-query")
        s.put("tls", JSONObject().apply {
            put("enabled", true)
            put("server_name", "cloudflare-dns.com")
        })
        return true
    }

    internal fun splitHostPort(addr: String): Pair<String, Int> {
        val a = addr.trim()
        if (a.isEmpty()) return "" to 0

        // IPv6 в скобках: [::1]:5353
        if (a.startsWith("[")) {
            val end = a.indexOf(']')
            if (end > 0) {
                val host = a.substring(1, end)
                val rest = a.substring(end + 1)
                if (rest.startsWith(":")) {
                    val p = rest.substring(1).toIntOrNull()
                    if (p != null && p in 1..65535) return host to p
                }
                return host to 0
            }
        }

        // "host:port" — только если двоеточие ровно одно (иначе это голый IPv6)
        val idx = a.lastIndexOf(':')
        if (idx > 0 && a.count { it == ':' } == 1) {
            val host = a.substring(0, idx)
            val p = a.substring(idx + 1).toIntOrNull()
            if (p != null && p in 1..65535) return host to p
            // Порт неразборчив ("1.1.1.1:abc") или вне диапазона ("1.1.1.1:99999").
            // Отбрасываем его и возвращаем хост с портом 0: sing-box возьмёт
            // дефолт транспорта, и VPN заработает.
            //
            // Альтернатива — вернуть строку целиком — означала бы, что одна
            // опечатка в поле DNSsettings лишает пользователя подключения
            // с невнятной ошибкой разрешения имени. Молчаливый дефолт здесь
            // явно лучше: хост-то валидный, сломан только порт.
            Log.w(TAG, "splitHostPort: порт '${a.substring(idx + 1)}' некорректен, использую хост '$host' и порт по умолчанию")
            return host to 0
        }

        return a to 0
    }

    /**
     * Проверка для отладки: возвращает список полей, которые заведомо отвергнет
     * парсер sing-box v1.14.2. Используется в логах, чтобы причина была видна
     * до попытки подключения, а не в виде загадочной ошибки от ядра.
     */
    fun audit(configJson: String): List<String> {
        val problems = mutableListOf<String>()
        try {
            val root = JSONObject(configJson)
            val dns = root.optJSONObject("dns")
            val servers = dns?.optJSONArray("servers")
            if (servers != null) {
                for (i in 0 until servers.length()) {
                    val s = servers.optJSONObject(i) ?: continue
                    for (bad in listOf("address", "address_strategy", "address_fallback_delay")) {
                        if (s.has(bad)) problems += "dns.servers[$i].$bad"
                    }
                    // server обязателен для любого транспорта, кроме hosts/local/fakeip
                    val type = s.optString("type")
                    if (type !in setOf("hosts", "local", "fakeip", "dhcp", "mdns") &&
                        !s.has("server")
                    ) {
                        problems += "dns.servers[$i]: нет поля server (тип $type)"
                    }
                }
            }
            // legacy-поля inbound — фатальная ошибка разбора в v1.14.2
            val inbounds = root.optJSONArray("inbounds")
            if (inbounds != null) {
                for (i in 0 until inbounds.length()) {
                    val inb = inbounds.optJSONObject(i) ?: continue
                    for (legacy in LEGACY_INBOUND_FIELDS) {
                        if (inb.has(legacy)) {
                            problems += "inbounds[$i].$legacy — удалено в sing-box 1.13.0, " +
                                "нужно route-правило {action:sniff}"
                        }
                    }
                }
            }
        } catch (e: Exception) {
            problems += "конфиг не разбирается: ${e.message}"
        }
        return problems
    }

    // ------------------------------------------------------------------
    //  v4.0.7: обход для x86-эмуляторов с ARM-трансляцией (Houdini)
    // ------------------------------------------------------------------
    //
    //  Симптом (BlueStacks/LDPlayer/Nox, x86_64 + libhoudini.so): при тапе
    //  «Подключить» процесс умирает БЕЗ диалога, в системном crash-буфере:
    //
    //      F/libc : Fatal signal 6 (SIGABRT) in tid ... (Thread-9)
    //      backtrace: #00 pc ... /system/lib64/libhoudini.so
    //
    //  Транслятор ARM→x86 не вывозит дефолтный tun-стек «mixed» (gvisor
    //  netstack: плотный unsafe/указатели/сигналы внутри 60-МБ Go-бинарника).
    //  Системный стек («system») отдаёт TCP/IP ядру Android и такой экзотики
    //  не требует. На реальных ARM-устройствах ничего не меняется — там
    //  остаётся оптимальный mixed.

    /**
     * true, если процесс работает на x86 через ARM-трансляцию
     * (Houdini на BlueStacks/LDPlayer/Nox или ndk_translation в AVD API 30+).
     */
    fun isArmTranslated(): Boolean {
        val primary = try {
            android.os.Build.SUPPORTED_ABIS.firstOrNull() ?: ""
        } catch (_: Throwable) { "" }
        if (!primary.startsWith("x86")) return false
        val bridge = try {
            Class.forName("android.os.SystemProperties")
                .getMethod("get", String::class.java, String::class.java)
                .invoke(null, "ro.dalvik.vm.native.bridge", "") as? String
        } catch (_: Throwable) { null }
        if (!bridge.isNullOrEmpty() && bridge != "0") return true
        return java.io.File("/system/lib64/libhoudini.so").exists() ||
            java.io.File("/system/lib/libhoudini.so").exists() ||
            java.io.File("/system/lib64/libndk_translation.so").exists()
    }

    /**
     * Чистая трансформация (без проверки устройства — удобно тестировать):
     * выставляет tun-inbound'ам `"stack": "system"`.
     */
    fun forceSystemStack(configJson: String): String {
        return try {
            val root = JSONObject(configJson)
            val inbounds = root.optJSONArray("inbounds") ?: return configJson
            var changed = false
            for (i in 0 until inbounds.length()) {
                val inb = inbounds.optJSONObject(i) ?: continue
                if (inb.optString("type") == "tun") {
                    inb.put("stack", "system")
                    changed = true
                }
            }
            if (changed) root.toString() else configJson
        } catch (e: Exception) {
            Log.w(FlickerApp.TAG, "forceSystemStack: ${e.message}")
            configJson
        }
    }

    /**
     * Если работаем под ARM-трансляцией — заменяет tun-стек на «system»,
     * иначе возвращает конфиг как есть.
     */
    fun emulatorTunStack(configJson: String): String {
        if (!isArmTranslated()) return configJson
        Log.i(FlickerApp.TAG, "Обнаружена ARM-трансляция (x86-эмулятор): tun stack -> system")
        return forceSystemStack(configJson)
    }

    /**
     * v4.2.0: принудительно выставляет "auto_route": true на tun-inbound.
     *
     * Генератор конфига, зашитый в libflickerbox.so, это поле НЕ пишет, а
     * sing-box трактует его отсутствие как false. Следствие: libbox сообщает
     * приложению TunOptions.getAutoRoute() == false, и openTun() раньше не
     * добавлял дефолтные маршруты в VpnService.Builder. На части прошивок
     * получался VPN, который «включён» (ключик в шторке есть), но НЕ пропускает
     * трафик — «что с VPN, что без VPN одно и то же». Эталонная SFA всегда
     * строит конфиг с auto_route:true. Страховка в openTun() (маршруты
     * безусловно) + этот инжект закрывают проблему с двух сторон.
     */
    private fun forceAutoRoute(root: JSONObject): Boolean {
        val inbounds = root.optJSONArray("inbounds") ?: return false
        var changed = false
        for (i in 0 until inbounds.length()) {
            val inb = inbounds.optJSONObject(i) ?: continue
            if (inb.optString("type") == "tun" && !inb.optBoolean("auto_route", false)) {
                inb.put("auto_route", true)
                changed = true
            }
        }
        return changed
    }

    /**
     * v4.5.0: ПРЯМОЙ резолвер имён + ipv4_only.
     *
     * -----------------------------------------------------------------------
     *  БАГ, который стоил пользователю всего трафика на доменных узлах
     * -----------------------------------------------------------------------
     *  Конфиг ядра (native/mobile/mobile.go, BuildTunConfig) содержит ровно
     *  ОДИН удалённый DNS-сервер, и он ходит ЧЕРЕЗ УЗЕЛ:
     *
     *      dns.servers = [ {type:hosts}, {type:udp→https(DoH), detour:<узел>} ]
     *      dns.final   = "remote"
     *
     *  Если сам узел задан ДОМЕНОМ (ru-1-2.unturned-rust-dead.lol,
     *  maple.hubnori.ink, ember.datanexi.store, swerka.loknietotop.digital…),
     *  то чтобы соединиться с узлом, sing-box должен сначала разрешить его
     *  имя. Он идёт в DNS-роутер → единственный сервер → DoH → который
     *  поедет через этот же самый ещё не подключённый узел. Замкнутый круг.
     *
     *  sing-box его обнаруживает и рвёт запрос:
     *
     *      ERROR connection: open connection to api.ipify.org:443 using
     *      outbound/vless[out]: lookup swerka.loknietotop.digital:
     *      DNS query loopback in transport[doh]
     *
     *  Воспроизведено в песочнице на sing-box CLI v1.14.2 (2026-10-13):
     *  с доменным узлом и единственным DNS через него — 000/ошибка на ВСЕХ
     *  трёх целях; после добавления default_domain_resolver тот же узел даёт
     *  ipify=200, api.telegram.org=404, instagram=200.
     *
     *  ЛЕЧЕНИЕ: второй DNS-сервер БЕЗ detour (значит — прямой сокет, на
     *  Android он protect()'нут через autoDetectInterfaceControl и идёт мимо
     *  туннеля) и route.default_domain_resolver, который sing-box использует
     *  именно для имён в dial-полях (option/route.go:18,
     *  option/outbound.go:104 — DomainResolveOptions, MarshalJSON принимает
     *  просто строку-тэг сервера).
     *
     *  Заодно strategy=ipv4_only: в tun IPv6 выключен (Repository.tunParamsJson
     *  disableIpv6=true), а дефолтная prefer_ipv4 возвращает и AAAA тоже —
     *  приложение пробует IPv6-адрес и виснет до фолбэка.
     */
    private const val RESOLVER_TAG = "flicker-resolver"

    private fun ensureDirectResolver(root: JSONObject): Boolean {
        val dns = root.optJSONObject("dns") ?: return false
        val servers = dns.optJSONArray("servers") ?: return false

        var changed = false
        if (dns.optString("strategy") != "ipv4_only") {
            dns.put("strategy", "ipv4_only")
            changed = true
        }

        var hasResolver = false
        for (i in 0 until servers.length()) {
            if (servers.optJSONObject(i)?.optString("tag") == RESOLVER_TAG) { hasResolver = true; break }
        }
        if (!hasResolver) {
            servers.put(
                JSONObject()
                    .put("type", "https")
                    .put("tag", RESOLVER_TAG)
                    .put("server", "1.1.1.1")
                    .put("server_port", 443)
                    .put("path", "/dns-query")
                    // НАМЕРЕННО без "detour": отсутствие detour = прямой dial.
                    // (detour на direct-outbound sing-box отвергает:
                    //  "detour to an empty direct outbound makes no sense".)
                    .put(
                        "tls", JSONObject()
                            .put("enabled", true)
                            .put("server_name", "cloudflare-dns.com")
                    )
            )
            changed = true
        }

        val route = root.optJSONObject("route") ?: return changed
        if (route.optString("default_domain_resolver") != RESOLVER_TAG) {
            route.put("default_domain_resolver", RESOLVER_TAG)
            changed = true
        }
        return changed
    }

    /**
     * v4.5.0: журнал ядра — В ФАЙЛ, а не только через CommandClient.
     *
     * В отчёте пользователя за 2026-10-13 раздел «ЖУРНАЛ ЯДРА» пуст при том,
     * что туннель поднимался 8 раз подряд и на каждом узле что-то отказывало.
     * CommandClient(CommandLog) в этот раз не принёс ни строки — а это
     * источник строк вида
     *   "connection: open connection to … using outbound/vless[out]: <причина>"
     * Без них диагностика вслепую.
     *
     * log/log.go New():
     *   switch logOptions.Output {
     *   case "":            logWriter = options.DefaultWriter   // -> libbox
     *   case "stderr":      …
     *   default:            logWriter = io.Discard
     *                       logFilePath = logOptions.Output     // -> файл
     *   }
     *   NewDefaultFactory(ctx, formatter, logWriter, logFilePath,
     *                     options.PlatformWriter, options.Observable)
     *
     * КЛЮЧЕВОЕ: PlatformWriter и Observable передаются В ОБА ветки, то есть
     * файловый вывод НЕ отключает поток в libbox/CommandClient. Получаем оба
     * канала сразу; если один молчит — второй всё равно запишет причину.
     *
     * Уровень info (не trace): trace логирует каждый пакет, на M21 это
     * лишняя нагрузка; info/warn/error покрывают все отказы соединений.
     */
    private fun applyCoreLog(root: JSONObject, logFile: String?): Boolean {
        if (logFile.isNullOrEmpty()) return false
        val log = root.optJSONObject("log") ?: JSONObject().also { root.put("log", it) }
        var changed = false
        if (log.optString("level") != "info") { log.put("level", "info"); changed = true }
        if (log.optString("output") != logFile) { log.put("output", logFile); changed = true }
        if (!log.optBoolean("timestamp", false)) { log.put("timestamp", true); changed = true }
        return changed
    }

    /**
     * v4.2.0: режим «Прокси» (метод ByeByeDPI-x-tg): вместо TUN — локальный
     * SOCKS5-inbound на 127.0.0.1:[port]. Системный VPN не поднимается
     * (разрешение ОС не нужно, ключика в шторке нет), клиент прописывается
     * вручную — например, Telegram умеет SOCKS5-прокси прямо в настройках.
     * dns/route/outbounds сохраняются: sing-box сам резолвит имена и уносит
     * всё на зарубежный узел, а ТСПУ видит лишь соединение до узла.
     */
    fun toProxyConfig(configJson: String, port: Int): String {
        return try {
            val root = JSONObject(configJson)
            val socks = JSONObject()
                .put("type", "socks")
                .put("tag", "proxy-in")
                .put("listen", "127.0.0.1")
                .put("listen_port", port)
            root.put("inbounds", JSONArray().put(socks))
            root.toString()
        } catch (e: Throwable) {
            Log.w(FlickerApp.TAG, "toProxyConfig: ${e.message}")
            configJson
        }
    }
}

