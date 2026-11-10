// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Тесты миграции конфига sing-box к схеме v1.14.2.
 *
 * Регрессия на реальную ошибку с устройства:
 *   start or reload service: decode config:
 *   dns.servers(1).address: json: unknown field "address"
 *
 * Эти тесты — единственная автоматическая защита от того, что миграцию
 * кто-нибудь удалит или сломает. Без них ошибка вернётся молча: сборка
 * пройдёт, а падать будет только при подключении к узлу.
 */
class ConfigMigrateTest {

    /** Ровно тот конфиг, который генерит старый Mobile.buildTunConfig(). */
    private fun legacyConfig(dnsAddr: String = "1.1.1.1") = JSONObject().apply {
        put("log", JSONObject().put("level", "warning"))
        put("dns", JSONObject().apply {
            put("servers", JSONArray().apply {
                put(JSONObject().put("type", "hosts").put("tag", "hosts"))
                put(JSONObject().put("type", "udp").put("tag", "remote")
                    .put("address", dnsAddr).put("detour", "flicker-out"))
            })
            put("final", "remote")
        })
        put("inbounds", JSONArray().apply {
            put(JSONObject().put("type", "tun").put("tag", "tun-in")
                .put("address", JSONArray().put("172.19.0.1/30"))
                .put("mtu", 9000).put("sniff", true))
        })
        put("route", JSONObject().put("final", "flicker-out").put("auto_detect_interface", true))
    }.toString()

    private fun dnsServer(json: String, index: Int): JSONObject =
        JSONObject(json).getJSONObject("dns").getJSONArray("servers").getJSONObject(index)

    // --- основная регрессия ---------------------------------------------------

    @Test
    fun `address заменяется на server`() {
        val out = ConfigMigrate.migrate(legacyConfig("1.1.1.1"))
        val s = dnsServer(out, 1)
        assertFalse("поле address должно быть удалено", s.has("address"))
        // v4.4.0: сервер с detour (ходит через узел) переводится на DoH-443:
        // бесплатные узлы массово режут порт 53, а 443 неотличим от HTTPS.
        assertEquals("https", s.getString("type"))
        assertEquals("1.1.1.1", s.getString("server"))
        assertEquals(443, s.getInt("server_port"))
        assertEquals("/dns-query", s.getString("path"))
        assertEquals("cloudflare-dns.com", s.getJSONObject("tls").getString("server_name"))
        assertEquals(true, s.getJSONObject("tls").getBoolean("enabled"))
        assertEquals("remote", s.getString("tag"))
        assertEquals("flicker-out", s.getString("detour"))
    }

    @Test
    fun `hosts-сервер не трогается`() {
        val out = ConfigMigrate.migrate(legacyConfig())
        val s = dnsServer(out, 0)
        assertEquals("hosts", s.getString("type"))
        assertEquals("hosts", s.getString("tag"))
        assertFalse("у hosts не должно появиться поле server", s.has("server"))
    }

    @Test
    fun `адрес с портом разделяется на server и server_port`() {
        // Без detour: прямой резолвер DoH-конверсии не подлежит.
        val cfg = JSONObject().apply {
            put("dns", JSONObject().put("servers", JSONArray().apply {
                put(JSONObject().put("address", "8.8.8.8:5353").put("tag", "direct-dns"))
            }))
        }.toString()
        val s = dnsServer(ConfigMigrate.migrate(cfg), 0)
        assertEquals("8.8.8.8", s.getString("server"))
        assertEquals(5353, s.getInt("server_port"))
        assertEquals("udp", s.getString("type"))
    }

    @Test
    fun `порт по умолчанию не пишется`() {
        // server_port не должен появляться, если порт не задан:
        // sing-box сам возьмёт дефолт транспорта. Без detour — без DoH.
        val cfg = JSONObject().apply {
            put("dns", JSONObject().put("servers", JSONArray().apply {
                put(JSONObject().put("address", "1.0.0.1").put("tag", "cf"))
            }))
        }.toString()
        assertFalse(dnsServer(ConfigMigrate.migrate(cfg), 0).has("server_port"))
    }

    @Test
    fun `тип подставляется, если не задан`() {
        val cfg = JSONObject().apply {
            put("dns", JSONObject().put("servers", JSONArray().apply {
                put(JSONObject().put("address", "9.9.9.9").put("tag", "quad9"))
            }))
        }.toString()
        val s = dnsServer(ConfigMigrate.migrate(cfg), 0)
        // v4.4.0: недостающий тип дополняется udp; без detour остаётся udp
        assertEquals("udp", s.getString("type"))
        assertEquals("9.9.9.9", s.getString("server"))
    }

    @Test
    fun `udp-сервер без detour не конвертируется в DoH`() {
        val cfg = JSONObject().apply {
            put("dns", JSONObject().put("servers", JSONArray().apply {
                put(JSONObject().put("type", "udp").put("tag", "plain")
                    .put("server", "9.9.9.9"))
            }))
        }.toString()
        val s = dnsServer(ConfigMigrate.migrate(cfg), 0)
        assertEquals("udp", s.getString("type"))
        assertEquals("9.9.9.9", s.getString("server"))
    }

    @Test
    fun `DoH-конверсия идемпотентна`() {
        val once = ConfigMigrate.migrate(legacyConfig())
        val twice = ConfigMigrate.migrate(once)
        assertEquals(once, twice)
    }

    // --- особые адреса --------------------------------------------------------

    @Test
    fun `local становится типом local без server`() {
        val cfg = JSONObject().apply {
            put("dns", JSONObject().put("servers", JSONArray().apply {
                put(JSONObject().put("address", "local").put("tag", "local"))
            }))
        }.toString()
        val s = dnsServer(ConfigMigrate.migrate(cfg), 0)
        assertEquals("local", s.getString("type"))
        assertFalse(s.has("address"))
        assertFalse("у local не должно быть server", s.has("server"))
    }

    @Test
    fun `fakeip получает inet4_range`() {
        val cfg = JSONObject().apply {
            put("dns", JSONObject().put("servers", JSONArray().apply {
                put(JSONObject().put("address", "fakeip").put("tag", "fakeip"))
            }))
        }.toString()
        val s = dnsServer(ConfigMigrate.migrate(cfg), 0)
        assertEquals("fakeip", s.getString("type"))
        assertEquals("198.18.0.0/15", s.getString("inet4_range"))
    }

    @Test
    fun `существующий inet4_range у fakeip не перезаписывается`() {
        val cfg = JSONObject().apply {
            put("dns", JSONObject().put("servers", JSONArray().apply {
                put(JSONObject().put("address", "fakeip").put("inet4_range", "100.64.0.0/10"))
            }))
        }.toString()
        assertEquals("100.64.0.0/10", dnsServer(ConfigMigrate.migrate(cfg), 0).getString("inet4_range"))
    }

    // --- сопутствующие устаревшие поля ----------------------------------------

    @Test
    fun `address_resolver переносится в domain_resolver`() {
        val cfg = JSONObject().apply {
            put("dns", JSONObject().put("servers", JSONArray().apply {
                put(JSONObject().put("address", "1.1.1.1").put("address_resolver", "local"))
            }))
        }.toString()
        val s = dnsServer(ConfigMigrate.migrate(cfg), 0)
        assertFalse(s.has("address_resolver"))
        assertEquals("local", s.getString("domain_resolver"))
    }

    @Test
    fun `address_strategy и address_fallback_delay удаляются`() {
        val cfg = JSONObject().apply {
            put("dns", JSONObject().put("servers", JSONArray().apply {
                put(JSONObject().put("address", "1.1.1.1")
                    .put("address_strategy", "ipv4_only")
                    .put("address_fallback_delay", "5s"))
            }))
        }.toString()
        val s = dnsServer(ConfigMigrate.migrate(cfg), 0)
        assertFalse(s.has("address_strategy"))
        assertFalse(s.has("address_fallback_delay"))
        assertEquals("1.1.1.1", s.getString("server"))
    }

    // --- то, что НЕ должно меняться -------------------------------------------

    @Test
    fun `tun address и mtu остаются, а sniff удаляется`() {
        // TunInboundOptions.Address объявлен как `json:"address"` и в v1.14.2
        // он ВАЛИДЕН — миграция не имеет права его трогать.
        //
        // А вот `sniff` — НЕвалиден, несмотря на то что поле по-прежнему объявлено
        // в InboundOptions с тегом json:"sniff,omitempty". option/inbound.go
        // сравнивает InboundOptions с нулевым значением структуры и на любом
        // непустом поле возвращает E.New(...) — фатальную ошибку разбора.
        //
        // Этот тест раньше утверждал обратное ("tun.sniff валиден через
        // InboundOptions") и тем закреплял ошибку разбора: я смотрел на
        // struct-теги, а не на код UnmarshalJSONContext. Теперь ассерт
        // соответствует реальному поведению sing-box v1.14.2.
        val out = ConfigMigrate.migrate(legacyConfig())
        val tun = JSONObject(out).getJSONArray("inbounds").getJSONObject(0)
        assertTrue("tun.address должен остаться", tun.has("address"))
        assertEquals(9000, tun.getInt("mtu"))
        assertEquals("tun", tun.getString("type"))
        assertFalse("sniff должен быть удалён — иначе конфиг отвергается целиком", tun.has("sniff"))
    }

    @Test
    fun `route и log не меняются`() {
        val out = ConfigMigrate.migrate(legacyConfig())
        val root = JSONObject(out)
        assertEquals("warning", root.getJSONObject("log").getString("level"))
        assertEquals(true, root.getJSONObject("route").getBoolean("auto_detect_interface"))
        assertEquals("flicker-out", root.getJSONObject("route").getString("final"))
    }

    // --- идемпотентность и устойчивость ---------------------------------------

    @Test
    fun `миграция идемпотентна`() {
        val once = ConfigMigrate.migrate(legacyConfig())
        val twice = ConfigMigrate.migrate(once)
        // второй прогон не должен ничего менять
        assertEquals(JSONObject(once).toString(), JSONObject(twice).toString())
    }

    @Test
    fun `конфиг без dns проходит без изменений`() {
        val cfg = JSONObject().put("outbounds", JSONArray()).toString()
        assertEquals(cfg, ConfigMigrate.migrate(cfg))
    }

    @Test
    fun `битый JSON возвращается как есть, а не роняет приложение`() {
        val garbage = "{ это не json"
        assertEquals(garbage, ConfigMigrate.migrate(garbage))
    }

    @Test
    fun `пустой список серверов не роняет миграцию`() {
        val cfg = JSONObject().apply {
            put("dns", JSONObject().put("servers", JSONArray()))
        }.toString()
        // v4.5.0: конфиг больше не возвращается байт-в-байт — ensureDirectResolver
        // всегда добавляет прямой резолвер и strategy. Важно, что не падает.
        val out = ConfigMigrate.migrate(cfg)
        val root = JSONObject(out)
        assertEquals(1, root.getJSONObject("dns").getJSONArray("servers").length())
    }

    // --- v4.5.0: прямой резолвер (DNS query loopback) -------------------------

    /**
     * Регрессия на отчёт пользователя от 2026-10-13.
     *
     * Единственный DNS-сервер конфига ходит через узел (detour). Если сам узел
     * задан доменом, sing-box не может разрешить его имя и рвёт запрос:
     *   lookup <узел>: DNS query loopback in transport[doh]
     * Воспроизведено на sing-box CLI v1.14.2. Лечится вторым DNS-сервером БЕЗ
     * detour и route.default_domain_resolver, указывающим на него.
     */
    @Test
    fun `добавляется прямой резолвер без detour`() {
        val out = ConfigMigrate.migrate(legacyConfig())
        val servers = JSONObject(out).getJSONObject("dns").getJSONArray("servers")
        var resolver: JSONObject? = null
        for (i in 0 until servers.length()) {
            val s = servers.getJSONObject(i)
            if (s.optString("tag") == "flicker-resolver") resolver = s
        }
        assertTrue("прямой резолвер не добавлен", resolver != null)
        resolver!!
        assertFalse("у прямого резолвера не должно быть detour — иначе снова loopback",
            resolver.has("detour"))
        assertEquals("https", resolver.getString("type"))
        assertEquals("1.1.1.1", resolver.getString("server"))
        assertEquals(443, resolver.getInt("server_port"))
        assertEquals("/dns-query", resolver.getString("path"))
        assertEquals("cloudflare-dns.com", resolver.getJSONObject("tls").getString("server_name"))
    }

    @Test
    fun `route получает default_domain_resolver`() {
        val out = ConfigMigrate.migrate(legacyConfig())
        assertEquals("flicker-resolver",
            JSONObject(out).getJSONObject("route").getString("default_domain_resolver"))
    }

    @Test
    fun `dns strategy - только IPv4`() {
        // В tun IPv6 выключен (Repository.tunParamsJson disableIpv6=true),
        // а дефолтная prefer_ipv4 отдаёт и AAAA — приложение пробует IPv6 и виснет.
        val out = ConfigMigrate.migrate(legacyConfig())
        assertEquals("ipv4_only", JSONObject(out).getJSONObject("dns").getString("strategy"))
    }

    @Test
    fun `основной DNS через узел остаётся первым в final`() {
        val out = ConfigMigrate.migrate(legacyConfig())
        val dns = JSONObject(out).getJSONObject("dns")
        assertEquals("remote", dns.getString("final"))
        // final-сервер обязан идти через узел, иначе IP утекает на прямого провайдера
        val servers = dns.getJSONArray("servers")
        var remote: JSONObject? = null
        for (i in 0 until servers.length()) {
            val s = servers.getJSONObject(i)
            if (s.optString("tag") == "remote") remote = s
        }
        assertEquals("flicker-out", remote!!.getString("detour"))
    }

    // --- v4.5.0: журнал ядра в файл -------------------------------------------

    /**
     * В отчёте от 2026-10-13 раздел «ЖУРНАЛ ЯДРА» был пуст при восьми попытках
     * подключения: CommandClient(CommandLog) не принёс ни строки, и причина
     * отказа каждого узла осталась неизвестной. log.output — второй, независимый
     * канал (log/log.go: PlatformWriter передаётся в обе ветки switch).
     */
    @Test
    fun `log output пишется в конфиг`() {
        val out = ConfigMigrate.migrate(legacyConfig(), "/data/user/0/dev.flicker.vpn/files/box/core-file.log")
        val log = JSONObject(out).getJSONObject("log")
        assertEquals("/data/user/0/dev.flicker.vpn/files/box/core-file.log", log.getString("output"))
        assertEquals("info", log.getString("level"))
        assertTrue(log.getBoolean("timestamp"))
    }

    @Test
    fun `без пути к файлу log не трогается`() {
        val out = ConfigMigrate.migrate(legacyConfig())
        val log = JSONObject(out).getJSONObject("log")
        assertEquals("warning", log.getString("level"))
        assertFalse(log.has("output"))
    }

    @Test
    fun `миграция с log output идемпотентна`() {
        val f = "/tmp/core-file.log"
        val once = ConfigMigrate.migrate(legacyConfig(), f)
        val twice = ConfigMigrate.migrate(once, f)
        assertEquals(JSONObject(once).toString(), JSONObject(twice).toString())
    }

    // --- splitHostPort --------------------------------------------------------

    @Test
    fun `splitHostPort - обычные адреса`() {
        assertEquals("1.1.1.1" to 0, ConfigMigrate.splitHostPort("1.1.1.1"))
        assertEquals("1.1.1.1" to 53, ConfigMigrate.splitHostPort("1.1.1.1:53"))
        assertEquals("dns.google" to 853, ConfigMigrate.splitHostPort("dns.google:853"))
        assertEquals(" 8.8.8.8 " .trim() to 0, ConfigMigrate.splitHostPort("  8.8.8.8  "))
    }

    @Test
    fun `splitHostPort - IPv6`() {
        // Голый IPv6 НЕ должен резаться по последнему двоеточию
        assertEquals("2001:4860:4860::8888" to 0,
            ConfigMigrate.splitHostPort("2001:4860:4860::8888"))
        // IPv6 в скобках с портом — должен
        assertEquals("2001:4860:4860::8888" to 53,
            ConfigMigrate.splitHostPort("[2001:4860:4860::8888]:53"))
        assertEquals("::1" to 0, ConfigMigrate.splitHostPort("[::1]"))
    }

    @Test
    fun `splitHostPort - некорректный порт игнорируется`() {
        assertEquals("1.1.1.1" to 0, ConfigMigrate.splitHostPort("1.1.1.1:abc"))
        assertEquals("1.1.1.1" to 0, ConfigMigrate.splitHostPort("1.1.1.1:0"))
        assertEquals("1.1.1.1" to 0, ConfigMigrate.splitHostPort("1.1.1.1:99999"))
        assertEquals("" to 0, ConfigMigrate.splitHostPort(""))
    }

    // --- audit ----------------------------------------------------------------

    @Test
    fun `audit находит немигрированный конфиг`() {
        val problems = ConfigMigrate.audit(legacyConfig())
        assertTrue("audit должен найти dns.servers[1].address: $problems",
            problems.any { "dns.servers[1].address" in it })
    }

    @Test
    fun `audit на мигрированном конфиге чист`() {
        val problems = ConfigMigrate.audit(ConfigMigrate.migrate(legacyConfig()))
        assertTrue("audit должен быть пуст, получено: $problems", problems.isEmpty())
    }

    @Test
    fun `audit на битом JSON сообщает об этом, а не падает`() {
        val problems = ConfigMigrate.audit("не json")
        assertTrue(problems.isNotEmpty())
        assertTrue(problems[0].contains("не разбирается"))
    }

    // --- РЕГРЕССИЯ: legacy inbound fields (фатальная ошибка в v1.14.2) -------
    //
    // sing-box option/inbound.go:
    //   if TakeListenOptions().InboundOptions != (InboundOptions{}) {
    //       return E.New("legacy inbound fields are deprecated in sing-box 1.11.0
    //                     and removed in sing-box 1.13.0, ...")
    //   }
    // Это E.New, то есть фатально: любое непустое поле из списка отвергает ВЕСЬ
    // конфиг. На устройстве выглядит как «не подключается ни к одному узлу».

    private fun tunInbound(json: String) =
        JSONObject(json).getJSONArray("inbounds").getJSONObject(0)

    private fun routeRules(json: String): JSONArray =
        JSONObject(json).getJSONObject("route").getJSONArray("rules")

    @Test
    fun `sniff удаляется из tun inbound`() {
        val before = tunInbound(legacyConfig())
        assertTrue("в исходном конфиге sniff должен быть", before.has("sniff"))

        val after = tunInbound(ConfigMigrate.migrate(legacyConfig()))
        assertFalse("sniff должен быть удалён", after.has("sniff"))
    }

    @Test
    fun `все пять legacy-полей inbound удаляются`() {
        val cfg = JSONObject().apply {
            put("inbounds", JSONArray().put(JSONObject().apply {
                put("type", "tun"); put("tag", "tun-in")
                put("sniff", true)
                put("sniff_override_destination", true)
                put("sniff_timeout", "300ms")
                put("domain_strategy", "ipv4_only")
                put("udp_disable_domain_unmapping", true)
            }))
        }.toString()
        val inb = tunInbound(ConfigMigrate.migrate(cfg))
        for (f in listOf("sniff","sniff_override_destination","sniff_timeout",
                           "domain_strategy","udp_disable_domain_unmapping")) {
            assertFalse("поле $f должно быть удалено", inb.has(f))
        }
        // сами настройки туннеля не должны пострадать
        assertEquals("tun", inb.getString("type"))
        assertEquals("tun-in", inb.getString("tag"))
    }

    @Test
    fun `вместо sniff добавляются route-правила sniff и hijack-dns`() {
        val rules = routeRules(ConfigMigrate.migrate(legacyConfig()))
        assertEquals("должно быть ровно 2 правила", 2, rules.length())
        assertEquals("sniff", rules.getJSONObject(0).getString("action"))
        assertEquals("dns", rules.getJSONObject(1).getString("protocol"))
        assertEquals("hijack-dns", rules.getJSONObject(1).getString("action"))
    }

    @Test
    fun `sniff идёт ПЕРЕД hijack-dns`() {
        // Порядок важен: правила обходятся сверху вниз. Если hijack-dns окажется
        // первым, DNS-пакеты уйдут на перехват не сниффингованными.
        val rules = routeRules(ConfigMigrate.migrate(legacyConfig()))
        assertEquals("sniff", rules.getJSONObject(0).getString("action"))
        assertEquals("hijack-dns", rules.getJSONObject(1).getString("action"))
    }

    @Test
    fun `существующие route-правила сохраняются после добавленных`() {
        val cfg = JSONObject().apply {
            put("inbounds", JSONArray().put(JSONObject().put("type","tun").put("sniff", true)))
            put("route", JSONObject().put("rules", JSONArray().apply {
                put(JSONObject().put("domain_suffix", "example.com").put("outbound", "direct"))
            }))
        }.toString()
        val rules = routeRules(ConfigMigrate.migrate(cfg))
        assertEquals(3, rules.length())
        assertEquals("sniff", rules.getJSONObject(0).getString("action"))
        assertEquals("hijack-dns", rules.getJSONObject(1).getString("action"))
        assertEquals("example.com", rules.getJSONObject(2).getString("domain_suffix"))
    }

    @Test
    fun `route-правила не дублируются при повторной миграции`() {
        val once = ConfigMigrate.migrate(legacyConfig())
        val twice = ConfigMigrate.migrate(once)
        assertEquals(2, routeRules(twice).length())
        assertEquals(JSONObject(once).toString(), JSONObject(twice).toString())
    }

    @Test
    fun `если sniff уже нет - route-правила не добавляются`() {
        // Идемпотентность: конфиг без legacy-полей не должен меняться вообще.
        // Иначе миграция добавляла бы правила к конфигу, где пользователь
        // намеренно их не заводил.
        // v4.2.0: auto_route:true в INPUT — единственное легальное изменение
        // migrate() теперь это инжект (см. forceAutoRoute); с ним конфиг
        // снова обязан выйти байт-в-байт.
        val cfg = JSONObject().apply {
            put("inbounds", JSONArray().put(JSONObject().put("type","tun").put("tag","tun-in").put("auto_route", true)))
            put("route", JSONObject().put("final","out"))
        }.toString()
        val out = ConfigMigrate.migrate(cfg)
        assertEquals(cfg, out)
        assertFalse("route не должен появиться", JSONObject(out).getJSONObject("route").has("rules"))
    }

    @Test
    fun `существующее правило sniff не дублируется`() {
        val cfg = JSONObject().apply {
            put("inbounds", JSONArray().put(JSONObject().put("type","tun").put("sniff", true)))
            put("route", JSONObject().put("rules", JSONArray().apply {
                put(JSONObject().put("action", "sniff"))
            }))
        }.toString()
        val rules = routeRules(ConfigMigrate.migrate(cfg))
        val sniffs = (0 until rules.length()).count { rules.getJSONObject(it).optString("action") == "sniff" }
        assertEquals("sniff должен остаться один", 1, sniffs)
    }

    @Test
    fun `audit находит legacy sniff`() {
        val problems = ConfigMigrate.audit(legacyConfig())
        assertTrue("audit должен найти inbounds[0].sniff: $problems",
            problems.any { "inbounds[0].sniff" in it })
    }

    @Test
    fun `audit на мигрированном конфиге чист и по sniff тоже`() {
        val problems = ConfigMigrate.audit(ConfigMigrate.migrate(legacyConfig()))
        assertTrue("audit должен быть пуст, получено: $problems", problems.isEmpty())
    }

    @Test
    fun forceSystemStack_setsSystemOnTunInbound() {
        val cfg = """{"inbounds":[{"type":"tun","tag":"tun-in","address":["172.19.0.1/30"],"mtu":9000}],"route":{}}"""
        val out = ConfigMigrate.forceSystemStack(cfg)
        val root = org.json.JSONObject(out)
        org.junit.Assert.assertEquals(
            "system",
            root.getJSONArray("inbounds").getJSONObject(0).getString("stack")
        )
    }

    @Test
    fun forceSystemStack_keepsInvalidJsonAsIs() {
        org.junit.Assert.assertEquals("not json", ConfigMigrate.forceSystemStack("not json"))
    }

    @Test
    fun migrate_injectsAutoRouteOnTunInbound() {
        val cfg = """{"inbounds":[{"type":"tun","tag":"tun-in","address":["172.19.0.1/30"],"mtu":1500}],"dns":{"servers":[]}}"""
        val out = ConfigMigrate.migrate(cfg)
        val root = org.json.JSONObject(out)
        org.junit.Assert.assertTrue(
            "auto_route обязан появиться на tun-inbound",
            root.getJSONArray("inbounds").getJSONObject(0).getBoolean("auto_route")
        )
    }

    @Test
    fun toProxyConfig_replacesTunWithSocks() {
        val cfg = """{"inbounds":[{"type":"tun","tag":"tun-in","auto_route":true}],"outbounds":[{"type":"direct","tag":"d"}],"route":{"final":"d"}}"""
        val out = ConfigMigrate.toProxyConfig(cfg, 10808)
        val root = org.json.JSONObject(out)
        val inb = root.getJSONArray("inbounds")
        org.junit.Assert.assertEquals(1, inb.length())
        org.junit.Assert.assertEquals("socks", inb.getJSONObject(0).getString("type"))
        org.junit.Assert.assertEquals("127.0.0.1", inb.getJSONObject(0).getString("listen"))
        org.junit.Assert.assertEquals(10808, inb.getJSONObject(0).getInt("listen_port"))
        // остальной конфиг не пострадал
        org.junit.Assert.assertEquals("d", root.getJSONObject("route").getString("final"))
        org.junit.Assert.assertEquals(1, root.getJSONArray("outbounds").length())
    }

    @Test
    fun toProxyConfig_invalidJson_returnedAsIs() {
        org.junit.Assert.assertEquals("мусор", ConfigMigrate.toProxyConfig("мусор", 10808))
    }

    @Test
    fun migrate_dnsUdpWithDetourBecomesDoh() {
        // v4.4.0: udp/tcp-резолвер, ходящий ЧЕРЕЗ УЗЕЛ (detour), переводится
        // на DoH-443: бесплатные узлы массово режут порт 53 (эксперимент
        // 2026-10-13), а 443 неотличим от HTTPS.
        val cfg = """{"dns":{"final":"remote","servers":[{"tag":"hosts","type":"hosts"},{"tag":"remote","type":"udp","server":"1.1.1.1","detour":"out"}]},"inbounds":[{"type":"tun","tag":"t","auto_route":true}]}"""
        val out = ConfigMigrate.migrate(cfg)
        val servers = org.json.JSONObject(out).getJSONObject("dns").getJSONArray("servers")
        val s1 = servers.getJSONObject(1)
        org.junit.Assert.assertEquals("https", s1.getString("type"))
        org.junit.Assert.assertEquals("1.1.1.1", s1.getString("server"))
        org.junit.Assert.assertEquals(443, s1.getInt("server_port"))
        org.junit.Assert.assertEquals("/dns-query", s1.getString("path"))
        org.junit.Assert.assertEquals("cloudflare-dns.com", s1.getJSONObject("tls").getString("server_name"))
        org.junit.Assert.assertEquals("out", s1.getString("detour"))
        org.junit.Assert.assertEquals("hosts", servers.getJSONObject(0).getString("type"))
    }

    @Test
    fun migrate_dnsUdpFromLegacyAddressAlsoBecomesDoh() {
        val cfg = """{"dns":{"final":"remote","servers":[{"tag":"hosts","type":"hosts"},{"tag":"remote","address":"1.1.1.1","detour":"out"}]},"inbounds":[{"type":"tun","tag":"t","auto_route":true}]}"""
        val out = ConfigMigrate.migrate(cfg)
        val s1 = org.json.JSONObject(out).getJSONObject("dns").getJSONArray("servers").getJSONObject(1)
        org.junit.Assert.assertEquals("https", s1.getString("type"))
        org.junit.Assert.assertEquals("1.1.1.1", s1.getString("server"))
        org.junit.Assert.assertFalse(s1.has("address"))
    }

    @Test
    fun migrate_dnsTcpWithDetourBecomesDoh() {
        // 4.3.2 уже перевёл udp→tcp; повторная миграция tcp+detour → DoH.
        val cfg = """{"dns":{"final":"remote","servers":[{"tag":"remote","type":"tcp","server":"8.8.8.8","server_port":53,"detour":"flicker-out"}]},"inbounds":[{"type":"tun","tag":"t","auto_route":true}]}"""
        val out = ConfigMigrate.migrate(cfg)
        val s1 = org.json.JSONObject(out).getJSONObject("dns").getJSONArray("servers").getJSONObject(0)
        org.junit.Assert.assertEquals("https", s1.getString("type"))
        org.junit.Assert.assertEquals("1.1.1.1", s1.getString("server"))
        org.junit.Assert.assertEquals(443, s1.getInt("server_port"))
        org.junit.Assert.assertEquals("flicker-out", s1.getString("detour"))
    }
}
