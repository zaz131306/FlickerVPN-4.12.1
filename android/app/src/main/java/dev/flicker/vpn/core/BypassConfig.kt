// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * Конфиг sing-box для режима «Обход DPI» — БЕЗ внешнего сервера.
 *
 * Схема:
 *
 *     [приложения] → TUN (sing-box)
 *                        ↓ route.final → outbound socks 127.0.0.1:PORT
 *                   [byedpi]  ← libbyedpi.so в процессе :byedpi
 *                        ↓ desync / split ClientHello / fake
 *                   [прямой интернет]
 *
 * То есть sing-box здесь работает как маршрутизатор и перехватчик DNS, а
 * обход DPI делает byedpi. Внешний узел не нужен, подписки не нужны.
 *
 * ЧТО ЭТО ДАЁТ ПО СРАВНЕНИЮ С hev-socks5-tunnel (схема ByeByeDPI-x-tg):
 *   * per-app и доменные правила маршрутизации sing-box вместо конфига hev;
 *   * sniffing — sing-box сам достаёт SNI/Host из потока, поэтому правила
 *     «обходить только для этих доменов» работают без списков IP;
 *   * DoH как резолвер, причём САМ DoH идёт через byedpi (детур), то есть
 *     блокировка cloudflare-dns.com по SNI тоже обходится;
 *   * серверные режимы (VLESS/Trojan/HY2/WG) остаются в том же приложении как
 *     запасной путь — у ByeByeDPI их нет в принципе.
 *
 * ТРЕБОВАНИЕ К openTun(): в этом режиме ОБЯЗАТЕЛЬНО
 * addDisallowedApplication(packageName). Иначе исходящие сокеты byedpi (другой
 * процесс того же пакета) попадут обратно в TUN → sing-box → socks → byedpi,
 * то есть в бесконечную петлю. Именно так это сделано в ByeByeDPI-x-tg:
 * ByeDpiVpnService.createTunnel() всегда вызывает
 * builder.addDisallowedApplication(applicationContext.packageName).
 */
object BypassConfig {

    /** Адрес внутри VPN-подсети, который объявляется системным DNS. */
    private const val TUN_ADDRESS = "172.19.0.1/30"
    private const val FAKE_DNS = "172.19.0.2"

    /**
     * MTU 1500, а не 9000.
     *
     * Дефолт mobile.go — 9000 (jumbo). На мобильной сети огромный MTU —
     * классическая причина «подключено, а страницы висят»: большие пакеты не
     * проходят по пути и чернеют. 1500 совпадает и с Repository.tunParamsJson
     * (v4.1.2), и с Intra (VPN_INTERFACE_MTU = 1500).
     */
    private const val MTU = 1500

    /**
     * @param socksPort порт, на котором уже слушает byedpi (из
     *                  [ByeDpiEngine.Result.Ready]).
     * @param coreLogFile путь для log.output; null — не писать файл.
     */
    fun build(socksPort: Int, coreLogFile: String?): String {
        val outbounds = JSONArray()
            .put(
                JSONObject()
                    .put("type", "socks")
                    .put("tag", "byedpi-out")
                    .put("server", "127.0.0.1")
                    .put("server_port", socksPort)
                    // "5", а не "4": byedpi — SOCKS5, и только пятая версия
                    // умеет UDP ASSOCIATE (нужен для QUIC и DNS).
                    .put("version", "5")
                    .put("udp_over_tcp", false)
            )
            .put(JSONObject().put("type", "direct").put("tag", "flicker-direct"))

        // DNS: DoH на 1.1.1.1 ЧЕРЕЗ byedpi.
        //
        // server задаётся IP-литералом, а не именем: резолвить имя резолвера
        // через сам резолвер нельзя. server_name остаётся для SNI/валидации
        // сертификата. Тот же приём, что в ConfigMigrate.dnsRemoteToDoh и в
        // Intra (doh.NewResolver получает сид-адреса, чтобы не зависеть от DNS).
        val remoteDns = JSONObject()
            .put("type", "https")
            .put("tag", "remote")
            .put("server", "1.1.1.1")
            .put("server_port", 443)
            .put("path", "/dns-query")
            .put(
                "tls", JSONObject()
                    .put("enabled", true)
                    .put("server_name", "cloudflare-dns.com")
            )
            // detour обязателен: без него DoH пойдёт напрямую и будет
            // заблокирован по SNI ровно так же, как обычные сайты.
            .put("detour", "byedpi-out")

        val dns = JSONObject()
            .put(
                "servers", JSONArray()
                    .put(JSONObject().put("type", "hosts").put("tag", "hosts"))
                    .put(remoteDns)
            )
            .put("final", "remote")
            // ipv4_only: IPv6 в tun выключен (address только v4), а дефолтная
            // стратегия вернула бы и AAAA — приложение пробовало бы IPv6 и
            // висело до фолбэка. Совпадает с ConfigMigrate.ensureDirectResolver.
            .put("strategy", "ipv4_only")

        val tunInbound = JSONObject()
            .put("type", "tun")
            .put("tag", "tun-in")
            .put("address", JSONArray().put(TUN_ADDRESS))
            .put("mtu", MTU)
            .put("auto_route", true)
        // auto_detect_interface оставляем включённым: вместе с
        // setUnderlyingNetworks() (v4.6.0) это страхует от привязки к
        // исчезнувшему интерфейсу после WiFi→LTE.

        val route = JSONObject()
            .put("final", "byedpi-out")
            .put("auto_detect_interface", true)
            .put(
                "rules", JSONArray()
                    // sniff ДОБАВЛЯЕТ домен из TLS/HTTP — без него доменные
                    // правила и DoH-резолвинг работали бы только по IP.
                    .put(JSONObject().put("action", "sniff"))
                    // Перехват DNS из TUN. В sing-box 1.11+ это rule-action,
                    // а не поле inbound (см. ConfigMigrate: легаси-поля
                    // заставляют парсер отвергнуть конфиг ЦЕЛИКОМ).
                    .put(
                        JSONObject()
                            .put("protocol", "dns")
                            .put("action", "hijack-dns")
                    )
            )

        val log = JSONObject().put("level", "info").put("timestamp", true)
        if (!coreLogFile.isNullOrEmpty()) log.put("output", coreLogFile)

        return JSONObject()
            .put("log", log)
            .put("dns", dns)
            .put("inbounds", JSONArray().put(tunInbound))
            .put("outbounds", outbounds)
            .put("route", route)
            .toString()
    }

    /**
     * Конфиг локального SOCKS5-режима без TUN («режим Прокси»): приложения
     * ходят в 127.0.0.1:port явно, системный VPN не поднимается.
     *
     * Здесь sing-box не нужен вовсе — byedpi сам слушает SOCKS5. Возвращает
     * null, чтобы вызывающий код знал: поднимать туннель не требуется.
     */
    fun proxyModeNeedsTunnel(): Boolean = false

    /** Адрес заглушки системного DNS внутри tun (используется openTun). */
    const val FAKE_DNS_SERVER: String = FAKE_DNS
}
