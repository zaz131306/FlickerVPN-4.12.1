// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn.data

/**
 * Режимы работы туннеля.
 *
 * Сейчас реализован только [Vpn]. [Proxy] зарезервирован под локальный
 * SOCKS5/HTTP-режим sing-box без TUN-интерфейса: он не требует системного
 * диалога согласия VPN, не конфликтует с другим VPN-приложением и не ловит
 * ForegroundServiceStartNotAllowedException по VPN-пути.
 *
 * Для его включения нужна правка Go-фасада: Mobile.buildTunConfig() собирает
 * конфиг с inbound tun. Нужен соседний Mobile.buildProxyConfig() без tun,
 * с inbound socks/http на 127.0.0.1 — см. docs/03-PORT-BYEBYEDPI.md §1.
 */
enum class TunnelMode {
    Vpn,
    Proxy;

    companion object {
        fun fromString(name: String?): TunnelMode = when (name?.lowercase()) {
            "proxy" -> Proxy
            else -> Vpn
        }
    }
}

/**
 * Состояние сервиса. [Failed] отделён от [Disconnected] намеренно: UI должен
 * уметь показать «не получилось подключиться» и причину, а не просто «выключено».
 */
enum class ServiceStatus { Disconnected, Connecting, Connected, Failed }

/**
 * Глобальное состояние туннеля.
 *
 * Держим в отдельном объекте, а не в companion object TunnelService, потому что
 * его читают три независимых потребителя: MainActivity, QuickTileService и
 * BootReceiver. Плитка в шторке живёт в своей привязке и про сервис ничего не
 * знает — без общего источника состояния она залипает в прошлом значении.
 */
object AppState {
    @Volatile var status: ServiceStatus = ServiceStatus.Disconnected
        private set

    @Volatile var mode: TunnelMode = TunnelMode.Vpn
        private set

    /** Последняя ошибка — для плитки, уведомления и лога. */
    @Volatile var lastError: String? = null
        private set

    /** Имя узла, к которому подключены. */
    @Volatile var serverName: String = ""
        private set

    val isRunning: Boolean get() = status == ServiceStatus.Connected

    fun update(
        newStatus: ServiceStatus,
        newMode: TunnelMode = mode,
        serverName: String = AppState.serverName,
        error: String? = null,
    ) {
        status = newStatus
        mode = newMode
        AppState.serverName = serverName
        if (error != null) lastError = error
        if (newStatus == ServiceStatus.Connected) lastError = null
    }

    fun reset() {
        status = ServiceStatus.Disconnected
        serverName = ""
    }
}
