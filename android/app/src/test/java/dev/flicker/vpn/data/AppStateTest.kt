// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * AppState — единственный источник правды о статусе туннеля для MainActivity,
 * плитки в шторке и BootReceiver. Если они разойдутся, плитка залипает в
 * прошлом значении, а автозапуск поднимает туннель «когда уже подключено».
 */
class AppStateTest {

    @Before
    fun reset() {
        AppState.reset()
    }

    @Test
    fun `начальное состояние - отключено`() {
        assertEquals(ServiceStatus.Disconnected, AppState.status)
        assertFalse(AppState.isRunning)
        assertEquals("", AppState.serverName)
    }

    @Test
    fun `isRunning истинно только при Connected`() {
        for (s in ServiceStatus.values()) {
            AppState.update(s)
            assertEquals("статус $s", s == ServiceStatus.Connected, AppState.isRunning)
        }
    }

    @Test
    fun `успешное подключение сбрасывает прошлую ошибку`() {
        AppState.update(ServiceStatus.Failed, error = "узел умер")
        assertEquals("узел умер", AppState.lastError)

        AppState.update(ServiceStatus.Connected, serverName = "NL-01")
        assertNull("после успешного подключения ошибка должна очиститься", AppState.lastError)
        assertEquals("NL-01", AppState.serverName)
    }

    @Test
    fun `режим сохраняется между обновлениями статуса`() {
        AppState.update(ServiceStatus.Connected, newMode = TunnelMode.Proxy)
        assertEquals(TunnelMode.Proxy, AppState.mode)

        // обновление статуса без явного режима не должно сбрасывать его в Vpn
        AppState.update(ServiceStatus.Disconnected)
        assertEquals(TunnelMode.Proxy, AppState.mode)
    }

    @Test
    fun `reset очищает статус и имя узла`() {
        AppState.update(ServiceStatus.Connected, serverName = "DE-02")
        AppState.reset()
        assertEquals(ServiceStatus.Disconnected, AppState.status)
        assertEquals("", AppState.serverName)
        assertFalse(AppState.isRunning)
    }

    @Test
    fun `TunnelMode fromString - неизвестное значение даёт Vpn`() {
        // Fallback на Vpn намеренный: это режим по умолчанию, и падать
        // на сохранённом в prefs мусоре приложение не должно.
        assertEquals(TunnelMode.Vpn, TunnelMode.fromString("vpn"))
        assertEquals(TunnelMode.Proxy, TunnelMode.fromString("proxy"))
        assertEquals(TunnelMode.Proxy, TunnelMode.fromString("PROXY"))
        assertEquals(TunnelMode.Vpn, TunnelMode.fromString("что-то не то"))
        assertEquals(TunnelMode.Vpn, TunnelMode.fromString(null))
        assertEquals(TunnelMode.Vpn, TunnelMode.fromString(""))
    }
}
