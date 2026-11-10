// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.net.Inet6Address
import java.net.InetAddress

/**
 * v4.0.9: safePrefix обязан отдавать только строки, которые
 * netip.MustParsePrefix (Go-ядро) съедает без паники. Паника там =
 * abort() = SIGABRT = молчаливая смерть приложения при подключении.
 */
class SafePrefixTest {

    @Test
    fun ipv4_normal() {
        val a = InetAddress.getByAddress(byteArrayOf(192.toByte(), 168.toByte(), 1, 5))
        assertEquals("192.168.1.5/24", TunnelService.safePrefix(a, 24))
    }

    @Test
    fun ipv4_negativePrefix_rejected() {
        val a = InetAddress.getByAddress(byteArrayOf(10, 0, 0, 1))
        assertNull(TunnelService.safePrefix(a, -1))
    }

    @Test
    fun ipv4_tooBigPrefix_rejected() {
        val a = InetAddress.getByAddress(byteArrayOf(10, 0, 0, 1))
        assertNull(TunnelService.safePrefix(a, 200))
    }

    @Test
    fun ipv6_withZone_zoneStripped() {
        val bytes = ByteArray(16)
        bytes[0] = 0xfe.toByte(); bytes[1] = 0x80.toByte()
        bytes[15] = 0xab.toByte()
        val zoned = Inet6Address.getByAddress("fe80::ab", bytes, 3) // scope_id -> зона
        val out = TunnelService.safePrefix(zoned, 64)
        assertEquals("zone обязана сниматься", true, out != null && !out.contains("%"))
        // развёрнутый формат валиден для netip.MustParsePrefix (проверено Go-тестом)
        assertEquals("fe80:0:0:0:0:0:0:ab/64", out)
    }

    @Test
    fun ipv6_normal() {
        val bytes = ByteArray(16)
        bytes[0] = 0x20; bytes[1] = 0x01; bytes[2] = 0x0d; bytes[3] = 0xb8.toByte()
        bytes[15] = 0x01
        val a = InetAddress.getByAddress(bytes)
        assertEquals("2001:db8:0:0:0:0:0:1/64", TunnelService.safePrefix(a, 64))
    }

    @Test
    fun nullAddress_rejected() {
        assertNull(TunnelService.safePrefix(null, 24))
    }
}
