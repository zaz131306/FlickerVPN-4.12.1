// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn.core

/**
 * JNI-мост к libhev-socks5-tunnel.so (tun2socks).
 *
 * v4.12.0: перенесён дословно из EwenLoy/ByeByeDPI-x-tg v1.0.1-build5
 * (io.github.romanvht.byedpi.core.TProxyService) вместе со всей схемой
 * обхода DPI: TUN (VpnService.Builder.establish()) → hev-socks5-tunnel →
 * SOCKS5 127.0.0.1:1080 (byedpi) → интернет с искажением пакетов.
 *
 * Нативные методы регистрируются через RegisterNatives в JNI_OnLoad
 * библиотеки (src/hev-jni.c): класс ищется по имени
 * `dev/flicker/vpn/core/TProxyService` (PKGNAME задаётся в
 * src/main/jni/Application.mk). Поэтому:
 *   * имя пакета/класса менять нельзя без правки PKGNAME;
 *   * в proguard-rules.pro стоит keep-правило (minify сейчас выключен,
 *     но правило обязательно, если его когда-нибудь включат).
 *
 * Библиотека собирается задачей runNdkBuild (gradle) из src/main/jni/
 * в src/main/hevlibs/<abi>/libhev-socks5-tunnel.so.
 *
 * Загрузка — безопасная (как в [ByeDpiProxy]): отсутствие .so не роняет
 * процесс, а фиксируется в [nativeReady]/[loadError]; UI показывает
 * внятную ошибку «пересоберите APK с NDK».
 */
object TProxyService {

    /** true, если libhev-socks5-tunnel.so загрузилась. */
    @Volatile
    var nativeReady: Boolean = false
        private set

    /** Причина, по которой библиотека не загрузилась (для диагностики). */
    @Volatile
    var loadError: String? = null
        private set

    init {
        try {
            System.loadLibrary("hev-socks5-tunnel")
            nativeReady = true
        } catch (t: Throwable) {
            nativeReady = false
            loadError = "${t.javaClass.simpleName}: ${t.message}"
        }
    }

    /**
     * Поднимает tun2socks на переданном fd TUN-интерфейса.
     *
     * @param configPath путь к YAML-конфигу (tunnel mtu / misc task-stack-size /
     *                   socks5 address+port+udp) — эталонный формат из
     *                   ByeByeDPI-x-tg ByeDpiVpnService.startTun2Socks().
     * @param fd         файловый дескриптор из VpnService.Builder.establish().
     */
    @JvmStatic
    external fun TProxyStartService(configPath: String, fd: Int)

    /** Останавливает tun2socks (блокирует до завершения рабочего потока). */
    @JvmStatic
    external fun TProxyStopService()

    /** Счётчики трафика tun2socks. */
    @JvmStatic
    @Suppress("unused")
    external fun TProxyGetStats(): LongArray
}
