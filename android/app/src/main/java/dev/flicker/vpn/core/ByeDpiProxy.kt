// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn.core

/**
 * JNI-обёртка над libbyedpi.so (hufrea/byedpi 17.3, commit e0fccf68 —
 * pinned-submodule из EwenLoy/ByeByeDPI-x-tg v1.0.1-build5).
 *
 * v4.12.0: обёртка приведена ДОСЛОВНО к эталону (cpp/native-lib.c из
 * ByeByeDPI-x-tg, переименованы только JNI-символы под наш пакет):
 *
 *  [startProxy] — БЛОКИРУЮЩИЙ вызов: уходит в main(argc, argv) самой byedpi и
 *  возвращается только после [stopProxy] (shutdown(server_fd)) или аварии.
 *  Вызывать только из выделенного потока.
 *
 *  Повторный запуск в ОДНОМ процессе — разрешён и безопасен: JNI перед каждым
 *  main() вызывает reset_params() (clear_params() + дефолты эталона:
 *  await_int=10, ipv6=1, resolve=1, udp=1, max_open=512, bfsize=16384).
 *  Флаг g_proxy_running защищает только от одновременного двойного старта.
 *  Прежняя одноразовость «один запуск = один процесс» (byedpi-jni.c) больше
 *  не применяется — это ровно поведение приложения, в котором обход у
 *  пользователя работает.
 *
 *  [ByeDpiEngineService] (процесс :byedpi, автоподбор пресетов) сохраняет свою
 *  одноразовость на уровне Kotlin-флага `used` и убийства процесса — она там
 *  по-прежнему штатна и безвредна.
 */
class ByeDpiProxy {

    companion object {
        /**
         * true, если libbyedpi.so удалось загрузить.
         *
         * UnsatisfiedLinkError здесь НЕ исключение, а штатная ситуация:
         * в сборке без NDK/CMake библиотеки просто нет. Поэтому грузим один раз
         * и запоминаем, а не роняем процесс при каждом обращении.
         */
        @Volatile
        var nativeReady: Boolean = false
            private set

        @Volatile
        var loadError: String? = null
            private set

        init {
            try {
                System.loadLibrary("byedpi")
                nativeReady = true
            } catch (t: Throwable) {
                nativeReady = false
                loadError = "${t.javaClass.simpleName}: ${t.message}"
            }
        }
    }

    /** Запускает SOCKS5-прокси с обходом DPI. Блокирует поток до остановки. */
    fun startProxy(args: Array<String>): Int = jniStartProxy(args)

    /** Просит прокси остановиться. Возвращает 0 при успехе, -1 если не запущен. */
    fun stopProxy(): Int = jniStopProxy()

    /**
     * Аварийное закрытие слушающего сокета (close(server_fd)) — из эталона:
     * если shutdown() по какой-то причине не освобождает порт, этот вызов
     * гарантирует, что сокет не останется висеть.
     */
    fun forceClose(): Int = jniForceClose()

    private external fun jniStartProxy(args: Array<String>): Int
    private external fun jniStopProxy(): Int
    private external fun jniForceClose(): Int
}
