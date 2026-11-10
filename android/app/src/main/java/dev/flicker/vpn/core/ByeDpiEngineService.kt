// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn.core

import android.app.Service
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.Process
import android.util.Log
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import kotlin.concurrent.thread

/**
 * Хост-процесс для byedpi.
 *
 * ЗАЧЕМ ОТДЕЛЬНЫЙ ПРОЦЕСС (в манифесте: android:process=":byedpi").
 *
 * byedpi — консольная программа: её main(argc, argv) вызывается из JNI и не
 * возвращается до остановки. Состояние она держит в глобальных переменных
 * (params, mpool, conev), которые между двумя запусками в одном процессе
 * корректно не сбросить. Поэтому JNI-обёртка разрешает РОВНО ОДИН запуск
 * (флаг proxy_started в byedpi-jni.c), а смена параметров делается
 * перезапуском процесса.
 *
 * Держать byedpi в основном процессе означало бы: чтобы поменять пресет, надо
 * убить процесс с VpnService и sing-box внутри — то есть порвать туннель и
 * потенциально показать пользователю системный диалог согласия VPN. В отдельном
 * процессе перезапуск обходника туннеля не касается вообще.
 *
 * Та же схема в EwenLoy/ByeByeDPI-x-tg: их ByeDpiVpnService и
 * ByeDpiProxyService объявлены с android:process=":native", а
 * NativeSession.terminate() (v4.12.1: stopSelf без killProcess).
 *
 * ВАЖНО ПРО ПЕТЛЮ МАРШРУТИЗАЦИИ: этот процесс принадлежит тому же пакету,
 * поэтому addDisallowedApplication(packageName) в openTun() исключает и его.
 * Без этого исходящие сокеты byedpi уходили бы обратно в TUN → sing-box →
 * socks-outbound → byedpi → бесконечная петля.
 */
class ByeDpiEngineService : Service() {

    companion object {
        private const val TAG = "FlickerByeDpi"

        /** Клиент → движку. */
        const val MSG_START = 1
        const val MSG_STOP = 2

        /** Движок → клиенту. */
        const val MSG_READY = 10
        const val MSG_DEAD = 11
        const val MSG_STOPPED = 12

        const val KEY_ARGS = "args"
        const val KEY_HOST = "host"
        const val KEY_PORT = "port"
        const val KEY_ERROR = "error"
        const val KEY_CODE = "code"

        /**
         * Код MSG_DEAD: процесс исчерпал свой единственный запуск движка.
         * Клиент (ByeDpiEngine.start) по этому коду понимает, что надо
         * подождать смерти процесса и повторить запуск на свежем — пользователю
         * ошибку не показываем (v4.10.3, см. docs/19).
         */
        const val CODE_PROCESS_USED = -2

        /**
         * Сколько ждём, пока SOCKS5 начнёт принимать соединения.
         *
         * v4.8.0: типы подобраны под места использования — в Kotlin НЕТ
         * неявного расширения Int→Long, поэтому «все три как Long» не компилируется:
         *  - READY_TIMEOUT_MS: Int, идёт в System.currentTimeMillis() + ….toLong();
         *  - PROBE_TIMEOUT_MS: Int, идёт в Socket.connect(addr, timeout: Int) и soTimeout;
         *  - PROBE_INTERVAL_MS: Long, идёт в Thread.sleep(Long).
         * Раньше все три были Long, и компилятор падал с «Type mismatch:
         * inferred type is Long but Int was expected».
         */
        private const val READY_TIMEOUT_MS: Int = 8_000
        private const val PROBE_TIMEOUT_MS: Int = 250
        private const val PROBE_INTERVAL_MS: Long = 50L

        /**
         * Процесс уже использовал свой единственный запуск. Любой новый MSG_START
         * после этого бессмыслен — клиент должен нас убить и привязаться заново.
         */
        @Volatile
        private var used = false
    }

    private var proxy: ByeDpiProxy? = null
    private var proxyThread: Thread? = null
    private var client: Messenger? = null

    /** MSG_READY уже отправлен: преждевременный возврат main() — это авария. */
    @Volatile
    private var readySent = false

    private val handler = Handler(Looper.getMainLooper()) { msg ->
        when (msg.what) {
            MSG_START -> onStart(msg)
            MSG_STOP -> onStop()
        }
        true
    }
    private val messenger = Messenger(handler)

    override fun onBind(intent: Intent?): IBinder = messenger.binder

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_NOT_STICKY

    private fun onStart(msg: Message) {
        client = msg.replyTo
        val args = msg.data?.getStringArray(KEY_ARGS)
        val host = msg.data?.getString(KEY_HOST) ?: "127.0.0.1"
        val port = msg.data?.getInt(KEY_PORT) ?: 0

        if (args == null || args.isEmpty() || port !in 1..65535) {
            dead("некорректные параметры движка (args=${args?.size}, port=$port)", -1)
            return
        }
        if (!ByeDpiProxy.nativeReady) {
            dead("libbyedpi.so не загружена: ${ByeDpiProxy.loadError ?: "?"}", -1)
            return
        }
        if (used) {
            // Второй запуск в этом процессе JNI всё равно отклонит. Сообщаем
            // клиенту код CODE_PROCESS_USED — тот пересоздаст нас повторным
            // bind и повторит запуск уже сам, без показа ошибки пользователю.
            dead("движок уже использован в этом процессе — нужен перезапуск процесса", CODE_PROCESS_USED)
            return
        }
        used = true

        Log.i(TAG, "запуск byedpi: ${args.joinToString(" ")}")
        val engine = ByeDpiProxy()
        proxy = engine

        // startProxy блокирует поток до остановки, поэтому только отдельный поток.
        proxyThread = thread(name = "ByeDPI", isDaemon = true) {
            val code = try {
                engine.startProxy(args)
            } catch (t: Throwable) {
                Log.e(TAG, "startProxy бросил", t)
                -1
            }
            Log.w(TAG, "byedpi завершилась с кодом $code")
            // Если main() вернулся сам (авария или неверные аргументы), а мы
            // ещё не сообщили «готово» — это смерть движка.
            handler.post {
                if (!readySent) dead("byedpi завершилась преждевременно, код $code", code)
            }
        }

        // Готовность проверяем честно: не «поток запущен», а «SOCKS5 отвечает
        // на рукопожатие». Тот же приём, что в ByeByeDPI-x-tg
        // (NativeSession.awaitProxy): послать 05 01 00 и ждать 05 00.
        thread(name = "ByeDPI-ready", isDaemon = true) {
            // deadline — Long: currentTimeMillis() возвращает Long,
            // а READY_TIMEOUT_MS — Int, поэтому явное .toLong().
            val deadline = System.currentTimeMillis() + READY_TIMEOUT_MS.toLong()
            while (System.currentTimeMillis() < deadline) {
                if (socks5Ready(host, port)) {
                    readySent = true
                    handler.post {
                        Log.i(TAG, "SOCKS5 готов на $host:$port")
                        reply(MSG_READY, Bundle().apply {
                            putString(KEY_HOST, host)
                            putInt(KEY_PORT, port)
                        })
                    }
                    return@thread
                }
                try {
                    Thread.sleep(PROBE_INTERVAL_MS)
                } catch (_: InterruptedException) {
                    return@thread
                }
            }
            handler.post { dead("SOCKS5 не поднялся за ${READY_TIMEOUT_MS}мс на $host:$port", -3) }
        }
    }

    /**
     * Рукопожатие SOCKS5: клиент шлёт 05 01 00 (версия 5, один метод — без
     * аутентификации), сервер обязан ответить 05 00.
     */
    private fun socks5Ready(host: String, port: Int): Boolean = try {
        Socket().use { s ->
            s.connect(InetSocketAddress(host, port), PROBE_TIMEOUT_MS)
            s.soTimeout = PROBE_TIMEOUT_MS
            s.getOutputStream().write(byteArrayOf(5, 1, 0))
            val input = s.getInputStream()
            input.read() == 5 && input.read() == 0
        }
    } catch (_: IOException) {
        false
    } catch (_: Throwable) {
        false
    }

    private fun onStop() {
        Log.i(TAG, "остановка byedpi")
        reply(MSG_STOPPED, Bundle())
        thread(name = "ByeDPI-stop", isDaemon = true) {
            try {
                proxy?.stopProxy()
                // v4.10.3: было join(2_000). Всё равно завершает уборку
                // раньше terminate() звал killProcess; v4.12.1 — только stopSelf;
                // окно гонки: новый bindService успевал попасть в этот ещё
                // живой процесс и получить CODE_PROCESS_USED (docs/19).
                // Полсекунды хватает, чтобы main() вернулся штатно; не
                // вернулся — убьём как есть.
                proxyThread?.join(500)
            } catch (t: Throwable) {
                Log.w(TAG, "stopProxy", t)
            } finally {
                terminate()
            }
        }
    }

    private fun dead(error: String, code: Int) {
        Log.e(TAG, "движок мёртв: $error (код $code)")
        reply(MSG_DEAD, Bundle().apply {
            putString(KEY_ERROR, error)
            putInt(KEY_CODE, code)
        })
        terminate()
    }

    private fun reply(what: Int, data: Bundle) {
        try {
            client?.send(Message.obtain(null, what).apply { this.data = data })
        } catch (t: Throwable) {
            Log.w(TAG, "не ответил клиенту ($what)", t)
        }
    }

    /**
     * Убить СВОЙ процесс. Единственный способ сбросить одноразовый
     * proxy_started в JNI и глобальное состояние byedpi.
     *
     * v4.12.1: только stopSelf(), без killProcess.
     */
    private fun terminate() {
        // v4.12.1: без killProcess — только stopSelf(). JNI-глобалы byedpi
        // сбрасываются при следующем старте сервиса best-effort.
        try {
            proxy?.stopProxy()
        } catch (_: Throwable) {}
        stopSelf()
    }

    override fun onDestroy() {
        // Если процесс убивают в обход MSG_STOP (система, нехватка памяти),
        // попытаться остановить прокси — иначе сокет останется висеть.
        try {
            proxy?.stopProxy()
        } catch (_: Throwable) {
        }
        super.onDestroy()
    }
}
