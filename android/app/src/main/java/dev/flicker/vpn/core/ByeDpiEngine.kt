// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn.core

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.util.Log
import kotlinx.coroutines.delay
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.resume

/**
 * Клиентская сторона движка обхода DPI.
 *
 * Живёт в основном процессе (рядом с TunnelService и sing-box), привязывается к
 * [ByeDpiEngineService] в процессе `:byedpi` и обменивается с ним сообщениями
 * через Messenger.
 *
 * Контракт простой:
 *   [start] → привязаться, послать MSG_START, дождаться MSG_READY (или MSG_DEAD)
 *   [stop]  → послать MSG_STOP и отвязаться; процесс движка убьёт себя сам
 *
 * Перезапуск (смена пресета) — это [stop] и новый [start]: движок одноразовый
 * на процесс, и новый bind поднимет уже чистый процесс.
 */
class ByeDpiEngine(private val context: Context) {

    companion object {
        private const val TAG = "FlickerByeDpi"

        /** Сколько ждём привязки к сервису. */
        private const val BIND_TIMEOUT_MS = 5_000L

        /**
         * Сколько ждём MSG_READY. Внутри движка свой дедлайн 8 с на поднятие
         * SOCKS5, поэтому здесь с запасом.
         */
        private const val START_TIMEOUT_MS = 12_000L

        /**
         * v4.10.3 (docs/19): перезапуск движка на свежем процессе, если bind
         * попал в ещё не умерший старый процесс `:byedpi`.
         *
         * Гонка: stop() → движок шлёт MSG_STOPPED и убивает себя НЕ МГНОВЕННО
         * (stopProxy + join), а новый bindService система отдаёт в этот же
         * живой процесс, где статический used уже выставлен → MSG_DEAD с
         * CODE_PROCESS_USED. Раньше это всплывало наружу как «движок уже
         * использован в этом процессе — нужен перезапуск процесса».
         *
         * Лечим повтором: к моменту повтора старый процесс уже завершил
         * terminate(), и bind поднимает чистый процесс. PROCESS_RETRY_MS растёт
         * с номером попытки: первой хватает 400 мс, вторая страхует медленные
         * устройства.
         */
        private const val MAX_PROCESS_RETRIES = 2
        private const val PROCESS_RETRY_MS = 400L

        /**
         * Порт SOCKS5 по умолчанию. Совпадает с PROXY_PORT в TunnelService
         * намеренно: в режиме «обход DPI» локальный прокси sing-box не
         * поднимается, порт свободен.
         */
        const val DEFAULT_PORT = 10808
    }

    /** Результат запуска. */
    sealed class Result {
        /** Движок слушает [host]:[port], можно строить конфиг sing-box. */
        data class Ready(val host: String, val port: Int) : Result()

        /** Не запустился. [fatal] = процесс движка надо пересоздать. */
        data class Failed(val error: String, val code: Int, val fatal: Boolean) : Result()
    }

    private var connection: ServiceConnection? = null
    private var engine: Messenger? = null

    @Volatile
    var running: Boolean = false
        private set

    /**
     * Запускает движок с указанными параметрами и ждёт готовности SOCKS5.
     *
     * @param presetId один из [ByeDpiArgs.PRESETS] (используется, если
     *                 [command] пуст).
     * @param command  произвольная командная строка byedpi (режим «свои
     *                 параметры»); имеет приоритет над [presetId].
     */
    suspend fun start(
        presetId: String?,
        command: String?,
        host: String = "127.0.0.1",
        port: Int = DEFAULT_PORT,
    ): Result {
        if (running) {
            return Result.Ready(host, port)
        }
        if (!ByeDpiProxy.nativeReady) {
            return Result.Failed(
                "libbyedpi.so не загружена: ${ByeDpiProxy.loadError ?: "причина неизвестна"}",
                -1, fatal = true
            )
        }
        var attempt = 0
        while (true) {
            val res = startOnce(presetId, command, host, port)
            if (res is Result.Failed &&
                (res.code == ByeDpiEngineService.CODE_PROCESS_USED ||
                    res.error.startsWith("IPC:")) &&
                attempt < MAX_PROCESS_RETRIES
            ) {
                attempt++
                val waitMs = PROCESS_RETRY_MS * attempt
                Log.w(TAG, "процесс :byedpi ещё не пересоздан (код ${res.code}); " +
                    "повтор $attempt через ${waitMs}мс")
                delay(waitMs)
                continue
            }
            return res
        }
    }

    /** Одна попытка: привязаться, послать MSG_START, дождаться ответа. */
    private suspend fun startOnce(
        presetId: String?,
        command: String?,
        host: String,
        port: Int,
    ): Result {
        val args = ByeDpiArgs.argsFor(presetId, command, host, port)
        Log.i(TAG, "start: ${args.joinToString(" ")}")

        val bound = bind()
        if (bound == null) {
            return Result.Failed("не удалось привязаться к ByeDpiEngineService", -1, fatal = false)
        }

        val outcome = withTimeoutOrNull(START_TIMEOUT_MS) {
            suspendCancellableCoroutine<Result> { cont ->
                val replyHandler = Handler(Looper.getMainLooper()) { msg ->
                    when (msg.what) {
                        ByeDpiEngineService.MSG_READY -> {
                            val h = msg.data?.getString(ByeDpiEngineService.KEY_HOST) ?: host
                            val p = msg.data?.getInt(ByeDpiEngineService.KEY_PORT) ?: port
                            if (cont.isActive) cont.resume(Result.Ready(h, p))
                        }

                        ByeDpiEngineService.MSG_DEAD -> {
                            val err = msg.data?.getString(ByeDpiEngineService.KEY_ERROR) ?: "неизвестная ошибка"
                            val code = msg.data?.getInt(ByeDpiEngineService.KEY_CODE) ?: -1
                            if (cont.isActive) cont.resume(Result.Failed(err, code, fatal = true))
                        }
                    }
                    true
                }

                val data = Bundle().apply {
                    putStringArray(ByeDpiEngineService.KEY_ARGS, args)
                    putString(ByeDpiEngineService.KEY_HOST, host)
                    putInt(ByeDpiEngineService.KEY_PORT, port)
                }
                val msg = Message.obtain(null, ByeDpiEngineService.MSG_START).apply {
                    this.data = data
                    // Ответ движок пришлёт на этот Messenger.
                    replyTo = Messenger(replyHandler)
                }
                try {
                    bound.send(msg)
                } catch (t: Throwable) {
                    Log.e(TAG, "не отправить MSG_START", t)
                    if (cont.isActive) cont.resume(Result.Failed("IPC: ${t.message}", -1, fatal = true))
                }

                cont.invokeOnCancellation {
                    replyHandler.removeCallbacksAndMessages(null)
                }
            }
        }

        return when (outcome) {
            is Result.Ready -> {
                running = true
                outcome
            }

            is Result.Failed -> {
                unbind()
                outcome
            }

            null -> {
                Log.e(TAG, "движок не ответил за ${START_TIMEOUT_MS}мс")
                unbind()
                Result.Failed("движок не ответил за ${START_TIMEOUT_MS}мс", -1, fatal = true)
            }
        }
    }

    /** Останавливает движок. Процесс `:byedpi` убьёт себя сам. */
    fun stop() {
        running = false
        val target = engine ?: run {
            unbind()
            return
        }
        try {
            target.send(Message.obtain(null, ByeDpiEngineService.MSG_STOP))
        } catch (t: Throwable) {
            Log.w(TAG, "не отправить MSG_STOP", t)
        }
        // Дать движку время обработать остановку до того, как мы отвяжемся.
        // v4.12.1: процесс не убиваем; graceful stop достаточнен.
        unbind()
    }

    private suspend fun bind(): Messenger? = withTimeoutOrNull(BIND_TIMEOUT_MS) {
        suspendCancellableCoroutine<Messenger?> { cont ->
            val conn = object : ServiceConnection {
                override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                    val m = service?.let { Messenger(it) }
                    engine = m
                    if (cont.isActive) cont.resume(m)
                }

                override fun onServiceDisconnected(name: ComponentName?) {
                    Log.w(TAG, "движок отключился (процесс умер?)")
                    engine = null
                    running = false
                }

                override fun onBindingDied(name: ComponentName?) {
                    Log.w(TAG, "binding died")
                    engine = null
                    running = false
                }

                override fun onNullBinding(name: ComponentName?) {
                    Log.e(TAG, "onNullBinding")
                    if (cont.isActive) cont.resume(null)
                }
            }
            connection = conn
            val intent = Intent(context, ByeDpiEngineService::class.java)
            val ok = try {
                context.bindService(intent, conn, Context.BIND_AUTO_CREATE)
            } catch (t: Throwable) {
                Log.e(TAG, "bindService", t)
                false
            }
            if (!ok && cont.isActive) cont.resume(null)
            cont.invokeOnCancellation {
                // v4.8.1: ИСПРАВЛЕНА ИНВЕРСИЯ. Отвязываться надо, если
                // привязка УСПЕЛА состояться (ok == true) — иначе связь
                // утекает. Было `if (!ok)`, то есть ровно наоборот: отвязка
                // вызывалась после неудачной привязки, где её и так нет.
                if (ok) runCatching { context.unbindService(conn) }
            }
        }
    }

    private fun unbind() {
        engine = null
        val conn = connection ?: return
        connection = null
        runCatching { context.unbindService(conn) }
            .onFailure { Log.w(TAG, "unbindService", it) }
    }
}
