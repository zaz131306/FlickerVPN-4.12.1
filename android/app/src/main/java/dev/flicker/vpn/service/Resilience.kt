// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn.service

import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlin.math.min
import kotlin.math.pow
import kotlin.random.Random

/**
 * Устойчивость соединения: backoff, watchdog, переподключение.
 *
 * ---------------------------------------------------------------------------
 *  ПОЧЕМУ ЭКСПОНЕНЦИАЛЬНЫЙ BACKOFF С ДЖИТТЕРОМ, А НЕ ФИКСИРОВАННАЯ ПАУЗА
 * ---------------------------------------------------------------------------
 *  * CDN подписок (GitHub raw и т.п.) отдают 403/429 при частых запросах.
 *    Фиксированный интервал с одного IP — ровно тот паттерн, за который
 *    блокируют. Отсюда и «ошибки http хостинга».
 *  * Без джиттера все клиенты, у которых узел отвалился одновременно, бьют в
 *    одну и ту же миллисекунду (thundering herd).
 *
 *  Формула: delay = min(cap, base·2^n) · U(0.5 … 1.0), cap = 5 минут.
 *
 * ---------------------------------------------------------------------------
 *  ПОЧЕМУ «N ПРОВАЛОВ ПОДРЯД», А НЕ ОДИН
 * ---------------------------------------------------------------------------
 *  Одиночный сбой проверки (потерянный пакет, GC-пауза, momentarily пропавший
 *  Wi-Fi) не должен рвать живое соединение. Иначе получаем ровно те самые
 *  «вылеты на ровном месте».
 * ---------------------------------------------------------------------------
 */
object Resilience {

    private const val TAG = "FlickerResil"

    const val BASE_DELAY_MS = 1_000L
    const val MAX_DELAY_MS = 5 * 60 * 1000L

    /** Сколько провалов watchdog подряд считаем смертью туннеля. */
    const val UNHEALTHY_THRESHOLD = 3

    /** Задержка перед попыткой номер [attempt] (нумерация с 0), с джиттером. */
    fun backoffDelay(attempt: Int): Long {
        val safe = attempt.coerceAtLeast(0)
        val exp = min(MAX_DELAY_MS.toDouble(), BASE_DELAY_MS * 2.0.pow(safe))
        val jittered = exp * (0.5 + Random.nextDouble() * 0.5)
        return jittered.toLong().coerceIn(BASE_DELAY_MS / 2, MAX_DELAY_MS)
    }

    /**
     * Ретраи с backoff.
     *
     * КРИТИЧНО: [CancellationException] пробрасывается НАРУЖУ. Если его
     * проглотить, отмена корутины перестанет работать — сервис не умрёт, а
     * джоба продолжит ретраить в фоне вечно. Классический симптом:
     * «выключил VPN, а он через минуту сам включился».
     *
     * @param isRetryable true, если ошибку имеет смысл ретраить
     */
    suspend fun <T> retry(
        maxRetries: Int,
        isRetryable: (Throwable) -> Boolean = ::isTransient,
        onRetry: ((attempt: Int, delayMs: Long, error: Throwable) -> Unit)? = null,
        block: suspend () -> T,
    ): T {
        var attempt = 0
        while (true) {
            try {
                return block()
            } catch (ce: CancellationException) {
                throw ce
            } catch (e: Throwable) {
                if (attempt >= maxRetries || !isRetryable(e)) {
                    Log.w(TAG, "попытка $attempt: ${e.javaClass.simpleName}: ${e.message} — без ретрая")
                    throw e
                }
                val d = retryDelayForHttp(attempt, null)
                Log.i(TAG, "попытка $attempt не удалась (${e.javaClass.simpleName}), ретрай через ${d}мс")
                onRetry?.invoke(attempt, d, e)
                delay(d)
                attempt++
            }
        }
    }

    /**
     * Временная ли ошибка.
     * Ретраим транспорт и 408/425/429/5xx. НЕ ретраим 400/401/404/410 —
     * повторный запрос даст тот же результат, а мы только сожжём лимит хостинга.
     */
    fun isTransient(e: Throwable): Boolean {
        if (e is java.io.InterruptedIOException) return true   // в т.ч. SocketTimeoutException
        if (e is java.net.ConnectException) return true
        if (e is java.net.NoRouteToHostException) return true
        if (e is java.net.UnknownHostException) return true    // DNS ещё не поднялся
        if (e is java.net.SocketException) return true
        if (e is javax.net.ssl.SSLException) return true
        if (e is java.io.IOException) return true
        val code = httpCodeOf(e) ?: return false
        return code in TRANSIENT_HTTP_CODES
    }

    /** Задержка с учётом Retry-After, если сервер его прислал. */
    fun retryDelayForHttp(attempt: Int, retryAfterSeconds: Long?): Long {
        if (retryAfterSeconds != null && retryAfterSeconds in 1..3600) {
            // Сервер явно сказал, когда прийти. Уважать обязательно, иначе 429 → бан.
            return retryAfterSeconds * 1000L
        }
        return backoffDelay(attempt)
    }

    /**
     * Watchdog-цикл: периодически зовёт [probe], и после [UNHEALTHY_THRESHOLD]
     * провалов подряд вызывает [onDead].
     */
    suspend fun watchdog(
        intervalMs: Long,
        probe: suspend () -> Boolean,
        onDead: suspend (consecutiveFailures: Int) -> Unit,
    ) {
        var fails = 0
        while (true) {
            delay(intervalMs)
            val healthy = try {
                probe()
            } catch (ce: CancellationException) {
                throw ce
            } catch (e: Throwable) {
                Log.w(TAG, "watchdog probe бросил исключение", e)
                false
            }
            if (healthy) {
                if (fails > 0) Log.i(TAG, "watchdog: снова здорово (было $fails провалов)")
                fails = 0
                continue
            }
            fails++
            Log.w(TAG, "watchdog: провал $fails/$UNHEALTHY_THRESHOLD")
            if (fails >= UNHEALTHY_THRESHOLD) {
                Log.e(TAG, "watchdog: туннель мёртв ($fails провалов) — перезапускаю")
                try {
                    onDead(fails)
                } catch (ce: CancellationException) {
                    throw ce
                } catch (e: Throwable) {
                    Log.e(TAG, "onDead бросил исключение", e)
                }
                fails = 0
                delay(intervalMs * 2)   // даём время подняться
            }
        }
    }

    private val TRANSIENT_HTTP_CODES: Set<Int> = buildSet {
        addAll(setOf(408, 425, 429, 500, 502, 503, 504, 507, 509))
        addAll(520..527)   // нестандартные коды Cloudflare — у CDN-подписок встречаются
    }

    /**
     * Достаёт HTTP-код из исключения.
     * Если введёшь свой sealed-класс ошибок — добавь сюда ветку для него,
     * парсинг из текста сообщения оставлен как fallback.
     */
    private fun httpCodeOf(e: Throwable): Int? {
        val m = e.message ?: return null
        val rx = Regex("""(?:HTTP|status|code)[^\d]{0,10}(\d{3})""", RegexOption.IGNORE_CASE)
        return rx.find(m)?.groupValues?.get(1)?.toIntOrNull()?.takeIf { it in 100..599 }
    }
}
