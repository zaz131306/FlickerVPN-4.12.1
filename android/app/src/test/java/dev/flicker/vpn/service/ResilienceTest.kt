// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException

/**
 * Тесты чистой логики устойчивости — без Android-фреймворка и без нативного ядра,
 * поэтому гоняются обычным `./gradlew testReleaseUnitTest` за секунды.
 *
 * Здесь проверяются ровно те свойства, из-за нарушения которых VPN-клиент
 * «лагает» или «сыплет ошибками хостинга»:
 *   * backoff должен РАСТИ и упираться в потолок, а не долбить с фиксированным интервалом;
 *   * джиттер обязан оставаться в диапазоне, иначе все клиенты бьют одновременно;
 *   * 404 не должен ретраиться (бессмысленно и жжёт лимит хостинга),
 *     а 429/5xx — должен.
 */
class ResilienceTest {

    @Test
    fun `backoff растёт экспоненциально`() {
        // Берём среднее по многим прогонам, чтобы джиттер не мешал сравнению.
        fun avg(attempt: Int) = (1..200).map { Resilience.backoffDelay(attempt) }.average()

        val a0 = avg(0)
        val a1 = avg(1)
        val a2 = avg(2)
        val a3 = avg(3)

        assertTrue("ожидается рост 0→1: $a0 → $a1", a1 > a0)
        assertTrue("ожидается рост 1→2: $a1 → $a2", a2 > a1)
        assertTrue("ожидается рост 2→3: $a2 → $a3", a3 > a2)
        // каждая ступень примерно вдвое больше предыдущей (с поправкой на джиттер)
        assertTrue("шаг 1→2 должен быть ~x2, получился x${a2 / a1}", a2 / a1 in 1.5..2.6)
    }

    @Test
    fun `backoff упирается в потолок и не переполняется`() {
        // attempt = 40 → 2^40 явно за пределами Long при наивном расчёте.
        // Проверяем, что cap применяется ДО переполнения.
        for (attempt in listOf(10, 20, 30, 40, 64, 1000)) {
            val d = Resilience.backoffDelay(attempt)
            assertTrue("attempt=$attempt: $d превысило потолок ${Resilience.MAX_DELAY_MS}",
                d <= Resilience.MAX_DELAY_MS)
            assertTrue("attempt=$attempt: $d меньше минимума", d >= Resilience.BASE_DELAY_MS / 2)
        }
    }

    @Test
    fun `отрицательный attempt не ломает расчёт`() {
        val d = Resilience.backoffDelay(-5)
        assertTrue("получилось $d", d in (Resilience.BASE_DELAY_MS / 2)..Resilience.MAX_DELAY_MS)
    }

    @Test
    fun `джиттер реально разбрасывает значения, а не даёт константу`() {
        // Если джиттера нет, все клиенты после обрыва узла бьют в одну
        // миллисекунду (thundering herd) и получают бан от CDN.
        val values = (1..50).map { Resilience.backoffDelay(3) }.toSet()
        assertTrue("ожидался разброс, получено ${values.size} уникальных из 50",
            values.size >= 10)
    }

    @Test
    fun `все значения джиттера в допустимом диапазоне`() {
        repeat(500) {
            val attempt = it % 8
            val d = Resilience.backoffDelay(attempt)
            assertTrue("attempt=$attempt d=$d вне диапазона",
                d in (Resilience.BASE_DELAY_MS / 2)..Resilience.MAX_DELAY_MS)
        }
    }

    // --- классификация ошибок -------------------------------------------------

    @Test
    fun `транспортные ошибки считаются временными`() {
        assertTrue(Resilience.isTransient(SocketTimeoutException("timeout")))
        assertTrue(Resilience.isTransient(ConnectException("connection refused")))
        assertTrue(Resilience.isTransient(UnknownHostException("raw.githubusercontent.com")))
        assertTrue(Resilience.isTransient(IOException("network unreachable")))
    }

    @Test
    fun `5xx и 429 ретраятся`() {
        for (code in listOf(429, 500, 502, 503, 504, 520, 524)) {
            assertTrue("HTTP $code должен ретраиться",
                Resilience.isTransient(RuntimeException("HTTP $code from source")))
        }
    }

    @Test
    fun `4xx не ретраятся - повторный запрос даст тот же результат`() {
        // Это и есть борьба с «ошибками http хостинга»: долбить 404 бессмысленно,
        // а лимит запросов к CDN сжигается мгновенно.
        for (code in listOf(400, 401, 403, 404, 410, 422)) {
            assertFalse("HTTP $code НЕ должен ретраиться",
                Resilience.isTransient(RuntimeException("HTTP $code from source")))
        }
    }

    @Test
    fun `ошибка без HTTP-кода и не транспортная - не временная`() {
        assertFalse(Resilience.isTransient(IllegalArgumentException("кривой JSON")))
        assertFalse(Resilience.isTransient(IllegalStateException("конфиг не собрался")))
    }

    @Test
    fun `Retry-After от сервера важнее собственного backoff`() {
        // Если сервер явно сказал «приходи через 120 секунд», уважать обязательно,
        // иначе 429 превратится в бан по IP.
        assertEquals(120_000L, Resilience.retryDelayForHttp(0, 120))
        assertEquals(1_000L, Resilience.retryDelayForHttp(0, 1))
    }

    @Test
    fun `безумный Retry-After игнорируется`() {
        // Защита от злонамеренного или сломанного сервера, приславшего Retry-After: 999999
        val d = Resilience.retryDelayForHttp(2, 999_999)
        assertTrue("получилось $d", d <= Resilience.MAX_DELAY_MS)
        val d2 = Resilience.retryDelayForHttp(2, -5)
        assertTrue("получилось $d2", d2 in (Resilience.BASE_DELAY_MS / 2)..Resilience.MAX_DELAY_MS)
    }
}
