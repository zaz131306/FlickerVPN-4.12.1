// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn.core

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL

/**
 * v4.8.0: автоподбор рабочей стратегии обхода DPI.
 *
 * ЗАЧЕМ ЭТО НУЖНО И ПОЧЕМУ БЕЗ ЭТОГО «ОБХОД НЕ РАБОТАЕТ».
 *
 * Обход DPI — это не «включил и работает», а подбор параметров под конкретного
 * провайдера. Один и тот же пресет у Ростелекома работает, у МТС — нет, а после
 * обновления фильтрации перестаёт работать и там. Поэтому «включается, слабый
 * поток идёт, а по факту обхода нет» — ожидаемое поведение при неподходящем
 * пресете, а не поломка.
 *
 * Именно для этого в ByeByeDPI-x-tg есть TestService.kt (17 КБ): он перебирает
 * стратегии и показывает, какие сайты открываются. Здесь — тот же принцип.
 *
 * ---------------------------------------------------------------------------
 *  ГЛАВНОЕ СВОЙСТВО: VPN ДЛЯ ТЕСТА НЕ НУЖЕН
 * ---------------------------------------------------------------------------
 *  byedpi — обычный SOCKS5-прокси на 127.0.0.1. Java умеет ходить через SOCKS
 *  штатно:
 *
 *      URL(u).openConnection(Proxy(Proxy.Type.SOCKS, InetSocketAddress(...)))
 *
 *  Значит тестер гоняет запросы НАПРЯМУЮ через byedpi, минуя TUN и sing-box.
 *  Отсюда три следствия:
 *    * тест не требует поднятого VPN и не мешает пользователю;
 *    * он проверяет ИМЕННО обход DPI, а не всю цепочку сразу — если сайт не
 *      открылся, виноват пресет, а не sing-box;
 *    * приложение не исключено из VPN (VPN выключен), поэтому его сокеты идут
 *      напрямую и петля маршрутизации невозможна.
 *
 *  Дополнительно прогоняем те же сайты БЕЗ прокси («базовая линия»). Это даёт
 *  осмысленный отчёт: «заблокировано без обхода → открылось с обходом» —
 *  доказательство, что пресет работает. Если сайт открывается и так, и так —
 *  он не заблокирован и как критерий бесполезен.
 * ---------------------------------------------------------------------------
 *
 * Про «успех». Успешным считается ЛЮБОЙ HTTP-код, включая 403/404/401: это
 * значит, что TCP-соединение установилось, TLS-рукопожатие прошло и сервер
 * ответил. То есть запрос дошёл сквозь DPI. При блокировке же соединение
 * обрывается на рукопожатии или сбрасывается — это исключение, а не код.
 * Тот же критерий использует сквозная самопроверка узла в TunnelService.
 */
class StrategyTester(private val context: Context) {

    companion object {
        private const val TAG = "FlickerTester"

        /** Порт для теста. Не BYEDPI_PORT: тест не должен пересекаться с рабочим туннелем. */
        const val TEST_PORT = 10999

        private const val CONNECT_TIMEOUT_MS = 7_000
        private const val READ_TIMEOUT_MS = 9_000

        /**
         * Пауза между пресетами. Движок byedpi одноразовый на процесс и после
         * stop() убивает себя, поэтому новому bindService нужен момент, чтобы
         * старый процесс действительно исчез и освободил порт.
         */
        private const val BETWEEN_PRESETS_MS = 700L

        /**
         * Сайты по умолчанию.
         *
         * Первые четыре — то, ради чего обход ставят. Последний (Яндекс) —
         * КОНТРОЛЬНЫЙ: он не заблокирован и обязан открываться всегда. Без него
         * «все сайты не открылись» неотличимо от «тестер сломался».
         */
        val DEFAULT_SITES: List<String> = listOf(
            "https://www.instagram.com/",
            "https://api.telegram.org/method/getMe",
            "https://www.youtube.com/",
            "https://discord.com/",
            "https://ya.ru/",
        )

        /** Сайт, который обязан работать всегда. По нему валиден ли прогон. */
        const val CONTROL_SITE = "https://ya.ru/"
    }

    /** Результат по одному сайту. */
    data class SiteResult(
        val site: String,
        val ok: Boolean,
        val ms: Long,
        val detail: String,
    )

    /** Результат по одному пресету. */
    data class PresetResult(
        val presetId: String,
        val title: String,
        val command: String,
        val throughProxy: List<SiteResult>,
        val baseline: List<SiteResult>,
    ) {
        /** Сколько сайтов открылось ЧЕРЕЗ обход. */
        val score: Int get() = throughProxy.count { it.ok }

        /**
         * Сколько сайтов открылось через обход, но НЕ открывались напрямую.
         * Это и есть настоящая польза пресета: базовая линия показывает, что
         * сайт заблокирован, а обход его открывает.
         */
        val gained: Int get() = throughProxy.count { r ->
            r.ok && baseline.firstOrNull { it.site == r.site }?.ok != true
        }

        val medianMs: Long
            get() {
                val v = throughProxy.filter { it.ok }.map { it.ms }.sorted()
                return if (v.isEmpty()) -1L else v[v.size / 2]
            }

        /** Контрольный сайт открылся — значит прогон вообще валиден. */
        val controlOk: Boolean
            get() = throughProxy.firstOrNull { it.site == CONTROL_SITE }?.ok == true
    }

    interface Listener {
        /** Начинается базовая линия (без прокси). */
        fun onBaselineStart(total: Int) {}
        fun onBaselineSite(r: SiteResult) {}

        /** Начинается очередной пресет. */
        fun onPresetStart(index: Int, total: Int, title: String) {}
        fun onPresetSite(title: String, r: SiteResult) {}
        fun onPresetDone(r: PresetResult) {}

        /** Движок не поднялся на этом пресете — пресет пропускается. */
        fun onPresetFailed(title: String, error: String) {}

        fun onFinished(results: List<PresetResult>) {}
    }

    @Volatile
    private var cancelled = false

    fun cancel() {
        cancelled = true
    }

    /**
     * Прогон: базовая линия + все пресеты.
     *
     * Стоимость: (N_пресетов × (перезапуск процесса ~1-2 с + N_сайтов × до 9 с)).
     * Для 9 пресетов и 5 сайтов — порядка 2-4 минут. Прогресс обязателен.
     */
    suspend fun run(
        presets: List<ByeDpiArgs.Preset> = ByeDpiArgs.PRESETS,
        sites: List<String> = DEFAULT_SITES,
        listener: Listener? = null,
    ): List<PresetResult> = withContext(Dispatchers.IO) {
        cancelled = false

        // 1. Базовая линия: те же сайты напрямую, БЕЗ обхода.
        listener?.onBaselineStart(sites.size)
        val baseline = sites.map { site ->
            if (cancelled) throw CancellationException("тест отменён")
            val r = fetch(site, proxy = null)
            listener?.onBaselineSite(r)
            r
        }
        Log.i(TAG, "базовая линия: ${baseline.count { it.ok }}/${baseline.size} открылось без обхода")

        // 2. Каждый пресет — через byedpi.
        val results = ArrayList<PresetResult>(presets.size)
        presets.forEachIndexed { i, preset ->
            if (cancelled) throw CancellationException("тест отменён")
            listener?.onPresetStart(i + 1, presets.size, preset.title)

            val engine = ByeDpiEngine(context)
            val started = engine.start(preset.id, null, "127.0.0.1", TEST_PORT)
            if (started !is ByeDpiEngine.Result.Ready) {
                val err = (started as ByeDpiEngine.Result.Failed).error
                Log.w(TAG, "пресет «${preset.title}»: движок не поднялся — $err")
                listener?.onPresetFailed(preset.title, err)
                engine.stop()
                delay(BETWEEN_PRESETS_MS)
                return@forEachIndexed
            }

            val perSite = sites.map { site ->
                if (cancelled) {
                    engine.stop()
                    throw CancellationException("тест отменён")
                }
                val r = fetch(site, proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", started.port)))
                listener?.onPresetSite(preset.title, r)
                r
            }
            engine.stop()

            val pr = PresetResult(preset.id, preset.title, preset.command, perSite, baseline)
            results += pr
            Log.i(
                TAG,
                "пресет «${preset.title}»: ${pr.score}/${sites.size} (новых ${pr.gained}), " +
                    "медиана ${pr.medianMs}мс, контроль ${if (pr.controlOk) "ок" else "ПРОВАЛ"}"
            )
            listener?.onPresetDone(pr)
            delay(BETWEEN_PRESETS_MS)
        }

        listener?.onFinished(results)
        results
    }

    /**
     * Один запрос. Никогда не бросает — результат всегда SiteResult.
     *
     * @param proxy null = напрямую (базовая линия), иначе через SOCKS5 byedpi.
     */
    private fun fetch(site: String, proxy: Proxy?): SiteResult {
        val t0 = System.currentTimeMillis()
        return try {
            val conn = if (proxy != null) URL(site).openConnection(proxy) else URL(site).openConnection()
            val http = conn as HttpURLConnection
            http.connectTimeout = CONNECT_TIMEOUT_MS
            http.readTimeout = READ_TIMEOUT_MS
            // Не следовать редиректам: нам важен факт ответа, а не куда он ведёт.
            http.instanceFollowRedirects = false
            http.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 12)")
            val code = http.responseCode
            try {
                http.disconnect()
            } catch (_: Throwable) {
            }
            SiteResult(site, true, System.currentTimeMillis() - t0, "HTTP $code")
        } catch (ce: CancellationException) {
            throw ce
        } catch (t: Throwable) {
            // Тип исключения здесь — главная диагностика:
            //   SSLHandshakeException / SSLException  → соединение сбросили на
            //       рукопожатии, то есть DPI увидел ClientHello и вмешался.
            //       Именно это лечится подбором пресета.
            //   SocketTimeoutException                → пакеты молча теряются.
            //   ConnectException                      → не смогли даже подключиться.
            //   UnknownHostException                  → не работает DNS (к обходу
            //       DPI отношения не имеет — это отдельная проблема).
            val msg = t.message?.replace('\n', ' ')?.take(90) ?: ""
            SiteResult(
                site, false, System.currentTimeMillis() - t0,
                "${t.javaClass.simpleName}${if (msg.isEmpty()) "" else ": $msg"}"
            )
        }
    }

    /**
     * Ранжирование результата.
     *
     * Сортировка: сначала [PresetResult.gained] (сколько сайтов ОТКРЫЛОСЬ
     * благодаря обходу), затем общий score, затем медианное время.
     * Пресеты, у которых провалился контрольный сайт, отправляются в конец:
     * если не открылся даже Яндекс, прогон невалиден и верить score нельзя.
     */
    fun rank(results: List<PresetResult>): List<PresetResult> =
        results.sortedWith(
            compareByDescending<PresetResult> { it.controlOk }
                .thenByDescending { it.gained }
                .thenByDescending { it.score }
                .thenBy { if (it.medianMs < 0) Long.MAX_VALUE else it.medianMs }
        )

    /** Человекочитаемый отчёт — в буфер обмена и в журнал сбоев. */
    fun report(results: List<PresetResult>): String {
        val ranked = rank(results)
        val sb = StringBuilder()
        sb.appendLine("=== Подбор стратегии обхода DPI ===")
        sb.appendLine("Сайтов: ${results.firstOrNull()?.throughProxy?.size ?: 0}, пресетов: ${results.size}")
        sb.appendLine()
        val base = results.firstOrNull()?.baseline.orEmpty()
        sb.appendLine("Базовая линия (БЕЗ обхода):")
        base.forEach { sb.appendLine("  ${if (it.ok) "открылся" else "НЕ открылся"} ${it.site} — ${it.detail}") }
        sb.appendLine()
        sb.appendLine("Пресеты (лучший сверху):")
        ranked.forEachIndexed { i, r ->
            sb.appendLine(
                "${i + 1}. ${r.title}: открылось ${r.score}/${r.throughProxy.size}, " +
                    "новых +${r.gained}, медиана ${r.medianMs}мс" +
                    if (!r.controlOk) "  ⚠ КОНТРОЛЬ ПРОВАЛЕН — прогон невалиден" else ""
            )
            sb.appendLine("   args: ${r.command}")
            r.throughProxy.forEach { sr ->
                sb.appendLine("     ${if (sr.ok) "✓" else "✗"} ${sr.site} — ${sr.detail} (${sr.ms}мс)")
            }
        }
        val best = ranked.firstOrNull { it.controlOk && it.gained > 0 } ?: ranked.firstOrNull { it.controlOk }
        sb.appendLine()
        sb.appendLine(
            if (best != null) "РЕКОМЕНДАЦИЯ: «${best.title}» (+${best.gained} сайтов)"
            else "НИ ОДИН пресет не открыл заблокированные сайты. Возможные причины: " +
                "провайдер блокирует не по SNI/ClientHello, нужен серверный режим (VPN-узел); " +
                "или не работает DNS (смотрите UnknownHostException в деталях)."
        )
        return sb.toString()
    }
}
