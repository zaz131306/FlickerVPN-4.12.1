// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn.core.tgws

import android.util.Log
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

/**
 * Кольцевой буфер лога натива (Rust-ядро пишет в logcat с тегом `TgWsProxy`).
 *
 * ЗАЧЕМ. Натив не отдаёт лог через API — только в logcat. Без него диагностика
 * «нажал Запустить, ничего не происходит» невозможна: StartProxy возвращает
 * код, но причина (нет сети, CF не отвечает, DC недоступен) видна только в
 * логе. Поэтому читаем logcat СВОЕГО процесса и держим последние строки
 * в памяти, а UI забирает их вместе с состоянием.
 *
 * Живёт в процессе `:tgws`, читает `--pid <свой pid>` — чужие строки
 * не попадают. `logcat --pid` доступен с API 24, наш minSdk = 24.
 *
 * ГОНКА stop→start (перезапуск прокси). Старый поток-читатель выходит из
 * readLine() не мгновенно: destroy() закрывает поток, и только потом
 * срабатывает его finally. Если к этому моменту start() уже успел создать
 * нового читателя и записать свой Process в [proc], безличный `proc = null`
 * в finally затёр бы ССЫЛКУ НА НОВЫЙ процесс — и следующий stop() не смог бы
 * его убить (висящий logcat до конца жизни процесса `:tgws`). Поэтому finally
 * обнуляет поле только если там всё ещё ЕГО процесс (`proc === p`).
 *
 * Память ограничена: [CAP] строк, лишнее выталкивается с головы. Broadcast
 * с состоянием несёт не больше [BROADCAST_CAP] строк — лимит Intent ~1 МБ,
 * но главное не раздувать Binder-транзакцию.
 */
object TgWsLog {

    private const val TAG = "FlickerTgWs"
    private const val CAP = 300
    private const val BROADCAST_CAP = 80
    private const val MAX_LINE = 400

    private val buf = ArrayDeque<String>()
    private val seq = AtomicLong(0)

    @Volatile
    private var reader: Thread? = null

    @Volatile
    private var proc: Process? = null

    @Volatile
    private var running = false

    @Synchronized
    fun start() {
        if (running) return
        running = true
        clear()
        reader = thread(name = "TgWsLog", isDaemon = true) {
            var p: Process? = null
            try {
                val pid = android.os.Process.myPid()
                p = ProcessBuilder("logcat", "-v", "brief", "--pid", pid.toString())
                    .redirectErrorStream(true)
                    .start()
                proc = p
                p.inputStream.bufferedReader().use { r ->
                    while (running) {
                        val line = try {
                            r.readLine()
                        } catch (_: Throwable) {
                            null
                        } ?: break
                        append(parse(line))
                    }
                }
            } catch (t: Throwable) {
                Log.w(TAG, "чтение logcat не удалось", t)
            } finally {
                try {
                    p?.destroy()
                } catch (_: Throwable) {
                }
                // Обнуляем поле ТОЛЬКО если там ещё наш процесс: иначе
                // перезатрём ссылку на нового читателя (см. шапку класса).
                if (proc === p) proc = null
            }
        }
    }

    @Synchronized
    fun stop() {
        running = false
        try {
            proc?.destroy()
        } catch (_: Throwable) {
        }
        proc = null
        reader = null
    }

    @Synchronized
    fun clear() {
        buf.clear()
        seq.set(0)
    }

    /** Последние строки, старые сверху. Для broadcast — не больше [BROADCAST_CAP]. */
    @Synchronized
    fun tail(limit: Int = BROADCAST_CAP): List<String> {
        val n = minOf(limit, buf.size)
        return if (n == 0) emptyList() else buf.toList().takeLast(n)
    }

    @Synchronized
    private fun append(line: String?) {
        if (line == null) return
        buf.addLast(line)
        while (buf.size > CAP) buf.removeFirst()
    }

    /**
     * `logcat -v brief` даёт `I/TgWsProxy( 1234): текст`.
     * Берём только строки натива и ошибки; весь остальной шум приложения
     * (FlickerTgWs, Flutter и т.д.) в буфер не кладём.
     */
    private fun parse(raw: String): String? {
        val body = raw.substringAfter("): ", raw)
        if (body.isBlank()) return null
        val tag = raw.substringBefore('(', "").substringAfterLast('/', "")
        val isError = raw.startsWith("E/") || raw.startsWith("W/") ||
            body.contains("[ERROR]") || body.contains("[WARN]")
        val keep = tag == "TgWsProxy" ||
            body.contains("[ERROR]") || body.contains("[WARN]") ||
            body.contains("tgwsproxy") || isError
        if (!keep) return null
        val mark = when {
            raw.startsWith("E/") -> "! "
            raw.startsWith("W/") -> "~ "
            else -> "  "
        }
        val trimmed = body.trim().let { if (it.length > MAX_LINE) it.take(MAX_LINE) + "…" else it }
        return "$mark$trimmed"
    }
}
