// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn

import android.content.Context
import android.os.Build
import android.util.Log
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Захват причины падения.
 *
 * ЗАЧЕМ: приложение закрывалось при подключении БЕЗ диалога ошибки. Молчаливое
 * закрытие — это почти всегда нативный крах (SIGSEGV/SIGABRT внутри
 * libflickerbox.so) либо исключение, улетевшее из Java-колбэка обратно в Go
 * через JNI. Ни то, ни другое стандартный краш-диалог Android не показывает.
 *
 * ДВА КАНАЛА, ПОТОМУ ЧТО ОДИН НЕ ПОКРЫВАЕТ ДРУГОГО:
 *
 *  1. [install] — Thread.setDefaultUncaughtExceptionHandler. Ловит Java/Kotlin
 *     исключения на ЛЮБОМ потоке, включая потоки GoMobile-колбэков. Пишет стек
 *     в файл, который можно прочитать из приложения без компьютера.
 *     НЕ ловит нативный крах: при SIGABRT обработчик не вызывается.
 *
 *  2. logcat — ловит и нативные крахи тоже (тэги DEBUG/libc + tombstone).
 *     Поэтому в [lastNativeHint] мы сохраняем признак «процесс умер внезапно»,
 *     а настоящую причину надо смотреть в logcat. Команды — в docs/06-TESTING.md.
 *
 * Как отличить одно от другого:
 *   * в crash.log ЕСТЬ запись с временем падения → Java-исключение, причина в файле;
 *   * в crash.log записи нет, а приложение закрылось → нативный крах, нужен logcat.
 */
object CrashLog {

    private const val TAG = FlickerApp.TAG
    private const val FILE = "crash.log"
    private const val MAX_BYTES = 256 * 1024
    private const val MAX_ENTRIES = 40

    /** Отметка о запуске — нужна, чтобы отличить «упало» от «просто закрыли». */
    private const val SESSION = "session.marker"

    // Канал №3 (v4.0.4b): самостоятельный захват logcat. Нативный крах
    // (SIGSEGV/SIGABRT в libflickerbox.so) не пишет НИ в crash.log, НИ в
    // CrashReport ядра, если смерть мгновенная — но он ВСЕГДА виден в
    // системном журнале: строка «F libc: Fatal signal ...» принадлежит
    // нашему процессу, а буфер «crash» хранит записи и после смерти процесса.
    // Чтение СВОИХ записей не требует никаких разрешений.
    private const val LOGCAT_FILE = "logcat-self.log"
    private const val CRASHBUF_FILE = "crash-buffer.log"
    private const val LOGCAT_MAX_BYTES = 768 * 1024

    @Volatile
    private var appContext: Context? = null

    /**
     * Ставит обработчик. Вызывать из Application.onCreate() САМЫМ ПЕРВЫМ —
     * до загрузки нативной библиотеки, иначе крах в loadLibrary не запишется.
     */
    fun install(context: Context) {
        appContext = context.applicationContext
        val previous = Thread.getDefaultUncaughtExceptionHandler()

        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            try {
                record(thread, throwable)
            } catch (e: Throwable) {
                // Сам обработчик не имеет права падать: иначе мы потеряем
                // и исходное исключение, и процесс завершится некорректно.
                Log.e(TAG, "CrashLog.record не сработал", e)
            }
            // Обязательно передаём дальше системному обработчику — иначе
            // Android не покажет свой диалог и не завершит процесс штатно.
            previous?.uncaughtException(thread, throwable)
        }

        // Помечаем «предыдущая сессия не завершилась нормально».
        // Если при следующем старте маркер на месте — процесс умер внезапно
        // (нативный крах или убийство системой), а не был закрыт пользователем.
        try {
            file(context, SESSION).writeText(System.currentTimeMillis().toString())
        } catch (e: Exception) {
            Log.w(TAG, "не записать маркер сессии", e)
        }
    }

    /**
     * Снимает маркер при штатном завершении. Вызывать из TunnelService.onDestroy()
     * и при нормальном выходе — тогда оставшийся маркер однозначно означает
     * внезапную смерть процесса.
     */
    fun markCleanExit(context: Context) {
        try {
            file(context, SESSION).delete()
        } catch (_: Exception) {
        }
    }

    /** true, если прошлая сессия не завершилась штатно. */
    fun previousSessionCrashed(context: Context): Boolean = try {
        file(context, SESSION).exists()
    } catch (_: Exception) {
        false
    }

    /** Записывает исключение. Можно звать и вручную из catch-блоков. */
    fun record(thread: Thread, throwable: Throwable) {
        val ctx = appContext ?: return
        val sw = StringWriter()
        val header = StringBuilder()
        header.append("=====").append('\n')
        header.append(time()).append("  v").append(BuildConfig.VERSION_NAME)
            .append(" (").append(BuildConfig.VERSION_CODE).append(')').append('\n')
        header.append("поток: ").append(thread.name).append('\n')
        header.append("устройство: ").append(Build.MANUFACTURER).append(' ')
            .append(Build.MODEL).append(" / Android ").append(Build.VERSION.RELEASE)
            .append(" (API ").append(Build.VERSION.SDK_INT).append(')').append('\n')
        header.append("ABI: ").append(Build.SUPPORTED_ABIS.joinToString()).append('\n')
        header.append("ядро загружено: ").append(Native.ready)
        if (!Native.ready) header.append("  причина: ").append(Native.failureReason)
        header.append('\n')
        PrintWriter(sw).use { pw ->
            pw.print(header)
            throwable.printStackTrace(pw)
        }
        append(ctx, sw.toString())
        Log.e(TAG, "крах записан в $FILE", throwable)
    }

    /** Записывает произвольное сообщение (например, «native-вызов вернул ошибку»). */
    fun note(context: Context, message: String) {
        append(context, "----- ${time()}  $message\n")
    }

    /**
     * Содержимое журнала для показа пользователю.
     *
     * Объединяет ОБА канала, потому что они ловят разные классы падений:
     *  * Java-исключения — из нашего файла crash.log (пишет [install]);
     *  * нативные крахи (Go-паника, SIGABRT/SIGSEGV) — из файла, куда libbox
     *    перенаправил stderr процесса (пишет само ядро, см. Native.CRASH_SOURCE).
     *
     * Второй канал критичен: именно он объясняет «приложение закрылось само,
     * без диалога». Java-обработчик такие падения не видит по определению.
     */
    fun read(context: Context, logcatBudget: Int = 16000, archiveBudget: Int = 12000): String {
        val sb = StringBuilder()

        sb.append("FlickerVPN v").append(BuildConfig.VERSION_NAME)
            .append(" (").append(BuildConfig.VERSION_CODE).append(") · ")
            .append(Build.MANUFACTURER).append(" ").append(Build.MODEL)
            .append(" · Android ").append(Build.VERSION.RELEASE)
            .append(" (API ").append(Build.VERSION.SDK_INT).append(")\n\n")

        sb.append("### ПРИЧИНА (кратко)\n")
        sb.append(panicSummary(context)).append("\n\n")

        sb.append("### АРХИВ ЯДРА (box/crash_reports/*/go.log — текст Go-паник)\n")
        sb.append(latestArchivedReports(context, 2, archiveBudget)).append("\n\n")

        sb.append("### NATIVE (stderr ядра -> ")
            .append(Native.nativeCrashReport(context).name)
            .append(")\n")
        val native = Native.readNativeCrashReport(context)
        sb.append(
            if (native != null) native
            else "(пусто — Go-паник и native-крахов ядро не записало)"
        ).append("\n\n")

        sb.append("### JAVA (UncaughtExceptionHandler -> $FILE)\n")
        sb.append(
            try {
                val f = file(context, FILE)
                if (!f.exists()) "(пусто — Java-исключений не записано)"
                else f.readText().ifBlank { "(пусто)" }
            } catch (e: Exception) {
                "Не удалось прочитать журнал: ${e.message}"
            }
        )

        sb.append("\n\n### ЖУРНАЛ ЯДРА·ФАЙЛ (log.output sing-box -> box/core-file.log)\n")
        sb.append(
            // v4.10.1: хвост БЕЗ штатного шума ядра — иначе окно в 12 000
            // символов целиком забивалось строками «failed to search process»
            // и реальная причина отказа из отчёта исчезала. См. coreLogTail.
            try {
                coreLogTail(
                    java.io.File(Native.workingDir(context), TunnelService.CORE_FILE_LOG),
                    12000
                )
            } catch (e: Throwable) { "не прочитать: ${e.message}" }
        )

        // v4.11.0: обход живёт в процессе :bypass со СВОИМ рабочим каталогом
        // (box-bypass, см. Native.workingDir). Без этой секции отчёт слеп
        // именно к тому режиму, по которому приходят жалобы (docs/21).
        sb.append("\n\n### ЖУРНАЛ ЯДРА·ФАЙЛ ОБХОДА (:bypass -> box-bypass/core-file.log)\n")
        sb.append(
            try {
                coreLogTail(
                    java.io.File(java.io.File(context.filesDir, "box-bypass"), TunnelService.CORE_FILE_LOG),
                    12000
                )
            } catch (e: Throwable) { "не прочитать: ${e.message}" }
        )

        sb.append("\n\n### ЖУРНАЛ ЯДРА·CommandClient (-> box/core.log)\n")
        sb.append(
            try {
                coreLogTail(java.io.File(Native.workingDir(context), "core.log"), 8000)
            } catch (e: Throwable) { "не прочитать: ${e.message}" }
        )

        sb.append("\n\n### КОНФИГ, УШЕДШИЙ В ЯДРО (last-config.json, секреты скрыты)\n")
        sb.append(try {
            val f = java.io.File(context.filesDir, "last-config.json")
            if (!f.exists()) "(нет — туннель ещё не запускался)" else maskSecrets(f.readText())
        } catch (e: Throwable) { "не прочитать: ${e.message}" })

        sb.append("\n\n### LOGCAT (последние строки своего процесса -> ").append(LOGCAT_FILE).append(")\n")
        sb.append(tailOf(context, LOGCAT_FILE, logcatBudget))

        sb.append("\n\n### CRASH-BUFFER (системный журнал крахов -> ").append(CRASHBUF_FILE).append(")\n")
        sb.append(tailOf(context, CRASHBUF_FILE))

        return sb.toString()
    }

    /**
     * v4.5.0: конфиг в отчёте — главный диагностический артефакт. По нему видно,
     * какой именно узел, какой DNS и какие route-правила ушли в sing-box.
     * Секреты (uuid/password/private_key/short_id/public_key) затираются:
     * отчёт пользователь пересылает в чат, نشرковать чужие ключи нельзя.
     */
    private fun maskSecrets(json: String): String {
        var out = json
        for (k in listOf("uuid", "password", "private_key", "public_key", "short_id", "token", "psk")) {
            out = out.replace(Regex("\"$k\"\\s*:\\s*\"[^\"]*\""), "\"$k\":\"…\"")
        }
        return if (out.length > 6000) out.take(6000) + "\n…(обрезано)" else out
    }

    /** true, если есть хоть что-то в одном из двух каналов. */
    fun hasAnyRecord(context: Context): Boolean =
        Native.readNativeCrashReport(context) != null ||
            runCatching { file(context, FILE).let { it.exists() && it.readText().isNotBlank() } }
                .getOrDefault(false) ||
            runCatching {
                java.io.File(Native.workingDir(context), "crash_reports")
                    .listFiles { f -> f.isDirectory }?.isNotEmpty() == true
            }.getOrDefault(false)

    /** Чистит все журналы: Java-файл, native-репорт ядра, logcat-каналы. */
    fun clear(context: Context) {
        try {
            file(context, FILE).delete()
            file(context, LOGCAT_FILE).delete()
            file(context, CRASHBUF_FILE).delete()
        } catch (_: Exception) {
        }
        try {
            Native.nativeCrashReport(context).delete()
        } catch (e: Exception) {
            Log.w(TAG, "не удалить native crash report", e)
        }
    }

    /** Путь к файлу — чтобы вытащить его через adb без интерфейса. */
    fun path(context: Context): String = file(context, FILE).absolutePath

    // ------------------------------------------------------------------
    //  Канал №3: self-logcat
    // ------------------------------------------------------------------

    @Volatile
    private var logcatThread: Thread? = null

    /**
     * Непрерывный захват logcat СВОЕГО процесса в файл [LOGCAT_FILE].
     * Последние строки перед нативным крахом обычно содержат:
     *   F libc : Fatal signal 11 (SIGSEGV), code 1 ..., fault addr 0x...
     * а также текст Go-паники (тэг GoLog), если ядро успело его вывести.
     * Вызывать из Application.onCreate().
     */
    fun startSelfLogcat(context: Context) {
        if (logcatThread != null) return
        val f = file(context, LOGCAT_FILE)
        val pid = android.os.Process.myPid()
        val t = Thread {
            try {
                // Не затираем прошлую сессию целиком: её хвост — это и есть
                // момент падения (строки «Fatal signal», Go-паники). Оставляем
                // последние 64 КБ под разделителем.
                try {
                    if (f.exists()) {
                        val prev = f.readText()
                        val keep = if (prev.length > 64 * 1024) "…(обрезано)…\n" + prev.takeLast(64 * 1024) else prev
                        f.writeText("==== ПРОШЛАЯ СЕССИЯ (хвост) ====\n" + keep +
                            "\n==== ТЕКУЩАЯ СЕССИЯ " + time() + " ====\n")
                    }
                } catch (_: Exception) {
                    try { f.delete() } catch (_: Exception) {}
                }
                val proc = startLogcat("-v", "time", "--pid=" + pid)
                if (proc != null) {
                    proc.inputStream.use { input ->
                        java.io.FileOutputStream(f, true).use { out ->
                            val buf = ByteArray(8192)
                            var total = 0L
                            while (total < LOGCAT_MAX_BYTES) {
                                val n = input.read(buf)
                                if (n < 0) break
                                out.write(buf, 0, n)
                                out.flush()
                                total += n
                            }
                        }
                    }
                }
            } catch (_: Throwable) {
                // захват — best effort, на работу приложения влиять не должен
            }
        }
        t.isDaemon = true
        t.name = "self-logcat"
        logcatThread = t
        t.start()
    }

    /**
     * При старте после НЕШТАТНОГО завершения выгребает системный буфер «crash»
     * (записи нашего UID остаются там после смерти процесса) в [CRASHBUF_FILE].
     */
    /**
     * v4.0.8: безусловный слив системного буфера «crash» (записи нашего UID
     * хранятся там днями — полный tombstone с Abort message и ВСЕМИ кадрами
     * доступен даже спустя время после краша).
     */
    fun dumpCrashBuffer(context: Context) {
        val t = Thread { dumpCrashBufferSync(context) }
        t.isDaemon = true
        t.name = "crashbuf-dump"
        t.start()
    }

    /** Синхронный слив crash-буфера в [CRASHBUF_FILE]; true если что-то записано. */
    fun dumpCrashBufferSync(context: Context): Boolean = try {
        val proc = startLogcat("-d", "-b", "crash", "-v", "threadtime")
        if (proc == null) {
            false
        } else {
            val text = proc.inputStream.bufferedReader().use { it.readText() }
            // Process.waitFor(timeout) и destroyForcibly() — только API 26+,
            // а minSdk 24: ниже — совместимый вариант (lint NewApi).
            val finished = if (Build.VERSION.SDK_INT >= 26) {
                proc.waitFor(6, java.util.concurrent.TimeUnit.SECONDS)
            } else {
                val deadline = System.currentTimeMillis() + 6_000
                var done = false
                while (System.currentTimeMillis() < deadline) {
                    try { proc.exitValue(); done = true; break }
                    catch (_: IllegalThreadStateException) { Thread.sleep(100) }
                }
                done
            }
            if (!finished) {
                if (Build.VERSION.SDK_INT >= 26) proc.destroyForcibly() else proc.destroy()
            }
            if (text.isNotBlank()) {
                file(context, CRASHBUF_FILE).writeText("==== выгребено " + time() + " ====\n" + text)
                true
            } else false
        }
    } catch (t: Throwable) {
        Log.w(TAG, "dumpCrashBufferSync", t)
        false
    }

    /**
     * v4.0.8: АРХИВ паник ядра. libbox при КАЖДОМ запуске (redirectStderr ->
     * archiveCrashReport) переносит прошлый CrashReport-*.log в
     * box/crash_reports/<метка>/go.log и прикладывает снимок конфига
     * (configuration.json). Именно там лежит ТЕКСТ Go-паники, которого нет
     * в live-файле. Показываем последние [maxReports] архива.
     */
    fun latestArchivedReports(context: Context, maxReports: Int = 2, budget: Int = 12000): String {
        return try {
            val dir = java.io.File(Native.workingDir(context), "crash_reports")
            val subs: List<java.io.File> =
                dir.listFiles { f -> f.isDirectory }?.sortedByDescending { it.name } ?: emptyList()
            if (subs.isEmpty()) return "(архив пуст — libbox ещё не архивировал паники ядра)"
            val sb = StringBuilder()
            for (d in subs.take(maxReports)) {
                sb.append("\n--- ").append(d.name).append(" ---\n")
                val go = java.io.File(d, "go.log")
                if (go.exists() && go.length() > 0) {
                    val t = go.readText()
                    // v4.1.0: НАЧАЛО важнее хвоста — строка «panic:/fatal error:»
                    // и стек паникующей горутины всегда в первых килобайтах.
                    sb.append(
                        if (t.length > budget)
                            t.take(budget) + "\n…(середина дампа обрезана)…\n" + t.takeLast(1500)
                        else t
                    )
                } else {
                    for (f in d.listFiles() ?: emptyArray()) sb.append("(в архиве: ").append(f.name).append(")\n")
                }
                val cfg = java.io.File(d, "configuration.json")
                if (cfg.exists()) {
                    sb.append("\n[снимок конфига ядра, первые 4000 символов]:\n")
                    val t = cfg.readText()
                    sb.append(if (t.length > 4000) t.take(4000) + "…" else t).append("\n")
                }
            }
            sb.toString()
        } catch (e: Throwable) {
            "не прочитать архив: ${e.message}"
        }
    }

    private fun startLogcat(vararg args: String): Process? = try {
        ProcessBuilder(listOf("/system/bin/logcat") + args).apply { redirectErrorStream(true) }.start()
    } catch (_: Throwable) {
        try {
            ProcessBuilder(listOf("logcat") + args).apply { redirectErrorStream(true) }.start()
        } catch (_: Throwable) { null }
    }

    /**
     * v4.1.0: выдёргивает строки-причины (panic:/fatal error:/[signal/Fatal
     * signal/Abort message/FATAL EXCEPTION) из всех источников — архив ядра,
     * live-репорт, logcat, crash-буфер — и показывает их ПЕРВЫМ разделом.
     */
    fun panicSummary(context: Context, maxLines: Int = 8): String {
        val found = LinkedHashSet<String>()
        fun scan(text: String?) {
            if (text.isNullOrEmpty()) return
            for (line in text.lineSequence()) {
                if (found.size >= maxLines) return
                // logcat-строки имеют префикс "MM-DD hh:mm:ss.mmm X/TAG ( pid): " — срезаем его
                val core = line.substringAfter("): ", line).trim()
                if (core.startsWith("panic:") || core.startsWith("fatal error:") ||
                    core.startsWith("[signal ") || core.startsWith("Abort message:") ||
                    core.startsWith("FATAL EXCEPTION") || core.contains("Fatal signal") ||
                    core.startsWith("SIGQUIT:") || core.startsWith("runtime: ")
                ) {
                    found.add(core.take(400))
                }
            }
        }
        try {
            val dir = java.io.File(Native.workingDir(context), "crash_reports")
            dir.listFiles { f -> f.isDirectory }?.sortedByDescending { it.name }?.take(2)
                ?.forEach { d -> scan(runCatching { java.io.File(d, "go.log").readText() }.getOrNull()) }
        } catch (_: Throwable) {}
        scan(Native.readNativeCrashReport(context))
        scan(runCatching { file(context, LOGCAT_FILE).readText() }.getOrNull())
        scan(runCatching { file(context, CRASHBUF_FILE).readText() }.getOrNull())
        return if (found.isEmpty())
            "(строка причины не найдена — воспроизведите падение, перезапустите приложение и откройте журнал заново)"
        else found.joinToString("\n")
    }

    private fun tailOf(context: Context, name: String, max: Int = 8000): String = try {
        val f = file(context, name)
        if (!f.exists()) "(пусто)"
        else {
            val t = f.readText()
            when {
                t.isBlank() -> "(пусто)"
                t.length > max -> "…(начало обрезано)…\n" + t.takeLast(max)
                else -> t
            }
        }
    } catch (e: Exception) { "не прочитать: ${e.message}" }

    // ------------------------------------------------------------------------
    //  v4.10.1: хвост журнала ядра без штатного шума Android-ядра
    // ------------------------------------------------------------------------

    /**
     * Строка, которой sing-box v1.14.2 отвечает на КАЖДЫЙ отказ
     * FindConnectionOwner.
     *
     * Почему она вообще появляется. На Android ядро ищет владельца соединения
     * всегда: `searchProcessInfo` вызывается из `prepareMatchMetadata`
     * (route/route.go:546) для каждого соединения и из `hijackDNSStream`
     * (route/dns.go:21) для каждого перехваченного DNS-пакета. При этом:
     *
     *   * `route.find_process` в конфиге на это НЕ влияет — `searchProcessInfo`
     *     проверяет только `processSearcher == nil`, а на Android он создаётся
     *     всегда (`newPlatformSearcher`);
     *   * `platformSearcher.FindProcessInfo` первым делом спрашивает
     *     `UsePlatformConnectionOwnerFinder()`, а обёртка libbox возвращает
     *     `true` жёстко (experimental/libbox/service.go:189-191);
     *   * значит, вызов уходит в Kotlin-реализацию `findConnectionOwner`.
     *
     * Возвращать оттуда `null` нельзя: Go разыменовывает результат без
     * проверки (`result.UserId`, service.go:221-231) → nil pointer dereference
     * → SIGSEGV → SIGABRT → приложение умирает молча, без диалога. Именно так
     * оно и падало до v4.1.1 на первом же DNS-пакете (дамп — в
     * `uploads/1_ошибки.txt`). Единственный рабочий ответ — исключение:
     * gobind штатно превращает его в Go-error, ядро пишет строку INFO
     * «failed to search process: …» и продолжает маршрутизацию
     * (process_cache.go:47-50). Так же делает эталонная sing-box-for-android.
     *
     * Цена — по строке INFO на каждое соединение. Отсюда этот фильтр.
     */
    private const val CORE_LOG_NOISE = "failed to search process"

    /**
     * Сколько байт журнала читать с конца. `core-file.log` пишет само ядро и
     * ротации у него нет (в отличие от `core.log`, который подрезает
     * `TunnelService.appendCoreLog`), поэтому после долгой сессии файл может
     * быть десятки мегабайт; `readText()` целиком грозил OOM ровно в тот
     * момент, когда пользователь открывает отчёт о сбое.
     */
    private const val CORE_LOG_READ_MAX = 512 * 1024

    private fun coreLogTail(f: File, budget: Int): String {
        return try {
            if (!f.exists() || f.length() == 0L) {
                "(пусто — ядро ничего не писало)"
            } else {
                val lines = readTailBytes(f, CORE_LOG_READ_MAX).split('\n')
                var noise = 0
                val kept = StringBuilder()
                for (line in lines) {
                    if (CORE_LOG_NOISE in line) {
                        noise++
                        continue
                    }
                    kept.append(line).append('\n')
                }
                var body = kept.toString().trimEnd('\n')
                if (body.isBlank()) {
                    body = "(в прочитанном хвосте — только штатный шум: $noise строк «$CORE_LOG_NOISE»)"
                } else if (body.length > budget) {
                    body = "…(начало обрезано)…\n" + body.takeLast(budget)
                }
                // Число отброшенных строк само по себе диагноз: значит, туннель
                // поднят и ядро реально маршрутизирует соединения.
                if (noise > 0) {
                    "(отброшено $noise строк «$CORE_LOG_NOISE» — штатный шум " +
                        "Android-ядра, не ошибка)\n" + body
                } else {
                    body
                }
            }
        } catch (e: Throwable) {
            "не прочитать: ${e.message}"
        }
    }

    /**
     * Читает не больше [max] последних байт файла и выбрасывает первую
     * (неполную) строку, чтобы в отчёт не попал обрывок.
     */
    private fun readTailBytes(f: File, max: Int): String {
        val len = f.length()
        if (len <= max) return f.readText()
        java.io.RandomAccessFile(f, "r").use { raf ->
            raf.seek(len - max)
            val buf = ByteArray(max)
            var off = 0
            while (off < buf.size) {
                val n = raf.read(buf, off, buf.size - off)
                if (n <= 0) break
                off += n
            }
            val s = String(buf, 0, off, Charsets.UTF_8)
            val nl = s.indexOf('\n')
            return if (nl in 0 until s.length - 1) s.substring(nl + 1) else s
        }
    }

    // ------------------------------------------------------------------------

    private fun file(context: Context, name: String) = File(context.filesDir, name)

    private fun time(): String =
        SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())

    /**
     * Дописывает в конец и обрезает файл, чтобы он не рос бесконечно.
     * Держим самые свежие записи — они и нужны.
     */
    private fun append(context: Context, text: String) {
        try {
            val f = file(context, FILE)
            val existing = if (f.exists()) f.readText() else ""
            var combined = existing + text
            if (combined.length > MAX_BYTES) {
                combined = combined.substring(combined.length - MAX_BYTES)
                // обрезаем по границе записи, чтобы не показывать обрывок стека
                val cut = combined.indexOf("=====")
                if (cut > 0) combined = combined.substring(cut)
            }
            f.writeText(combined)
        } catch (e: Exception) {
            Log.w(TAG, "CrashLog.append", e)
        }
    }

    /** Сколько записей в журнале — для бейджа в меню. */
    fun entryCount(context: Context): Int = try {
        read(context).split("=====").size - 1
    } catch (_: Exception) {
        0
    }.coerceAtMost(MAX_ENTRIES)
}
