// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn

import android.util.Log

/**
 * Единая точка проверки готовности нативного ядра.
 *
 * ЗАЧЕМ ЭТОТ КЛАСС СУЩЕСТВУЕТ
 * ----------------------------
 * Каждый метод `dev.flicker.mobile.Mobile.*` и `dev.flicker.libbox.Libbox.*` —
 * native. Если `libflickerbox.so` не загрузилась, первый же вызов кидает
 * `UnsatisfiedLinkError`. Это Error, а не Exception, поэтому `catch (e: Exception)`
 * его НЕ ловит — он пробивает любой такой блок и валит процесс.
 *
 * Если это происходит внутри `Application.onCreate()`, приложение умирает ДО
 * создания первой Activity. Для пользователя это выглядит ровно как
 * «иконка есть, тапаю — ничего не происходит». Никакого краш-диалога, никакого
 * лога на экране: процесс умер до того, как успел что-либо показать.
 *
 * Когда .so может не загрузиться:
 *   1. AAR собран не под ту ABI. В build.gradle.kts стоит
 *      abiFilters = ["arm64-v8a", "x86_64"], то есть на любом armeabi-v7a
 *      (32-битном) устройстве библиотеки в APK просто нет. Гарантированный краш.
 *   2. AAR не пересобран после смены `-libname`/`-javapkg`, и символы не совпали.
 *   3. `useLegacyPackaging = false` + .so без 16KB-выравнивания: на устройствах
 *      с 16-килобайтной страницей (Android 15+) dlopen падает.
 *   4. Не хватило места при распаковке .so (64 МБ).
 *
 * ПРАВИЛО: ни один вызов Mobile.* / Libbox.* не должен выполняться без [ready].
 *
 * Использование:
 * ```
 * val sorted = Native.call("sortServers", fallback = serversJson) {
 *     Mobile.sortServers(serversJson)
 * }
 * ```
 */
object Native {

    /**
     * Тег лога. @PublishedApi internal — а не private, потому что [call] и [run]
     * объявлены inline: inline-функция не имеет права обращаться к private-члену,
     * компилятор Kotlin это запрещает ("Public-API inline function cannot access
     * non-public-API").
     */
    @PublishedApi
    internal const val TAG: String = FlickerApp.TAG

    /** Загружено ли ядро. Ставится в FlickerApp.onCreate после успешного Libbox.setup. */
    @Volatile
    var ready: Boolean = false
        internal set

    /** Причина, по которой ядро не готово, — для показа пользователю. */
    @Volatile
    var failureReason: String? = null
        private set

    /**
     * Имя источника краш-репорта. Совпадает с `crashReportSource` в SetupOptions
     * и входит в имя файла, который пишет libbox.
     */
    const val CRASH_SOURCE: String = "FlickerVPN"

    /** Рабочий каталог ядра — тот, что передаётся в `workingPath`. */
    // v4.11.0: у процесса :bypass каталог СВОЙ (box-bypass). Иначе основной
    // процесс и обходный делили бы unix-сокет CommandServer, core.log и
    // crash-файл libbox: при переключении режимов сокет оказывался «занят»,
    // а журналы перетирались (docs/21).
    fun workingDir(app: android.content.Context): java.io.File =
        java.io.File(app.filesDir, "box" + processDirSuffix())

    /** Суффикс рабочего каталога по имени процесса: "" или "-bypass". */
    private fun processDirSuffix(): String = try {
        val cmd = java.io.File("/proc/self/cmdline").readText()
        if (cmd.trim { it == '\u0000' || it.isWhitespace() }.endsWith(":bypass")) "-bypass" else ""
    } catch (_: Throwable) {
        ""
    }

    /**
     * Файл, куда libbox перенаправил stderr процесса.
     *
     * Это ГЛАВНЫЙ источник истины о нативных крахах: Go-паника внутри
     * libflickerbox.so пишет стек именно сюда, а не в Java-обработчик
     * (Thread.setDefaultUncaughtExceptionHandler её не видит по определению).
     *
     * Путь повторяет Go-код из experimental/libbox/setup.go:
     *   filepath.Join(sWorkingPath, "CrashReport-"+sCrashReportSource+".log")
     */
    fun nativeCrashReport(app: android.content.Context): java.io.File =
        java.io.File(workingDir(app), "CrashReport-$CRASH_SOURCE.log")

    /**
     * Содержимое native-краш-репорта, или null если файла нет/он пуст.
     * Хвост важнее начала: свежая паника — в конце.
     */
    fun readNativeCrashReport(app: android.content.Context, maxChars: Int = 20000): String? {
        val f = nativeCrashReport(app)
        return try {
            if (!f.exists() || f.length() == 0L) null
            else {
                val t = f.readText()
                if (t.isBlank()) null else if (t.length > maxChars) "…" + t.takeLast(maxChars) else t
            }
        } catch (e: Throwable) {
            Log.w(TAG, "не прочитать native crash report", e)
            null
        }
    }

    /** Текст ошибки для UI. Не null, только если ядро не готово. */
    val userVisibleError: String?
        get() = if (ready) null else (failureReason ?: "Ядро sing-box не загружено")

    /**
     * Загрузка библиотеки + инициализация libbox.
     * Вызывается один раз из [FlickerApp.onCreate]. Никогда не бросает наружу.
     */
    fun bootstrap(app: FlickerApp): Boolean {
        if (ready) return true
        try {
            System.loadLibrary("flickerbox")
        } catch (e: Throwable) {
            // UnsatisfiedLinkError — самая частая причина «не запускается»
            failureReason = describeLoadFailure(e)
            Log.e(TAG, "libflickerbox.so не загружена: $failureReason", e)
            return false
        }

        try {
            val workDir = java.io.File(app.filesDir, "box")
            workDir.mkdirs()
            val options = dev.flicker.libbox.SetupOptions().apply {
                basePath = app.filesDir.absolutePath
                workingPath = workDir.absolutePath
                tempPath = app.cacheDir.absolutePath
                fixAndroidStack = true
                // 3000, как в SFA: при 500 строках хвост лога ядра обрезается
                // раньше, чем успеваешь его прочитать.
                logMaxLines = 3000
                appVersion = BuildConfig.VERSION_NAME
                appMarketingVersion = BuildConfig.VERSION_NAME
                // ОБЯЗАТЕЛЬНО: Libbox.setup() в Go делает
                //   redirectStderr(workingPath + "/CrashReport-" + sCrashReportSource + ".log")
                // то есть ПЕРЕНАПРАВЛЯЕТ STDERR ПРОЦЕССА В ФАЙЛ. Туда попадают
                // Go-паники и runtime fatals — ровно те случаи, когда приложение
                // закрывается молча, без Java-краш-диалога, и logcat может уже
                // ничего не показать.
                //
                // Без этого поля файл называется "CrashReport-.log" (пустой
                // source) — имя непредсказуемое, и найти его вслепую нельзя.
                crashReportSource = CRASH_SOURCE
                oomKillerEnabled = true
                // oomMemoryLimit намеренно НЕ ставим. В Go (setup.go):
                //   if sOOMMemoryLimit > 0 { SetMemoryLimit(limit*4/5) }
                //   else { SetMemoryLimit(math.MaxInt64) }
                // Ветка с дефолтным лимитом существует только для iOS
                // (C.IsIos). На Android лимит 0 = безлимита, то есть OOM-killer
                // процесс не убивает. Ставить сюда число значило бы разрешить
                // ядру самостоятельно завершать процесс по превышению памяти —
                // ещё один источник «молчаливого закрытия».
                oomMemoryLimit = 0
            }
            dev.flicker.libbox.Libbox.setup(options)
        } catch (e: Throwable) {
            failureReason = "Libbox.setup: ${e.message ?: e.javaClass.simpleName}"
            Log.e(TAG, "Libbox.setup не удался", e)
            return false
        }

        ready = true
        failureReason = null
        Log.i(TAG, "libbox setup ok, core v${versionOrUnknown()}")
        return true
    }

    /**
     * Безопасный вызов native-метода.
     *
     * @param what      имя операции — только для лога
     * @param fallback  что вернуть, если ядро не готово или вызов упал
     * @param block     сам вызов
     *
     * Ловит `Throwable`, а не `Exception`: `UnsatisfiedLinkError`,
     * `ExceptionInInitializerError` и `NoClassDefFoundError` — все Error.
     */
    inline fun <T> call(what: String, fallback: T, block: () -> T): T {
        if (!ready) {
            Log.w(TAG, "$what пропущен: ядро не готово ($failureReason)")
            return fallback
        }
        return try {
            block()
        } catch (e: Throwable) {
            Log.e(TAG, "$what упал", e)
            fallback
        }
    }

    /**
     * То же, но для операций без возвращаемого значения.
     * @return true, если вызов прошёл
     */
    inline fun run(what: String, block: () -> Unit): Boolean {
        if (!ready) {
            Log.w(TAG, "$what пропущен: ядро не готово ($failureReason)")
            return false
        }
        return try {
            block()
            true
        } catch (e: Throwable) {
            Log.e(TAG, "$what упал", e)
            false
        }
    }

    /**
     * human-readable причина падения loadLibrary.
     * По тексту UnsatisfiedLinkError обычно сразу видно, что случилось.
     */
    private fun describeLoadFailure(e: Throwable): String {
        val msg = e.message.orEmpty()
        val abis = try {
            android.os.Build.SUPPORTED_ABIS.joinToString()
        } catch (_: Throwable) {
            "?"
        }
        return when {
            msg.contains("dlopen failed") && msg.contains("16 KB") ->
                "Библиотека не выровнена по 16 КБ — устройство со страницей 16 КБ (Android 15+). " +
                    "Пересоберите AAR или поставьте useLegacyPackaging = true."
            msg.contains("dlopen failed") ->
                "dlopen отклонил библиотеку: ${msg.take(160)}"
            msg.contains("library") && msg.contains("not found") ->
                "В APK нет libflickerbox.so под это устройство. ABI устройства: [$abis]. " +
                    "Проверьте, что AAR собран под нужные ABI (tools/build-libbox-aar.sh)."
            else -> "${e.javaClass.simpleName}: ${msg.take(160)} (ABI устройства: [$abis])"
        }
    }

    private fun versionOrUnknown(): String = try {
        dev.flicker.mobile.Mobile.version() ?: "?"
    } catch (e: Throwable) {
        "?"
    }
}
