// SPDX-License-Identifier: GPL-3.0-or-later
//
// Flicker VPN для Android — Copyright (C) 2025 FlickerVPN contributors
// Лицензия: GNU GPL v3 или новее (см. android/LICENSE).
// Внутри используется sing-box (libbox, GPL-3.0) — производное произведение.
package dev.flicker.vpn

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import android.util.Log

/**
 * Application: одноразовая инициализация libbox (Setup) и загрузка
 * нативной библиотеки. libflickerbox.so содержит sing-box (libbox) и
 * Go-фасад dev.flicker.mobile (парсеры подписок, пробы, конфиги).
 *
 * ---------------------------------------------------------------------------
 *  ЧТО ИЗМЕНЕНО И ПОЧЕМУ
 * ---------------------------------------------------------------------------
 *  Было:
 *      createChannels()
 *      Repository.init(this)          // ← БЕЗ try/catch
 *
 *  Repository.init() → loadAll() → Mobile.defaultSources() и Mobile.sortServers().
 *  Оба — native-методы. Если libflickerbox.so не загрузилась, они кидают
 *  UnsatisfiedLinkError. Это Error, а не Exception, поэтому он пробивает любой
 *  catch(Exception) и вылетает из Application.onCreate().
 *
 *  Результат на устройстве: процесс умирает ДО создания MainActivity. Иконка
 *  есть, тап — ничего не происходит, краш-диалога нет. Это и есть симптом
 *  «ставится, но не запускается».
 *
 *  Стало: загрузка ядра вынесена в [Native.bootstrap] (никогда не бросает),
 *  а Repository.init() вызывается ТОЛЬКО если ядро готово, и дополнительно
 *  обёрнут в catch(Throwable) как страховка.
 * ---------------------------------------------------------------------------
 */
class FlickerApp : Application() {

    companion object {
        const val TAG = "FlickerVPN"
        const val CHANNEL_TUNNEL = "flicker-tunnel"
        const val CHANNEL_STATUS = "flicker-status"

        /** v4.10.0: отдельный канал для Telegram-туннеля — см. TgWsService. */
        const val CHANNEL_TGWS = "flicker-tgws"

        /**
         * Готово ли нативное ядро.
         * Оставлено для совместимости: его читают MainActivity и TunnelService.
         * Реальное состояние хранится в [Native.ready], это просто алиас.
         */
        val nativeReady: Boolean
            get() = Native.ready
    }

    override fun onCreate() {
        super.onCreate()

        // -------------------------------------------------------------------
        //  v4.10.0: ВСПОМОГАТЕЛЬНЫЕ ПРОЦЕССЫ НЕ ГРУЗЯТ ЯДРО.
        //
        //  Application.onCreate() вызывается в КАЖДОМ процессе приложения. У нас
        //  их три: основной, ":byedpi" (ByeDpiEngineService) и ":tgws"
        //  (TgWsService). Без этой проверки в каждом из них происходило:
        //
        //    * Native.bootstrap() → System.loadLibrary("flickerbox") →
        //      64 МБ синглтона sing-box в памяти процесса, которому он не
        //      нужен вовсе. На Galaxy M21 (4 ГБ, Exynos 9611) лишний процесс
        //      с таким маппингом — прямой путь к LMK-убийству основного;
        //    * Repository.init() → чтение И ЗАПИСЬ json-файлов серверов из
        //      двух процессов одновременно. Гонка, которая проявляется как
        //      «список узлов иногда пустой» и не воспроизводится по заказу;
        //    * CrashLog.startSelfLogcat() → два процесса пишут в ОДИН файл
        //      logcat-self.log, перетирая друг друга.
        //
        //  Теперь вспомогательный процесс создаёт только каналы уведомлений
        //  (они нужны его собственному foreground-сервису) и ставит обработчик крахов.
        //  Ничего из перечисленного выше ему не требуется: ByeDpiEngineService
        //  работает через libbyedpi.so, TgWsService — через libtgwsproxy.so.
        // -------------------------------------------------------------------
        if (processName()?.endsWith(":bypass") == true) {
            // v4.11.0: :bypass — САМОДОСТАТОЧНЫЙ процесс обхода DPI (docs/21):
            // здесь крутится sing-box (TUN) и byedpi, поэтому ядро НУЖНО, а
            // репозиторий узлов — нет (узлов в обходе нет вовсе).
            // startSelfLogcat() не включаем: файл logcat-self.log один на
            // приложение, два писателя перетирают друг друга.
            Log.i(TAG, "процесс :bypass — инициализирую ядро без репозитория")
            CrashLog.install(this)
            createChannels()
            Native.bootstrap(this)
            if (Native.ready) {
                try {
                    Repository.initWithoutNative(this)
                } catch (e: Throwable) {
                    Log.e(TAG, "Repository.initWithoutNative в :bypass не удался", e)
                }
            } else {
                Log.e(TAG, "Ядро не готово в :bypass: ${Native.failureReason}")
            }
            return
        }

        if (!isMainProcess()) {
            Log.i(TAG, "процесс ${processName()} — вспомогательный, ядро и репозиторий не инициализирую")
            createChannels()
            return
        }

        // 0. Обработчик крахов — ПЕРВЫМ, до загрузки нативной библиотеки.
        //    Иначе падение внутри loadLibrary/bootstrap не запишется, а именно
        //    такие падения выглядят как «тапнул по иконке — ничего не произошло».
        CrashLog.install(this)

        // 0b. Диагностика нативных крахов (канал №3): если прошлая сессия
        //     умерла нештатно — выгрести системный crash-буфер, и сразу начать
        //     непрерывный захват logcat своего процесса. Нативный крах
        //     (SIGSEGV/SIGABRT в libflickerbox.so) виден ТОЛЬКО там.
        if (CrashLog.previousSessionCrashed(this)) {
            CrashLog.note(this, "Прошлая сессия завершилась нештатно (нативный крах/убийство системой). " +
                "Полный tombstone — в разделе CRASH-BUFFER, текст Go-паники — в разделе АРХИВ ЯДРА журнала сбоев.")
        }
        CrashLog.dumpCrashBuffer(this)
        CrashLog.startSelfLogcat(this)

        // 1. Каналы уведомлений — ДО загрузки ядра: они нужны даже если ядро
        //    не поднимется (иначе не сможем показать ошибку пользователю).
        createChannels()

        // 2. Ядро. bootstrap() не бросает исключений наружу ни при каких условиях.
        Native.bootstrap(this)

        // 3. Репозиторий. Внутри loadAll() есть native-вызовы, поэтому:
        //    - не зовём вообще, если ядро не готово;
        //    - дополнительно страхуемся catch(Throwable) — Error тоже ловим.
        if (Native.ready) {
            try {
                Repository.init(this)
            } catch (e: Throwable) {
                Log.e(TAG, "Repository.init не удался", e)
            }
        } else {
            // Инициализируем хранилище БЕЗ обращения к ядру, чтобы UI не упал
            // на lateinit и смог показать список ошибок/настройки.
            try {
                Repository.initWithoutNative(this)
            } catch (e: Throwable) {
                Log.e(TAG, "Repository.initWithoutNative не удался", e)
            }
            Log.e(TAG, "Ядро не готово: ${Native.failureReason}")
        }

        // 4. Плитка в шторке должна начать слушать статус.
        //    Вызов через рефлексию: сам класс появляется только после переноса
        //    drop-in/app/src/main/java/dev/flicker/vpn/service/QuickTileService.kt.
        //    Пока его нет в проекте — молча пропускаем, чтобы не ломать сборку.
        try {
            Class.forName("dev.flicker.vpn.service.QuickTileService")
                .getMethod("refreshListeningState", android.content.Context::class.java)
                .invoke(null, this)
        } catch (_: ClassNotFoundException) {
            // плитка ещё не добавлена в проект — это нормально
        } catch (e: Throwable) {
            Log.w(TAG, "QuickTileService.refreshListeningState", e)
        }
    }

    private fun createChannels() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        try {
            val nm = getSystemService(NotificationManager::class.java) ?: return
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_TUNNEL,
                    getString(R.string.channel_tunnel),
                    // LOW: уведомление висит постоянно и не должно орать
                    NotificationManager.IMPORTANCE_LOW
                ).apply {
                    setShowBadge(false)
                    enableVibration(false)
                    description = getString(R.string.channel_tunnel_desc)
                }
            )
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_STATUS,
                    getString(R.string.channel_status),
                    NotificationManager.IMPORTANCE_DEFAULT
                ).apply {
                    setShowBadge(false)
                    description = getString(R.string.channel_status_desc)
                }
            )
            // v4.10.0: канал Telegram-туннеля. Создаётся в КАЖДОМ процессе —
            // TgWsService живёт в ":tgws", и если канала там нет, его
            // foreground-уведомление молча не показывается (Android 8+).
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_TGWS,
                    getString(R.string.channel_tgws),
                    NotificationManager.IMPORTANCE_LOW
                ).apply {
                    setShowBadge(false)
                    enableVibration(false)
                    description = getString(R.string.channel_tgws_desc)
                }
            )
        } catch (e: Throwable) {
            // Крайне маловероятно, но Application.onCreate не имеет права падать:
            // упадёт здесь — приложение не запустится вообще.
            Log.e(TAG, "createChannels", e)
        }
    }

    /**
     * Имя текущего процесса.
     *
     * `Application.getProcessName()` есть только с API 28, а minSdk = 24, поэтому
     * читаем /proc/self/cmdline: там лежит ровно то же значение, первым
     * NUL-терминированным полем. Работает на всех версиях и не требует ни
     * ActivityManager (который на части прошивок отвечает с задержкой), ни
     * рефлексии в скрытый ActivityThread.
     */
    private fun processName(): String = try {
        val raw = java.io.File("/proc/self/cmdline").readBytes()
        val end = raw.indexOf(0.toByte()).let { if (it < 0) raw.size else it }
        String(raw, 0, end, Charsets.US_ASCII).trim()
    } catch (t: Throwable) {
        ""
    }

    /**
     * Основной ли это процесс. Если имя определить не удалось, считаем процесс
     * основным: лучше один раз зря загрузить ядро, чем остаться без VPN.
     */
    private fun isMainProcess(): Boolean {
        val name = processName()
        if (name.isBlank()) return true
        val pkg = packageName
        return name == pkg || !name.startsWith("$pkg:")
    }
}
