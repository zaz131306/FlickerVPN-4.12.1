// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn.core.tgws

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import dev.flicker.vpn.FlickerApp
import dev.flicker.vpn.R
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import kotlin.concurrent.thread

/**
 * v4.10.0: foreground-сервис Telegram-туннеля (MTProto-WS).
 *
 * ---------------------------------------------------------------------------
 *  ОТДЕЛЬНЫЙ ПРОЦЕСС `:tgws` — НЕ КОСМЕТИКА
 * ---------------------------------------------------------------------------
 *  Ядро — Rust-библиотека `libtgwsproxy.so` с tokio-рантаймом на 4 воркера.
 *  Два соображения, почему её нельзя держать в основном процессе:
 *
 *   1. КРАШИ. Паника в Rust-cdylib по умолчанию заканчивается `abort()`, то
 *      есть SIGABRT всего процесса. В основном процессе это означало бы смерть
 *      VpnService вместе с синглтоном sing-box: туннель рвётся, а ключик в
 *      статусбаре остаётся — ровно тот баг, который чинили в v4.7.1. В
 *      отдельном процессе падение натива убивает только прокси Telegram,
 *      VPN продолжает работать.
 *
 *   2. СОСТОЯНИЕ. Глобальный tokio-рантайм в этой библиотеке «никогда не
 *      дропается» (комментарий в её src/lib.rs), воркеры живут до конца
 *      процесса. Держать их рядом с 64-мегабайтной libflickerbox.so незачем.
 *
 *  Та же схема в ByeByeDPI-x-tg (`android:process=":native"`) и в нашем
 *  собственном ByeDpiEngineService (`:byedpi`).
 *
 *  ЦЕНА отдельного процесса: StateFlow сервиса из UI не виден. Поэтому
 *  состояние уходит broadcast'ом — см. [TgWsClient].
 *
 * ---------------------------------------------------------------------------
 *  ЭТО НЕ VpnService
 * ---------------------------------------------------------------------------
 *  Сервис поднимает обычный TCP-слушатель на 127.0.0.1:[port]. Ни TUN, ни
 *  разрешения VpnService, ни ключика в статусбаре. Telegram подключается к нему
 *  как к MTProto-прокси (прокси прописывается внутри Telegram).
 *
 *  Поэтому сервис полностью независим от TunnelService: его можно включить
 *  при выключенном VPN, при включённом VPN и в режиме обхода DPI.
 */
class TgWsService : Service() {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    /**
     * Отдельный scope для остановки. Основной отменяется в onDestroy(), а
     * стоп-последовательность (native stop → stopForeground → stopSelf)
     * обязана завершиться, иначе уведомление останется висеть в шторке
     * навсегда. Тот же приём, что в TunnelService.stopTunnel().
     */
    private val stopScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private var wakeLock: PowerManager.WakeLock? = null
    private var wakeLockAt = 0L

    /**
     * @Volatile: тикер создаётся в потоке "TgWsStart", а отменяется в главном
     * (onStartCommand) и в stopScope. Без volatile главный поток может не
     * увидеть присваивание и оставить тикер жить после остановки.
     */
    @Volatile private var ticker: Job? = null
    @Volatile private var restartJob: Job? = null

    @Volatile private var stopping = false
    @Volatile private var pendingStart = false
    @Volatile private var started = false      // startForeground() уже вызван
    @Volatile private var running = false      // прокси считается запущенным
    @Volatile private var verified = false     // StartProxy вернул 0, порт слушается
    @Volatile private var autoRestarts = 0

    // Параметры последнего старта — для рестарта и для ответа на QUERY.
    @Volatile private var bindIp = TgWsConfig.DEFAULT_BIND
    @Volatile private var port = TgWsConfig.DEFAULT_PORT
    @Volatile private var dcIps = ""
    @Volatile private var poolSize = TgWsConfig.DEFAULT_POOL
    @Volatile private var cfEnabled = true
    @Volatile private var cfPriority = true
    @Volatile private var cfDomain = ""
    @Volatile private var secret = ""
    @Volatile private var verbose = true
    @Volatile private var keepAwake = true
    @Volatile private var secretFull = ""
    @Volatile private var lastStats = ""
    @Volatile private var lastError = ""

    @Volatile private var lastNotifText = ""
    @Volatile private var lastNotifAt = 0L

    override fun onCreate() {
        super.onCreate()
        createChannel()
        // JNA: путь к .so прописываем ДО первого обращения к классам JNA —
        // NativeLibrary читает jna.library.path в статическом инициализаторе.
        TgWsNative.init(applicationInfo.nativeLibraryDir)
        TgWsLog.start()
        Log.i(TAG, "процесс :tgws создан, pid=${android.os.Process.myPid()}")
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        when (action) {
            TgWsClient.ACTION_START -> {
                readExtras(intent)
                autoRestarts = 0
                if (stopping) {
                    // Остановка ещё идёт (натив освобождает порт до 3,5 с).
                    // Молча выбросить старт — значит получить «нажал, ничего
                    // не произошло». Запоминаем и поднимаем сразу после teardown.
                    pendingStart = true
                    Log.i(TAG, "старт во время остановки — повторю после teardown")
                    broadcast()
                } else {
                    startProxy()
                }
            }

            TgWsClient.ACTION_STOP -> {
                pendingStart = false
                stopEverything("stop")
            }

            TgWsClient.ACTION_RESTART -> restart()

            TgWsClient.ACTION_QUERY -> broadcast()

            null -> {
                // START_REDELIVER_INTENT: система пересоздала сервис после
                // убийства и вернула последний интент... кроме случая, когда
                // intent всё-таки null. Тогда конфигурации нет — гасим честно,
                // а не висим пустым foreground-сервисом с мёртвым прокси.
                if (secret.isNotBlank() && port in 1..65535) {
                    Log.w(TAG, "сервис пересоздан системой — поднимаю прокси заново")
                    startProxy()
                } else {
                    Log.w(TAG, "сервис пересоздан без параметров — останавливаюсь")
                    stopEverything("no-config")
                }
            }

            else -> broadcast()
        }

        // -------------------------------------------------------------------
        //  ОБЯЗАТЕЛЬНО: снять 5-секундное требование startForeground.
        //
        //  Команды QUERY/STOP/RESTART могут прийти через
        //  startForegroundService() (так делает TgWsClient, когда обычный
        //  startService запрещён из фона). Система при этом взводит таймер:
        //  не вызвал startForeground() за ~5 с — RemoteServiceException и
        //  убийство процесса. Для команд, которые прокси НЕ поднимают,
        //  startForeground не вызывается вовсе, поэтому сервис надо честно
        //  погасить здесь же: stopSelf(startId) снимает требование.
        //
        //  Без этой ветки любой запрос состояния при выключенном туннеле
        //  (а MainActivity шлёт его в каждом onResume) ронял бы процесс
        //  через 5 секунд — с ключиком VPN в статусбаре, если VPN был поднят.
        // -------------------------------------------------------------------
        if (!started) {
            Log.i(TAG, "после '$action' сервис не в foreground — завершаюсь")
            stopping = false
            pendingStart = false
            stopSelf(startId)
            return START_NOT_STICKY
        }
        // REDELIVER, а не STICKY: STICKY пересоздаёт сервис с null-intent,
        // и прокси поднялся бы с параметрами по умолчанию. REDELIVER возвращает
        // последний интент со всеми extras — конфигурация не теряется.
        return START_REDELIVER_INTENT
    }

    private fun readExtras(i: Intent) {
        bindIp = i.getStringExtra(TgWsClient.EXTRA_BIND_IP) ?: TgWsConfig.DEFAULT_BIND
        port = i.getIntExtra(TgWsClient.EXTRA_PORT, TgWsConfig.DEFAULT_PORT)
        dcIps = i.getStringExtra(TgWsClient.EXTRA_IPS) ?: ""
        poolSize = i.getIntExtra(TgWsClient.EXTRA_POOL_SIZE, TgWsConfig.DEFAULT_POOL)
        cfEnabled = i.getBooleanExtra(TgWsClient.EXTRA_CF_ENABLED, true)
        cfPriority = i.getBooleanExtra(TgWsClient.EXTRA_CF_PRIORITY, true)
        cfDomain = i.getStringExtra(TgWsClient.EXTRA_CF_DOMAIN) ?: ""
        secret = i.getStringExtra(TgWsClient.EXTRA_SECRET) ?: ""
        verbose = i.getBooleanExtra(TgWsClient.EXTRA_VERBOSE, true)
        keepAwake = i.getBooleanExtra(TgWsClient.EXTRA_KEEP_AWAKE, true)
    }

    // -----------------------------------------------------------------------
    //  Старт
    // -----------------------------------------------------------------------

    private fun startProxy() {
        if (running || stopping) {
            broadcast()
            return
        }

        // Проверки, после которых перезапускать бессмысленно.
        val fatal = when {
            !TgWsConfig.isValidSecret(secret) ->
                "Секрет некорректен: нужны ровно 32 hex-символа"
            port !in 1..65535 ->
                "Порт вне диапазона 1..65535: $port"
            !TgWsNative.ready ->
                "libtgwsproxy.so не загружена: ${TgWsNative.loadError ?: "причина неизвестна"}"
            else -> null
        }
        if (fatal != null) {
            lastError = fatal
            Log.e(TAG, fatal)
            failFast()
            return
        }

        lastError = ""
        verified = false
        TgWsLog.clear()
        TgWsLog.start()

        // startForeground ОБЯЗАН идти до любой долгой работы: после
        // ContextCompat.startForegroundService() есть ~5 секунд, иначе
        // ForegroundServiceDidNotStartInTimeException и убийство процесса.
        // Старт натива может занять больше (он тянет список доменов CF),
        // поэтому сначала уведомление, потом работа в отдельном потоке.
        running = true
        enterForeground(getString(R.string.tgws_starting))
        broadcast()

        thread(name = "TgWsStart", isDaemon = true) {
            // Порт проверяем сами: так «занято» отличается от «натив не смог».
            if (!portFree(bindIp, port)) {
                lastError = "Порт $port занят (другой прокси или прошлый запуск не завершился)"
                Log.e(TAG, lastError)
                scheduleRetryOrStop()
                return@thread
            }
            try {
                TgWsNative.setPoolSize(poolSize)
                TgWsNative.setCfProxyCacheDir(cacheDir.absolutePath)
                TgWsNative.setCfProxyConfig(cfEnabled, cfPriority, cfDomain)
                TgWsNative.setSecret(secret)

                val code = TgWsNative.startProxy(bindIp, port, dcIps, secret, verbose)
                if (code == null) {
                    lastError = "Натив не ответил: ${TgWsNative.loadError ?: "?"}"
                    scheduleRetryOrStop()
                    return@thread
                }
                if (code != 0) {
                    lastError = "Старт не удался: ${TgWsNative.explainStartCode(code)}"
                    Log.e(TAG, lastError)
                    scheduleRetryOrStop()
                    return@thread
                }

                autoRestarts = 0
                verified = true
                secretFull = TgWsNative.secretWithPrefix().orEmpty()
                if (keepAwake) acquireWakeLock()
                Log.i(TAG, "прокси слушает $bindIp:$port, secret=${mask(secretFull)}")
                scope.launch {
                    updateNotification(getString(R.string.tgws_running), force = true)
                    broadcast()
                }
                startTicker()
            } catch (t: Throwable) {
                // Ловим Throwable: JNA кидает UnsatisfiedLinkError (это Error),
                // а его catch(Exception) не берёт.
                lastError = "${t.javaClass.simpleName}: ${t.message ?: "?"}"
                Log.e(TAG, "старт натива бросил", t)
                scheduleRetryOrStop()
            }
        }
    }

    /**
     * Ошибка, при которой рестарт бессмыслен (нет .so, битый секрет, порт 0).
     * Показываем её в уведомлении, даём прочитать и гасим сервис — иначе он
     * висел бы foreground'ом вечно с нерабочим прокси.
     */
    private fun failFast() {
        running = false
        verified = false
        enterForeground(lastError)
        broadcast()
        stopScope.launch {
            // Даём прочитать ошибку в уведомлении и на экране, потом гасим.
            // teardown() сам обработает pendingStart: если за эти 6 секунд
            // пользователь нажал «Запустить» снова, прокси поднимется.
            delay(6_000)
            teardown()
        }
    }

    /**
     * Переходная ошибка (порт занят прошлым запуском, CF не ответил). Пробуем
     * ещё [MAX_AUTO_RESTARTS] раза с паузой.
     */
    private fun scheduleRetryOrStop() {
        verified = false
        scope.launch {
            updateNotification(lastError, force = true)
            broadcast()
            if (autoRestarts < MAX_AUTO_RESTARTS && !stopping) {
                autoRestarts++
                Log.w(TAG, "автоперезапуск $autoRestarts/$MAX_AUTO_RESTARTS через ${RETRY_DELAY_MS}мс")
                running = false
                // Натив мог частично подняться — гасим перед повтором, иначе
                // StartProxy вернёт -1 («уже запущен»).
                nativeStopQuietly("retry")
                delay(RETRY_DELAY_MS)
                if (!stopping) startProxy()
            } else {
                Log.e(TAG, "автоперезапуски исчерпаны — останавливаю сервис")
                delay(3_000)
                stopEverything("retries-exhausted")
            }
        }
    }

    private fun restart() {
        if (restartJob?.isActive == true) return
        if (secret.isBlank()) {
            Log.w(TAG, "restart без сохранённых параметров — игнорирую")
            broadcast()
            return
        }
        restartJob = scope.launch {
            Log.i(TAG, "перезапуск прокси")
            updateNotification(getString(R.string.tgws_restarting), force = true)
            stopTicker()
            nativeStopQuietly("restart")
            releaseWakeLock()
            running = false
            verified = false
            lastStats = ""
            broadcast()
            delay(500)
            if (!stopping) startProxy()
        }
    }

    // -----------------------------------------------------------------------
    //  Статистика
    // -----------------------------------------------------------------------

    private fun startTicker() {
        stopTicker()
        ticker = scope.launch {
            while (isActive) {
                delay(STATS_MS)
                if (!running || stopping) continue
                val s = try {
                    withContext(Dispatchers.IO) { TgWsNative.stats() }
                } catch (t: Throwable) {
                    Log.w(TAG, "GetStats", t)
                    null
                }
                if (!s.isNullOrEmpty()) {
                    lastStats = s
                    updateNotification(formatStats(s))
                }
                // Wakelock держим с таймаутом — продлеваем, пока прокси жив.
                if (keepAwake && System.currentTimeMillis() - wakeLockAt > WAKELOCK_REFRESH_MS) {
                    acquireWakeLock()
                }
                broadcast()
            }
        }
    }

    private fun stopTicker() {
        ticker?.cancel()
        ticker = null
    }

    /**
     * `total=12 active=3 ws=2 tcp_fb=0 cf=5 bad=0 err=0 pool=2/4 up=1.2MB down=800KB`
     * → «3 сесс · ws 2 · cf 5 · ↑1.2MB ↓800KB».
     *
     * Формат строки прочитан из бинарника (см. TgWsNative). Парсер терпит
     * отсутствие любого поля: если форк поменяет вывод, уведомление покажет
     * меньше деталей, а не упадёт.
     */
    internal fun formatStats(raw: String): String {
        fun num(key: String): String? {
            val i = raw.indexOf(key)
            if (i < 0) return null
            val from = i + key.length
            val to = raw.indexOf(' ', from).let { if (it < 0) raw.length else it }
            return raw.substring(from, to).trim().ifBlank { null }
        }
        val parts = mutableListOf<String>()
        num("active=")?.let { parts += "$it сесс" }
        num("ws=")?.let { parts += "ws $it" }
        num("cf=")?.let { parts += "cf $it" }
        num("tcp_fb=")?.let { if (it != "0") parts += "tcp $it" }
        num("err=")?.let { if (it != "0") parts += "ошибок $it" }
        num("bad=")?.let { if (it != "0") parts += "bad $it" }
        num("up=")?.let { parts += "↑$it" }
        num("down=")?.let { parts += "↓$it" }
        return if (parts.isEmpty()) getString(R.string.tgws_running) else parts.joinToString(" · ")
    }

    // -----------------------------------------------------------------------
    //  Остановка
    // -----------------------------------------------------------------------

    private fun stopEverything(reason: String) {
        if (stopping) return
        stopping = true
        Log.i(TAG, "остановка ($reason)")
        restartJob?.cancel()
        restartJob = null
        stopTicker()
        // Запоминаем ДО сброса флагов: натив надо гасить, только если он
        // действительно поднимался. Иначе StopProxy() отработает вхолостую
        // (вернёт -1), а мы потеряем до 3,5 с на ожидании.
        val hadNative = running || verified
        stopScope.launch {
            running = false
            verified = false
            updateNotification(getString(R.string.tgws_stopping), force = true)
            broadcast()
            if (hadNative) nativeStopQuietly(reason)
            releaseWakeLock()
            teardown()
        }
    }

    /**
     * StopProxy блокирует вызывающий поток до ~2 с (внутри `block_on` с
     * timeout). Поэтому только отдельный поток и свой лимит ожидания сверху:
     * если Rust зависнет, сервис всё равно завершится и уведомление не
     * останется висеть.
     */
    private suspend fun nativeStopQuietly(reason: String) {
        val done = CompletableDeferred<Unit>()
        thread(name = "TgWsStop-$reason", isDaemon = true) {
            try {
                Log.i(TAG, "StopProxy($reason) → ${TgWsNative.stopProxy()}")
            } catch (t: Throwable) {
                Log.w(TAG, "StopProxy($reason) бросил", t)
            } finally {
                done.complete(Unit)
            }
        }
        val ok = withTimeoutOrNull(NATIVE_STOP_WAIT_MS) { done.await(); true } ?: false
        if (!ok) Log.w(TAG, "натив не остановился за ${NATIVE_STOP_WAIT_MS}мс ($reason)")
    }

    /** Снять foreground, убрать уведомление, остановить сервис. Идемпотентно. */
    private fun teardown() {
        try {
            if (started) ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        } catch (t: Throwable) {
            Log.w(TAG, "stopForeground", t)
        }
        // stopForeground(REMOVE) не всегда убирает уведомления, обновлённые
        // через notify() — снимаем явно.
        try {
            getSystemService(NotificationManager::class.java)?.cancel(NOTIF_ID)
        } catch (t: Throwable) {
            Log.w(TAG, "cancel уведомления", t)
        }
        started = false
        running = false
        verified = false
        lastStats = ""
        broadcast()
        TgWsLog.stop()

        if (pendingStart) {
            // Пока мы останавливались, пользователь нажал «Запустить» снова.
            // Сервис ещё жив — поднимаем прокси здесь же, без нового
            // startForegroundService (и без риска попасть в 5-секундное окно).
            pendingStart = false
            stopping = false
            Log.i(TAG, "отложенный старт после teardown")
            startProxy()
            return
        }

        stopping = false
        stopSelf()
    }

    override fun onDestroy() {
        Log.i(TAG, "onDestroy")
        stopTicker()
        releaseWakeLock()
        // stopScope НЕ отменяем: стоп-последовательность должна дожить.
        scope.cancel()
        TgWsLog.stop()
        super.onDestroy()
    }

    /**
     * Свапнули из недавних приложений. Сервис остаётся жить
     * (stopWithTask="false" в манифесте): прокси Telegram не должен рваться
     * от того, что пользователь закрыл UI.
     */
    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        Log.i(TAG, "onTaskRemoved: прокси продолжает работать")
        broadcast()
    }

    // -----------------------------------------------------------------------
    //  Foreground / уведомление
    // -----------------------------------------------------------------------

    private fun enterForeground(text: String) {
        if (started) {
            updateNotification(text, force = true)
            return
        }
        try {
            ServiceCompat.startForeground(this, NOTIF_ID, buildNotification(text), fgType())
            started = true
            lastNotifText = text
            lastNotifAt = System.currentTimeMillis()
        } catch (t: Throwable) {
            Log.e(TAG, "startForeground не удался", t)
            // Без foreground сервис убьют почти сразу, а прокси останется
            // слушать порт. Честнее остановиться.
            lastError = "Не удалось перейти в фоновый режим: ${t.javaClass.simpleName}"
            stopEverything("fg-failed")
        }
    }

    private fun fgType(): Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_MANIFEST
        } else 0

    private fun updateNotification(text: String, force: Boolean = false) {
        if (!started) return
        val now = System.currentTimeMillis()
        if (!force) {
            if (text == lastNotifText) return
            // Не дёргаем NotificationManager чаще раза в секунду: на части
            // прошивок шторка от этого мигает.
            if (now - lastNotifAt < 1_000L) return
        }
        lastNotifText = text
        lastNotifAt = now
        try {
            getSystemService(NotificationManager::class.java)?.notify(NOTIF_ID, buildNotification(text))
        } catch (t: Throwable) {
            Log.w(TAG, "notify", t)
        }
    }

    private fun buildNotification(text: String): Notification {
        val body = when {
            text.isNotBlank() -> text
            lastError.isNotBlank() -> lastError
            else -> getString(R.string.tgws_notif_title)
        }
        val b = NotificationCompat.Builder(this, FlickerApp.CHANNEL_TGWS)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(getString(R.string.tgws_notif_title))
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setOngoing(true)
            .setSilent(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .setContentIntent(openScreen())

        if (verified) {
            b.addAction(0, getString(R.string.tgws_action_restart), svc(TgWsClient.ACTION_RESTART, RC_RESTART))
        }
        b.addAction(0, getString(R.string.action_disconnect), svc(TgWsClient.ACTION_STOP, RC_STOP))
        return b.build()
    }

    /**
     * Тап по уведомлению открывает экран Telegram-туннеля.
     *
     * Intent собирается ПО ИМЕНИ КЛАССА (`setClassName`), а не через
     * `Intent(this, TgWsActivity::class.java)` или `Class.forName(...)`.
     * Причина — процесс. Этот сервис живёт в `:tgws`, а экран в основном
     * процессе; любая ссылка на класс MainActivity/TgWsActivity заставила бы
     * загрузчик классов `:tgws` тянуть их в память вместе со всем графом
     * зависимостей UI (ViewBinding, Material, Repository) в процесс, которому
     * они не нужны. `setClassName` — просто строка в Intent, класс не
     * загружается вовсе, а резолвит его система уже в основном процессе.
     *
     * Падать здесь нечему: если экран переименуют и имя устареет, система
     * не найдёт Activity и тап по уведомлению просто ничего не сделает —
     * сервис при этом продолжит работать.
     */
    private fun openScreen(): PendingIntent = PendingIntent.getActivity(
        this, RC_OPEN,
        // ACTION не нужен: Intent явный (компонент задан), система резолвит его напрямую.
        Intent().setClassName(packageName, ACTIVITY_CLASS)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP),
        piFlags()
    )

    private fun piFlags() = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE

    private fun svc(action: String, rc: Int) = PendingIntent.getService(
        this, rc, Intent(this, TgWsService::class.java).setAction(action), piFlags()
    )

    private fun createChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        try {
            val nm = getSystemService(NotificationManager::class.java) ?: return
            nm.createNotificationChannel(
                NotificationChannel(
                    FlickerApp.CHANNEL_TGWS,
                    getString(R.string.channel_tgws),
                    NotificationManager.IMPORTANCE_LOW
                ).apply {
                    setShowBadge(false)
                    enableVibration(false)
                    description = getString(R.string.channel_tgws_desc)
                }
            )
        } catch (t: Throwable) {
            Log.w(TAG, "createChannel", t)
        }
    }

    // -----------------------------------------------------------------------
    //  Broadcast состояния
    // -----------------------------------------------------------------------

    private fun broadcast() {
        try {
            sendBroadcast(
                Intent(TgWsClient.BROADCAST_STATE)
                    // setPackage делает broadcast явным: наружу он не уходит и
                    // никаких разрешений на приём не требует.
                    .setPackage(packageName)
                    .putExtra(TgWsClient.EXTRA_RUNNING, running)
                    .putExtra(TgWsClient.EXTRA_VERIFIED, verified)
                    .putExtra(TgWsClient.EXTRA_BIND_IP, bindIp)
                    .putExtra(TgWsClient.EXTRA_PORT, port)
                    .putExtra(TgWsClient.EXTRA_SECRET_FULL, secretFull)
                    .putExtra(TgWsClient.EXTRA_STATS, lastStats)
                    .putExtra(TgWsClient.EXTRA_ERROR, lastError)
                    .putExtra(TgWsClient.EXTRA_TS, System.currentTimeMillis())
                    .putExtra(TgWsClient.EXTRA_LOG, TgWsLog.tail().toTypedArray())
            )
        } catch (t: Throwable) {
            Log.w(TAG, "broadcast", t)
        }
    }

    // -----------------------------------------------------------------------
    //  Wakelock
    // -----------------------------------------------------------------------

    /**
     * Без wakelock CPU засыпает, сокеты прокси замирают и Telegram отваливается
     * через минуту-другую после выключения экрана. Держим с таймаутом и
     * продлеваем: бессрочные wakelock'и часть прошивок игнорирует, а сажать
     * батарею навсегда нельзя.
     */
    private fun acquireWakeLock() {
        try {
            wakeLock?.let { if (it.isHeld) it.release() }
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "FlickerVPN::TgWs").apply {
                setReferenceCounted(false)
                acquire(WAKELOCK_TIMEOUT_MS)
            }
            wakeLockAt = System.currentTimeMillis()
        } catch (t: Throwable) {
            Log.w(TAG, "wakelock", t)
            wakeLock = null
        }
    }

    private fun releaseWakeLock() {
        try {
            wakeLock?.let { if (it.isHeld) it.release() }
        } catch (t: Throwable) {
            Log.w(TAG, "release wakelock", t)
        }
        wakeLock = null
        wakeLockAt = 0L
    }

    // -----------------------------------------------------------------------

    private fun portFree(ip: String, p: Int): Boolean = try {
        ServerSocket().use { s ->
            s.reuseAddress = true
            s.bind(InetSocketAddress(InetAddress.getByName(ip), p))
            true
        }
    } catch (_: Throwable) {
        false
    }

    private fun mask(s: String): String =
        if (s.length <= 8) "…" else s.take(4) + "…" + s.takeLast(2)

    companion object {
        private const val TAG = "FlickerTgWs"

        const val NOTIF_ID = 20

        private const val ACTIVITY_CLASS = "dev.flicker.vpn.TgWsActivity"

        private const val RC_OPEN = 200
        private const val RC_STOP = 201
        private const val RC_RESTART = 202

        private const val STATS_MS = 5_000L
        private const val NATIVE_STOP_WAIT_MS = 3_500L
        private const val MAX_AUTO_RESTARTS = 3
        private const val RETRY_DELAY_MS = 2_000L

        /** Держим 25 минут, продлеваем каждые 20 — до системного таймаута. */
        private const val WAKELOCK_TIMEOUT_MS = 25L * 60 * 1000
        private const val WAKELOCK_REFRESH_MS = 20L * 60 * 1000
    }
}
