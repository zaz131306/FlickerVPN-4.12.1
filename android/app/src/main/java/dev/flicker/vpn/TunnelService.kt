// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn

import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.system.OsConstants
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import dev.flicker.libbox.BridgeOptions
import dev.flicker.libbox.BridgeSession
import dev.flicker.libbox.CommandClient
import dev.flicker.libbox.CommandClientHandler
import dev.flicker.libbox.CommandClientOptions
import dev.flicker.libbox.CommandServer
import dev.flicker.libbox.ConnectionEvents
import dev.flicker.libbox.LogIterator
import dev.flicker.libbox.OutboundGroupItemIterator
import dev.flicker.libbox.OutboundGroupIterator
import dev.flicker.libbox.StatusMessage
import dev.flicker.libbox.StringIterator
import dev.flicker.libbox.CommandServerHandler
import dev.flicker.libbox.ConnectionOwner
import dev.flicker.libbox.InterfaceUpdateListener
import dev.flicker.libbox.Libbox
import dev.flicker.libbox.LocalDNSTransport
import dev.flicker.libbox.NeighborUpdateListener
import dev.flicker.libbox.NetworkInterface as BoxNetworkInterface
import dev.flicker.libbox.NetworkInterfaceIterator
import dev.flicker.libbox.Notification as BoxNotification
import dev.flicker.libbox.OverrideOptions
import dev.flicker.libbox.PlatformInterface
import dev.flicker.libbox.PlatformUser
import dev.flicker.libbox.RoutePrefix
import dev.flicker.libbox.RoutePrefixIterator
import dev.flicker.libbox.ShellSession
import dev.flicker.libbox.SystemProxyStatus
import dev.flicker.libbox.TunOptions
import dev.flicker.libbox.WIFIState
import dev.flicker.mobile.Mobile
import dev.flicker.mobile.ProbeListener
import dev.flicker.mobile.SocketProtector
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import dev.flicker.vpn.data.AppState
import dev.flicker.vpn.data.ServiceStatus
import dev.flicker.vpn.util.Notifications
import org.json.JSONArray
import org.json.JSONObject
import java.net.InetAddress
import java.net.NetworkInterface as JavaNetworkInterface

/**
 * TunnelService — VpnService с sing-box (libbox) внутри.
 *
 * Архитектура повторяет SFA (Sing-box For Android):
 *  - VpnService.establish() возвращает fd туннеля → libbox.OpenTun;
 *  - сокеты sing-box'а защищаются через protect(fd)
 *    (UsePlatformAutoDetectInterfaceControl=true → AutoDetectInterfaceControl);
 *  - сокеты Go-проб защищаются через Mobile.setSocketProtector — иначе
 *    проверки зацикливались бы в собственный туннель;
 *  - CommandServer — управление конфигом (StartOrReloadService) и логи.
 *
 * v4.12.2: класс OPEN — от него наследуется [BypassVpnService] (режим
 * «Обход DPI»). Соответственно поля/функции, которые нужны наследнику
 * (started, initialized, startForegroundNotif, broadcastState, stopTunnel),
 * помечены open/protected.
 */
open class TunnelService : VpnService(), PlatformInterface, CommandServerHandler, SocketProtector, ProbeListener {

    companion object {
        const val ACTION_CONNECT = "dev.flicker.vpn.CONNECT"
        const val ACTION_DISCONNECT = "dev.flicker.vpn.DISCONNECT"

        internal fun safePrefix(addr: java.net.InetAddress?, prefix: Int): String? {
            return try {
                if (addr == null) {
                    null
                } else if (prefix < 0 || prefix > 128) {
                    null
                } else {
                    val host = if (addr is java.net.Inet6Address) {
                        java.net.Inet6Address.getByAddress(addr.address)?.hostAddress
                    } else {
                        addr.hostAddress
                    }
                    if (host.isNullOrEmpty() || host.indexOf('%') >= 0 || host.indexOf(' ') >= 0) {
                        null
                    } else {
                        "$host/$prefix"
                    }
                }
            } catch (_: Throwable) {
                null
            }
        }

        private const val ESTABLISH_RETRIES = 3
        private const val ESTABLISH_RETRY_MS = 500L

        fun targetClass(context: android.content.Context): Class<out TunnelService> =
            if (dev.flicker.vpn.util.Prefs.mode(context) ==
                dev.flicker.vpn.util.Prefs.MODE_BYPASS
            ) {
                BypassVpnService::class.java
            } else {
                TunnelService::class.java
            }

        const val ACTION_PAUSE = "dev.flicker.vpn.PAUSE"
        const val ACTION_RESUME = "dev.flicker.vpn.RESUME"
        const val EXTRA_SERVER = "server"
        const val BROADCAST_STATE = "dev.flicker.vpn.STATE"
        const val EXTRA_CONNECTED = "connected"
        const val EXTRA_MESSAGE = "message"
        const val EXTRA_NAME = "name"

        fun isVpnInterfaceUp(context: android.content.Context): Boolean {
            val cm = context.getSystemService(android.net.ConnectivityManager::class.java)
                ?: return false
            return try {
                cm.allNetworks.any { n ->
                    cm.getNetworkCapabilities(n)
                        ?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) == true
                }
            } catch (t: Throwable) {
                Log.w(FlickerApp.TAG, "isVpnInterfaceUp", t)
                false
            }
        }

        const val NOTIF_ID = 1
        const val PROXY_PORT = 10808
        const val BYEDPI_PORT = 10888
        const val BYPASS_NO_SERVER = "\u0000bypass"

        internal fun isBypass(serverJson: String?): Boolean = serverJson == BYPASS_NO_SERVER
        private const val WATCHDOG_INTERVAL_MS = 15 * 60 * 1000L
        private const val HANDOVER_DEBOUNCE_MS = 1000L
        const val CORE_FILE_LOG = "core-file.log"
        private const val CORE_FILE_LOG_MAX = 400_000L
        private const val CORE_FILE_LOG_KEEP = 200_000L

        private val CHECK_TARGETS: List<Pair<String, String>> = listOf(
            "Telegram" to "https://api.telegram.org/method/getMe",
            "Instagram" to "https://www.instagram.com/",
            "ipify" to "https://api.ipify.org/?format=json",
        )

        @Volatile
        var instance: TunnelService? = null
            private set

        fun hardStop(context: Context) {
            Log.w(FlickerApp.TAG, "hardStop: запрошено аварийное отключение")
            stop(context)
            val t = Thread {
                try {
                    Thread.sleep(7_000)
                } catch (_: InterruptedException) {
                    return@Thread
                }
                val svc = instance ?: return@Thread
                if (!svc.isAnyVpnUp()) {
                    Log.i(FlickerApp.TAG, "hardStop: VPN-интерфейс уже снят")
                    return@Thread
                }
                Log.e(FlickerApp.TAG, "hardStop: VPN-интерфейс всё ещё поднят через 7 с")
                CrashLog.note(svc, "hardStop: штатная остановка не сняла VPN-интерфейс за 7 с")
                svc.forceTeardown("hardStop")
            }
            t.isDaemon = true
            t.name = "hard-stop"
            t.start()
        }

        val isLive: Boolean
            get() = instance?.started == true

        fun start(context: Context, serverJson: String) {
            val intent = Intent(context, targetClass(context))
                .setAction(ACTION_CONNECT)
                .putExtra(EXTRA_SERVER, serverJson)
            ContextCompat.startForegroundService(context, intent)
        }

        fun stop(context: Context) {
            val intent = Intent(context, targetClass(context)).setAction(ACTION_DISCONNECT)
            try {
                ContextCompat.startForegroundService(context, intent)
            } catch (e: Exception) {
                Log.w(FlickerApp.TAG, "stop через startForegroundService не прошёл", e)
                val svc = instance
                if (svc != null) {
                    try {
                        svc.serviceStop()
                        return
                    } catch (t: Throwable) {
                        Log.w(FlickerApp.TAG, "stop через instance.serviceStop() не прошёл", t)
                    }
                }
                try {
                    context.stopService(intent)
                } catch (e2: Exception) {
                    Log.e(FlickerApp.TAG, "stop не удался вообще", e2)
                }
            }
        }
    }

    private val mainHandler = Handler(Looper.getMainLooper())
    private val ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @Volatile
    private var pendingServerJson: String? = null

    private val sessionDeadNodes = mutableSetOf<String>()
    private var autoSwitchCount = 0
    private val AUTO_SWITCH_MAX = 8

    @Volatile
    var tunFdNumber: Int = -1
        private set
    private val tunHandedOut = java.util.concurrent.atomic.AtomicInteger(0)

    private val tunActive = java.util.concurrent.atomic.AtomicBoolean(false)
    private val HARD_STOP_DEADLINE_MS = 15_000L
    private val SETTLE_MS = 400L

    @Volatile private var lastDownlinkTotal: Long = 0L
    @Volatile private var lastUplinkTotal: Long = 0L
    @Volatile private var lastTrafficAt: Long = 0L
    @Volatile private var stalledSince: Long = 0L
    @Volatile private var stallReported: Boolean = false
    @Volatile private var peakConnsIn: Long = 0L

    @Volatile var statUplink: Long = 0L; private set
    @Volatile var statDownlink: Long = 0L; private set
    @Volatile var statUplinkTotal: Long = 0L; private set
    @Volatile var statDownlinkTotal: Long = 0L; private set
    @Volatile var statConnectionsIn: Long = 0L; private set

    private val STATUS_STALL_MS = 12_000L
    private val STATUS_INTERVAL_MS = 2_000L

    @Volatile var coreProtectFails: Int = 0; private set
    @Volatile var probeProtectFails: Int = 0; private set

    @PublishedApi
    internal val nativeLock = java.util.concurrent.locks.ReentrantLock()
    @PublishedApi
    internal val NATIVE_CLOSE_WAIT_MS = 3_000L

    @PublishedApi
    internal inline fun withNativeLock(what: String, block: () -> Unit) {
        val acquired = try {
            nativeLock.tryLock(NATIVE_CLOSE_WAIT_MS, java.util.concurrent.TimeUnit.MILLISECONDS)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
        if (!acquired) {
            Log.w(FlickerApp.TAG, "$what: nativeLock занят дольше ${NATIVE_CLOSE_WAIT_MS}мс — операция пропущена")
            return
        }
        try {
            block()
        } finally {
            nativeLock.unlock()
        }
    }

    @Volatile
    private var commandServer: CommandServer? = null
    private var commandClient: CommandClient? = null
    private val coreLogLock = Any()
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    @Volatile
    private var upstreamNetwork: Network? = null
    @Volatile
    private var handoverJob: kotlinx.coroutines.Job? = null

    /** v4.12.2: OPEN — читается наследником [BypassVpnService]. */
    @Volatile
    protected open var started = false

    @Volatile
    private var currentServerJson: String? = null

    @Volatile
    private var byedpiEngine: dev.flicker.vpn.core.ByeDpiEngine? = null

    /** v4.12.2: OPEN — наследник читает/сбрасывает в своих проверках. */
    @Volatile
    protected open var initialized = false

    private val watchdog = object : Runnable {
        override fun run() {
            if (!started) return
            runWatchdog()
            mainHandler.postDelayed(this, WATCHDOG_INTERVAL_MS)
        }
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
    }

    private fun ensureInitialized() {
        if (initialized) return
        initialized = true

        startForegroundNotif(getString(R.string.notif_starting))

        if (!FlickerApp.nativeReady) {
            Log.e(FlickerApp.TAG, "нативная библиотека не готова — туннель не запускается")
            stopSelf()
            return
        }

        ioScope.launch {
            val ok = initNative()
            withContext(Dispatchers.Main) {
                if (!ok) {
                    broadcastState(false, getString(R.string.err_native_missing))
                    stopSelf()
                    return@withContext
                }
                mainHandler.postDelayed(watchdog, WATCHDOG_INTERVAL_MS)
                pendingServerJson?.let { json ->
                    pendingServerJson = null
                    startTunnel(json)
                }
            }
        }
    }

    private fun initNative(): Boolean {
        try {
            val server = Libbox.newCommandServer(this, this)
            nativeLock.lock()
            try {
                server.start()
            } finally {
                nativeLock.unlock()
            }
            commandServer = server
            try {
                val opts = CommandClientOptions()
                opts.addCommand(Libbox.CommandLog)
                opts.addCommand(Libbox.CommandStatus)
                opts.setStatusInterval(STATUS_INTERVAL_MS)
                val client = CommandClient(CoreLogHandler(), opts)
                client.connect()
                commandClient = client
                Log.i(FlickerApp.TAG, "core log client: подключён")
                CrashLog.note(this, "CommandClient(CommandLog) подключён — жду журнал ядра")
            } catch (t: Throwable) {
                Log.w(FlickerApp.TAG, "CommandClient не запущен", t)
                CrashLog.note(
                    this,
                    "CommandClient(CommandLog) НЕ запущен: ${t.javaClass.simpleName}: ${t.message}" +
                        " — журнал ядра будет только из файла box/$CORE_FILE_LOG"
                )
            }
        } catch (e: Throwable) {
            Log.e(FlickerApp.TAG, "CommandServer", e)
            CrashLog.note(this, "CommandServer.start() не удался: ${e.javaClass.simpleName}: ${e.message}")
            return false
        }
        Native.run("setSocketProtector") { Mobile.setSocketProtector(this) }
        return true
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val act = intent?.action
        if (!initialized && (act == ACTION_DISCONNECT || act == ACTION_PAUSE)) {
            val target = targetClass(this)
            Log.i(FlickerApp.TAG, "инертный экземпляр: $act пересылается в $target")
            if (target != this.javaClass) {
                try {
                    ContextCompat.startForegroundService(
                        this, Intent(this, target).setAction(act)
                    )
                } catch (t: Throwable) {
                    Log.w(FlickerApp.TAG, "форвард $act", t)
                }
            }
            stopSelf()
            return START_NOT_STICKY
        }
        when (intent?.action) {
            ACTION_DISCONNECT -> stopTunnel(andStop = true)

            ACTION_PAUSE -> {
                Log.i(FlickerApp.TAG, "пауза: полная остановка сервиса, VPN освобождается")
                val pauseJson = currentServerJson ?: Repository.selectedServerJson()
                if (pauseJson != null && !isBypass(pauseJson)) {
                    Repository.setSelectedId(
                        try { JSONObject(pauseJson).optString("id") } catch (_: Throwable) { null }
                    )
                }
                stopTunnel(andStop = true)
                Notifications.notify(this, Notifications.PAUSE_ID, Notifications.buildPause(this))
            }

            ACTION_RESUME -> {
                Log.i(FlickerApp.TAG, "возобновление туннеля")
                Notifications.cancel(this, Notifications.PAUSE_ID)
                val bypass = dev.flicker.vpn.util.Prefs.mode(this) ==
                    dev.flicker.vpn.util.Prefs.MODE_BYPASS
                val json = currentServerJson
                    ?: if (bypass) BYPASS_NO_SERVER else Repository.selectedServerJson()
                if (json == null) {
                    broadcastState(false, getString(R.string.err_no_server))
                    stopSelf()
                } else {
                    if (bypass) {
                        startBypassTunnel(json)
                    } else if (commandServer == null) {
                        Log.i(FlickerApp.TAG, "resume: ядро ещё инициализируется — подключение отложено")
                        ensureInitialized()
                        pendingServerJson = json
                    } else {
                        startTunnel(json)
                    }
                }
            }

            else -> {
                val bypass = dev.flicker.vpn.util.Prefs.mode(this) ==
                    dev.flicker.vpn.util.Prefs.MODE_BYPASS
                val serverJson = if (bypass) BYPASS_NO_SERVER
                    else intent?.getStringExtra(EXTRA_SERVER) ?: Repository.selectedServerJson()
                if (serverJson == null) {
                    broadcastState(false, getString(R.string.err_no_server))
                    stopSelf()
                } else if (bypass) {
                    startBypassTunnel(serverJson)
                } else if (commandServer == null) {
                    Log.i(FlickerApp.TAG, "ядро ещё инициализируется — подключение отложено")
                    ensureInitialized()
                    pendingServerJson = serverJson
                } else {
                    startTunnel(serverJson)
                }
            }
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        mainHandler.removeCallbacks(watchdog)
        handoverJob?.cancel()
        handoverJob = null
        upstreamNetwork = null

        CrashLog.note(
            this,
            "onDestroy: tunFd=$tunFdNumber, tunActive=${tunActive.get()}, " +
                "выдач туннеля=${tunHandedOut.get()}, " +
                "protect-отказов ядра=$coreProtectFails, проб=$probeProtectFails, " +
                "пик connectionsIn=$peakConnsIn, downlinkTotal=$lastDownlinkTotal, " +
                "последний трафик ${android.os.SystemClock.elapsedRealtime() - lastTrafficAt} мс назад"
        )

        startLastResort("onDestroy")
        ioScope.cancel()

        val acquired = try {
            nativeLock.tryLock(NATIVE_CLOSE_WAIT_MS, java.util.concurrent.TimeUnit.MILLISECONDS)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
        if (!acquired) {
            Log.w(FlickerApp.TAG, "onDestroy: native-операция не завершилась за ${NATIVE_CLOSE_WAIT_MS}мс — закрываю принудительно")
            CrashLog.note(this, "onDestroy: nativeLock не получен за ${NATIVE_CLOSE_WAIT_MS}мс")
        }
        try {
            Native.run("setSocketProtector(null)") { Mobile.setSocketProtector(null) }
            try { commandClient?.disconnect() } catch (_: Throwable) {}
            commandClient = null
            try {
                commandServer?.closeService()
            } catch (e: Throwable) {
                Log.w(FlickerApp.TAG, "closeService", e)
            }
            try {
                commandServer?.close()
            } catch (e: Throwable) {
                Log.w(FlickerApp.TAG, "close", e)
            }
        } finally {
            if (acquired) nativeLock.unlock()
        }
        commandServer = null

        unregisterNetworkCallback()
        started = false
        instance = null

        if (initialized && isAnyVpnUp()) {
            forceTeardown("onDestroy: VPN-интерфейс не снялся")
        }

        CrashLog.markCleanExit(this)
        Repository.setConnected(false, "")
        broadcastState(false, null)
        super.onDestroy()
    }

    override fun onRevoke() {
        CrashLog.note(this, "onRevoke: VPN отозван системой (переключатель в настройках или другое VPN-приложение)")
        if (!initialized) {
            val target = targetClass(this)
            if (target != this.javaClass) {
                try {
                    ContextCompat.startForegroundService(
                        this, Intent(this, target).setAction(ACTION_DISCONNECT)
                    )
                } catch (t: Throwable) {
                    Log.w(FlickerApp.TAG, "onRevoke: форвард стопа", t)
                }
            }
            stopSelf()
        } else {
            stopTunnel(andStop = true)
        }
        try {
            if (dev.flicker.vpn.util.Prefs.autoStart(this)) {
                dev.flicker.vpn.util.Prefs.setAutoStart(this, false)
                CrashLog.note(this, "onRevoke: автозапуск снят (VPN отозван системным переключателем)")
            }
        } catch (t: Throwable) {
            Log.w(FlickerApp.TAG, "onRevoke: не снять автозапуск", t)
        }
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        Log.i(FlickerApp.TAG, "onTaskRemoved: туннель сохраняем, приложение закрыто")
        if (started) {
            startForegroundNotif(
                getString(R.string.notif_connected, Repository.selectedServer()?.name ?: "")
            )
        }
        super.onTaskRemoved(rootIntent)
    }

    private fun startTunnel(serverJson: String, auto: Boolean = false) {
        if (!auto) {
            synchronized(sessionDeadNodes) { sessionDeadNodes.clear() }
            autoSwitchCount = 0
        }
        if (!FlickerApp.nativeReady) {
            broadcastState(false, "libflickerbox.so не загружена — пересоберите AAR (BUILD-ANDROID.md)")
            stopSelf()
            return
        }
        AppState.update(ServiceStatus.Connecting)
        ioScope.launch {
            val result = runCatching { buildAndStart(serverJson) }
            withContext(Dispatchers.Main) {
                result.onSuccess { name ->
                    currentServerJson = serverJson
                    started = true
                    if (!isBypass(serverJson)) {
                        Repository.setSelectedId(
                            try { JSONObject(serverJson).optString("id") } catch (e: Exception) { null }
                        )
                    }
                    Repository.setConnected(true, name)
                    startForegroundNotif(getString(R.string.notif_connected, name))
                    broadcastState(true, null, name)
                    resetStallDetector()
                    scheduleNodeLivenessCheck()
                }.onFailure { e ->
                    Log.e(FlickerApp.TAG, "startTunnel", e)
                    CrashLog.note(this@TunnelService,
                        "startTunnel: ${e.javaClass.simpleName}: ${e.message}")
                    val exclude = synchronized(sessionDeadNodes) { sessionDeadNodes.toSet() }
                    if (autoSwitchCount < AUTO_SWITCH_MAX && Repository.nextCandidate(exclude) != null) {
                        handleDeadNode("startTunnel: старт кандидата упал (${e.javaClass.simpleName}) — пробую следующего")
                    } else {
                        broadcastState(false, e.message ?: e.javaClass.simpleName)
                        stopSelf()
                    }
                }
            }
        }
    }

    private suspend fun buildAndStart(serverJson: String): String {
        if (isBypass(serverJson)) return buildAndStartBypass()

        val name = try {
            JSONObject(serverJson).optString("name")
        } catch (e: Exception) {
            ""
        }
        val rawConfig = Mobile.buildTunConfig(serverJson, Repository.tunParamsJson())
        val coreLogFile = java.io.File(Native.workingDir(this), CORE_FILE_LOG)
        try {
            if (coreLogFile.exists()) coreLogFile.delete()
        } catch (_: Throwable) {
        }
        val migrated = ConfigMigrate.emulatorTunStack(
            ConfigMigrate.migrate(rawConfig, coreLogFile.absolutePath)
        )
        val proxyMode = dev.flicker.vpn.util.Prefs.mode(this) == "proxy"
        val config = if (proxyMode) ConfigMigrate.toProxyConfig(migrated, PROXY_PORT) else migrated
        AppState.update(
            AppState.status,
            if (proxyMode) dev.flicker.vpn.data.TunnelMode.Proxy else dev.flicker.vpn.data.TunnelMode.Vpn
        )
        Log.i(FlickerApp.TAG, if (proxyMode) "режим: ПРОКСИ (SOCKS5 127.0.0.1:$PROXY_PORT)" else "режим: VPN-туннель")
        ConfigMigrate.audit(config).forEach { Log.w(FlickerApp.TAG, "конфиг: $it") }
        try {
            java.io.File(filesDir, "last-config.json").writeText(config)
        } catch (_: Throwable) {
        }

        val server = commandServer
            ?: throw IllegalStateException("CommandServer не инициализирован")
        Native.run("cancelProbe") { Mobile.cancelProbe() }

        withNativeLock("startOrReloadService") {
            server.startOrReloadService(config, OverrideOptions())
        }
        return name
    }

    protected open fun startBypassTunnel(serverJson: String) {
        if (commandServer == null) {
            Log.i(FlickerApp.TAG, "обход: ядро ещё инициализируется — подключение отложено")
            ensureInitialized()
            pendingServerJson = serverJson
        } else {
            startTunnel(serverJson)
        }
    }

    protected open suspend fun startByedpi(
        presetId: String?,
        command: String?,
        host: String,
        port: Int,
    ): dev.flicker.vpn.core.ByeDpiEngine.Result {
        val engine = dev.flicker.vpn.core.ByeDpiEngine(this)
        byedpiEngine = engine
        return engine.start(presetId, command, host, port)
    }

    protected open fun stopByedpi() {
        byedpiEngine?.let { e ->
            byedpiEngine = null
            try {
                e.stop()
            } catch (t: Throwable) {
                Log.w(FlickerApp.TAG, "остановка byedpi", t)
            }
        }
    }

    private suspend fun buildAndStartBypass(): String {
        val presetId = dev.flicker.vpn.util.Prefs.byedpiPreset(this)
        val command = dev.flicker.vpn.util.Prefs.byedpiCommand(this)
        val presetTitle = dev.flicker.vpn.core.ByeDpiArgs.preset(presetId).title
        Log.i(FlickerApp.TAG, "режим: ОБХОД DPI (byedpi, пресет «$presetTitle»)")
        AppState.update(AppState.status, dev.flicker.vpn.data.TunnelMode.Vpn)

        stopByedpi()

        val res = startByedpi(presetId, command, "127.0.0.1", BYEDPI_PORT)
        if (res !is dev.flicker.vpn.core.ByeDpiEngine.Result.Ready) {
            val failed = res as dev.flicker.vpn.core.ByeDpiEngine.Result.Failed
            stopByedpi()
            CrashLog.note(
                this,
                "byedpi не запустился: ${failed.error} (код ${failed.code}, fatal=${failed.fatal})"
            )
            throw IllegalStateException("обход DPI не запустился: ${failed.error}")
        }
        CrashLog.note(this, "byedpi слушает 127.0.0.1:${res.port}, пресет «$presetTitle»")

        val coreLogFile = java.io.File(Native.workingDir(this), CORE_FILE_LOG)
        try {
            if (coreLogFile.exists()) coreLogFile.delete()
        } catch (_: Throwable) {
        }

        val config = dev.flicker.vpn.core.BypassConfig.build(res.port, coreLogFile.absolutePath)
        try {
            java.io.File(filesDir, "last-config.json").writeText(config)
        } catch (_: Throwable) {
        }

        val server = commandServer
            ?: throw IllegalStateException("CommandServer не инициализирован")
        Native.run("cancelProbe") { Mobile.cancelProbe() }

        withNativeLock("startOrReloadService") {
            server.startOrReloadService(config, OverrideOptions())
        }
        return "Обход DPI · $presetTitle"
    }

    private fun scheduleNodeLivenessCheck() {
        val mode = dev.flicker.vpn.util.Prefs.mode(this)
        if (mode == "proxy") return
        if (mode == dev.flicker.vpn.util.Prefs.MODE_BYPASS) {
            Log.i(FlickerApp.TAG, "режим обхода DPI: самопроверка узла пропущена (узла нет)")
            return
        }
        ioScope.launch {
            kotlinx.coroutines.delay(3500)
            if (!started) return@launch
            val res = probeTargets()
            if (!started) return@launch
            val alive = res.any { it.second.startsWith("HTTP ") }
            val summary = res.joinToString(" · ") { "${it.first}=${it.second}" }
            val deadId = try { JSONObject(currentServerJson ?: "").optString("id") } catch (_: Throwable) { "" }
            val deadName = Repository.selectedServer()?.name ?: deadId.ifEmpty { "?" }

            if (!alive && lastDownlinkTotal > 0L) {
                autoSwitchCount = 0
                Log.i(FlickerApp.TAG, "самопроверка: контрольные цели молчат ($summary), но ядро видит трафик (downlinkTotal=$lastDownlinkTotal) — узел жив")
                CrashLog.note(
                    this@TunnelService,
                    "Самопроверка узла «$deadName»: $summary — НО downlinkTotal=$lastDownlinkTotal, трафик ИДЁТ, узел признан живым"
                )
                return@launch
            }

            if (alive) {
                autoSwitchCount = 0
                Log.i(FlickerApp.TAG, "самопроверка узла: $summary")
                CrashLog.note(this@TunnelService, "Самопроверка узла «$deadName»: $summary — трафик ИДЁТ")
                return@launch
            }
            Log.w(FlickerApp.TAG, "самопроверка узла: $summary")
            handleDeadNode("Самопроверка узла «$deadName»: $summary — трафик НЕ пошёл")
        }
    }

    private fun handleDeadNode(note: String) {
        val deadId = try {
            JSONObject(currentServerJson ?: "").optString("id")
        } catch (_: Throwable) { "" }
        val deadName = Repository.selectedServer()?.name ?: deadId.ifEmpty { "?" }

        if (deadId.isNotEmpty()) {
            synchronized(sessionDeadNodes) { sessionDeadNodes.add(deadId) }
        }
        CrashLog.note(this, note)

        if (!dev.flicker.vpn.util.Prefs.autoReconnect(this)) {
            Notifications.notify(
                this, Notifications.ERROR_ID,
                Notifications.buildError(
                    this,
                    "Узел «$deadName» не пропускает трафик. Автопереподключение выключено — VPN отключён"
                )
            )
            stopTunnel(andStop = true)
            return
        }

        if (dev.flicker.vpn.util.Prefs.mode(this) ==
            dev.flicker.vpn.util.Prefs.MODE_BYPASS
        ) {
            Notifications.notify(
                this, Notifications.ERROR_ID,
                Notifications.buildError(
                    this,
                    "Обход DPI почти не даёт трафика на пресете «${
                        dev.flicker.vpn.core.ByeDpiArgs.preset(
                            dev.flicker.vpn.util.Prefs.byedpiPreset(this)
                        ).title
                    }». Меню ⋮ → «Подобрать обход DPI»."
                )
            )
            return
        }

        if (autoSwitchCount < AUTO_SWITCH_MAX) {
            val next = Repository.nextCandidate(
                synchronized(sessionDeadNodes) { sessionDeadNodes.toSet() }
            )
            if (next != null) {
                autoSwitchCount++
                Notifications.notify(
                    this, Notifications.ERROR_ID,
                    Notifications.buildError(
                        this,
                        "Узел «$deadName» не пропускает трафик — переключаюсь на «${next.name}» (попытка $autoSwitchCount из $AUTO_SWITCH_MAX)"
                    )
                )
                startTunnel(next.json, auto = true)
                return
            }
        }
        Notifications.notify(
            this, Notifications.ERROR_ID,
            Notifications.buildError(
                this,
                "Живых узлов не осталось (перебрано $autoSwitchCount) — VPN ОТКЛЮЧЁН, телефон на прямом интернете. Обновите подписки (📥) и подключитесь снова"
            )
        )
        stopTunnel(andStop = true)
    }

    private fun onCoreStatus(m: StatusMessage) {
        if (!started) return
        val trafficAvailable = try { m.trafficAvailable } catch (_: Throwable) { false }
        if (!trafficAvailable) return

        val down = try { m.downlinkTotal.toLong() } catch (_: Throwable) { return }
        val up = try { m.uplinkTotal.toLong() } catch (_: Throwable) { return }
        val connsIn = try { m.connectionsIn.toLong() } catch (_: Throwable) { 0L }
        val now = android.os.SystemClock.elapsedRealtime()

        statDownlinkTotal = down
        statUplinkTotal = up
        statConnectionsIn = connsIn
        try {
            statDownlink = m.downlink.toLong()
            statUplink = m.uplink.toLong()
        } catch (_: Throwable) {
        }

        val moved = down > lastDownlinkTotal || up > lastUplinkTotal
        lastDownlinkTotal = down
        lastUplinkTotal = up
        if (moved) {
            lastTrafficAt = now
            stalledSince = 0L
            if (stallReported) {
                stallReported = false
                CrashLog.note(this, "Трафик снова идёт (downlink=$down, uplink=$up)")
            }
            return
        }

        if (connsIn > peakConnsIn) peakConnsIn = connsIn
        if (peakConnsIn <= 0L) return
        if (stalledSince == 0L) {
            stalledSince = now
            lastTrafficAt = now
            return
        }
        val stalledFor = now - stalledSince
        if (stalledFor < STATUS_STALL_MS || stallReported) return

        stallReported = true
        val summary = "ядро: $stalledFor мс нет трафика при connectionsIn=$connsIn " +
            "(downlinkTotal=$down, uplinkTotal=$up)"
        Log.w(FlickerApp.TAG, "детектор stalled: $summary")
        CrashLog.note(this, "Детектор stalled: $summary — узел принимает, но не выпускает")
        if (coreProtectFails > 0) {
            CrashLog.note(
                this,
                "ВНИМАНИЕ: protect() для сокетов ядра вернул false $coreProtectFails раз(а) — " +
                    "возможен цикл маршрутизации, а не мёртвый узел"
            )
        }
        mainHandler.post {
            if (!started) return@post
            handleDeadNode("Пассивный детектор: $summary")
        }
    }

    private fun resetStallDetector() {
        lastDownlinkTotal = 0L
        lastUplinkTotal = 0L
        lastTrafficAt = android.os.SystemClock.elapsedRealtime()
        stalledSince = 0L
        stallReported = false
        peakConnsIn = 0L
        statUplink = 0L
        statDownlink = 0L
        statUplinkTotal = 0L
        statDownlinkTotal = 0L
        statConnectionsIn = 0L
    }

    private suspend fun probeTargets(): List<Pair<String, String>> = coroutineScope {
        CHECK_TARGETS.map { (name, url) ->
            async(Dispatchers.IO) { name to checkOne(url) }
        }.awaitAll()
    }

    private fun checkOne(url: String): String {
        return try {
            val c = java.net.URL(url).openConnection() as javax.net.ssl.HttpsURLConnection
            c.connectTimeout = 11000
            c.readTimeout = 11000
            c.instanceFollowRedirects = false
            val code = c.responseCode
            try { c.disconnect() } catch (_: Throwable) {}
            "HTTP $code"
        } catch (t: Throwable) {
            val m = t.message?.replace('\n', ' ')?.take(70) ?: ""
            "${t.javaClass.simpleName}${if (m.isEmpty()) "" else ": $m"}"
        }
    }

    private inner class CoreLogHandler : CommandClientHandler {
        override fun connected() {}
        override fun disconnected(message: String?) {
            Log.w(FlickerApp.TAG, "core log отключён: $message")
        }
        override fun setDefaultLogLevel(level: Int) {}
        override fun clearLogs() {}
        override fun writeLogs(messageList: LogIterator?) {
            try {
                val it = messageList ?: return
                val sb = StringBuilder()
                while (it.hasNext()) {
                    val e = it.next() ?: continue
                    sb.append(e.message ?: "").append('\n')
                }
                if (sb.isNotEmpty()) appendCoreLog(sb.toString())
            } catch (t: Throwable) {
                Log.w(FlickerApp.TAG, "writeLogs", t)
            }
        }
        override fun writeStatus(message: StatusMessage?) {
            try {
                if (message != null) onCoreStatus(message)
            } catch (t: Throwable) {
                Log.w(FlickerApp.TAG, "writeStatus", t)
            }
        }
        override fun writeGroups(message: OutboundGroupIterator?) {}
        override fun writeOutbounds(message: OutboundGroupItemIterator?) {}
        override fun initializeClashMode(modeList: StringIterator?, currentMode: String?) {}
        override fun updateClashMode(newMode: String?) {}
        override fun writeConnectionEvents(events: ConnectionEvents?) {}
    }

    private fun appendCoreLog(text: String) {
        try {
            val f = java.io.File(Native.workingDir(this), "core.log")
            synchronized(coreLogLock) {
                if (f.exists() && f.length() > 300_000) {
                    f.writeText(f.readText().takeLast(150_000))
                }
                java.io.FileOutputStream(f, true).use { it.write(text.toByteArray()) }
            }
        } catch (_: Throwable) {
        }
        trimCoreFileLog()
    }

    private fun trimCoreFileLog() {
        try {
            val f = java.io.File(Native.workingDir(this), CORE_FILE_LOG)
            if (!f.exists() || f.length() <= CORE_FILE_LOG_MAX) return
            val before = f.length()
            synchronized(coreLogLock) {
                if (f.length() <= CORE_FILE_LOG_MAX) return
                val keep = CORE_FILE_LOG_KEEP.toInt()
                val tail = java.io.RandomAccessFile(f, "r").use { raf ->
                    val from = maxOf(0L, raf.length() - keep - 4096L)
                    raf.seek(from)
                    val buf = ByteArray((raf.length() - from).toInt().coerceAtLeast(0))
                    var off = 0
                    while (off < buf.size) {
                        val n = raf.read(buf, off, buf.size - off)
                        if (n <= 0) break
                        off += n
                    }
                    val s = String(buf, 0, off, Charsets.UTF_8)
                    val nl = s.indexOf('\n')
                    if (nl in 0 until s.length - 1) s.substring(nl + 1) else s
                }
                f.writeText(tail)
            }
            Log.i(
                FlickerApp.TAG,
                "core-file.log обрезан: $before → ${f.length()} байт (потолок $CORE_FILE_LOG_MAX)"
            )
        } catch (t: Throwable) {
            Log.w(FlickerApp.TAG, "trimCoreFileLog", t)
        }
    }

    private fun isAnyVpnUp(): Boolean {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return false
        return try {
            cm.allNetworks.any { n ->
                cm.getNetworkCapabilities(n)
                    ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            }
        } catch (t: Throwable) {
            Log.w(FlickerApp.TAG, "isAnyVpnUp", t)
            CrashLog.note(this, "isAnyVpnUp: не удалось определить состояние VPN — принято false")
            false
        }
    }

    private fun forceTeardown(where: String): Boolean {
        closeTunFdForced(where)
        try {
            Thread.sleep(SETTLE_MS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        if (!isAnyVpnUp()) {
            Log.i(FlickerApp.TAG, "$where: VPN-интерфейс снят, процесс остаётся жив")
            CrashLog.note(this, "$where: VPN-интерфейс снят после закрытия fd")
            tunActive.set(false)
            return false
        }
        Log.e(FlickerApp.TAG, "$where: VPN-интерфейс ВСЁ ЕЩЁ поднят после закрытия fd — процесс сохранён, нужен перезапуск приложения")
        CrashLog.note(this, "$where: VPN-интерфейс не снялся после закрытия fd — процесс сохранён")
        return true
    }

    private fun closeNative() {
        withNativeLock("stopTunnel") {
            try {
                commandServer?.closeService()
                tunActive.set(false)
            } catch (e: Throwable) {
                Log.w(FlickerApp.TAG, "closeService", e)
            }
        }
    }

    private fun closeTunFdForced(where: String): Boolean {
        if (!tunActive.compareAndSet(true, false)) return false
        val fd = tunFdNumber
        if (fd < 0) return false
        return try {
            try {
                android.os.ParcelFileDescriptor.adoptFd(fd).close()
                Log.w(FlickerApp.TAG, "$where: fd туннеля ($fd) закрыт через adoptFd")
            } catch (primary: Throwable) {
                Log.w(FlickerApp.TAG, "$where: adoptFd не сработал, пробую запасной путь", primary)
                val fdesc = java.io.FileDescriptor()
                val field = java.io.FileDescriptor::class.java.getDeclaredField("descriptor")
                field.isAccessible = true
                field.setInt(fdesc, fd)
                android.system.Os.close(fdesc)
                Log.w(FlickerApp.TAG, "$where: fd туннеля ($fd) закрыт через FileDescriptor")
            }
            Log.w(FlickerApp.TAG, "$where: fd туннеля ($fd) закрыт принудительно — интерфейс VPN должен исчезнуть")
            CrashLog.note(this, "$where: fd туннеля ($fd) закрыт принудительно из Java")
            true
        } catch (t: Throwable) {
            Log.e(FlickerApp.TAG, "$where: не закрыть fd $fd", t)
            CrashLog.note(this, "$where: НЕ удалось закрыть fd $fd — ${t.javaClass.simpleName}: ${t.message}")
            false
        }
    }

    private fun startLastResort(where: String) {
        val t = Thread {
            try {
                Thread.sleep(HARD_STOP_DEADLINE_MS)
            } catch (_: InterruptedException) {
                return@Thread
            }
            if (!isAnyVpnUp()) return@Thread
            Log.e(FlickerApp.TAG, "$where: туннель всё ещё жив через ${HARD_STOP_DEADLINE_MS}мс — снимаю принудительно")
            CrashLog.note(this, "$where: LAST RESORT — туннель не снят за ${HARD_STOP_DEADLINE_MS}мс")
            forceTeardown("$where/last-resort")
        }
        t.isDaemon = true
        t.name = "vpn-last-resort"
        t.start()
    }

    /**
     * v4.12.2: OPEN/PROTECTED — вызывается наследником [BypassVpnService].
     */
    protected open fun stopTunnel(andStop: Boolean = false) {
        if (!initialized) {
            Log.i(FlickerApp.TAG, "stopTunnel: экземпляр инертен, туннель не в этом процессе")
            return
        }
        started = false
        currentServerJson = null

        handoverJob?.cancel()
        handoverJob = null
        resetStallDetector()

        stopByedpi()

        if (andStop) {
            Notifications.cancel(this, NOTIF_ID)
            Notifications.cancel(this, Notifications.PAUSE_ID)
            try {
                ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
            } catch (t: Throwable) {
                Log.w(FlickerApp.TAG, "stopForeground", t)
            }
        }

        if (andStop) startLastResort("stopTunnel")

        val stopScope = if (ioScope.isActive) {
            ioScope
        } else {
            Log.w(FlickerApp.TAG, "stopTunnel: ioScope отменён — останавливаюсь в аварийном скоупе")
            CrashLog.note(this, "stopTunnel при отменённом ioScope — использован аварийный скоуп")
            CoroutineScope(SupervisorJob() + Dispatchers.IO)
        }
        stopScope.launch {
            val deadlineMs = NATIVE_CLOSE_WAIT_MS + 3000L
            val closer = Thread {
                try {
                    closeNative()
                } catch (t: Throwable) {
                    Log.w(FlickerApp.TAG, "closeNative", t)
                }
            }
            closer.isDaemon = true
            closer.name = "native-closer"
            closer.start()
            closer.join(deadlineMs)
            val stuck = closer.isAlive
            if (stuck) {
                CrashLog.note(
                    this@TunnelService,
                    "closeService() не завершился за ${deadlineMs}мс — останавливаю сервис принудительно"
                )
                forceTeardown("stopTunnel: closeService завис")
            }
            if (andStop && !stuck && isAnyVpnUp()) {
                Log.w(FlickerApp.TAG, "stopTunnel: closeService() отработал, но VPN-интерфейс всё ещё поднят")
                CrashLog.note(
                    this@TunnelService,
                    "stopTunnel: штатная остановка не сняла VPN-интерфейс — снимаю принудительно"
                )
                forceTeardown("stopTunnel: интерфейс не снялся")
            }

            withContext(Dispatchers.Main) {
                Repository.setConnected(false, "")
                broadcastState(false, null)
                if (andStop) {
                    if (stuck || tunActive.get()) {
                        Log.e(FlickerApp.TAG, "stopTunnel: нативный поток завис или tunActive=true — закрываю fd принудительно, процесс НЕ убиваю")
                        CrashLog.note(this@TunnelService, "stopTunnel: closeService завис (stuck=$stuck, tunActive=${tunActive.get()}) — процесс сохранён, fd закрыт принудительно")
                        closeTunFdForced("stopTunnel: повторное закрытие fd")
                        tunActive.set(false)
                    }
                    stopSelf()
                }
            }
        }
    }

    private fun runWatchdog() {
        val json = currentServerJson ?: return
        if (isBypass(json)) return
        ioScope.launch {
            try {
                val specs = Mobile.probeSpecsFromServers(
                    JSONArray().put(JSONObject(json)).toString(), true
                )
                if (JSONArray(specs).length() == 0) return@launch
                val opts = JSONObject().apply {
                    put("mode", "quick")
                    put("concurrency", 1)
                }.toString()
                Mobile.probeServers(specs, opts, this@TunnelService)
            } catch (e: Throwable) {
                Log.w(FlickerApp.TAG, "watchdog", e)
            }
        }
    }

    override fun onProbeStage(resultJSON: String?) {
    }

    override fun onProbeDone(resultJSON: String?) {
        if (resultJSON == null) return
        if (dev.flicker.vpn.util.Prefs.mode(this) ==
            dev.flicker.vpn.util.Prefs.MODE_BYPASS) return
        mainHandler.post {
            try {
                val o = JSONObject(resultJSON)
                if (o.has("error")) return@post
                val alive = o.optInt("alive")
                if (alive > 0) return@post
                val backup = Repository.bestAliveServer()
                if (backup != null && backup.json != currentServerJson) {
                    Log.w(FlickerApp.TAG, "watchdog: сервер умер, переключаюсь на ${backup.name}")
                    notifyStatus(getString(R.string.notif_switched, backup.name))
                    startTunnel(backup.json)
                } else {
                    notifyStatus(getString(R.string.notif_server_died))
                    stopTunnel(andStop = true)
                }
            } catch (e: Exception) {
                Log.w(FlickerApp.TAG, "watchdogDone", e)
            }
        }
    }

    override fun protectFd(fd: Int): Boolean = try {
        val ok = protect(fd)
        if (!ok) {
            probeProtectFails++
            Log.w(FlickerApp.TAG, "protectFd(fd=$fd) вернул false — проба идёт сквозь собственный туннель (всего отказов: $probeProtectFails)")
        }
        ok
    } catch (t: Throwable) {
        probeProtectFails++
        false
    }

    override fun serviceStop() {
        mainHandler.post {
            stopTunnel(andStop = true)
        }
    }

    override fun serviceReload() {
        val json = currentServerJson ?: return
        ioScope.launch {
            try {
                val config = ConfigMigrate.migrate(
                    Mobile.buildTunConfig(json, Repository.tunParamsJson())
                )
                withNativeLock("serviceReload") {
                    commandServer?.startOrReloadService(config, OverrideOptions())
                }
            } catch (e: Throwable) {
                Log.e(FlickerApp.TAG, "serviceReload", e)
                CrashLog.note(this@TunnelService,
                    "serviceReload: ${e.javaClass.simpleName}: ${e.message}")
            }
        }
    }

    override fun getSystemProxyStatus(): SystemProxyStatus {
        val status = SystemProxyStatus()
        status.available = false
        status.enabled = false
        return status
    }

    override fun setSystemProxyEnabled(enabled: Boolean) {
        throw UnsupportedOperationException("system proxy не поддерживается на Android")
    }

    override fun triggerNativeCrash() {
        throw UnsupportedOperationException("triggerNativeCrash недоступен")
    }

    override fun writeDebugMessage(message: String?) {
        Log.d(FlickerApp.TAG, "box: $message")
    }

    override fun connectSSHAgent(): Int = 0

    override fun localDNSTransport(): LocalDNSTransport? = null
    override fun usePlatformAutoDetectInterfaceControl(): Boolean = true

    override fun autoDetectInterfaceControl(fd: Int) {
        try {
            if (!protect(fd)) {
                coreProtectFails++
                Log.w(FlickerApp.TAG, "protect(fd=$fd) вернул false — сокет не защищён от маршрутизации в туннель (всего отказов: $coreProtectFails)")
            }
        } catch (e: Throwable) {
            coreProtectFails++
            Log.e(FlickerApp.TAG, "autoDetectInterfaceControl(fd=$fd)", e)
        }
    }

    private fun establishWithRetry(builder: Builder): android.os.ParcelFileDescriptor? {
        var attempt = 0
        while (true) {
            val pfd = try {
                builder.establish()
            } catch (t: Throwable) {
                Log.w(FlickerApp.TAG, "openTun: establish() бросил", t)
                null
            }
            if (pfd != null) {
                return pfd
            }
            attempt++
            if (attempt > ESTABLISH_RETRIES) return null
            CrashLog.note(this, "openTun: establish() null, попытка $attempt/${ESTABLISH_RETRIES + 1}")
            try {
                Thread.sleep(ESTABLISH_RETRY_MS)
            } catch (_: InterruptedException) {
                return null
            }
        }
    }

    private fun establishFailureReason(): String {
        val needConsent = try {
            prepare(this) != null
        } catch (_: Throwable) {
            false
        }
        return if (needConsent) {
            "establish() вернул null: система снова спрашивает согласие на VPN. " +
                "Нажмите «Подключить» ещё раз и разрешите VPN в диалоге"
        } else {
            "establish() вернул null: VPN занят другим приложением или для " +
                "другого приложения включён «Постоянный VPN» (always-on). " +
                "Выключите чужой VPN в настройках и подключитесь снова"
        }
    }

    override fun openTun(options: TunOptions): Int {
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(options.getMTU().toInt())

        val configureIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        builder.setConfigureIntent(configureIntent)

        var hasV4 = false
        var hasV6 = false
        options.inet4Address.forEachPrefix { rp ->
            if (addAddressSafe(builder, rp.address(), rp.prefix().toInt(), "inet4")) hasV4 = true
        }
        options.inet6Address.forEachPrefix { rp ->
            if (addAddressSafe(builder, rp.address(), rp.prefix().toInt(), "inet6")) hasV6 = true
        }
        if (!hasV4) addAddressSafe(builder, "172.19.0.1", 30, "inet4-fallback")
        if (hasV6) builder.allowFamily(OsConstants.AF_INET6)

        val dnsMode = options.getDNSMode()?.value ?: ""
        if (dnsMode == "native") {
            val servers = try {
                options.getDNSServerAddress().toStringList()
            } catch (e: Exception) {
                emptyList()
            }
            val valid = servers.filter { addDnsSafe(builder, it) }
            if (valid.isEmpty()) addDnsSafe(builder, "172.19.0.2")
        } else {
            addDnsSafe(builder, "172.19.0.2")
        }

        builder.addRoute("0.0.0.0", 0)
        if (hasV6) builder.addRoute("::", 0)

        if (dev.flicker.vpn.util.Prefs.mode(this) ==
            dev.flicker.vpn.util.Prefs.MODE_BYPASS
        ) {
            try {
                builder.addDisallowedApplication(packageName)
                Log.i(FlickerApp.TAG, "openTun: собственный пакет исключён из VPN (режим обхода DPI)")
            } catch (t: Throwable) {
                Log.e(FlickerApp.TAG, "openTun: НЕ удалось исключить собственный пакет — возможна петля маршрутизации", t)
                CrashLog.note(this, "openTun: addDisallowedApplication не сработал — возможна петля")
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            try {
                builder.setMetered(false)
            } catch (t: Throwable) {
                Log.w(FlickerApp.TAG, "openTun: setMetered(false) не сработал", t)
            }
        }

        val pfd = establishWithRetry(builder)
            ?: throw IllegalStateException(establishFailureReason())
        val fd = pfd.detachFd()
        tunFdNumber = fd
        tunActive.set(true)
        tunHandedOut.incrementAndGet()
        Log.i(FlickerApp.TAG, "openTun: туннель установлен, fd=$fd (всего выдач: ${tunHandedOut.get()})")
        upstreamNetwork?.let { applyUnderlyingNetworks(it) }
        return fd
    }

    override fun useProcFS(): Boolean = false

    override fun findConnectionOwner(
        ipProtocol: Int,
        sourceAddress: String?,
        sourcePort: Int,
        destinationAddress: String?,
        destinationPort: Int
    ): ConnectionOwner {
        throw IllegalStateException("android: connection owner not found")
    }

    override fun startDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val caps = cm.getNetworkCapabilities(network)
                if (caps != null && isVpnNetwork(caps)) return
                onUpstreamChanged(network)
                if (caps != null) reportDefaultInterface(cm, network, caps, listener)
            }

            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                if (isVpnNetwork(caps)) return
                applyUnderlyingNetworks(network)
                reportDefaultInterface(cm, network, caps, listener)
            }

            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) {
                val caps = cm.getNetworkCapabilities(network) ?: return
                if (isVpnNetwork(caps)) return
                reportDefaultInterface(cm, network, caps, listener)
            }

            override fun onLost(network: Network) {
                if (network == upstreamNetwork) {
                    upstreamNetwork = null
                    clearUnderlyingNetworks()
                }
            }
        }
        try {
            cm.registerDefaultNetworkCallback(callback)
            networkCallback = callback
        } catch (e: Exception) {
            Log.w(FlickerApp.TAG, "registerDefaultNetworkCallback", e)
        }
        val active = cm.activeNetwork
        val caps = active?.let { cm.getNetworkCapabilities(it) }
        if (active != null && caps != null && !isVpnNetwork(caps)) {
            upstreamNetwork = active
            applyUnderlyingNetworks(active)
            reportDefaultInterface(cm, active, caps, listener)
        }
    }

    private fun isVpnNetwork(caps: NetworkCapabilities): Boolean =
        caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)

    private fun applyUnderlyingNetworks(network: Network) {
        if (tunFdNumber < 0) return
        runCatching { setUnderlyingNetworks(arrayOf(network)) }
            .onFailure { Log.w(FlickerApp.TAG, "setUnderlyingNetworks", it) }
    }

    private fun clearUnderlyingNetworks() {
        if (tunFdNumber < 0) return
        runCatching { setUnderlyingNetworks(null) }
            .onFailure { Log.w(FlickerApp.TAG, "setUnderlyingNetworks(null)", it) }
    }

    private fun onUpstreamChanged(network: Network) {
        val old = upstreamNetwork
        upstreamNetwork = network
        applyUnderlyingNetworks(network)
        if (old == null || old == network) return
        Log.i(FlickerApp.TAG, "базовая сеть сменилась: $old → $network")
        CrashLog.note(this, "Смена базовой сети (handover) — перезапускаю ядро на том же туннеле")
        handoverJob?.cancel()
        handoverJob = ioScope.launch {
            try {
                kotlinx.coroutines.delay(HANDOVER_DEBOUNCE_MS)
                if (!started) return@launch
                withContext(Dispatchers.Main) { serviceReload() }
            } catch (ce: kotlinx.coroutines.CancellationException) {
                throw ce
            } catch (t: Throwable) {
                Log.w(FlickerApp.TAG, "handover reload", t)
            }
        }
    }

    private fun reportDefaultInterface(
        cm: ConnectivityManager,
        network: Network,
        caps: NetworkCapabilities,
        listener: InterfaceUpdateListener
    ) {
        try {
            val lp = cm.getLinkProperties(network) ?: return
            val name = lp.interfaceName ?: return
            val index = try {
                JavaNetworkInterface.getByName(name)?.index ?: 0
            } catch (e: Exception) {
                0
            }
            val expensive = !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
            val constrained = false
            listener.updateDefaultInterface(name, index, expensive, constrained)
            val path = when {
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
                else -> "other"
            }
            listener.updateNetworkPath(path)
        } catch (e: Exception) {
            Log.w(FlickerApp.TAG, "reportDefaultInterface", e)
        }
    }

    override fun closeDefaultInterfaceMonitor(listener: InterfaceUpdateListener?) {
        unregisterNetworkCallback()
    }

    private fun unregisterNetworkCallback() {
        networkCallback?.let { cb ->
            try {
                getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(cb)
            } catch (_: Exception) {
            }
        }
        networkCallback = null
    }

    override fun getInterfaces(): NetworkInterfaceIterator {
        val items = ArrayList<BoxNetworkInterface>()
        try {
            JavaNetworkInterface.getNetworkInterfaces()?.toList()?.forEach { jif ->
                try {
                    val ni = BoxNetworkInterface()
                    ni.index = jif.index
                    ni.name = jif.name ?: ""
                    try { ni.setMTU(jif.mtu) } catch (_: Throwable) {}
                    ni.type = guessInterfaceType(jif.name ?: "")
                    ni.metered = false
                    var flags = 0
                    try {
                        if (jif.isUp) flags = flags or OsConstants.IFF_UP or OsConstants.IFF_RUNNING
                        if (jif.isLoopback) flags = flags or OsConstants.IFF_LOOPBACK
                        if (jif.isPointToPoint) flags = flags or OsConstants.IFF_POINTOPOINT
                        if (jif.supportsMulticast()) flags = flags or OsConstants.IFF_MULTICAST
                    } catch (_: Throwable) {}
                    ni.flags = flags
                    val addresses = try {
                        jif.interfaceAddresses?.mapNotNull { ia ->
                            safePrefix(ia.address, ia.networkPrefixLength.toInt())
                        } ?: emptyList()
                    } catch (_: Throwable) { emptyList() }
                    ni.addresses = addresses.toStringIterator()
                    items.add(ni)
                } catch (e: Throwable) {
                    Log.w(FlickerApp.TAG, "getInterfaces: пропущен ${jif.name}", e)
                }
            }
        } catch (e: Exception) {
            Log.w(FlickerApp.TAG, "getInterfaces", e)
        }
        return object : NetworkInterfaceIterator {
            private var i = 0
            override fun hasNext(): Boolean = i < items.size
            override fun next(): BoxNetworkInterface = items[i++]
        }
    }

    private fun guessInterfaceType(name: String): Int = when {
        name.startsWith("wlan") || name.startsWith("wifi") || name.startsWith("ap") -> 0
        name.startsWith("rmnet") || name.startsWith("ccmni") || name.startsWith("usb") -> 1
        name.startsWith("eth") -> 2
        else -> 3
    }

    override fun underNetworkExtension(): Boolean = false
    override fun includeAllNetworks(): Boolean = false
    override fun readWIFIState(): WIFIState? = null
    override fun clearDNSCache() {}

    override fun sendNotification(notification: BoxNotification) {
        try {
            val nm = getSystemService(NotificationManager::class.java) ?: return
            val id = 1000 + notification.typeID.toInt()
            val n = NotificationCompat.Builder(this, FlickerApp.CHANNEL_STATUS)
                .setSmallIcon(R.drawable.ic_notification)
                .setContentTitle(notification.title ?: getString(R.string.app_name))
                .setContentText(notification.body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(notification.body))
                .setAutoCancel(true)
                .build()
            nm.notify(id, n)
        } catch (e: Exception) {
            Log.w(FlickerApp.TAG, "sendNotification", e)
        }
    }

    override fun cancelNotification(identifier: String?, typeID: Int) {
        try {
            getSystemService(NotificationManager::class.java)?.cancel(1000 + typeID)
        } catch (_: Exception) {
        }
    }

    override fun startNeighborMonitor(listener: NeighborUpdateListener?) {}
    override fun closeNeighborMonitor(listener: NeighborUpdateListener?) {}
    override fun registerMyInterface(name: String?) {}
    override fun usePlatformShell(): Boolean = false
    override fun checkPlatformShell() {}

    override fun openShellSession(
        user: PlatformUser?,
        command: String?,
        environ: StringIterator?,
        term: String?,
        rows: Int,
        cols: Int
    ): ShellSession = throw UnsupportedOperationException("shell не поддерживается")

    override fun lookupUser(username: String?): PlatformUser? =
        throw IllegalStateException("android: user lookup not supported")

    override fun lookupSFTPServer(): String = ""
    override fun readSystemSSHHostKey(): String = ""
    override fun tailscaleHostname(): String = ""
    override fun usePlatformBridge(): Boolean = false
    override fun createBridge(options: BridgeOptions?): BridgeSession =
        throw UnsupportedOperationException("bridge не поддерживается")

    /**
     * v4.12.2: OPEN/PROTECTED — вызывается наследником [BypassVpnService].
     */
    protected open fun startForegroundNotif(text: String) {
        if (started) {
            ServiceCompat.startForeground(
                this, NOTIF_ID,
                Notifications.buildTunnel(this, Repository.selectedServer()?.name),
                fgType()
            )
            return
        }
        val n = NotificationCompat.Builder(this, FlickerApp.CHANNEL_TUNNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setOngoing(true)
            .setSilent(true)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .setContentIntent(
                PendingIntent.getActivity(
                    this, 0, Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )
            )
            .addAction(
                R.drawable.ic_notification, getString(R.string.action_disconnect),
                PendingIntent.getService(
                    this, 1,
                    Intent(this, targetClass(this)).setAction(ACTION_DISCONNECT),
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )
            )
            .build()
        ServiceCompat.startForeground(this, NOTIF_ID, n, fgType())
    }

    private fun fgType(): Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_MANIFEST
        } else 0

    private fun notifyStatus(text: String) {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        val n = NotificationCompat.Builder(this, FlickerApp.CHANNEL_STATUS)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setAutoCancel(true)
            .build()
        nm.notify(2, n)
    }

    private fun addAddressSafe(builder: Builder, address: String?, prefix: Int, what: String): Boolean {
        if (address.isNullOrBlank()) {
            Log.w(FlickerApp.TAG, "openTun/$what: пустой адрес, пропускаю")
            return false
        }
        return try {
            builder.addAddress(InetAddress.getByName(address), prefix)
            true
        } catch (e: Throwable) {
            Log.e(FlickerApp.TAG, "openTun/$what: не добавить $address/$prefix", e)
            false
        }
    }

    private fun addDnsSafe(builder: Builder, address: String?): Boolean {
        if (address.isNullOrBlank()) return false
        return try {
            builder.addDnsServer(address)
            true
        } catch (e: Throwable) {
            Log.e(FlickerApp.TAG, "openTun: не добавить DNS $address", e)
            false
        }
    }

    /**
     * v4.12.2: OPEN/PROTECTED — вызывается наследником [BypassVpnService].
     */
    protected open fun publishState(nameOverride: String? = null) {
        val connected = started
        val bypass = dev.flicker.vpn.util.Prefs.mode(this) ==
            dev.flicker.vpn.util.Prefs.MODE_BYPASS
        AppState.update(
            newStatus = when {
                connected -> ServiceStatus.Connected
                AppState.lastError != null -> ServiceStatus.Failed
                else -> ServiceStatus.Disconnected
            },
            serverName = when {
                !connected -> ""
                nameOverride != null -> nameOverride
                bypass -> AppState.serverName
                else -> Repository.selectedServer()?.name.orEmpty()
            },
        )
        try {
            dev.flicker.vpn.service.QuickTileService.updateTile(this)
        } catch (e: Throwable) {
            Log.w(FlickerApp.TAG, "updateTile", e)
        }
    }

    /**
     * v4.12.2: OPEN/PROTECTED — вызывается наследником [BypassVpnService].
     */
    protected open fun broadcastState(connected: Boolean, message: String?, name: String? = null) {
        if (!connected && message != null) {
            AppState.update(ServiceStatus.Failed, error = message)
        }
        publishState(if (connected) name else null)
        val intent = Intent(BROADCAST_STATE)
            .setPackage(packageName)
            .putExtra(EXTRA_CONNECTED, connected)
        if (message != null) intent.putExtra(EXTRA_MESSAGE, message)
        if (connected && !name.isNullOrEmpty()) intent.putExtra(EXTRA_NAME, name)
        sendBroadcast(intent)
    }
}

// ---------- помощники итераторов libbox ----------

private fun RoutePrefixIterator.forEachPrefix(block: (RoutePrefix) -> Unit) {
    while (hasNext()) {
        val rp = next() ?: continue
        block(rp)
    }
}

private fun StringIterator.toStringList(): List<String> {
    val out = ArrayList<String>()
    while (hasNext()) {
        next()?.let { out.add(it) }
    }
    return out
}

private fun List<String>.toStringIterator(): StringIterator {
    val self = this
    return object : StringIterator {
        private var i = 0
        override fun len(): Int = self.size
        override fun hasNext(): Boolean = i < self.size
        override fun next(): String = self[i++]
    }
}
