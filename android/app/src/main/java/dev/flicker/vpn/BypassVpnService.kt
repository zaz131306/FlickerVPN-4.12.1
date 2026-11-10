// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn

import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.ServiceCompat
import dev.flicker.vpn.core.ByeDpiArgs
import dev.flicker.vpn.core.ByeDpiProxy
import dev.flicker.vpn.core.TProxyService
import dev.flicker.vpn.data.AppState
import dev.flicker.vpn.data.ServiceStatus
import dev.flicker.vpn.data.TunnelMode
import dev.flicker.vpn.util.Notifications
import dev.flicker.vpn.util.Prefs
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import kotlin.concurrent.thread

class BypassVpnService : TunnelService() {

    private var proxy: ByeDpiProxy? = null
    private var proxyThread: Thread? = null
    private var tunFd: ParcelFileDescriptor? = null
    private var tunConfigFile: File? = null

    @Volatile
    private var hevActive = false

    @Volatile
    private var userStop = false

    @Volatile
    private var currentBypassName: String = ""

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    companion object {
        const val SOCKS_PORT = 1080
        const val DEFAULT_DNS = "8.8.8.8"
        private const val READY_TIMEOUT_MS = 8_000L
        private const val PROBE_TIMEOUT_MS = 250
        private const val PROBE_INTERVAL_MS = 50L
    }

    override fun startBypassTunnel(serverJson: String) {
        if (hevActive || started) {
            Log.i(FlickerApp.TAG, "обход: уже поднят, повторный старт игнорирую")
            return
        }
        if (!ByeDpiProxy.nativeReady || !TProxyService.nativeReady) {
            startForegroundNotif(getString(R.string.notif_starting))
            val err = buildString {
                append("Библиотеки обхода DPI не загружены:")
                if (!ByeDpiProxy.nativeReady) append(" libbyedpi.so (").append(ByeDpiProxy.loadError ?: "?").append(");")
                if (!TProxyService.nativeReady) append(" libhev-socks5-tunnel.so (").append(TProxyService.loadError ?: "?").append(");")
                append(" — пересоберите APK с NDK (BUILD-ANDROID.md, задачи runNdkBuild + externalNativeBuild)")
            }
            Log.e(FlickerApp.TAG, err)
            CrashLog.note(this, err)
            broadcastState(false, err)
            stopSelf()
            return
        }
        doStart()
    }

    private fun doStart() {
        scope.launch {
            val presetId = Prefs.byedpiPreset(this@BypassVpnService)
            val command = Prefs.byedpiCommand(this@BypassVpnService)
            val name = if (command.isNotBlank()) {
                "Обход DPI · своя командная строка"
            } else {
                "Обход DPI · ${ByeDpiArgs.preset(presetId).title}"
            }
            try {
                startForegroundNotif(getString(R.string.notif_starting))
                initialized = true
                userStop = false
                currentBypassName = name

                withContext(Dispatchers.IO) {
                    startProxy(presetId, command)
                    awaitSocks5()
                    startTun2Socks()
                }

                hevActive = true
                started = true
                AppState.update(ServiceStatus.Connected, TunnelMode.Vpn, name)
                Repository.setConnected(true, name)
                updateForeground(name)
                broadcastState(true, null, name)
                CrashLog.note(this@BypassVpnService, "обход DPI поднят: $name, SOCKS5 127.0.0.1:$SOCKS_PORT")
                Log.i(FlickerApp.TAG, "обход: подключено — $name")
            } catch (t: Throwable) {
                if (t is kotlinx.coroutines.CancellationException) throw t
                Log.e(FlickerApp.TAG, "обход: старт не удался", t)
                CrashLog.note(
                    this@BypassVpnService,
                    "обход DPI не поднялся: ${t.javaClass.simpleName}: ${t.message}"
                )
                withContext(Dispatchers.IO) { hevCleanup() }
                started = false
                broadcastState(false, "Обход DPI не запустился: ${t.message ?: t.javaClass.simpleName}")
                stopSelf()
            }
        }
    }

    private fun startProxy(presetId: String?, command: String?) {
        val args = ByeDpiArgs.argsFor(presetId, command, "127.0.0.1", SOCKS_PORT)
        Log.i(FlickerApp.TAG, "обход: byedpi: ${args.joinToString(" ")}")
        val engine = ByeDpiProxy()
        proxy = engine
        proxyThread = thread(name = "ByeDPI", isDaemon = true) {
            val code = try {
                engine.startProxy(args)
            } catch (t: Throwable) {
                Log.e(FlickerApp.TAG, "обход: startProxy бросил", t)
                -1
            }
            Log.w(FlickerApp.TAG, "обход: byedpi завершилась с кодом $code")
            if (!userStop && hevActive) {
                scope.launch {
                    withContext(Dispatchers.IO) { hevCleanup() }
                    started = false
                    Repository.setConnected(false, "")
                    broadcastState(false, "Обход DPI: движок byedpi неожиданно завершился (код $code)")
                    stopSelf()
                }
            }
        }
    }

    private fun awaitSocks5() {
        val deadline = System.currentTimeMillis() + READY_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            if (socks5Ready("127.0.0.1", SOCKS_PORT)) return
            val t = proxyThread
            if (t != null && !t.isAlive) {
                throw IOException("byedpi завершилась преждевременно — SOCKS5 не поднят (проверьте аргументы; лог: tag byedpi)")
            }
            try {
                Thread.sleep(PROBE_INTERVAL_MS)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                break
            }
        }
        throw IOException("SOCKS5 byedpi не поднялся за ${READY_TIMEOUT_MS}мс на 127.0.0.1:$SOCKS_PORT")
    }

    private fun socks5Ready(host: String, port: Int): Boolean = try {
        Socket().use { s ->
            s.connect(InetSocketAddress(host, port), PROBE_TIMEOUT_MS)
            s.soTimeout = PROBE_TIMEOUT_MS
            s.getOutputStream().write(byteArrayOf(5, 1, 0))
            val input = s.getInputStream()
            input.read() == 5 && input.read() == 0
        }
    } catch (_: IOException) {
        false
    } catch (_: Throwable) {
        false
    }

    private fun startTun2Socks() {
        try { tunFd?.close() } catch (_: Exception) {}
        tunFd = null

        val dns = Prefs.bypassDns(this).ifBlank { DEFAULT_DNS }

        val config = buildString {
            appendLine("tunnel:")
            appendLine("  mtu: 8500")
            appendLine("misc:")
            appendLine("  task-stack-size: 81920")
            appendLine("socks5:")
            appendLine("  address: 127.0.0.1")
            appendLine("  port: $SOCKS_PORT")
            appendLine("  udp: udp")
        }
        val configFile = File.createTempFile("config", "tmp", cacheDir).apply { writeText(config) }
        tunConfigFile = configFile

        val fd = createBuilder(dns).establish()
            ?: throw IllegalStateException(
                "VPN establish() вернул null — система не выдала TUN " +
                    "(согласие не дано или VPN перехвачен другим приложением)"
            )
        tunFd = fd
        TProxyService.TProxyStartService(configFile.absolutePath, fd.fd)
    }

    private fun createBuilder(dns: String): Builder {
        val builder = Builder()
        builder.setSession("FlickerVPN")
        builder.setConfigureIntent(
            PendingIntent.getActivity(
                this, 0, Intent(this, MainActivity::class.java),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        )
        builder.addAddress("10.10.10.10", 32).addRoute("0.0.0.0", 0)
        if (dns.isNotBlank()) builder.addDnsServer(dns)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            try { builder.setMetered(false) } catch (_: Throwable) {}
        }
        builder.addDisallowedApplication(packageName)
        return builder
    }

    override fun stopTunnel(andStop: Boolean) {
        if (!initialized) {
            super.stopTunnel(andStop)
            return
        }
        userStop = true
        started = false
        hevActive = false

        if (andStop) {
            Notifications.cancel(this, NOTIF_ID)
            Notifications.cancel(this, Notifications.PAUSE_ID)
            try {
                ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
            } catch (t: Throwable) {
                Log.w(FlickerApp.TAG, "обход: stopForeground", t)
            }
        }

        scope.launch {
            withContext(Dispatchers.IO) { hevCleanup() }
            Repository.setConnected(false, "")
            broadcastState(false, null)
            if (andStop) stopSelf()
        }
    }

    private fun hevCleanup() {
        userStop = true
        val p = proxy
        val t = proxyThread
        proxy = null
        proxyThread = null
        try { p?.stopProxy() } catch (e: Throwable) { Log.w(FlickerApp.TAG, "обход: proxy stop", e) }
        try { t?.join(500) } catch (_: InterruptedException) { Thread.currentThread().interrupt() }
        try { TProxyService.TProxyStopService() } catch (e: Throwable) { Log.w(FlickerApp.TAG, "обход: tproxy stop", e) }
        try { tunConfigFile?.delete() } catch (_: Exception) {}
        tunConfigFile = null
        try { tunFd?.close() } catch (_: Exception) {}
        tunFd = null
        hevActive = false
    }

    override fun onDestroy() {
        userStop = true
        try { proxy?.stopProxy() } catch (_: Throwable) {}
        try { tunFd?.close() } catch (_: Throwable) {}
        tunFd = null
        scope.cancel()
        super.onDestroy()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        Log.i(FlickerApp.TAG, "обход: onTaskRemoved — туннель сохраняем")
        if (started) updateForeground(currentBypassName)
    }

    private fun updateForeground(name: String) {
        val n = Notifications.buildTunnel(this, name)
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_MANIFEST
        } else 0
        ServiceCompat.startForeground(this, NOTIF_ID, n, type)
    }
}
