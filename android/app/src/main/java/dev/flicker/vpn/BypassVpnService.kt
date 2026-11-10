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

/**
 * v4.12.0: обход DPI — ПОРТ РАБОЧЕЙ СХЕМЫ ByeByeDPI-x-tg v1.0.1-build5.
 *
 * ============================================================================
 *  ЧТО ИМЕННО ПЕРЕНЕСЕНО (дословно из эталона, см. DPI-INTEGRATION.md)
 * ============================================================================
 *
 *  Стек (ByeDpiVpnService.doStart + startTun2Socks + createBuilder):
 *
 *      [приложения] → TUN (VpnService.Builder.establish())
 *                         ↓ fd
 *                   [hev-socks5-tunnel]  (tun2socks, libhev-socks5-tunnel.so,
 *                         ↓               конфиг: mtu 8500, task-stack 81920,
 *                   SOCKS5 127.0.0.1:1080  udp: udp)
 *                         ↓
 *                   [byedpi]  (libbyedpi.so, JNI main(argc,argv), те же
 *                         ↓    исходники и та же обёртка native-lib.c, что
 *                   [интернет]  в эталоне; desync/split/OOB/fake)
 *
 *  Последовательность старта — как в эталоне: сначала поднимается byedpi и
 *  ДОЖИДАЕТСЯ готовности SOCKS5 (рукопожатие 05 01 00 → 05 00 — приём
 *  NativeSession.awaitProxy оттуда же), затем establish() TUN и
 *  TProxyStartService(config, fd).
 *
 *  Параметры TUN — как в эталоне (createBuilder): 10.10.10.10/32, маршрут
 *  0.0.0.0/0, DNS 8.8.8.8 (настраивается Prefs.bypassDns), setMetered(false),
 *  addDisallowedApplication(собственный пакет) — ОБЯЗАТЕЛЬНО, иначе исходящие
 *  сокеты byedpi/hev уйдут обратно в TUN → бесконечная петля.
 *
 *  Командная строка byedpi по умолчанию («ref»-пресет ByeDpiArgs) — байт-в-байт
 *  дефолт эталона:  ciadpi --ip 127.0.0.1 --port 1080 -c512 -b16384 -Kt,h -o1
 *  -e97 -An -Ku -a1 -An
 *
 * ============================================================================
 *  ЧТО СОХРАНЕНО ИЗ FLICKER 4.11.0 (и почему это не мешает эталону)
 * ============================================================================
 *
 *  * Процесс :bypass (v4.12.1: без killProcess в onDestroy) — одноразовый процесс
 *    даёт гарантированно чистое состояние после остановки (у эталона ту же
 *    роль играет reset_params() в JNI; теперь есть оба механизма).
 *  * Контракты UI: BROADCAST_STATE (+ имя в EXTRA_NAME), Repository.setConnected,
 *    AppState, Notifications.buildTunnel (кнопки «Пауза»/«Отключить» через
 *    targetClass() приходят обратно в этот сервис).
 *
 *  Sing-box (libflickerbox.so) в режиме обхода НЕ участвует ВООБЩЕ: ни
 *  CommandServer, ни BypassConfig, ни hijack-dns. Обход больше не может
 *  сломаться от версии/конфига Go-ядра — ровно как в эталоне, где никакого
 *  sing-box на этом пути нет.
 */
class BypassVpnService : TunnelService() {

    // ---------- состояние эталонного стека ----------

    private var proxy: ByeDpiProxy? = null
    private var proxyThread: Thread? = null
    private var tunFd: ParcelFileDescriptor? = null
    private var tunConfigFile: File? = null

    /** tun2socks поднят и TUN жив. */
    @Volatile
    private var hevActive = false

    /** Остановка запрошена пользователем/сервисом — «неожиданный» выход main() не аварийный. */
    @Volatile
    private var userStop = false

    /** Имя для уведомления/UI: «Обход DPI · <пресет>». */
    @Volatile
    private var currentBypassName: String = ""

    /**
     * Собственный скоуп (аналог lifecycleScope эталона): Main.immediate для
     * состояния/UI, тяжёлое — через withContext(Dispatchers.IO).
     */
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    companion object {
        /**
         * Порт SOCKS5 byedpi — 1080, КАК В ЭТАЛОНЕ (UISettings.port = 1080,
         * "byedpi_proxy_port" default "1080"). Не TunnelService.BYEDPI_PORT
         * (10888): тот принадлежал прежней sing-box-схеме.
         */
        const val SOCKS_PORT = 1080

        /** DNS по умолчанию — как в эталоне ("dns_ip" default "8.8.8.8"). */
        const val DEFAULT_DNS = "8.8.8.8"

        /** Сколько ждём готовности SOCKS5 (дедлайн эталонного awaitProxy). */
        private const val READY_TIMEOUT_MS = 8_000L
        private const val PROBE_TIMEOUT_MS = 250
        private const val PROBE_INTERVAL_MS = 50L
    }

    // ==================================================================
    //  СТАРТ — переопределение хука v4.12.0 (см. TunnelService)
    // ==================================================================

    override fun startBypassTunnel(serverJson: String) {
        if (hevActive || started) {
            Log.i(FlickerApp.TAG, "обход: уже поднят, повторный старт игнорирую")
            return
        }
        if (!ByeDpiProxy.nativeReady || !TProxyService.nativeReady) {
            // Контракт FGS: подняты через startForegroundService — обязаны
            // либо startForeground, либо stopSelf. Делаем и то, и другое.
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

    /**
     * Порт ByeDpiVpnService.doStart(): proxy → готовность SOCKS5 → TUN →
     * tun2socks → статус Connected.
     */
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
                // FGS-уведомление ПЕРВЫМ (правило 5 секунд после
                // startForegroundService) — порядок из эталона/Flicker.
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

    /**
     * Порт ByeDpiVpnService.startProxy(): JNI main(argc, argv) в выделенном
     * потоке (вызов блокирующий). Внезапный возврат main() при поднятом
     * туннеле — авария: роняем всё и сообщаем (в эталоне за этим следит
     * proxyJob).
     */
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

    /**
     * Готовность SOCKS5 — рукопожатие 05 01 00 → 05 00 (приём эталона).
     * В эталоне вместо этого delay(400); проба строже и не ломает порядок:
     * TUN поднимается ТОЛЬКО после того, как прокси начал слушать.
     */
    private fun awaitSocks5() {
        val deadline = System.currentTimeMillis() + READY_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            if (socks5Ready("127.0.0.1", SOCKS_PORT)) return
            // main() уже вернулся (неверные аргументы, авария) — ждать
            // дедлайн бессмысленно, сообщаем сразу (причина — в logcat
            // с тегом byedpi и в CrashLog).
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

    /**
     * Порт ByeDpiVpnService.startTun2Socks(): конфиг hev-socks5-tunnel
     * один в один (mtu 8500, task-stack-size 81920, socks5 + udp: udp),
     * establish() и передача fd в нативку.
     */
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

    /**
     * Порт ByeDpiVpnService.createBuilder() — параметры эталона дословно:
     * 10.10.10.10/32 + 0.0.0.0/0 + DNS + setMetered(false) + всегда
     * addDisallowedApplication(собственный пакет).
     */
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
        // ОБЯЗАТЕЛЬНО (петля маршрутизации): byedpi и hev-socks5-tunnel живут
        // в этом же пакете (процесс :bypass); без исключения их исходящие
        // сокеты попали бы обратно в TUN → SOCKS5 → byedpi → ... В эталоне
        // addDisallowedApplication(packageName) вызывается всегда.
        builder.addDisallowedApplication(packageName)
        return builder
    }

    // ==================================================================
    //  ОСТАНОВКА
    // ==================================================================

    /**
     * Переопределение базовой остановки: у эталонного стека нет ни
     * CommandServer, ни closeService() — вместо них doCleanup() эталона:
     * stopProxy → TProxyStopService → удалить конфиг → закрыть fd.
     */
    override fun stopTunnel(andStop: Boolean) {
        if (!initialized) {
            // Инертный экземпляр (контрольный bind) — базовый guard сделает no-op.
            super.stopTunnel(andStop)
            return
        }
        userStop = true
        started = false
        hevActive = false

        // Порядок базового класса: уведомление и foreground снимаются
        // СИНХРОННО (пользователь видит результат нажатия мгновенно), а
        // «Отключить»/«Пауза» не должны ждать нативной остановки. PAUSE_ID
        // снимается здесь же, как в базе: при ACTION_PAUSE базовый
        // onStartCommand выставит новое уведомление паузы ПОСЛЕ возврата.
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

    /**
     * Порт ByeDpiVpnService.doCleanup()/stopTun2Socks(). Порядок эталона:
     * сначала прокси (shutdown(server_fd) — main() возвращается), потом
     * tun2socks, потом fd. Вызывается из IO-контекста.
     */
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

    /**
     * Атомарный teardown (сохранено из 4.11.0, docs/21): процесс :bypass
     * умирает вместе с туннелем — глобалы byedpi, hev-сокеты и fd обнуляются
     * смертью процесса, следующий старт гарантированно с чистого листа.
     * Перед этим — best-effort остановка штатными вызовами.
     */
    override fun onDestroy() {
        userStop = true
        try { proxy?.stopProxy() } catch (_: Throwable) {}
        try { tunFd?.close() } catch (_: Throwable) {}
        tunFd = null
        scope.cancel()
        super.onDestroy()
        // v4.12.1: процесс :bypass НЕ убиваем. Штатной остановки proxy+fd достаточно;
        // killProcess выглядел как вылет приложения.
    }

    /** Смахнули из «недавних» — туннель сохраняем (как в базовом классе), уведомление освежаем. */
    override fun onTaskRemoved(rootIntent: Intent?) {
        Log.i(FlickerApp.TAG, "обход: onTaskRemoved — туннель сохраняем")
        if (started) updateForeground(currentBypassName)
        // super.onTaskRemoved не зовём: базовая реализация пересобирает
        // уведомление с именем УЗЛА (Repository.selectedServer), которого в
        // режиме обхода нет.
    }

    // ==================================================================
    //  Уведомление
    // ==================================================================

    private fun updateForeground(name: String) {
        val n = Notifications.buildTunnel(this, name)
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_MANIFEST
        } else 0
        ServiceCompat.startForeground(this, NOTIF_ID, n, type)
    }
}
