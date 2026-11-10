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
 * Конфиг туннеля строит Go-фасад Mobile.buildTunConfig (тот же
 * internal/singcfg, что на десктопе): VLESS+Reality+Vision / Trojan / VMess /
 * Shadowsocks / WireGuard (включая «матрёшку» через VLESS-детур) / HY2-запасной.
 */
class TunnelService : VpnService(), PlatformInterface, CommandServerHandler, SocketProtector, ProbeListener {

    companion object {
        const val ACTION_CONNECT = "dev.flicker.vpn.CONNECT"
        const val ACTION_DISCONNECT = "dev.flicker.vpn.DISCONNECT"

        /**
         * v4.0.9: «ip/prefix», гарантированно съедаемый netip.MustParsePrefix
         * на Go-стороне (libbox NetworkInterfaces). Возвращает null вместо
         * строк, на которых Go-ядро упало бы с abort(): зоны IPv6, префиксы
         * вне 0..128, пустые/мусорные host-строки.
         */
        internal fun safePrefix(addr: java.net.InetAddress?, prefix: Int): String? {
            return try {
                if (addr == null) {
                    null
                } else if (prefix < 0 || prefix > 128) {
                    null
                } else {
                    val host = if (addr is java.net.Inet6Address) {
                        // пересоздание из байтов снимает зону (%wlan0), как в SFA toPrefix()
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

        /**
         * Пауза/возобновление из уведомления.
         *
         * Пауза глушит туннель, НО не останавливает сервис: foreground-сервис
         * остаётся жив, и «возобновить» происходит мгновенно, без повторного
         * системного диалога согласия VPN. На бесплатных узлах это важно:
         * они умирают часто, и переподключаться кнопкой быстрее, чем заново
         * проходить VpnService.prepare().
         */
        /**
         * v4.10.4: повторы builder.establish() при null-ответе системы.
         *
         * establish() возвращает null, пока системный VpnManager не довёл
         * нашу сессию до готового состояния (или если согласие отозвано /
         * VPN перехвачен другим приложением). Мгновенный throw на первый
         * null превращал лаг системы в «ошибку» на ровном месте; три повтора
         * через 500 мс покрывают наблюдаемые лаги, а если null держится —
         * establishFailure() говорит пользователю КУДА смотреть (docs/20).
         */
        private const val ESTABLISH_RETRIES = 3
        private const val ESTABLISH_RETRY_MS = 500L

        /**
         * v4.11.0: компонент-обработчик запроса (docs/21).
         *
         * Обход DPI живёт в отдельном одноразовом процессе :bypass
         * ([BypassVpnService]), VPN/прокси-режимы — здесь. Все intent'ы на
         * старт/стоп/паузу/возобновление и все PendingIntent уведомлений
         * ОБЯЗАНЫ строиться через этот метод:	intent, посланный в «не тот»
         * процесс, либо поднимет второй туннель, либо уйдёт в инертный
         * экземпляр и потеряется.
         *
         * Правило одно и везде: текущий режим из Prefs. Переключение режима
         * всегда сопровождается остановкой туннеля, поэтому рассинхрон
         * «режим изменился, а intent ушёл в старый процесс» переживает только
         * уже остановленный туннель.
         */
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

        /**
         * v4.12.0: имя подключения в broadcast BROADCAST_STATE.
         *
         * Обход DPI живёт в процессе :bypass, а UI — в основном. Repository и
         * AppState — внутрипроцессные синглтоны, поэтому без имени в broadcast
         * главный процесс не мог показать, к чему именно подключено. Теперь
         * MainActivity.stateReceiver зеркалит состояние к себе из extras.
         */
        const val EXTRA_NAME = "name"

        /**
         * v4.12.0: поднят ли сейчас ХОТЯ БЫ ОДИН VPN-интерфейс (системная,
         * кросс-процессная правда).
         *
         * Зачем: обход DPI работает в процессе :bypass, и `isLive`
         * (instance?.started) в основном процессе про него ничего не знает —
         * статик на процесс свой. Наличие VPN-транспорта в системе видно всем.
         * Используем только как признак «наш обход жив» в режиме MODE_BYPASS
         * (допущение то же, что уже делает isAnyVpnUp(): другим VPN-приложениям
         * мы работать не даём — см. предупреждение в диагностике).
         */
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

        /** v4.2.0: порт локального SOCKS5 в режиме «Прокси» (метод ByeByeDPI). */
        const val PROXY_PORT = 10808

        /**
         * v4.7.1: порт SOCKS5, на котором byedpi слушает в режиме «Обход DPI».
         * Отдельный от PROXY_PORT, чтобы режимы не конфликтовали при быстром
         * переключении и чтобы в логах было видно, кто именно слушает.
         */
        const val BYEDPI_PORT = 10888

        /**
         * v4.7.1: значение serverJson для режима обхода DPI.
         *
         * Отдельный маркер, а не null и не пустая строка: startTunnel() и
         * buildAndStart() на протяжении всего пути обращаются с serverJson как
         * с непустой строкой (currentServerJson, JSONObject(...), setSelectedId),
         * и переделка всей цепочки под nullable рискованнее, чем явный маркер.
         */
        const val BYPASS_NO_SERVER = "\u0000bypass"

        /** Режим обхода DPI активен? */
        internal fun isBypass(serverJson: String?): Boolean = serverJson == BYPASS_NO_SERVER
        private const val WATCHDOG_INTERVAL_MS = 15 * 60 * 1000L // фоновая перепроверка

        /**
         * v4.6.0: дебаунс смены базовой сети перед перезапуском ядра.
         * Значение — из v2rayNG NetworkMonitor.HANDOVER_DEBOUNCE_MS.
         * Без дебаунса каждое моргание сети (лифт, метро, переключение
         * WiFi↔LTE) дёргало бы перезапуск ядра.
         */
        private const val HANDOVER_DEBOUNCE_MS = 1000L

        /** v4.5.0: имя файла, куда sing-box пишет свой журнал (log.output). */
        const val CORE_FILE_LOG = "core-file.log"

        /**
         * v4.10.1: потолок размера [CORE_FILE_LOG] перед обрезкой.
         *
         * ЗАЧЕМ. Этот файл sing-box пишет САМ (log.output), и ротации у ядра
         * нет — в отличие от box/core.log, который ведёт приложение и который
         * [appendCoreLog] подрезает на 300 КБ. До v4.10.1 файл рос всю сессию
         * без ограничения.
         *
         * Почему он растёт быстро: на Android sing-box v1.14.2 вызывает
         * FindConnectionOwner на КАЖДОМ соединении (route.go:546
         * prepareMatchMetadata → searchProcessInfo) и на каждом перехваченном
         * DNS-пакете (route/dns.go:21), а наш [findConnectionOwner] отвечает
         * исключением — иначе nil-паника. Ядро на это пишет строку
         * «failed to search process: …» уровня INFO, то есть по строке на
         * соединение. Отключить этот вызов конфигом НЕЛЬЗЯ: searchProcessInfo
         * не смотрит на route.find_process, а platformSearcher на Android
         * создаётся всегда и UsePlatformConnectionOwnerFinder() жёстко
         * возвращает true (service.go:189-191).
         *
         * Обрезка безопасна: ядро открывает файл с
         * O_APPEND|O_CREATE|O_WRONLY (log/observable.go:79), поэтому после
         * setLength/перезаписи следующая его дозапись встанет в новый конец
         * файла, без «дыр». Это обычная семантика logrotate copytruncate.
         */
        private const val CORE_FILE_LOG_MAX = 400_000L

        /** v4.10.1: сколько последних байт [CORE_FILE_LOG] оставлять при обрезке. */
        private const val CORE_FILE_LOG_KEEP = 200_000L

        /**
         * v4.5.0: цели сквозной самопроверки узла (см. probeTargets).
         * Порядок = порядок в строке отчёта. Первые две — то, ради чего
         * пользователь ставит VPN; ipify — общий маркер «интернет есть».
         */
        private val CHECK_TARGETS: List<Pair<String, String>> = listOf(
            "Telegram" to "https://api.telegram.org/method/getMe",
            "Instagram" to "https://www.instagram.com/",
            "ipify" to "https://api.ipify.org/?format=json",
        )

        @Volatile
        var instance: TunnelService? = null
            private set

        /**
         * v4.7.0: аварийное отключение — для случая «обычное не помогло».
         *
         * Симптом, ради которого это существует: пользователь жмёт «Отключить»,
         * уведомление пропадает, а ключик в статусбаре остаётся, весь трафик
         * телефона уходит в мёртвый интерфейс, и помогает только переустановка
         * приложения. Значит fd туннеля так и не был закрыт.
         *
         * Делаем обычную остановку и параллельно — независимый поток-страховку:
         * через 4 секунды, если туннель всё ещё жив, закрываем fd принудительно
         * и убиваем процесс. Процесс свой же, настройки сохранены синхронно,
         * поэтому убийство безопасно; при следующем запуске приложение стартует
         * с чистым состоянием.
         *
         * Вызывать из UI (меню ⋮ → «Экстренно выключить VPN»).
         */
        fun hardStop(context: Context) {
            Log.w(FlickerApp.TAG, "hardStop: запрошено аварийное отключение")
            stop(context)
            val t = Thread {
                try {
                    // 7 с, а не меньше: штатный путь stopTunnel() ждёт
                    // closeNative() до 6 с (NATIVE_CLOSE_WAIT_MS + 3000) и только
                    // потом решает. Дёрнув fd раньше, мы убили бы процесс
                    // посреди нормальной, просто медленной остановки.
                    Thread.sleep(7_000)
                } catch (_: InterruptedException) {
                    return@Thread
                }
                val svc = instance ?: return@Thread
                // v4.7.1: проверяем реальность (видит ли система VPN-сеть),
                // а не внутренний флаг tunActive. Флаг может быть снят, а
                // интерфейс — остаться: именно так это выглядит на Galaxy M21.
                if (!svc.isAnyVpnUp()) {
                    Log.i(FlickerApp.TAG, "hardStop: VPN-интерфейс уже снят")
                    return@Thread
                }
                Log.e(FlickerApp.TAG, "hardStop: VPN-интерфейс всё ещё поднят через 7 с")
                CrashLog.note(svc, "hardStop: штатная остановка не сняла VPN-интерфейс за 7 с")
                // forceTeardown сам решит, нужно ли убивать процесс: если после
                // закрытия fd интерфейс снялся, приложение останется открытым.
                svc.forceTeardown("hardStop")
            }
            t.isDaemon = true
            t.name = "hard-stop"
            t.start()
        }

        /**
         * v4.6.0: живой ли туннель НА САМОМ ДЕЛЕ.
         *
         * `AppState.status` — хранимая переменная: её кто-то должен обновить.
         * Если путь обновления не выполнился (отменённая корутина, гонка,
         * убитый процесс), она застревает в Connected навсегда, и плитка с UI
         * показывают «подключено» при мёртвом туннеле.
         *
         * Эталон — Intra: `on = intraVpnService != null && intraVpnService.isOn()`,
         * то есть состояние ВЫЧИСЛЯЕТСЯ из живого сервиса. v2rayNG так же:
         * `isRunning() = coreController.isRunning`. Здесь — тот же принцип.
         */
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
            // БЫЛО: context.startService(intent)
            //
            // На Android 8+ (API 26) startService из фона кидает
            // IllegalStateException. stop() вызывают в том числе из
            // BroadcastReceiver и из уведомления — то есть ровно тогда,
            // когда приложение может быть в фоне. Краш выглядел как
            // «выключил VPN — приложение упало».
            //
            // startForegroundService здесь корректен: сервис уже foreground,
            // и он сам себя остановит в onStartCommand по ACTION_DISCONNECT.
            // Если и он не прошёл (Android 12+ запрет на запуск FGS из фона),
            // пробуем stopService — это всегда разрешено.
            try {
                ContextCompat.startForegroundService(context, intent)
            } catch (e: Exception) {
                Log.w(FlickerApp.TAG, "stop через startForegroundService не прошёл", e)
                // v4.6.0: fallback больше не полагается на onDestroy().
                //
                // context.stopService(intent) НЕ доставляет intent в
                // onStartCommand — он сразу вызывает onDestroy(). То есть
                // ACTION_DISCONNECT в этом пути не обрабатывается ВОВСЕ, и вся
                // остановка ложится на onDestroy(), который закрывает ядро
                // СИНХРОННО НА ГЛАВНОМ ПОТОКЕ. По собственному комментарию
                // проекта closeService() «на живых соединениях может
                // заблокироваться навсегда» → ANR → ключик висит ещё секунды.
                //
                // Поэтому сначала дёргаем остановку напрямую через живой
                // экземпляр сервиса (тот же путь, который использует ядро в
                // serviceStop()): stopTunnel(andStop = true) → stopSelf().
                // stopService() — только если экземпляра уже нет.
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

    /**
     * Скоуп для native-работы. SupervisorJob: падение одной джобы не валит
     * остальные. Dispatchers.IO — потому что CommandServer.start() и
     * startOrReloadService() блокирующие и тяжёлые, на главном потоке они
     * дают ANR.
     */
    private val ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /**
     * Запрошенный сервер, если подключение пришло до завершения initNative().
     * Без этого первый тап по «Подключить» терялся: onStartCommand отрабатывал
     * раньше, чем CommandServer успевал создаться.
     */
    @Volatile
    private var pendingServerJson: String? = null

    // v4.3.0: состояние авторотации узлов в пределах сессии подключения.
    // sessionDeadNodes — узлы, провалившие сквозную самопроверку (трафик
    // не пошёл); autoSwitchCount — сколько раз уже переключались сами.
    private val sessionDeadNodes = mutableSetOf<String>()
    private var autoSwitchCount = 0
    private val AUTO_SWITCH_MAX = 8

    // ---------------------------------------------------------------------
    //  v4.6.0: учёт fd туннеля.
    //
    //  ВАЖНО, ПОЧЕМУ ТОЛЬКО УЧЁТ, А НЕ ЗАКРЫТИЕ.
    //  Intra и v2rayNG держат ParcelFileDescriptor у Java и закрывают его сами
    //  (GoVpnAdapter.tunFd / CoreVpnService.mInterface). Это безопасно, потому
    //  что их ядро делает копию дескриптора и не трогает чужой:
    //      Intra, tuntap/tun.go:  newfd, _ := unix.Dup(fd)
    //      «Make a copy of fd so that os.File's finalizer doesn't close fd»
    //  libbox устроен иначе: эталонная SFA передаёт fd через detachFd(), то
    //  есть ОТДАЁТ владение, и ядро закрывает его само в closeService().
    //  Закрывать такой fd из Java нельзя: если ядро уже закрыло его, номер
    //  мог быть переиспользован другим open() — и мы закроем чужой дескриптор.
    //
    //  Поэтому: fd запоминается только для диагностики (видно, выдавался ли
    //  туннель и сколько раз), а гарантированное снятие интерфейса при
    //  зависшем closeService() — v4.12.1: процесс НЕ убиваем, только force close fd
    //  закрывает все дескрипторы разом, ядром.
    // ---------------------------------------------------------------------
    @Volatile
    var tunFdNumber: Int = -1
        private set
    private val tunHandedOut = java.util.concurrent.atomic.AtomicInteger(0)

    /**
     * v4.7.0: жив ли fd туннеля, который мы выдали ядру.
     *
     * true  — establish() состоялся, fd у libbox, интерфейс VPN поднят.
     * false — либо closeService() отработал штатно (ядро закрыло fd само),
     *         либо fd принудительно закрыли из Java (см. closeTunFdForced).
     *
     * На этом флаге держится инвариант остановки: ЛЮБОЕ отключение обязано
     * закончиться либо tunActive == false, либо смертью процесса. Третьего не
     * дано — именно третье и выглядит как «ключик висит, весь трафик жрёт,
     * помогает только переустановка».
     */
    private val tunActive = java.util.concurrent.atomic.AtomicBoolean(false)

    /**
     * Последний рубеж: сколько ждём до принудительного закрытия fd и убийства
     * процесса. Больше, чем дедлайн closeNative (6 с) + запас на переключение
     * в главный поток, иначе страховка сработает раньше штатного пути.
     */
    private val HARD_STOP_DEADLINE_MS = 15_000L

    /** Сколько даём системе на снятие интерфейса после закрытия fd. */
    private val SETTLE_MS = 400L


    // ---------------------------------------------------------------------
    //  v4.6.0: ПАССИВНАЯ детекция мёртвого узла по счётчикам ядра.
    //
    //  libbox отдаёт StatusMessage (uplink/downlink/connectionsIn/…), но
    //  подписка была только на CommandLog, а writeStatus() имел пустое тело —
    //  статистика приходила и молча выбрасывалась. Вместо неё живость узла
    //  угадывалась тремя HTTPS-запросами раз в 15 минут.
    //
    //  Признак «узел принимает, но не выпускает» (ровно то, что дают узлы
    //  «БЕЛЫЕ СПИСКИ») виден напрямую:
    //      connectionsIn > 0  &&  downlinkTotal не растёт
    //  Эталон подхода — Intra: состояние WORKING/FAILING выводится из каждого
    //  прошедшего запроса (recordTransaction), а не из периодических проб.
    // ---------------------------------------------------------------------
    @Volatile
    private var lastDownlinkTotal: Long = 0L
    @Volatile
    private var lastUplinkTotal: Long = 0L
    @Volatile
    private var lastTrafficAt: Long = 0L
    @Volatile
    private var stalledSince: Long = 0L
    @Volatile
    private var stallReported: Boolean = false
    /** Пик connectionsIn за текущее подключение: были ли обращения вообще. */
    @Volatile
    private var peakConnsIn: Long = 0L

    // ---------------------------------------------------------------------
    //  v4.7.0: счётчики трафика для UI.
    //
    //  Данные приходят из StatusMessage (подписка на Libbox.CommandStatus,
    //  добавлена в 4.6.0) каждые STATUS_INTERVAL_MS. Раньше они
    //  использовались только внутри детектора stalled и наружу не отдавались,
    //  поэтому карточка состояния на главном экране не могла показать трафик.
    //
    //  uplink/downlink — мгновенная скорость в байт/с (их отдаёт само ядро),
    //  *Total — накопительно за подключение.
    // ---------------------------------------------------------------------
    @Volatile
    var statUplink: Long = 0L
        private set
    @Volatile
    var statDownlink: Long = 0L
        private set
    @Volatile
    var statUplinkTotal: Long = 0L
        private set
    @Volatile
    var statDownlinkTotal: Long = 0L
        private set
    @Volatile
    var statConnectionsIn: Long = 0L
        private set

    /**
     * Сколько секунд отсутствия трафика при живых входящих соединениях
     * считаем смертью узла.
     *
     * Не меньше [STATUS_STALL_MS] от момента подключения: первые секунды
     * трафика может не быть на законных основаниях (пользователь ещё ничего не открыл).
     */
    private val STATUS_STALL_MS = 12_000L

    /** Интервал опроса статусов ядра. */
    private val STATUS_INTERVAL_MS = 2_000L

    /**
     * Счётчики отказов protect(). Нужны, потому что отказ сейчас только
     * логируется, и «петля из-за незащищённого сокета ядра» внешне неотличима
     * от «узел мёртв».
     *
     *  - coreProtectFails: sing-box не смог исключить СОБСТВЕННЫЙ outbound-сокет
     *    из туннеля → пакеты к узлу возвращаются обратно в TUN → петля.
     *  - probeProtectFails: Go-фасад не смог защитить сокет пробы → проба идёт
     *    сквозь туннель и её результат ничего не значит.
     */
    @Volatile
    var coreProtectFails: Int = 0
        private set
    @Volatile
    var probeProtectFails: Int = 0
        private set


    /**
     * Сериализует доступ к CommandServer.
     *
     * ЗАЧЕМ (это следствие переноса запуска в ioScope):
     * `startOrReloadService()` — БЛОКИРУЮЩИЙ native-вызов, он поднимает весь стек
     * sing-box и может идти сотни миллисекунд. Отмена корутины его НЕ прерывает:
     * cancellation в Kotlin кооперативный, а мы сидим внутри JNI.
     *
     * Значит, если onDestroy() вызовет commandServer.close() в момент, когда
     * фоновая джоба ещё внутри startOrReloadService(), получится use-after-free
     * в нативной памяти → SIGSEGV → процесс умирает без диалога.
     *
     * До переноса в ioScope такой гонки не было: startTunnel и onDestroy шли
     * по главному потоку и были сериализованы самим Looper'ом. Перенеся запуск
     * в фон, я обязан был добавить явную синхронизацию.
     *
     * ReentrantLock, а не synchronized: нужен tryLock с таймаутом, чтобы
     * onDestroy не висел вечно, если native-вызов действительно завис.
     */
    // @PublishedApi internal — а не private, потому что [withNativeLock]
    // объявлен inline: inline-функция не имеет права обращаться к private-члену
    // ("Public-API inline function cannot access non-public-API").
    @PublishedApi
    internal val nativeLock = java.util.concurrent.locks.ReentrantLock()

    /** Сколько ждём завершения native-операции в onDestroy перед принудительным закрытием. */
    @PublishedApi
    internal val NATIVE_CLOSE_WAIT_MS = 3_000L

    /**
     * Выполняет [block] под [nativeLock].
     *
     * Таймаут на захват нужен, чтобы фоновая джоба не зависла навсегда, если
     * native-вызов встал намертво. При таймауте блок НЕ выполняется — лучше не
     * сделать операцию, чем повиснуть и получить ANR.
     */
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
    // @Volatile: пишется в ioScope (initNative), читается и на главном потоке
    // (onStartCommand проверяет commandServer == null), и в onDestroy.
    @Volatile
    private var commandServer: CommandServer? = null
    // v4.3.2: подписка на журнал ядра (sing-box) — без неё причины
    // «подключено, а трафика нет» не видны нигде.
    private var commandClient: CommandClient? = null
    private val coreLogLock = Any()
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    // v4.6.0: базовая (не VPN) сеть, поверх которой работает туннель, и
    // отложенный перезапуск ядра после её смены. См. onUpstreamChanged().
    @Volatile
    private var upstreamNetwork: Network? = null
    @Volatile
    private var handoverJob: kotlinx.coroutines.Job? = null

    @Volatile
    protected var started = false

    @Volatile
    private var currentServerJson: String? = null

    /**
     * v4.7.1: движок обхода DPI (byedpi в процессе :byedpi).
     * Не null только в режиме MODE_BYPASS, пока туннель поднят.
     */
    @Volatile
    private var byedpiEngine: dev.flicker.vpn.core.ByeDpiEngine? = null

    /**
     * v4.11.0: прошёл ли экземпляр полную инициализацию (ensureInitialized).
     * false у экземпляра, созданного системным контрольным bind'ом: туннеля в
     * этом процессе нет, и stopTunnel()/forceTeardown() здесь обязаны быть
     * no-op — иначе lastResort увидит ЧУЖОЙ (обходный) VPN-интерфейс и убьёт
     * процесс (docs/21).
     */
    protected var initialized = false

    private val watchdog = object : Runnable {
        override fun run() {
            // БЫЛО: postDelayed вызывался безусловно, то есть Handler будил
            // процесс каждые 15 минут даже когда туннель выключен, и так
            // всё время жизни сервиса. Теперь переставляем только пока
            // туннель действительно поднят.
            if (!started) return
            runWatchdog()
            mainHandler.postDelayed(this, WATCHDOG_INTERVAL_MS)
        }
    }

    // ---------- жизненный цикл ----------

    override fun onCreate() {
        super.onCreate()
        instance = this
        // v4.11.0: инициализация ВЫНЕСЕНА в ensureInitialized() и вызывается из
        // onStartCommand при запросах старта/возобновления (docs/21).
        //
        // ПРИЧИНА: onCreate вызывается не только на наш старт, но и на
        // системный контрольный bind (действие android.net.VpnService, которым
        // система держит callback для onRevoke). Во время работы обхода такой
        // bind приходит в ЭТОТ (основной) процесс: прежний onCreate немедленно
        // ставил foreground-уведомление и тянул 64 МБ ядра в процесс, которому
        // оно не нужно, — ровно то, от чего FlickerApp бережёт вспомогательные
        // процессы. Теперь bind-экземпляр остаётся инертным (initialized=false),
        // а весь прежний порядок «сначала startForeground, потом ядро»
        // сохранён в ensureInitialized() без изменений.
    }

    /**
     * v4.11.0: полная инициализация при первом запросе старта/возобновления.
     * Тело onCreate образца 4.10.x, включая комментарий про «startForeground
     * ОБЯЗАН идти первым» — он по-прежнему актуален и перенесён сюда.
     */
    private fun ensureInitialized() {
        if (initialized) return
        initialized = true

        // startForeground() ОБЯЗАН идти ПЕРВЫМ, до любой другой работы.
        //
        // БЫЛО (до 4.10.x включительно): сначала Libbox.newCommandServer() +
        // server.start() + Mobile.setSocketProtector() (три native-вызова), и
        // только потом startForegroundNotif(). Это ломается двумя способами,
        // и оба выглядят одинаково — приложение закрывается без диалога:
        //
        //  1. ContextCompat.startForegroundService() обязывает вызвать
        //     startForeground() в течение ~5 секунд. Если native-инициализация
        //     зависнет или окажется медленной, система кидает
        //     ForegroundServiceDidNotStartInTimeException и УБИВАЕТ процесс.
        //     Диалога при этом нет.
        //
        //  2. Если native-вызов вообще упадёт (Go-паника в c-shared библиотеке
        //     = abort() = SIGABRT), startForegroundNotif() не выполнится
        //     никогда. Сервис так и не станет foreground, и система добьёт
        //     процесс по тому же таймауту.
        //
        // Поэтому: сначала становимся foreground, потом всё остальное.
        startForegroundNotif(getString(R.string.notif_starting))

        if (!FlickerApp.nativeReady) {
            Log.e(FlickerApp.TAG, "нативная библиотека не готова — туннель не запускается")
            // stopSelf() после startForeground() безопасен: ограничение
            // «успеть за 5 секунд» уже выполнено.
            stopSelf()
            return
        }

        // Native-инициализация — в фоне. CommandServer.start() поднимает
        // управляющий сокет, это не мгновенно, а блокировка главного потока
        // даёт ANR (и тоже убийство процесса без внятной причины).
        ioScope.launch {
            val ok = initNative()
            withContext(Dispatchers.Main) {
                if (!ok) {
                    broadcastState(false, getString(R.string.err_native_missing))
                    stopSelf()
                    return@withContext
                }
                mainHandler.postDelayed(watchdog, WATCHDOG_INTERVAL_MS)
                // Если подключение уже запрошено, пока шла инициализация,
                // запускаем туннель теперь.
                pendingServerJson?.let { json ->
                    pendingServerJson = null
                    startTunnel(json)
                }
            }
        }
    }

    /**
     * Инициализация нативной части. Вызывается из [ioScope], не с главного потока.
     * @return true, если CommandServer готов к работе
     */
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
            // v4.3.2: читаем журнал ядра. sing-box логирует точную причину
            // каждого отказа (dial timeout / TLS error / connection reset) —
            // раньше эти строки выбрасывались, и «зелёный узел не пускает
            // трафик» было невозможно диагностировать без adb.
            try {
                val opts = CommandClientOptions()
                opts.addCommand(Libbox.CommandLog)
                // v4.6.0: ВТОРАЯ команда — статусы ядра. Даёт uplink/downlink,
                // накопительные итоги и количество входящих/исходящих соединений
                // каждые STATUS_INTERVAL_MS. Это и есть пассивная детекция
                // мёртвого узла (см. writeStatus ниже).
                //
                // Стоимость: один маленький IPC раз в 2 секунды, собственного
                // сетевого трафика не создаёт вовсе — в отличие от трёх
                // TLS-рукопожатий активной самопроверки.
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
        } catch (e: Throwable) {   // Throwable: Libbox — native, кидает Error
            Log.e(FlickerApp.TAG, "CommandServer", e)
            CrashLog.note(this, "CommandServer.start() не удался: ${e.javaClass.simpleName}: ${e.message}")
            return false
        }
        // protect(fd) для Go-проб. Без него проверки зацикливаются в собственный
        // туннель. Обёрнуто: native-вызов, при неготовом ядре — UnsatisfiedLinkError.
        Native.run("setSocketProtector") { Mobile.setSocketProtector(this) }
        return true
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // v4.11.0: инертный экземпляр (создан системным контрольным bind'ом,
        // туннеля в этом процессе нет). Запросы стопа/паузы адресованы НЕ нам —
        // пересылаем их в процесс, где живёт туннель, и самоуничтожаемся.
        // stopSelf() без startForeground() безопасен: остановка сервиса снимает
        // обязательство «успеть startForeground за 5 секунд» (docs/21).
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
            ACTION_DISCONNECT -> {
                // stopSelf() внутри, ПОСЛЕ closeNative() — см. stopTunnel(andStop)
                stopTunnel(andStop = true)
            }

            ACTION_PAUSE -> {
                // v4.3.3: «пауза» — теперь ПОЛНАЯ остановка сервиса.
                //
                // БЫЛО: туннель закрывался, но сервис оставался живым, и
                // Android продолжал считать VPN активным: ключик в статусбаре
                // висел, а ВЕСЬ трафик телефона шёл в мёртвый VPN-интерфейс
                // (чёрная дыра). Это и есть симптом «отключился, а ключик
                // висит и жрёт трафик».
                //
                // СТАЛО: stopTunnel(andStop=true) полностью освобождает
                // системный VPN — ключик гаснет, телефон сразу на прямом
                // интернете. «Возобновить» из уведомления перезапускает
                // сервис на том же узле; диалог согласия VPN система помнит,
                // повторно он не появляется.
                Log.i(FlickerApp.TAG, "пауза: полная остановка сервиса, VPN освобождается")
                val pauseJson = currentServerJson ?: Repository.selectedServerJson()
                // v4.8.1: в режиме обхода currentServerJson == BYPASS_NO_SERVER,
                // и JSONObject на нём бросает → setSelectedId(null) стирал выбор
                // узла. При возврате в VPN-режим приходилось выбирать заново.
                if (pauseJson != null && !isBypass(pauseJson)) {
                    Repository.setSelectedId(
                        try { JSONObject(pauseJson).optString("id") } catch (_: Throwable) { null }
                    )
                }
                stopTunnel(andStop = true)
                // Уведомление «пауза» ставим ПОСЛЕ остановки — оно обычное
                // (не foreground), переживёт stopSelf и даст кнопки
                // «Возобновить» / «Отключить».
                Notifications.notify(this, Notifications.PAUSE_ID, Notifications.buildPause(this))
            }

            ACTION_RESUME -> {
                Log.i(FlickerApp.TAG, "возобновление туннеля")
                Notifications.cancel(this, Notifications.PAUSE_ID)
                // v4.8.1: в режиме обхода узла нет — «возобновить» из
                // уведомления раньше падало на err_no_server.
                val bypass = dev.flicker.vpn.util.Prefs.mode(this) ==
                    dev.flicker.vpn.util.Prefs.MODE_BYPASS
                val json = currentServerJson
                    ?: if (bypass) BYPASS_NO_SERVER else Repository.selectedServerJson()
                if (json == null) {
                    broadcastState(false, getString(R.string.err_no_server))
                    stopSelf()
                } else {
                    // v4.3.3: после паузы сервис поднимается «холодным»
                    // (пауза теперь останавливает его полностью).
                    // v4.11.0: «холодным» в буквальном смысле — инициализация
                    // в этом процессе ещё не шла (ленивая, docs/21), поэтому
                    // ensureInitialized() стартует её сейчас, а туннель
                    // поднимет колбэк initNative() через pendingServerJson.
                    // v4.12.0: обход DPI — через хук startBypassTunnel():
                    // в BypassVpnService это путь эталона ByeByeDPI-x-tg
                    // (byedpi + hev-socks5-tunnel) БЕЗ инициализации Go-ядра.
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
                // v4.7.1: в режиме «Обход DPI» внешнего сервера нет ВООБЩЕ —
                // трафик идёт напрямую, только с искажением пакетов. Требовать
                // выбранный узел здесь нельзя: иначе подключение невозможно.
                val bypass = dev.flicker.vpn.util.Prefs.mode(this) ==
                    dev.flicker.vpn.util.Prefs.MODE_BYPASS
                val serverJson = if (bypass) BYPASS_NO_SERVER
                    else intent?.getStringExtra(EXTRA_SERVER) ?: Repository.selectedServerJson()
                if (serverJson == null) {
                    broadcastState(false, getString(R.string.err_no_server))
                    stopSelf()
                } else if (bypass) {
                    // v4.12.0: обход DPI — через хук. BypassVpnService поднимает
                    // эталонный стек ByeByeDPI-x-tg (byedpi SOCKS5 + tun2socks
                    // hev-socks5-tunnel) без Go-ядра; базовая реализация ниже —
                    // прежний путь через sing-box (сохранён как запасной).
                    startBypassTunnel(serverJson)
                } else if (commandServer == null) {
                    // Инициализация ядра ещё идёт (она в ioScope). Запоминаем
                    // запрос — initNative() запустит туннель по завершении.
                    // БЫЛО: startTunnel() вызывался сразу и падал на
                    // «CommandServer не инициализирован».
                    // v4.11.0: если процесс поднят этим же запросом,
                    // инициализация стартует сейчас (ленивая, docs/21).
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

        // v4.6.0: отложенный перезапуск ядра по handover обязан быть снят до
        // отмены скоупа — иначе он может попытаться поднять туннель на
        // уничтожаемом сервисе.
        handoverJob?.cancel()
        handoverJob = null
        upstreamNetwork = null

        // v4.6.0: следы, которые иначе теряются вместе с процессом. Именно по
        // ним в отчёте можно отличить «узел мёртв» от «protect() не сработал и
        // получилась петля» и от «туннель вообще не выдавался».
        CrashLog.note(
            this,
            "onDestroy: tunFd=$tunFdNumber, tunActive=${tunActive.get()}, " +
                "выдач туннеля=${tunHandedOut.get()}, " +
                "protect-отказов ядра=$coreProtectFails, проб=$probeProtectFails, " +
                "пик connectionsIn=$peakConnsIn, downlinkTotal=$lastDownlinkTotal, " +
                "последний трафик ${android.os.SystemClock.elapsedRealtime() - lastTrafficAt} мс назад"
        )
        // v4.7.0: tunFdNumber БОЛЬШЕ НЕ СБРАСЫВАЕТСЯ ЗДЕСЬ. Он нужен
        // closeTunFdForced() — и страховке последнего рубежа, которая может
        // сработать позже. Обнуление здесь означало бы, что принудительно
        // закрывать уже нечего, и ключик остаётся висеть.

        // v4.7.0: страховка ДО блокирующих вызовов. Ниже идёт
        // nativeLock.tryLock(3 с) и closeService() на ГЛАВНОМ потоке; если
        // closeService() зависнет, главный поток встанет, ANR, и до штатного
        // завершения onDestroy дело не дойдёт. Отдельный поток не зависит от
        // этого и снимет туннель в любом случае.
        startLastResort("onDestroy")

        // 1. Сначала просим фоновые джобы остановиться. Отмена НЕ прерывает
        //    идущий native-вызов (cancellation кооперативный, а мы внутри JNI),
        //    поэтому дальше ждём освобождения nativeLock.
        ioScope.cancel()

        // 2. Ждём, пока завершится текущая native-операция. Без этого
        //    close() попадёт в середину startOrReloadService() — use-after-free
        //    в нативной памяти, SIGSEGV, смерть процесса без диалога.
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
            // ВАЖНО: onCreate() делает ранний return при !nativeReady, но onDestroy()
            // вызывается всё равно (из-за stopSelf()). Прямой native-вызов здесь
            // давал UnsatisfiedLinkError при уничтожении сервиса — краш на выходе.
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
        // Штатное завершение — снимаем маркер. Если он останется, при следующем
        // запуске приложение сообщит «прошлый запуск завершился аварийно».
        // Именно так мы отличаем нативный крах (маркер остался) от нормального
        // выхода (маркер снят).
        // v4.7.0: onDestroy отработал, а туннель всё ещё жив — значит
        // closeService() либо бросил исключение, либо не был вызван (не достался
        // nativeLock). Закрываем fd немедленно, не дожидаясь 15-секундной
        // страховки: интерфейс VPN должен исчезнуть вместе с сервисом.
        // v4.7.1: проверяем результат, а не флаг (см. isAnyVpnUp).
        // v4.12.0: guard initialized — инертный экземпляр (системный
        // контрольный bind) НЕ должен делать forceTeardown: настоящий туннель
        // может жить в :bypass (или быть поднят другим экземпляром), а
        // forceTeardown при «VPN ещё поднят» убивает ЭТОТ процесс. Раньше это
        // грозило смертью основного процесса с UI при работающем обходе.
        if (initialized && isAnyVpnUp()) {
            forceTeardown("onDestroy: VPN-интерфейс не снялся")
        }

        CrashLog.markCleanExit(this)
        Repository.setConnected(false, "")
        broadcastState(false, null)
        super.onDestroy()
    }

    override fun onRevoke() {
        // v4.10.4: отзыв виден в отчёте. Перехват согласия чужим приложением
        // (или always-on) приходит сюда, а со стороны выглядел как молчаливый
        // «establish() вернул null» на следующей попытке старта.
        CrashLog.note(this, "onRevoke: VPN отозван системой (переключатель в настройках или другое VPN-приложение)")
        // v4.11.0: контрольный bind системы во время работы обхода приходит в
        // основной процесс, где экземпляр инертен. Остановка там была бы
        // no-op'ом, а настоящий туннель живёт в :bypass — пересылаем стоп туда
        // (docs/21).
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
            // Порядок тот же, что в ACTION_DISCONNECT: сначала closeNative(),
            // потом stopSelf() — иначе гонка на закрытии CommandServer.
            stopTunnel(andStop = true)
        }
        // пользователь выключил VPN системным переключателем
        // v4.6.0: сбрасываем автозапуск. Intra делает ровно это:
        //   onRevoke() { stopSelf(); PersistentState.setVpnEnabled(this, false); }
        //   // "Disable autostart if VPN permission is revoked."
        // Без сброса Prefs.autoStart остаётся true, и после перезагрузки
        // BootReceiver.restartIfWasEnabled() поднимает туннель заново — хотя
        // пользователь его только что выключил системным переключателем.
        // Со стороны это выглядит как «приложение не отключается».
        try {
            if (dev.flicker.vpn.util.Prefs.autoStart(this)) {
                dev.flicker.vpn.util.Prefs.setAutoStart(this, false)
                CrashLog.note(this, "onRevoke: автозапуск снят (VPN отозван системным переключателем)")
            }
        } catch (t: Throwable) {
            Log.w(FlickerApp.TAG, "onRevoke: не снять автозапуск", t)
        }
    }

    /**
     * Пользователь смахнул приложение из «недавних».
     *
     * Без этого метода поведение зависит от прошивки: чистый Android сервис
     * оставляет, а MIUI/EMUI/ColorOS убивают процесс вместе с задачей —
     * туннель рвётся молча, и уведомление может остаться висеть.
     *
     * Здесь туннель СОЗНАТЕЛЬНО сохраняем: у VPN-клиента смахивание из
     * «недавних» не означает «выключить VPN», пользователь ждёт обратного.
     * Но уведомление обновляем, чтобы было видно, что мы живы.
     *
     * Если понадобится обратное поведение (смахнул = выключил), заменить тело
     * на stopTunnel(); stopSelf().
     */
    override fun onTaskRemoved(rootIntent: Intent?) {
        Log.i(FlickerApp.TAG, "onTaskRemoved: туннель сохраняем, приложение закрыто")
        if (started) {
            startForegroundNotif(
                getString(R.string.notif_connected, Repository.selectedServer()?.name ?: "")
            )
        }
        super.onTaskRemoved(rootIntent)
    }

    // ---------- туннель ----------

    /**
     * Запуск туннеля.
     *
     * Тяжёлая часть (buildTunConfig + startOrReloadService) выполняется в
     * [ioScope]: startOrReloadService() поднимает весь стек sing-box —
     * парсит конфиг, создаёт outbound'ы, открывает TUN. Это сотни миллисекунд
     * и больше, а на главном потоке блокировка дольше 5 секунд даёт ANR,
     * после чего система убивает процесс.
     */
    private fun startTunnel(serverJson: String, auto: Boolean = false) {
        if (!auto) {
            // ручное подключение — новая сессия, история авторотации сброшена.
            // v4.6.0: под synchronized — handleDeadNode() теперь вызывается и из
            // ioScope, и из mainHandler, а set не потокобезопасен.
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
                    // v4.7.1: в режиме обхода узла нет — не затираем выбор
                    // пользователя, иначе при возврате в VPN-режим придётся
                    // выбирать заново.
                    if (!isBypass(serverJson)) {
                        Repository.setSelectedId(
                            try { JSONObject(serverJson).optString("id") } catch (e: Exception) { null }
                        )
                    }
                    Repository.setConnected(true, name)
                    startForegroundNotif(getString(R.string.notif_connected, name))
                    broadcastState(true, null, name)
                    // v4.6.0: обнуляем счётчики пассивного детектора — иначе
                    // итоги от предыдущего узла дадут ложное «трафик есть».
                    resetStallDetector()
                    // v4.2.1: через 7 секунд сами проверим, несёт ли узел трафик
                    scheduleNodeLivenessCheck()
                }.onFailure { e ->
                    Log.e(FlickerApp.TAG, "startTunnel", e)
                    CrashLog.note(this@TunnelService,
                        "startTunnel: ${e.javaClass.simpleName}: ${e.message}")
                    // v4.12.1: ошибка старта кандидата — НЕ конец перебора.
                    // Раньше здесь был голый stopSelf(), и цикл автопереключения
                    // обрывался, хотя живые кандидаты ещё были.
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

    /**
     * Собственно запуск: конфиг -> миграция -> ядро.
     * Выполняется в [ioScope]. Возвращает имя узла для уведомления.
     */
    private suspend fun buildAndStart(serverJson: String): String {
        // v4.7.1: режим «Обход DPI» — совершенно другой путь. Ни сервера, ни
        // подписки, ни миграции конфига: TUN → sing-box → SOCKS5 (byedpi) →
        // прямой интернет.
        if (isBypass(serverJson)) return buildAndStartBypass()

        val name = try {
            JSONObject(serverJson).optString("name")
        } catch (e: Exception) {
            ""
        }
        // Конфиг правится МИГРАЦИЕЙ перед передачей в ядро: libflickerbox.so
        // собрана со старым генератором, который пишет dns.servers[].address
        // и sniff на tun-inbound, а sing-box v1.14.2 их отвергает. Без миграции
        // подключение падало на ЛЮБОМ узле.
        val rawConfig = Mobile.buildTunConfig(serverJson, Repository.tunParamsJson())
        // v4.5.0: файл журнала ядра. Пустой «ЖУРНАЛ ЯДРА» в отчёте пользователя
        // означал полную слепоту: sing-box пишет точную причину каждого отказа
        // («dial tcp …: i/o timeout», «DNS query loopback in transport[doh]»),
        // но до приложения эти строки не доходили. log.output даёт второй,
        // независимый от CommandClient канал (см. ConfigMigrate.applyCoreLog).
        val coreLogFile = java.io.File(Native.workingDir(this), CORE_FILE_LOG)
        try {
            if (coreLogFile.exists()) coreLogFile.delete()
        } catch (_: Throwable) {
        }
        // v4.0.7: на x86-эмуляторах с ARM-трансляцией (Houdini — BlueStacks и др.)
        // дефолтный gvisor-стек роняет транслятор (SIGABRT в libhoudini.so при
        // старте туннеля). emulatorTunStack() подменяет stack на "system" ТОЛЬКО
        // там; на реальных устройствах конфиг не меняется.
        val migrated = ConfigMigrate.emulatorTunStack(
            ConfigMigrate.migrate(rawConfig, coreLogFile.absolutePath)
        )
        // v4.2.0: режим «Прокси» (метод ByeByeDPI-x-tg) — вместо TUN локальный
        // SOCKS5 на 127.0.0.1:PROXY_PORT; системный VPN не устанавливается.
        val proxyMode = dev.flicker.vpn.util.Prefs.mode(this) == "proxy"
        val config = if (proxyMode) ConfigMigrate.toProxyConfig(migrated, PROXY_PORT) else migrated
        AppState.update(
            AppState.status,
            if (proxyMode) dev.flicker.vpn.data.TunnelMode.Proxy else dev.flicker.vpn.data.TunnelMode.Vpn
        )
        Log.i(FlickerApp.TAG, if (proxyMode) "режим: ПРОКСИ (SOCKS5 127.0.0.1:$PROXY_PORT)" else "режим: VPN-туннель")
        ConfigMigrate.audit(config).forEach { Log.w(FlickerApp.TAG, "конфиг: $it") }
        // v4.0.8: сохраняем конфиг, ушедший в ядро, — при нативном крахе видно,
        // на каком именно sing-box споткнулся (дубль снимка ядра в crash_reports).
        try {
            java.io.File(filesDir, "last-config.json").writeText(config)
        } catch (_: Throwable) {
        }

        val server = commandServer
            ?: throw IllegalStateException("CommandServer не инициализирован")
        // v4.1.0: гасим фоновые пробы живости ПЕРЕД стартом туннеля.
        // В краше на M21 (дамп Go-паники) пробы — сотни параллельных dial'ов,
        // каждый с JNI-колбэком protectFd — шли ОДНОВРЕМЕННО со стартом
        // туннеля и первыми пакетами. Это единственная массовая JNI-нагрузка,
        // которой нет в эталонной SFA. Пробы возобновятся после отключения.
        Native.run("cancelProbe") { Mobile.cancelProbe() }

        // Тяжёлый native-вызов: поднимает весь стек sing-box. Выполняется
        // в ioScope, поэтому главный поток не блокируется и ANR не возникает.
        // Под nativeLock — иначе onDestroy() может закрыть CommandServer прямо
        // во время этого вызова (см. описание nativeLock).
        // Исключения НЕ ловим здесь — их обработает runCatching в startTunnel(),
        // который вернёт ошибку в главный поток и покажет её пользователю.
        withNativeLock("startOrReloadService") {
            server.startOrReloadService(config, OverrideOptions())
        }
        return name
    }

    /**
     * v4.12.0: запуск режима «Обход DPI» — ХУК ТОЧКИ ВХОДА.
     *
     * Вызывается из onStartCommand (новое подключение и «возобновить») вместо
     * ensureInitialized()/startTunnel(), когда Prefs.mode == MODE_BYPASS.
     *
     * Базовая реализация (этот класс) — прежний путь через sing-box:
     * ensureInitialized() → pendingServerJson → startTunnel() →
     * buildAndStartBypass() (BypassConfig → ядро). Сохранена как запасная:
     * через targetClass() обход всегда уходит в [BypassVpnService], а та
     * переопределяет хук портом эталона ByeByeDPI-x-tg: byedpi (JNI, SOCKS5
     * 127.0.0.1:1080) + tun2socks hev-socks5-tunnel на fd из
     * VpnService.Builder.establish(). libflickerbox.so в обходе не участвует.
     */
    protected open fun startBypassTunnel(serverJson: String) {
        if (commandServer == null) {
            Log.i(FlickerApp.TAG, "обход: ядро ещё инициализируется — подключение отложено")
            ensureInitialized()
            pendingServerJson = serverJson
        } else {
            startTunnel(serverJson)
        }
    }

    /**
     * v4.11.0: хук запуска движка обхода (docs/21).
     *
     * По умолчанию — прежняя схема: отдельный процесс :byedpi, обмен через
     * Messenger ([dev.flicker.vpn.core.ByeDpiEngine]). В [BypassVpnService]
     * переопределён: движок крутится В ТОМ ЖЕ процессе, что и TUN, прямым
     * JNI-вызовом — как в эталоне ByeByeDPI-x-tg, где proxy и VPN-сервис
     * живут вместе в :native и умирают вместе.
     */
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

    /** v4.11.0: парный хук остановки движка. */
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

    /**
     * v4.7.1: запуск в режиме «Обход DPI» — БЕЗ внешнего сервера.
     *
     * Последовательность строгая:
     *   1. поднять byedpi (отдельный процесс :byedpi) и ДОЖДАТЬСЯ, пока его
     *      SOCKS5 ответит на рукопожатие. Конфиг sing-box содержит адрес этого
     *      прокси, поэтому строить его до готовности нельзя;
     *   2. собрать конфиг (BypassConfig) — TUN inbound, socks outbound на
     *      127.0.0.1:BYEDPI_PORT, DoH через тот же outbound;
     *   3. отдать конфиг ядру.
     *
     * Возвращает имя для уведомления («Обход DPI · <пресет>»).
     */
    private suspend fun buildAndStartBypass(): String {
        val presetId = dev.flicker.vpn.util.Prefs.byedpiPreset(this)
        val command = dev.flicker.vpn.util.Prefs.byedpiCommand(this)
        val presetTitle = dev.flicker.vpn.core.ByeDpiArgs.preset(presetId).title
        Log.i(FlickerApp.TAG, "режим: ОБХОД DPI (byedpi, пресет «$presetTitle»)")
        AppState.update(AppState.status, dev.flicker.vpn.data.TunnelMode.Vpn)

        // Старый движок, если остался от прошлой попытки, — остановить: он
        // одноразовый на процесс и держит порт.
        // v4.11.0: через хуки stopByedpi()/startByedpi() — в :bypass движок
        // поднимается в этом же процессе прямым JNI (docs/21).
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
        // Фоновые пробы узлов в этом режиме бессмысленны (узлов нет), а JNI-
        // нагрузка на старте туннеля нам не нужна — тот же вывод, что в 4.1.0.
        Native.run("cancelProbe") { Mobile.cancelProbe() }

        withNativeLock("startOrReloadService") {
            server.startOrReloadService(config, OverrideOptions())
        }
        return "Обход DPI · $presetTitle"
    }

    /**
     * v4.2.1: самопроверка узла сразу после подключения.
     *
     * ПРОБЛЕМА: бесплатный узел может принять соединение (TCP-рукопожатие
     * проходит, приложение рапортует «Подключено»), но НЕ выпускать трафик —
     * backend мёртв. DNS через такой узел не резолвится (UnknownHostException
     * во всех приложениях), и выглядит это как «VPN включён, а интернета нет».
     * Раньше причину было видно только в логах; теперь через 7 секунд после
     * подключения делаем контрольный HTTPS-запрос. Сокеты самого приложения
     * НЕ защищены protect(), поэтому запрос идёт именно через туннель —
     * это честная проверка сквозного пути.
     *
     * Только для VPN-режима: в прокси-режиме собственный трафик приложения
     * мимо прокси, проверка бессмысленна.
     */
    private fun scheduleNodeLivenessCheck() {
        val mode = dev.flicker.vpn.util.Prefs.mode(this)
        // Прокси-режим: собственный трафик мимо прокси, проверка бессмысленна.
        if (mode == "proxy") return
        // v4.7.1: режим обхода DPI — узла нет ВООБЩЕ, переключаться некуда.
        // Живость всё равно контролируется пассивно, по счётчикам ядра
        // (onCoreStatus → CommandStatus), которые работают в любом режиме.
        if (mode == dev.flicker.vpn.util.Prefs.MODE_BYPASS) {
            Log.i(FlickerApp.TAG, "режим обхода DPI: самопроверка узла пропущена (узла нет)")
            return
        }
        ioScope.launch {
            // v4.5.0: было 7 с. Сокращено, чтобы цикл «проверка → смена узла»
            // проходил быстрее: теперь кандидатов много и перебор дешевле.
            kotlinx.coroutines.delay(3500)
            if (!started) return@launch
            val res = probeTargets()
            if (!started) return@launch
            val alive = res.any { it.second.startsWith("HTTP ") }
            val summary = res.joinToString(" · ") { "${it.first}=${it.second}" }
            val deadId = try { JSONObject(currentServerJson ?: "").optString("id") } catch (_: Throwable) { "" }
            val deadName = Repository.selectedServer()?.name ?: deadId.ifEmpty { "?" }

            // v4.6.0: активная проба БОЛЬШЕ НЕ ЕДИНСТВЕННЫЙ судья.
            //
            // Если все три контрольные цели недоступны, но ядро при этом видит
            // РЕАЛЬНЫЙ трафик пользователя (downlinkTotal > 0) — узел жив, и
            // переключаться с него нельзя. Именно эту ошибку v4.5.0 пыталась
            // закрыть, заменив один ipify на три цели (Telegram/Instagram/ipify):
            // узел, который режет контрольные домены, но выпускает нужный
            // пользователю трафик, объявлялся мёртвым, и цикл автопереключения
            // выжигал все 8 попыток впустую.
            //
            // Теперь решение принимается по факту переноса трафика, а не по
            // доступности трёх конкретных сайтов. Это же принцип Intra:
            // состояние WORKING/FAILING выводится из реальных транзакций.
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

    /**
     * v4.6.0: единая точка реакции на мёртвый узел.
     *
     * Вынесено из [scheduleNodeLivenessCheck], потому что теперь смерть узла
     * определяется ДВУМЯ независимыми способами:
     *   1. активная сквозная самопроверка (три HTTPS-цели) — как раньше;
     *   2. пассивный детектор по счётчикам ядра ([onCoreStatus]) — новый.
     * Логика «пометить мёртвым → переключиться → иначе отключиться» должна быть
     * одна, иначе два пути разойдутся.
     *
     * Потокобезопасно: вызывается и из [ioScope], и из [mainHandler].
     *
     * @param note текст для CrashLog и для уведомления (причина).
     */
    private fun handleDeadNode(note: String) {
        val deadId = try {
            JSONObject(currentServerJson ?: "").optString("id")
        } catch (_: Throwable) { "" }
        val deadName = Repository.selectedServer()?.name ?: deadId.ifEmpty { "?" }

        if (deadId.isNotEmpty()) {
            synchronized(sessionDeadNodes) { sessionDeadNodes.add(deadId) }
        }
        CrashLog.note(this, note)

        // v4.6.0: настройка «переподключаться автоматически» наконец-то
        // что-то делает. Раньше Prefs.autoReconnect читался ровно один раз —
        // чтобы нарисовать переключатель в настройках (MainActivity), — и на
        // поведение не влиял вообще.
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

        // v4.7.1: в режиме обхода DPI переключаться некуда — внешнего узла
        // нет. Не жгли попытки и не показывали «живых узлов не осталось»:
        // вместо этого честно говорим, что обход не сработал на этом пресете.
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
            // v4.8.1: туннель НЕ РВЁМ.
            //
            // С узловым режимом это несравнимо: там мёртвый узел — это чёрная
            // дыра, весь трафик телефона уходит в никуда, и отключиться лучше,
            // чем висеть. Здесь же слабый пресет обычно пропускает ЧАСТЬ
            // трафика (ровно то, что наблюдалось: «слабый поток идёт»).
            // Разорвав туннель, мы сделали бы строго хуже — пользователь
            // остался бы вообще без обхода, да ещё и с необходимостью
            // подключаться заново.
            //
            // Плюс в этом режиме некуда переключаться автоматически, поэтому
            // разрыв означал бы просто «выключилось само».
            return
        }

        // v4.3.0: АВТОПЕРЕКЛЮЧЕНИЕ на следующего кандидата — пользователю
        // больше не нужно вручную перебирать мёртвые узлы.
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
        // v4.3.1: ГЛАВНОЕ — не оставляем телефон висеть на мёртвом туннеле.
        // Весь трафик (включая DNS) уходит в чёрную дыру, и телефон фактически
        // остаётся БЕЗ интернета, пока пользователь не отключит VPN вручную.
        // Теперь — автоматическое отключение: телефон возвращается на прямой
        // интернет, а пользователь получает внятное уведомление.
        Notifications.notify(
            this, Notifications.ERROR_ID,
            Notifications.buildError(
                this,
                "Живых узлов не осталось (перебрано $autoSwitchCount) — VPN ОТКЛЮЧЁН, телефон на прямом интернете. Обновите подписки (📥) и подключитесь снова"
            )
        )
        stopTunnel(andStop = true)
    }

    /**
     * v4.6.0: приём статусов ядра (CommandStatus) каждые [STATUS_INTERVAL_MS].
     *
     * ЗАЧЕМ. Активная самопроверка бьёт в три HTTPS-цели и смотрит, ответил ли
     * хоть кто-нибудь. У этого два фундаментальных недостатка, оба видны в
     * отчёте пользователя от 2026-10-13:
     *
     *   * проба зависит от DNS, а DNS идёт через тот же мёртвый узел. Поэтому
     *     5 из 7 провалов выглядели как `UnknownHostException: Unable to
     *     resolve host "api.ipify.org"` — то есть проба не могла отличить
     *     «узел мёртв» от «DNS сломан»;
     *   * узел, который режет ipify/Telegram, но выпускает нужный пользователю
     *     трафик, объявлялся мёртвым (это и описано в release/ИНСТРУКЦИЯ.md).
     *
     * Счётчики ядра лишены обоих недостатков: они показывают, идёт ли РЕАЛЬНЫЙ
     * трафик РЕАЛЬНЫХ приложений. Эталон подхода — Intra, которая выводит
     * состояние WORKING/FAILING из каждого прошедшего запроса
     * (IntraVpnService.recordTransaction), а не из периодических проб.
     *
     * Признак «узел принимает, но не выпускает» (узлы «БЕЛЫЕ СПИСКИ»):
     *     пик connectionsIn > 0  &&  downlinkTotal не растёт STATUS_STALL_MS.
     *
     * Вызывается из JNI-потока libbox, поэтому ничего тяжёлого не делает:
     * только обновляет счётчики и, при необходимости, постит решение на
     * главный поток.
     */
    private fun onCoreStatus(m: StatusMessage) {
        if (!started) return
        // Ядро сообщает, что статистика трафика в этой сборке доступна.
        // Если нет — счётчики всегда нулевые, и детектор сработал бы ложно.
        val trafficAvailable = try { m.trafficAvailable } catch (_: Throwable) { false }
        if (!trafficAvailable) return

        val down = try { m.downlinkTotal.toLong() } catch (_: Throwable) { return }
        val up = try { m.uplinkTotal.toLong() } catch (_: Throwable) { return }
        val connsIn = try { m.connectionsIn.toLong() } catch (_: Throwable) { 0L }
        val now = android.os.SystemClock.elapsedRealtime()

        // v4.7.0: наружу, для карточки состояния в UI.
        statDownlinkTotal = down
        statUplinkTotal = up
        statConnectionsIn = connsIn
        try {
            statDownlink = m.downlink.toLong()
            statUplink = m.uplink.toLong()
        } catch (_: Throwable) {
            // мгновенные скорости не критичны: оставим предыдущие значения
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

        // Трафика нет. Важно: его может не быть просто потому, что пользователь
        // ничего не открыл. Отличаем по входящим соединениям: если приложения
        // к нам ПРИХОДИЛИ (connectionsIn > 0 хотя бы раз за сессию), а вниз
        // ничего не вернулось — это уже не «простаиваем», а «узел не выпускает».
        //
        // Смотрим на ПИК, а не на текущее значение: sing-box закрывает входящие
        // соединения, и connectionsIn штатно падает до нуля между
        // запросами. Сбрасывать таймер на каждом нуле значило бы, что детектор
        // не срабатывает никогда.
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
        // Решение принимаем на главном потоке: handleDeadNode трогает UI-состояние
        // и вызывает startTunnel/stopTunnel, как остальные пути.
        mainHandler.post {
            if (!started) return@post
            handleDeadNode("Пассивный детектор: $summary")
        }
    }

    /** v4.6.0: сброс детектора при каждом новом подключении. */
    private fun resetStallDetector() {
        lastDownlinkTotal = 0L
        lastUplinkTotal = 0L
        lastTrafficAt = android.os.SystemClock.elapsedRealtime()
        stalledSince = 0L
        stallReported = false
        peakConnsIn = 0L
        // v4.7.0: иначе карточка состояния показывает счётчики прошлого узла.
        statUplink = 0L
        statDownlink = 0L
        statUplinkTotal = 0L
        statDownlinkTotal = 0L
        statConnectionsIn = 0L
    }

    /**
     * v4.5.0: контрольные цели самопроверки.
     *
     * ПОЧЕМУ НЕ ОДИН api.ipify.org (как было в 4.2.1—4.4.0):
     * отчёт пользователя от 2026-10-13 показал три РАЗНЫХ исхода на узлах,
     * которые приложение объявило мёртвыми:
     *
     *     09:05:29  SSLHandshakeException: connection closed
     *     09:05:36  ConnectException: Failed to connect to api.ipify.org/104.26.13.205:443
     *     09:07:50  SocketTimeoutException: Read timed out
     *
     * Обратите внимание на 09:05:36: имя api.ipify.org РАЗРЕШИЛОСЬ (в логе
     * виден IP 104.26.13.205) — значит DoH через узел работает, туннель
     * живой. Отказал именно ipify. Часть бесплатных узлов режет «чужие»
     * цели, но выпускает Telegram/Instagram — а пользователю нужны ровно они.
     * Проверяя один ipify, мы объявляли мёртвыми узлы, на которых Telegram
     * работал, и цикл автопереключения выжигал все попытки впустую.
     *
     * Теперь целей три, они опрашиваются ПАРАЛЛЕЛЬНО, и узел считается
     * живым, если ОТВЕТИЛ ХОТЯ БЫ ОДИН (любой HTTP-код — даже 403/404:
     * это значит, что узел донёс запрос и вернул ответ).
     */
    private suspend fun probeTargets(): List<Pair<String, String>> = coroutineScope {
        CHECK_TARGETS.map { (name, url) ->
            async(Dispatchers.IO) { name to checkOne(url) }
        }.awaitAll()
    }

    /** Один контрольный HTTPS-запрос через туннель. Никогда не бросает. */
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

    /**
     * Нативная часть остановки. Вызывается из [ioScope].
     *
     * Под [nativeLock]: closeService() не должен попасть в середину
     * startOrReloadService(), иначе use-after-free в нативной памяти.
     * Идемпотентна: повторный вызов безопасен, исключение глушится.
     */
    /** v4.3.2: приём журнала ядра; пишем в box/core.log (ротация по размеру). */
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
            // v4.6.0: было `{}` — статистика ядра приходила и выбрасывалась.
            try {
                if (message != null) onCoreStatus(message)
            } catch (t: Throwable) {
                // Колбэк идёт из Go через JNI: любое улетевшее обратно
                // исключение превращается в Go-панику → abort() → SIGABRT.
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
            // журнал — best effort, на туннель влиять не должен
        }
        // v4.10.1: заодно держим в рамках файл, который ядро пишет САМО
        // (log.output). Вызов здесь, а не в watchdog, потому что watchdog
        // приходит раз в 15 минут — за это время файл успевает вырасти
        // на десятки мегабайт, а appendCoreLog дёргается на каждой пачке
        // строк журнала. Проверка размера — это один stat(), дёшево.
        trimCoreFileLog()
    }

    /**
     * v4.10.1: обрезка `box/core-file.log` по размеру. Причины и почему это
     * безопасно — в комментарии к [CORE_FILE_LOG_MAX].
     *
     * Хвост сохраняем (а не обнуляем файл), чтобы в отчёте оставались строки
     * запуска туннеля: [CrashLog] берёт из этого файла последние 12 000
     * символов, и обнуление оставило бы отчёт пустым ровно тогда, когда
     * что-то пошло не так.
     */
    private fun trimCoreFileLog() {
        try {
            val f = java.io.File(Native.workingDir(this), CORE_FILE_LOG)
            if (!f.exists() || f.length() <= CORE_FILE_LOG_MAX) return
            val before = f.length()
            synchronized(coreLogLock) {
                // между первой проверкой и входом под блокировку файл мог
                // подрезать другой поток — не переписываем второй раз
                if (f.length() <= CORE_FILE_LOG_MAX) return
                // Читаем НЕ весь файл: до появления этой обрезки он успевал
                // вырасти до десятков мегабайт, и readText() целиком на потоке
                // колбэка ядра — это риск OOM/ANR. Берём ровно столько байт
                // с конца, сколько собираемся оставить (плюс запас на неполную
                // первую строку, которую выбрасываем).
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
                    // первую строку — возможно неполную — выбрасываем
                    val nl = s.indexOf('\n')
                    if (nl in 0 until s.length - 1) s.substring(nl + 1) else s
                }
                // writeText() truncates + пишет: у ядра fd открыт с O_APPEND
                // (log/observable.go:79), поэтому его следующая дозапись
                // встанет в новый конец файла, «дыр» не появится.
                f.writeText(tail)
            }
            Log.i(
                FlickerApp.TAG,
                "core-file.log обрезан: $before → ${f.length()} байт (потолок $CORE_FILE_LOG_MAX)"
            )
        } catch (t: Throwable) {
            // журнал — best effort, на туннель влиять не должен
            Log.w(FlickerApp.TAG, "trimCoreFileLog", t)
        }
    }

    /**
     * v4.7.1: поднят ли в системе ХОТЬ КАКОЙ-ТО VPN-интерфейс.
     *
     * ЗАЧЕМ ЭТО НУЖНО И ПОЧЕМУ НЕ ФЛАГ.
     *
     * Прежняя схема (4.7.0) решала, закрывать ли fd и убивать ли процесс, по
     * флагу tunActive: он снимался, как только closeService() возвращался без
     * исключения. Проверка на реальном телефоне (Galaxy M21, Android 12)
     * показала, что этого НЕДОСТАТОЧНО: штатное «Отключить» ключик не снимает,
     * а «Экстренно выключить» (принудительное закрытие fd; v4.12.1 без killProcess) —
     * снимает. Значит closeService() у нас возвращается, а интерфейс VPN
     * остаётся поднятым.
     *
     * Вывод: судить надо не по внутреннему флагу и не по возвращаемому
     * значению, а по РЕЗУЛЬТАТУ — видит ли система VPN-сеть. Это единственный
     * признак, напрямую связанный с ключиком: ключик рисуется именно потому,
     * что VPN-интерфейс существует.
     *
     * Оговорка: метод не отличает НАШ VPN от чужого. На практике не важно —
     * в Android активен один VPN, и если мы только что отключались, а VPN-сеть
     * на месте, значит это наша.
     */
    private fun isAnyVpnUp(): Boolean {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return false
        return try {
            cm.allNetworks.any { n ->
                cm.getNetworkCapabilities(n)
                    ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            }
        } catch (t: Throwable) {
            Log.w(FlickerApp.TAG, "isAnyVpnUp", t)
            // v4.12.1: не смогли определить состояние VPN — считаем, что он СНЯТ.
            // Раньше здесь возвращалось true, и это вело к убийству процесса
            // (см. stopTunnel). «Неизвестно» — не основание что-либо убивать.
            CrashLog.note(this, "isAnyVpnUp: не удалось определить состояние VPN — принято false")
            false
        }
    }

    /**
     * v4.7.1: гарантированное снятие туннеля.
     *
     * Последовательность: принудительно закрыть fd → дать системе [SETTLE_MS]
     * на снятие интерфейса → ПРОВЕРИТЬ, снялся ли.
     *
     * v4.12.1: процесс НЕ убиваем. Если интерфейс не снялся — возвращаем true
     * и пишем в CrashLog; пользователь видит уведомление, а не «вылет».
     *
     * @return true, если интерфейс не снялся после закрытия fd.
     */
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
        // v4.12.1: интерфейс не снялся после закрытия fd. Процесс НЕ убиваем:
        // возвращаем true (принудительное снятие не удалось), а вызывающий код
        // показывает пользователю уведомление вместо вылета.
        Log.e(FlickerApp.TAG, "$where: VPN-интерфейс ВСЁ ЕЩЁ поднят после закрытия fd — процесс сохранён, нужен перезапуск приложения")
        CrashLog.note(this, "$where: VPN-интерфейс не снялся после закрытия fd — процесс сохранён")
        return true
    }

    private fun closeNative() {
        withNativeLock("stopTunnel") {
            try {
                commandServer?.closeService()
                // v4.7.0: штатный путь — ядро закрыло fd туннеля само
                // (именно для этого openTun() и отдаёт владение через
                // detachFd()). Снимаем флаг, чтобы страховка не закрывала fd
                // повторно.
                tunActive.set(false)
            } catch (e: Throwable) {   // Throwable: native-вызов
                Log.w(FlickerApp.TAG, "closeService", e)
                // Флаг НЕ снимаем: раз closeService бросил, состояние fd
                // неизвестно, и пусть страховка отработает принудительно.
            }
        }
        // withNativeLock мог не получить замок (таймаут 3 с) и вообще не
        // вызвать блок. Тогда closeService не выполнялся — tunActive остаётся
        // true, и это правильно: страховка закроет fd и убьёт процесс.
    }

    /**
     * v4.7.0: принудительно закрыть fd туннеля из Java. Путь А.
     *
     * ВЫЗЫВАЕТСЯ ТОЛЬКО КОГДА МЫ ЗНАЕМ, ЧТО ЯДРО fd НЕ ЗАКРЫЛО — то есть
     * closeService() завис (stuck == true), бросил исключение или не был
     * вызван вовсе. В этот момент номер дескриптора всё ещё наш и валидный,
     * поэтому закрытие безопасно.
     *
     * Почему нельзя закрывать безусловно: openTun() делает detachFd(), то есть
     * отдаёт владение libbox. Если ядро уже закрыло fd, номер мог быть
     * переиспользован другим open() — и мы закрыли бы чужой дескриптор.
     * Отсюда и условие: только при подтверждённом зависании, ровно как
     * предложено в разборе (Путь А, «компромисс: закрывать fd только если
     * closeService() не завершился за таймаут»).
     *
     * Идемпотентно через tunActive.compareAndSet.
     *
     * @return true, если fd действительно закрыт этим вызовом.
     */
    private fun closeTunFdForced(where: String): Boolean {
        if (!tunActive.compareAndSet(true, false)) return false
        val fd = tunFdNumber
        if (fd < 0) return false
        // v4.8.1: ИСПРАВЛЕНА ОШИБКА КОМПИЛЯЦИИ.
        //
        // Было `android.system.Os.close(fd)` с Int. Правильная сигнатура —
        // Os.close(FileDescriptor): передать номер дескриптора напрямую нельзя.
        //
        // Два способа, публичный первым:
        //
        // (1) ParcelFileDescriptor.adoptFd(fd).close() — ПУБЛИЧНОЕ API с
        //     Android 1.0. adoptFd забирает владение готовым номером fd, а
        //     close() вызывает под ним close(2). Метод создан ровно для этого:
        //     «есть сырой номер, полученный из detachFd(), надо его закрыть».
        //
        // (2) Запасной путь — FileDescriptor через рефлексию. Работает, но поле
        //     java.io.FileDescriptor#descriptor скрытое: с Android 9 на таких
        //     полях ограничения (сейчас категория «unsupported» — работает с
        //     предупреждением в logcat, но Google может закрыть её в следующей
        //     версии). Поэтому держим только как fallback.
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

    /**
     * v4.7.0: страховка последнего рубежа.
     *
     * Отдельный поток, который НЕ зависит ни от ioScope (может быть отменён),
     * ни от Dispatchers.Main (может быть заблокирован), ни от успеха
     * closeNative(). Если через [HARD_STOP_DEADLINE_MS] туннель всё ещё жив —
     * закрываем fd и убиваем процесс.
     *
     * Зачем нужно: v4.12.1 killProcess из stopTunnel убран, остаётся только
     * внутри withContext(Dispatchers.Main). Достаточно заблокированного
     * главного потока (ANR) или отменённого скоупа — и до него не доходит.
     * Симптом у пользователя ровно этот: «не отключается, висит в трее и жрёт
     * трафик, помогает только переустановка».
     */
    private fun startLastResort(where: String) {
        val t = Thread {
            try {
                Thread.sleep(HARD_STOP_DEADLINE_MS)
            } catch (_: InterruptedException) {
                return@Thread
            }
            // v4.7.1: проверяем не внутренний флаг, а реальность. Флаг может
            // быть снят (closeService() вернулся), а интерфейс — остаться.
            if (!isAnyVpnUp()) return@Thread       // VPN действительно снят
            Log.e(FlickerApp.TAG, "$where: туннель всё ещё жив через ${HARD_STOP_DEADLINE_MS}мс — снимаю принудительно")
            CrashLog.note(this, "$where: LAST RESORT — туннель не снят за ${HARD_STOP_DEADLINE_MS}мс")
            // v4.7.1: единый путь — закрыли fd, проверили результат, убили
            // процесс только если интерфейс так и не снялся.
            forceTeardown("$where/last-resort")
        }
        t.isDaemon = true
        t.name = "vpn-last-resort"
        t.start()
    }

    /**
     * Остановка туннеля.
     *
     * native-часть — в [ioScope], обновление состояния — на главном потоке.
     *
     * БЫЛО: всё синхронно на главном. После введения [nativeLock] с ожиданием
     * до 3 секунд это давало подморозку UI при нажатии «Отключить»/«Пауза»:
     * главный поток стоял бы в tryLock, пока фоновый startOrReloadService()
     * не освободит замок.
     *
     * @param andStop если true — после native-остановки вызывается stopSelf().
     *   Именно ПОСЛЕ, а не до: иначе onDestroy() начнёт закрывать CommandServer
     *   одновременно с остановкой туннеля.
     */
    protected open fun stopTunnel(andStop: Boolean = false) {
        // v4.11.0: инертный экземпляр (контрольный bind, туннеля в этом
        // процессе нет). Без этого guard'а startLastResort() ниже увидел бы
        // через isAnyVpnUp() ЧУЖОЙ VPN-интерфейс (обход в :bypass) и убил бы
        // этот процесс — ровно та «занятость», с которой воюем (docs/21).
        if (!initialized) {
            Log.i(FlickerApp.TAG, "stopTunnel: экземпляр инертен, туннель не в этом процессе")
            return
        }
        // Состояние сбрасываем СИНХРОННО, до запуска корутины.
        //
        // Это не косметика: вызывающий код читает started сразу после
        // stopTunnel(). В ACTION_PAUSE за ним идёт publishState(), который
        // делает `val connected = started`. Если сбрасывать в корутине
        // (withContext(Dispatchers.Main) отрабатывает ПОСЛЕ текущего блока
        // главного потока), publishState() увидит started == true и
        // опубликует Connected вместо остановки. Плитка и UI залипнут
        // в «подключено» при выключенном туннеле.
        started = false
        currentServerJson = null

        // v4.6.0: гасим отложенный перезапуск ядра по handover. Иначе он может
        // поднять туннель заново уже ПОСЛЕ остановки — со стороны это выглядит
        // как «выключил, а он сам включился».
        handoverJob?.cancel()
        handoverJob = null
        resetStallDetector()

        // v4.7.1: движок обхода DPI останавливается вместе с туннелем.
        // v4.11.0: через хук stopByedpi(): в основном процессе он убивает
        // :byedpi через Messenger, в :bypass — останавливает прямой JNI-движок
        // (процесс всё равно умрёт в onDestroy, docs/21).
        stopByedpi()

        // v4.1.3: при полном отключении убираем уведомление и foreground
        // СРАЗУ. Пользователь обязан видеть результат нажатия «Отключить»
        // мгновенно, даже если нативная остановка ниже зависнет.
        if (andStop) {
            Notifications.cancel(this, NOTIF_ID)
            Notifications.cancel(this, Notifications.PAUSE_ID)
            try {
                ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
            } catch (t: Throwable) {
                Log.w(FlickerApp.TAG, "stopForeground", t)
            }
        }

        // v4.6.0: ЕСЛИ ioScope УЖЕ ОТМЕНЁН, launch молча не запускает тело —
        // и stopSelf() не выполняется НИКОГДА. Такое возможно, когда stopTunnel()
        // вызывается после onDestroy() (отложенный колбэк, гонка). Последствие
        // ровно то, что чиним: сервис жив, fd туннеля не закрыт, ключик висит.
        // Берём одноразовый аварийный скоуп — остановка обязана завершиться.
        // v4.7.0: страховка последнего рубежа СТАРТУЕТ ДО всего остального и
        // живёт в собственном потоке. Если зависнет closeNative(), или
        // отменится скоуп, или встанет главный поток — через
        // HARD_STOP_DEADLINE_MS туннель всё равно будет снят.
        if (andStop) startLastResort("stopTunnel")

        val stopScope = if (ioScope.isActive) {
            ioScope
        } else {
            Log.w(FlickerApp.TAG, "stopTunnel: ioScope отменён — останавливаюсь в аварийном скоупе")
            CrashLog.note(this, "stopTunnel при отменённом ioScope — использован аварийный скоуп")
            CoroutineScope(SupervisorJob() + Dispatchers.IO)
        }
        stopScope.launch {
            // v4.1.3: нативная остановка — на отдельном потоке с ЖЁСТКИМ
            // дедлайном. closeService() разбирает gvisor/tun и на живых
            // соединениях может заблокироваться навсегда; раньше это
            // блокировало данную корутину, stopSelf() не выполнялся НИКОГДА,
            // и VPN оставался подключённым — «Отключить» в шторке как бы
            // не работал. Теперь ждём не больше дедлайна и останавливаем
            // сервис безусловно.
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
                // v4.7.0 ПУТЬ А: ядро fd точно НЕ закрыло (оно зависло), значит
                // номер дескриптора всё ещё наш и валидный.
                // v4.7.1: закрываем И СРАЗУ ПРОВЕРЯЕМ результат — снялся ли
                // интерфейс. Делаем это ДО withContext(Dispatchers.Main): если
                // главный поток заблокирован, до штатного продолжения дело не
                // дойдёт, а снять туннель мы можем прямо отсюда.
                forceTeardown("stopTunnel: closeService завис")
            }
            // v4.7.1 ГЛАВНОЕ: проверяем РЕЗУЛЬТАТ, а не наши предположения.
            //
            // closeService() мог вернуться без ошибки и без исключения
            // (stuck == false, tunActive == false), а интерфейс VPN при этом
            // остался поднятым. На Galaxy M21 / Android 12 наблюдается ровно
            // это: штатное «Отключить» ключик не снимает, а принудительное
            // снятие — снимает. Значит судить надо по тому, видит ли система
            // VPN-сеть, а не по внутренним флагам.
            //
            // Делаем это ЗДЕСЬ, в IO-потоке, а не в Main: forceTeardown() спит
            // SETTLE_MS (400 мс), давая системе снять интерфейс, и на главном
            // потоке это была бы подморозка UI.
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
                    // v4.12.1: процесс НЕ убиваем никогда. Если нативный поток
                    // завис или tunActive остался true — закрываем fd
                    // принудительно ещё раз, пишем причину в CrashLog и
                    // останавливаем сервис. Висящий ключик лечится повторным
                    // закрытием fd, а не убийством приложения.
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

    /**
     * Фоновая перепроверка текущего сервера (как background-refresh на
     * десктопе): quick-проба через 15 минут; если умер — автопереключение
     * на лучший живой узел, иначе остановка с уведомлением.
     */
    /**
     * Периодическая проверка живости текущего узла.
     *
     * Вызывается из [watchdog], а тот висит на [mainHandler] — то есть на
     * ГЛАВНОМ потоке. При этом внутри два native-вызова:
     * `probeSpecsFromServers` (парсит JSON в Go) и `probeServers` (поднимает
     * проверки). Тот же антипаттерн, что был в startTunnel/serviceReload:
     * блокировка главного потока → ANR → убийство процесса системой.
     *
     * Перенесено в [ioScope]. Ответ comes через ProbeListener-колбэки,
     * которые и так маршалируются на главный поток отдельно.
     */
    private fun runWatchdog() {
        val json = currentServerJson ?: return
        // v4.8.1: в режиме обхода узла нет, а json == BYPASS_NO_SERVER.
        // JSONObject() на нём бросал, исключение глушилось — то есть каждые
        // 15 минут watchdog впустую дёргал native-вызов и падал в catch.
        // Пробовать нечего: переключаться не на что.
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
                // this@TunnelService — это ProbeListener; внутри launch «this» это
                // CoroutineScope, поэтому нужна полная квалификация.
                Mobile.probeServers(specs, opts, this@TunnelService)
            } catch (e: Throwable) {   // native-вызовы
                Log.w(FlickerApp.TAG, "watchdog", e)
            }
        }
    }

    // ---------- ProbeListener (watchdog) ----------

    override fun onProbeStage(resultJSON: String?) {
        // не используется watchdog'ом
    }

    override fun onProbeDone(resultJSON: String?) {
        if (resultJSON == null) return
        // v4.8.1: в режиме обхода результат пробы узла не значит ничего —
        // узла нет. Без этой проверки alive == 0 уводил в handleDeadNode,
        // а тот рвал РАБОЧИЙ туннель обхода.
        if (dev.flicker.vpn.util.Prefs.mode(this) ==
            dev.flicker.vpn.util.Prefs.MODE_BYPASS) return
        mainHandler.post {
            try {
                val o = JSONObject(resultJSON)
                if (o.has("error")) return@post
                val alive = o.optInt("alive")
                if (alive > 0) return@post
                // текущий сервер умер
                val backup = Repository.bestAliveServer()
                if (backup != null && backup.json != currentServerJson) {
                    Log.w(FlickerApp.TAG, "watchdog: сервер умер, переключаюсь на ${backup.name}")
                    notifyStatus(getString(R.string.notif_switched, backup.name))
                    startTunnel(backup.json)
                } else {
                    notifyStatus(getString(R.string.notif_server_died))
                    // v4.6.0 ИСПРАВЛЕН БАГ «ключик висит постоянно».
                    //
                    // БЫЛО: stopTunnel(); stopSelf() — подряд.
                    // stopTunnel() асинхронный (ioScope.launch), stopSelf()
                    // синхронный и приводит к onDestroy() → ioScope.cancel().
                    // Корутина остановки отменялась, не успев закрыть ядро, а
                    // ветка `if (stuck)` раньше звала killProcess; v4.12.1 — нет,
                    // потому что andStop был false. Итог: сервис уничтожен,
                    // процесс жив, Go держит fd туннеля → интерфейс VPN поднят
                    // неограниченно долго, ключик в статусбаре остаётся,
                    // AppState застревает в Connected.
                    //
                    // Тот же паттерн уже был описан как сломанный в комментариях
                    // к onTaskRemoved и serviceStop() — здесь его пропустили.
                    // Это был ЕДИНСТВЕННЫЙ вызов stopTunnel() без andStop=true.
                    stopTunnel(andStop = true)
                }
            } catch (e: Exception) {
                Log.w(FlickerApp.TAG, "watchdogDone", e)
            }
        }
    }

    // ---------- SocketProtector (Go-пробы) ----------

    override fun protectFd(fd: Int): Boolean = try {
        val ok = protect(fd)
        if (!ok) {
            // v4.6.0: это сокеты Go-проб (Mobile.probeServers). Незащищённый
            // сокет пробы уходит в собственный туннель, и результат такой пробы
            // не значит ничего. Считаем, чтобы в отчёте было видно, когда
            // «узел мёртв» на самом деле означает «проба соврала».
            probeProtectFails++
            Log.w(FlickerApp.TAG, "protectFd(fd=$fd) вернул false — проба идёт сквозь собственный туннель (всего отказов: $probeProtectFails)")
        }
        ok
    } catch (t: Throwable) {
        // v4.1.0: Throwable, не Exception — этот метод вызывается из Go через
        // JNI на каждом сокете проб; любое исключение, улетевшее обратно в Go,
        // превращается в панику и убивает процесс (SIGABRT без диалога).
        probeProtectFails++
        false
    }

    // ---------- CommandServerHandler ----------

    override fun serviceStop() {
        mainHandler.post {
            // stopSelf() — ВНУТРИ stopTunnel(andStop = true), то есть ПОСЛЕ
            // closeNative(). БЫЛО: stopTunnel(); stopSelf() подряд, и после
            // перевода stopTunnel() в ioScope это сломалось — stopSelf()
            // срабатывал мгновенно, onDestroy() начинал закрывать CommandServer
            // одновременно с ещё идущей остановкой туннеля.
            stopTunnel(andStop = true)
        }
    }

    /**
     * Вызывается ядром, когда конфиг надо перечитать.
     *
     * БЫЛО: mainHandler.post { ... startOrReloadService(...) } — то есть тяжёлый
     * блокирующий native-вызов на ГЛАВНОМ потоке. Это прямой путь к ANR, а ANR
     * на сервисе система карает убийством процесса без внятного диалога.
     *
     * СТАЛО: ioScope + nativeLock, как и основной путь запуска.
     */
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
            } catch (e: Throwable) {   // Throwable: native-вызовы
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
        // отладочный путь libbox (TriggerDebugCrash) не используется в проде
        throw UnsupportedOperationException("triggerNativeCrash недоступен")
    }

    override fun writeDebugMessage(message: String?) {
        Log.d(FlickerApp.TAG, "box: $message")
    }

    override fun connectSSHAgent(): Int = 0

    // ---------- PlatformInterface ----------

    override fun localDNSTransport(): LocalDNSTransport? = null

    override fun usePlatformAutoDetectInterfaceControl(): Boolean = true

    /**
     * Вызывается Go-ядром через JNI на КАЖДЫЙ сокет, который открывает sing-box.
     *
     * БЫЛО:
     *     if (!protect(fd)) throw IllegalStateException("protect(fd=$fd) отклонён системой")
     *
     * ПОЧЕМУ ЭТО БЫЛО НЕПРАВИЛЬНО:
     * `VpnService.protect(fd)` возвращает false ШТАТНО в нескольких случаях:
     *   * туннель ещё не установлен (establish() не завершён), а ядро уже
     *     открывает сокеты — на старте это происходит регулярно;
     *   * fd уже закрыт к моменту вызова (гонка между Go и закрытием сокета);
     *   * fd не является сокетом.
     * То есть false — это ожидаемое состояние, а не авария.
     *
     * Исключение отсюда уходит обратно в Go через JNI. Дальше два плохих
     * исхода, и оба выглядят одинаково для пользователя:
     *   * sing-box получает ошибку на создании сокета и рвёт запуск туннеля;
     *   * Go-паника внутри c-shared библиотеки приводит к abort() → SIGABRT,
     *     процесс умирает БЕЗ Java-диалога краша.
     *
     * Эталон (sing-box-for-android, VPNService.kt) делает ровно так:
     *     override fun autoDetectInterfaceControl(fd: Int) { protect(fd) }
     * то есть результат намеренно игнорируется. Незащищённый сокет — это
     * деградация маршрутизации конкретного соединения, а смерть protect()
     * на старте убивает весь туннель.
     *
     * Лог оставляем: если protect() начнёт возвращать false постоянно, это
     * будет видно в logcat, а не проявится как «просто не работает».
     */
    override fun autoDetectInterfaceControl(fd: Int) {
        try {
            if (!protect(fd)) {
                // v4.6.0: считаем. Это СОБСТВЕННЫЕ сокеты sing-box (outbound к
                // узлу): незащищённый outbound отправляет пакеты обратно в TUN —
                // получается петля маршрутизации. Снаружи она неотличима от
                // «узел мёртв», поэтому счётчик уходит в отчёт и в детектор
                // stalled (onCoreStatus), который предупреждает о подмене
                // диагноза.
                coreProtectFails++
                Log.w(FlickerApp.TAG, "protect(fd=$fd) вернул false — сокет не защищён от маршрутизации в туннель (всего отказов: $coreProtectFails)")
            }
        } catch (e: Throwable) {
            coreProtectFails++
            // Ничего не должно улететь обратно в JNI: отсюда исключение
            // превращается либо в обрыв туннеля, либо в SIGABRT.
            Log.e(FlickerApp.TAG, "autoDetectInterfaceControl(fd=$fd)", e)
        }
    }

    /**
     * v4.10.4: establish() с ретраями (см. ESTABLISH_RETRIES).
     *
     * Вызывается из JNI-потока (libbox OpenTun), поэтому Thread.sleep здесь
     * безопасен: это не главный поток и не поток колбэков ядра.
     */
    private fun establishWithRetry(builder: Builder): android.os.ParcelFileDescriptor? {
        var attempt = 0
        while (true) {
            val pfd = try {
                builder.establish()
            } catch (t: Throwable) {
                // Ошибки Builder'а отсеяны выше по коду; здесь ловим только
                // сюрпризы самого establish().
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

    /**
     * v4.10.4: человекочитаемая причина establish()=null. Идёт и в диалог
     * пользователю, и в отчёт (через message broadcastState).
     *
     * prepare() != null  → система хочет согласие заново (диалог не завершён,
     *                      согласие сброшено после обновления/переподписи);
     * prepare() == null  → согласие валидно, но туннель нам не отдают: его
     *                      держит другое приложение или always-on VPN.
     */
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
        // InetAddress.getByName() бросает UnknownHostException на неразборчивом
        // адресе, а Builder.addAddress() — IllegalArgumentException на неверном
        // префиксе. Этот метод вызывается из JNI, поэтому каждое исключение
        // обёрнуто: один кривой адрес не должен ронять весь туннель.
        options.inet4Address.forEachPrefix { rp ->
            if (addAddressSafe(builder, rp.address(), rp.prefix().toInt(), "inet4")) hasV4 = true
        }
        options.inet6Address.forEachPrefix { rp ->
            if (addAddressSafe(builder, rp.address(), rp.prefix().toInt(), "inet6")) hasV6 = true
        }
        if (!hasV4) addAddressSafe(builder, "172.19.0.1", 30, "inet4-fallback")
        if (hasV6) builder.allowFamily(OsConstants.AF_INET6)

        // DNS: native → серверы из опций; иначе sing-box перехватывает DNS
        // внутри туннеля (hijack) — ставим заглушку из нашей подсети.
        val dnsMode = options.getDNSMode()?.value ?: ""
        if (dnsMode == "native") {
            val servers = try {
                options.getDNSServerAddress().toStringList()
            } catch (e: Exception) {
                emptyList()
            }
            // addDnsServer() бросает IllegalArgumentException на невалидном IP.
            // Серверы приходят из ядра, поэтому фильтруем, а не доверяем.
            val valid = servers.filter { addDnsSafe(builder, it) }
            if (valid.isEmpty()) addDnsSafe(builder, "172.19.0.2")
        } else {
            addDnsSafe(builder, "172.19.0.2")
        }

        // v4.2.0: дефолтные маршруты — БЕЗУСЛОВНО. Раньше они добавлялись
        // только при options.getAutoRoute(), но генератор конфига в .so не
        // пишет auto_route, и тот всегда был false → на части прошивок VPN
        // «включался», но трафик не перехватывал («что с VPN, что без — одно
        // и то же»). ConfigMigrate теперь ещё и инжектит auto_route:true
        // в конфиг — две независимые страховки.
        builder.addRoute("0.0.0.0", 0)
        if (hasV6) builder.addRoute("::", 0)

        // v4.7.1: в режиме обхода DPI ОБЯЗАТЕЛЬНО исключаем собственный пакет.
        //
        // byedpi живёт в процессе :byedpi того же пакета и держит SOCKS5 на
        // 127.0.0.1. Если пакет не исключён, её исходящие сокеты попадают
        // обратно в TUN → sing-box → socks-outbound → byedpi → бесконечная
        // петля. Именно так это сделано в ByeByeDPI-x-tg
        // (ByeDpiVpnService.createTunnel: addDisallowedApplication всегда).
        //
        // В серверных режимах исключать пакет НЕЛЬЗЯ: сквозная самопроверка
        // узла построена на том, что сокеты приложения идут через туннель
        // (см. docs/11-FIXES-4.6.0.md §3.1).
        if (dev.flicker.vpn.util.Prefs.mode(this) ==
            dev.flicker.vpn.util.Prefs.MODE_BYPASS
        ) {
            try {
                builder.addDisallowedApplication(packageName)
                Log.i(FlickerApp.TAG, "openTun: собственный пакет исключён из VPN (режим обхода DPI)")
            } catch (t: Throwable) {
                // PackageManager.NameNotFoundException на собственном пакете
                // практически невозможен, но если случилось — петля гарантирована,
                // поэтому пишем явно и громко.
                Log.e(FlickerApp.TAG, "openTun: НЕ удалось исключить собственный пакет — возможна петля маршрутизации", t)
                CrashLog.note(this, "openTun: addDisallowedApplication не сработал — возможна петля")
            }
        }

        // v4.6.0: setMetered(false).
        //
        // Есть и в Intra (GoVpnAdapter.establishVpn: "There's no charge for
        // using Intra"), и в v2rayNG (CoreVpnService.configurePlatformFeatures).
        // Без этого система вправе применять к VPN-интерфейсу политики
        // лимитных сетей — в частности ограничивать фоновый трафик приложений.
        // Снаружи это выглядит ровно как «трафик не идёт на другие приложения».
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
        // v4.6.0: запоминаем для диагностики и считаем, сколько раз туннель
        // вообще выдавался.
        // v4.7.0: с этого момента fd — у libbox, и снять интерфейс VPN можно
        // либо штатно (closeService()), либо принудительно (closeTunFdForced),
        // либо убийством процесса. См. tunActive.
        tunFdNumber = fd
        tunActive.set(true)
        tunHandedOut.incrementAndGet()
        Log.i(FlickerApp.TAG, "openTun: туннель установлен, fd=$fd (всего выдач: ${tunHandedOut.get()})")
        // v4.6.0: применить базовую сеть, которую монитор запомнил ДО того,
        // как туннель был установлен (см. applyUnderlyingNetworks).
        upstreamNetwork?.let { applyUnderlyingNetworks(it) }
        return fd
    }

    override fun useProcFS(): Boolean = false

    /**
     * v4.1.1: КРАШ, УБИВАВШИЙ ПРОЦЕСС НА ПЕРВОМ ЖЕ DNS-ПАКЕТЕ В ТУННЕЛЕ.
     *
     * Дамп паники с Galaxy M21 (Android 12):
     *   panic: runtime error: invalid memory address or nil pointer dereference
     *   libbox.(*platformInterfaceWrapper).FindConnectionOwner  service.go:226
     *   route.hijackDNSStream → routeConnection → tun.(*Inbound).NewConnectionEx
     *
     * Go-сторона разыменовывает результат БЕЗ проверки на nil:
     *   result, err := iif.FindConnectionOwner(...)
     *   if err != nil { return nil, err }
     *   return &ConnectionOwner{UserId: result.UserId, ...}  // result==nil → panic → SIGABRT
     *
     * Прежняя реализация `= null` возвращала Java null → gobind давал Go
     * (nil, nil) → паника → abort() → молчаливая смерть приложения.
     *
     * Метод объявлен `throws Exception`, поэтому gobind штатно конвертирует
     * исключение в Go-error: роутер залогирует «owner not found», закэширует
     * (process_cache) и продолжит маршрутизацию. Ровно так делает эталонная
     * SFA, когда getConnectionOwnerUid не находит владельца. Возвращать null
     * здесь НЕЛЬЗЯ никогда.
     *
     * Настоящий lookup через ConnectivityManager.getConnectionOwnerUid (API 29+)
     * не делаем: в этом приложении нет process-based правил, информация
     * о процессе-владельце не используется.
     */
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
                // Обновляем привязку и при смене возможностей: сеть могла
                // перестать быть валидной (потеря NOT_SUSPENDED и т.п.).
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
                    // Сбрасываем привязку: иначе сокеты ядра останутся
                    // привязаны к исчезнувшей сети. Вызов вынесен в метод
                    // класса намеренно: setUnderlyingNetworks() — protected
                    // член VpnService, и дёргать его из анонимного колбэка
                    // не стоит.
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
        // сразу сообщаем о текущей сети
        val active = cm.activeNetwork
        val caps = active?.let { cm.getNetworkCapabilities(it) }
        if (active != null && caps != null && !isVpnNetwork(caps)) {
            upstreamNetwork = active
            applyUnderlyingNetworks(active)
            reportDefaultInterface(cm, active, caps, listener)
        }
    }

    /**
     * v4.6.0: наш ли это VPN-интерфейс.
     *
     * ЗАЧЕМ. `registerDefaultNetworkCallback` при поднятом VPN с маршрутом по
     * умолчанию возвращает в том числе САМ VPN-интерфейс. v2rayNG на этом
     * споткнулся и задокументировал:
     *
     *     "Unfortunately registerDefaultNetworkCallback is going to return our
     *      VPN interface:
     *      https://android.googlesource.com/platform/frameworks/base/+/dda156ab0c5d"
     *
     * Если передать его ядру как «интерфейс по умолчанию», sing-box с
     * `auto_detect_interface: true` привяжет собственные outbound-сокеты к
     * tun-интерфейсу — то есть к самому себе. Это мгновенная петля
     * маршрутизации: туннель поднят, ключик горит, а трафика нет.
     */
    private fun isVpnNetwork(caps: NetworkCapabilities): Boolean =
        caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)

    /**
     * v4.6.0: объявляем системе, поверх какой сети работает туннель.
     *
     * Intra делает это на каждое изменение сети (IntraVpnService.
     * setNetworkConnected) со ссылкой на issuetracker.google.com/issues/68657525;
     * v2rayNG — через NetworkMonitor.onUnderlyingNetworksChanged.
     *
     * БЕЗ ЭТОГО: сокеты, открытые ядром ДО смены сети, остаются привязаны к
     * старой. При WiFi→LTE (и обратно) туннель формально жив, `establish()`
     * успешен, приложение рапортует «Подключено», — а пакеты уходят в
     * мёртвый интерфейс. Это и есть «туннель не ложится на трафик».
     */
    private fun applyUnderlyingNetworks(network: Network) {
        // v4.6.0: setUnderlyingNetworks() бросает IllegalStateException, если
        // VPN ещё не активен. Монитор сети запускается ядром и может
        // стартовать РАНЬШЕ, чем openTun() вернёт fd, — поэтому до
        // установления туннеля просто запоминаем сеть: openTun() применит её
        // сразу после establish().
        if (tunFdNumber < 0) return
        // На пути остановки VPN может быть уже не активен — тогда система
        // бросит IllegalStateException. Глушим намеренно: привязка к базовой
        // сети на выключенном туннеле не нужна.
        runCatching { setUnderlyingNetworks(arrayOf(network)) }
            .onFailure { Log.w(FlickerApp.TAG, "setUnderlyingNetworks", it) }
    }

    /** v4.6.0: снять привязку к базовой сети (сеть исчезла). */
    private fun clearUnderlyingNetworks() {
        if (tunFdNumber < 0) return
        runCatching { setUnderlyingNetworks(null) }
            .onFailure { Log.w(FlickerApp.TAG, "setUnderlyingNetworks(null)", it) }
    }

    /**
     * v4.6.0: обработка смены базовой сети.
     *
     * Cellular→WiFi — это make-before-break: новая сеть объявляется, пока
     * старая ещё подключена, поэтому сокет до узла НЕ сбрасывается и ядро
     * продолжает пользоваться мёртвым соединением. Формулировка и решение —
     * из v2rayNG NetworkMonitor (дебаунс 1000 мс, затем перезапуск ядра).
     *
     * Перезапуск делаем через [serviceReload] — он поднимает тот же конфиг на
     * том же туннеле, то есть интерфейс VPN, уведомление и ключик не моргают.
     */
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
            // isConstrained в libbox — аналог iOS/macOS Low Data Mode.
            // В Android SDK константы NetworkCapabilities.NET_CAPABILITY_NOT_CONSTRAINED
            // НЕТ (проверено javap по android-35: есть только NOT_CONGESTED, NOT_METERED,
            // NOT_RESTRICTED, NOT_ROAMING, NOT_SUSPENDED, NOT_VPN), поэтому признак
            // «ограниченной» сети не определить — всегда false. На sing-box это влияет
            // только в связке с isExpensive (стратегии интерфейса), которая выше считается.
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
                // v4.0.9: КАЖДЫЙ интерфейс отдельно — одна кривая железка
                // (SocketException на mtu и т.п.) не должна ронять весь список.
                try {
                    val ni = BoxNetworkInterface()
                    ni.index = jif.index
                    ni.name = jif.name ?: ""
                    try { ni.setMTU(jif.mtu) } catch (_: Throwable) {}
                    ni.type = guessInterfaceType(jif.name ?: "")
                    ni.metered = false
                    // v4.0.9: флаги как в SFA — без них ядро считает интерфейс
                    // выключенным (linkFlags(0)) и auto-detect работает криво.
                    var flags = 0
                    try {
                        if (jif.isUp) flags = flags or OsConstants.IFF_UP or OsConstants.IFF_RUNNING
                        if (jif.isLoopback) flags = flags or OsConstants.IFF_LOOPBACK
                        if (jif.isPointToPoint) flags = flags or OsConstants.IFF_POINTOPOINT
                        if (jif.supportsMulticast()) flags = flags or OsConstants.IFF_MULTICAST
                    } catch (_: Throwable) {}
                    ni.flags = flags
                    // v4.0.9, ГЛАВНОЕ: Go-сторона парсит эти строки через
                    // netip.MustParsePrefix, который ПАНИКУЕТ (abort -> SIGABRT,
                    // молчаливая смерть приложения при подключении) на:
                    //   * IPv6 с зоной:  "fe80::abcd%wlan0/64"  («IPv6 zones
                    //     cannot be present in a prefix») — а Android отдаёт
                    //     hostAddress link-local адресов ИМЕННО с %zone;
                    //   * префикс -1:    "10.0.0.1/-1" («bad bits after slash») —
                    //     networkPrefixLength бывает -1 на точка-точка/модемах.
                    // Чиним как в эталонной SFA: IPv6 пересоздаём из байтов
                    // (Inet6Address.getByAddress — без зоны), невалидные префиксы
                    // отбрасываем, плюс защитный фильтр мусора.
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

    /** constant.InterfaceType: WIFI=0, Cellular=1, Ethernet=2, Other=3. */
    private fun guessInterfaceType(name: String): Int = when {
        name.startsWith("wlan") || name.startsWith("wifi") || name.startsWith("ap") -> 0
        name.startsWith("rmnet") || name.startsWith("ccmni") || name.startsWith("usb") -> 1
        name.startsWith("eth") -> 2
        else -> 3
    }

    override fun underNetworkExtension(): Boolean = false

    override fun includeAllNetworks(): Boolean = false

    override fun readWIFIState(): WIFIState? = null

    override fun clearDNSCache() {
        // системный кэш DNS недоступен приложению — sing-box управляет своим
    }

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
            // БЫЛО: catch (e: Exception) { throw e } — no-op, который к тому же
            // ронял сервис из-за уведомления. Уведомление от ядра не стоит
            // обрыва туннеля: логируем и живём дальше.
            Log.w(FlickerApp.TAG, "sendNotification", e)
        }
    }

    override fun cancelNotification(identifier: String?, typeID: Int) {
        try {
            getSystemService(NotificationManager::class.java)?.cancel(1000 + typeID)
        } catch (_: Exception) {
        }
    }

    override fun startNeighborMonitor(listener: NeighborUpdateListener?) {
        // не используется (нет route-exclude по соседям)
    }

    override fun closeNeighborMonitor(listener: NeighborUpdateListener?) {
        // не используется
    }

    override fun registerMyInterface(name: String?) {
        // не используется
    }

    override fun usePlatformShell(): Boolean = false

    override fun checkPlatformShell() {
        // платформа без shell-поддержки — ошибок нет
    }

    override fun openShellSession(
        user: PlatformUser?,
        command: String?,
        environ: StringIterator?,
        term: String?,
        rows: Int,
        cols: Int
    ): ShellSession = throw UnsupportedOperationException("shell не поддерживается")

    /**
     * v4.10.1: ПОСЛЕДНЯЯ МИНА ТОГО ЖЕ КЛАССА, ЧТО [findConnectionOwner].
     *
     * Go-сторона (sing-box v1.14.2, experimental/libbox/service.go:352-364)
     * разыменовывает результат БЕЗ проверки на nil:
     *
     *   platformUser, err := w.iif.LookupUser(username)
     *   if err != nil { return nil, err }
     *   return &adapter.PlatformUser{
     *       Username: platformUser.Username,   // ← nil → panic → SIGABRT
     *       ...
     *   }
     *
     * Прежнее `= null` давало gobind'у (nil, nil) → паника → молчаливая смерть
     * процесса. Ровно тот же механизм, который убивал приложение на первом
     * DNS-пакете до v4.1.1.
     *
     * Путь сейчас НЕДОСТИЖИМ: LookupUser вызывается только из Tailscale SSH,
     * а [usePlatformShell] возвращает false и [tailscaleHostname] пуст.
     * Но метод объявлен `throws`-совместимо, поэтому исключение штатно
     * превращается в Go-error — чиним заранее, чтобы включение любой
     * shell/tailscale-функциональности не вернуло этот краш.
     *
     * Ср. остальные nil-возвраты этого интерфейса: [readWIFIState] и
     * [localDNSTransport] БЕЗОПАСНЫ — Go их проверяет
     * (service.go:182-185 `if wifiState == nil`, config.go:32
     * `if localTransport := ...; localTransport != nil`).
     */
    override fun lookupUser(username: String?): PlatformUser? =
        throw IllegalStateException("android: user lookup not supported")

    override fun lookupSFTPServer(): String = ""

    override fun readSystemSSHHostKey(): String = ""

    override fun tailscaleHostname(): String = ""

    override fun usePlatformBridge(): Boolean = false

    override fun createBridge(options: BridgeOptions?): BridgeSession =
        throw UnsupportedOperationException("bridge не поддерживается")

    // ---------- уведомления / статусы ----------

    protected fun startForegroundNotif(text: String) {
        // Подключение установлено — показываем уведомление с действиями
        // «Пауза» и «Отключить» из общего билдера, чтобы оформление и
        // PendingIntent'ы (requestCode, флаги) не разъезжались в двух местах.
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

    /**
     * Тип foreground-сервиса для startForeground().
     *
     * Константы ServiceInfo.FOREGROUND_SERVICE_TYPE_VPN в SDK НЕ существует
     * (проверено javap по android-35: есть CAMERA, CONNECTED_DEVICE, DATA_SYNC,
     * HEALTH, LOCATION, MANIFEST, MEDIA_*, MICROPHONE, NONE, PHONE_CALL,
     * REMOTE_MESSAGING, SHORT_SERVICE, SPECIAL_USE, SYSTEM_EXEMPTED).
     *
     * Поэтому берём FOREGROUND_SERVICE_TYPE_MANIFEST (API 29+): система читает
     * тип из манифеста, где у нас foregroundServiceType="specialUse" с
     * property-подтипом "vpn" — каноническая комбинация для VpnService.
     */
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

    /**
     * addAddress без исключений.
     * @return true, если адрес добавлен
     */
    private fun addAddressSafe(builder: Builder, address: String?, prefix: Int, what: String): Boolean {
        if (address.isNullOrBlank()) {
            Log.w(FlickerApp.TAG, "openTun/$what: пустой адрес, пропускаю")
            return false
        }
        return try {
            builder.addAddress(InetAddress.getByName(address), prefix)
            true
        } catch (e: Throwable) {
            // UnknownHostException (неразборчивый адрес) или
            // IllegalArgumentException (префикс вне диапазона)
            Log.e(FlickerApp.TAG, "openTun/$what: не добавить $address/$prefix", e)
            false
        }
    }

    /**
     * addDnsServer без исключений.
     * @return true, если сервер принят
     */
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
     * Единая точка синхронизации внешнего состояния.
     *
     * Статус читают три независимых потребителя: MainActivity (через broadcast),
     * плитка в шторке (через AppState) и BootReceiver. Раньше они обновлялись в
     * разных местах и расходились — плитка залипала в прошлом значении.
     */
    protected fun publishState(nameOverride: String? = null) {
        val connected = started
        // v4.12.0: в режиме обхода DPI узла нет — имя подключения («Обход
        // DPI · <пресет>») приходит явно в [nameOverride], иначе берётся
        // текущее (раньше перезаписывалось пустой строкой из
        // Repository.selectedServer()).
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

    protected fun broadcastState(connected: Boolean, message: String?, name: String? = null) {
        if (!connected && message != null) {
            AppState.update(ServiceStatus.Failed, error = message)
        }
        publishState(if (connected) name else null)
        val intent = Intent(BROADCAST_STATE)
            .setPackage(packageName)
            .putExtra(EXTRA_CONNECTED, connected)
        if (message != null) intent.putExtra(EXTRA_MESSAGE, message)
        // v4.12.0: имя — для синхронизации UI основного процесса (обход живёт
        // в :bypass; см. MainActivity.stateReceiver).
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
