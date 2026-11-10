// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn.core.tgws

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.util.Log
import androidx.core.content.ContextCompat
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Состояние Telegram-туннеля, каким его видит UI.
 *
 * @param running   сервис поднят и foreground-уведомление висит.
 * @param verified  натив реально принял bind и слушает порт. Отличается от
 *                  [running] на время старта: между startForeground() и
 *                  возвратом StartProxy() проходит до нескольких секунд
 *                  (натив тянет список доменов CloudFlare). Показывать в этот
 *                  момент «работает» — значит врать, поэтому состояние
 *                  раздельное. Тот же приём, что в Intra (`VpnState.requested`
 *                  против `on`) и в v2rayNG.
 * @param stats     сырая строка GetStats(): `total=… active=… ws=… tcp_fb=…
 *                  cf=… bad=… err=… pool=…/… up=… down=…`
 * @param error     непустая — старт не удался, текст уже человекочитаемый.
 * @param log       последние строки лога натива (тег TgWsProxy из logcat).
 */
data class TgWsState(
    val running: Boolean = false,
    val verified: Boolean = false,
    val bindIp: String = "",
    val port: Int = 0,
    val secretFull: String = "",
    val stats: String = "",
    val error: String = "",
    val log: List<String> = emptyList(),
    val updatedAt: Long = 0L,
) {
    /** Адрес, который вписывается в Telegram. */
    val endpoint: String get() = if (bindIp.isBlank()) "" else "$bindIp:$port"
}

/**
 * Клиентская сторона: управление сервисом из основного процесса + приём
 * состояния broadcast'ом.
 *
 * ПОЧЕМУ BROADCAST, А НЕ bindService.
 * Сервис живёт в процессе `:tgws`. bindService дал бы более «плотную» связь,
 * но связал бы жизненные циклы: смерть клиента рвала бы соединение, а смерть
 * сервиса требовала бы перепривязки. Start+broadcast проще, переживает
 * выгрузку UI и ровно так же устроен в ByeByeDPI-x-tg.
 *
 * Broadcast помечен `setPackage(...)` — он явный, наружу не уходит и не
 * требует никаких разрешений.
 */
object TgWsClient {

    private const val TAG = "FlickerTgWs"

    /** Действия сервиса. Зеркалят константы в [TgWsService]. */
    const val ACTION_START = "dev.flicker.vpn.tgws.START"
    const val ACTION_STOP = "dev.flicker.vpn.tgws.STOP"
    const val ACTION_RESTART = "dev.flicker.vpn.tgws.RESTART"
    const val ACTION_QUERY = "dev.flicker.vpn.tgws.QUERY"

    /** Ответ сервиса. */
    const val BROADCAST_STATE = "dev.flicker.vpn.tgws.STATE"

    const val EXTRA_BIND_IP = "bind_ip"
    const val EXTRA_PORT = "port"
    const val EXTRA_IPS = "dc_ips"
    const val EXTRA_POOL_SIZE = "pool_size"
    const val EXTRA_CF_ENABLED = "cf_enabled"
    const val EXTRA_CF_PRIORITY = "cf_priority"
    const val EXTRA_CF_DOMAIN = "cf_domain"
    const val EXTRA_SECRET = "secret"
    const val EXTRA_VERBOSE = "verbose"
    const val EXTRA_KEEP_AWAKE = "keep_awake"

    const val EXTRA_RUNNING = "running"
    const val EXTRA_VERIFIED = "verified"
    const val EXTRA_SECRET_FULL = "secret_full"
    const val EXTRA_STATS = "stats"
    const val EXTRA_ERROR = "error"
    const val EXTRA_LOG = "log"
    const val EXTRA_TS = "ts"

    private val _state = MutableStateFlow(TgWsState())
    val state: StateFlow<TgWsState> = _state.asStateFlow()

    private var receiver: BroadcastReceiver? = null
    private var refCount = 0

    /**
     * Подписаться на состояние. Вызывать из Activity основного процесса;
     * [detach] обязателен и ОБЯЗАН быть парным (onCreate↔onDestroy или
     * onStart↔onStop).
     *
     * ПОЧЕМУ СЧЁТЧИК, А НЕ ОДИН RECEIVER.
     * Состояние нужно одновременно двум экранам: строке на MainActivity
     * («Telegram-туннель: работает») и самому TgWsActivity. Если бы attach()
     * просто перерегистрировал приёмник, открытие второго экрана отписывало бы
     * первый, а закрытие второго — вообще всех. Счётчик делает attach/detach
     * коммутирующими, и порядок открытия экранов перестаёт иметь значение.
     *
     * Регистрируем на applicationContext, а не на Activity: receiver,
     * зарегистрированный на Activity, снимается вместе с ней и может
     * «потерять» событие, пришедшее в момент пересоздания.
     */
    @Synchronized
    fun attach(context: Context) {
        refCount++
        if (receiver != null) return
        val app = context.applicationContext
        val r = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context?, intent: Intent?) {
                if (intent?.action != BROADCAST_STATE) return
                _state.value = fromIntent(intent)
            }
        }
        try {
            ContextCompat.registerReceiver(
                app, r, IntentFilter(BROADCAST_STATE), ContextCompat.RECEIVER_NOT_EXPORTED
            )
            receiver = r
        } catch (t: Throwable) {
            Log.w(TAG, "не удалось зарегистрировать приёмник состояния", t)
            refCount = 0
        }
    }

    @Synchronized
    fun detach(context: Context) {
        if (refCount > 0) refCount--
        if (refCount > 0) return
        refCount = 0
        val r = receiver ?: return
        receiver = null
        try {
            context.applicationContext.unregisterReceiver(r)
        } catch (_: Throwable) {
            // уже снят — не ошибка
        }
    }

    private fun fromIntent(i: Intent): TgWsState = TgWsState(
        running = i.getBooleanExtra(EXTRA_RUNNING, false),
        verified = i.getBooleanExtra(EXTRA_VERIFIED, false),
        bindIp = i.getStringExtra(EXTRA_BIND_IP).orEmpty(),
        port = i.getIntExtra(EXTRA_PORT, 0),
        secretFull = i.getStringExtra(EXTRA_SECRET_FULL).orEmpty(),
        stats = i.getStringExtra(EXTRA_STATS).orEmpty(),
        error = i.getStringExtra(EXTRA_ERROR).orEmpty(),
        log = i.getStringArrayExtra(EXTRA_LOG)?.toList() ?: emptyList(),
        updatedAt = i.getLongExtra(EXTRA_TS, System.currentTimeMillis()),
    )

    /** Сбросить кэшированное состояние (например, при закрытии экрана). */
    fun reset() {
        _state.value = TgWsState()
    }

    // -----------------------------------------------------------------------
    //  Управление
    // -----------------------------------------------------------------------

    /**
     * Запустить. Все параметры уезжают extras'ами: сервис prefs не читает
     * (другой процесс), а START_REDELIVER_INTENT вернёт этот же интент, если
     * систему понадобится пересоздать сервис после убийства.
     *
     * @return текст ошибки валидации, или null если старт запрошен.
     */
    fun start(context: Context, cfg: TgWsConfig): String? {
        if (!cfg.valid) {
            return when {
                cfg.port !in 1..65535 -> "Порт должен быть от 1 до 65535 (сейчас ${cfg.port})"
                !TgWsConfig.isValidSecret(cfg.secret) -> "Секрет повреждён — нажмите «Сменить секрет»"
                else -> "Некорректные настройки"
            }
        }
        val i = Intent(context, TgWsService::class.java).apply {
            action = ACTION_START
            putExtra(EXTRA_BIND_IP, cfg.bindIp)
            putExtra(EXTRA_PORT, cfg.port)
            putExtra(EXTRA_IPS, cfg.dcIps)
            putExtra(EXTRA_POOL_SIZE, cfg.poolSize)
            putExtra(EXTRA_CF_ENABLED, cfg.cfEnabled)
            // приоритет CF в нашем форке зарезервирован, всегда 1
            putExtra(EXTRA_CF_PRIORITY, true)
            putExtra(EXTRA_CF_DOMAIN, if (cfg.cfEnabled) cfg.cfDomain else "")
            putExtra(EXTRA_SECRET, cfg.secret)
            putExtra(EXTRA_VERBOSE, cfg.verbose)
            putExtra(EXTRA_KEEP_AWAKE, cfg.keepAwake)
        }
        return try {
            ContextCompat.startForegroundService(context, i)
            TgWsPrefs.setWasRunning(context, true)
            null
        } catch (t: Throwable) {
            // Android 12+: старт FGS из фона запрещён. Из открытого экрана —
            // разрешён, так что сюда попадаем редко (например, из BootReceiver).
            Log.e(TAG, "startForegroundService не удался", t)
            "${t.javaClass.simpleName}: ${t.message}"
        }
    }

    fun stop(context: Context) {
        sendCommand(context, ACTION_STOP)
        TgWsPrefs.setWasRunning(context, false)
    }

    /**
     * Перезапустить с сохранёнными параметрами (кнопка в уведомлении/на экране).
     *
     * Пауза 1,2 с: StopProxy() держит блокировку до ~2 с, но слушатель
     * закрывается сразу по cancel-токену. Если порт всё же не успеет
     * освободиться, StartProxy вернёт -3 и сервис сам повторит попытку
     * (scheduleRetryOrStop) — то есть гонка не фатальна, пауза лишь снижает
     * вероятность лишнего цикла.
     */
    fun restart(context: Context, cfg: TgWsConfig) {
        stop(context)
        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
            val err = start(context, cfg)
            if (err != null) Log.w(TAG, "restart: $err")
        }, 1_200L)
    }

    /**
     * Попросить сервис прислать текущее состояние. Нужно при открытии экрана:
     * сервис мог стартовать до того, как UI подписался, и кэш пуст.
     */
    fun query(context: Context) {
        sendCommand(context, ACTION_QUERY)
    }

    /**
     * Доставка команды, которая НЕ поднимает прокси (STOP / QUERY / RESTART).
     *
     * ПОЧЕМУ НЕ startForegroundService ПЕРВЫМ ДЕЛОМ.
     * `startForegroundService()` взводит в системе 5-секундный таймер: сервис
     * обязан вызвать `startForeground()`, иначе процесс убивают с
     * RemoteServiceException. Для STOP/QUERY foreground не нужен вовсе —
     * сервис просто отвечает и гаснет. Поэтому сначала пробуем обычный
     * `startService()` (таймера нет), и только если он запрещён (Android 8+:
     * старт сервиса из фона — IllegalStateException) откатываемся на
     * foreground-вариант. На нём сервис защищён своей веткой
     * `if (!started) stopSelf(startId)` в onStartCommand.
     *
     * @return true, если команду удалось отправить.
     */
    private fun sendCommand(context: Context, action: String): Boolean {
        val i = Intent(context, TgWsService::class.java).setAction(action)
        try {
            context.startService(i)
            return true
        } catch (t: Throwable) {
            Log.d(TAG, "startService($action) не прошёл: ${t.javaClass.simpleName}")
        }
        try {
            ContextCompat.startForegroundService(context, i)
            return true
        } catch (t: Throwable) {
            // Сервиса нет и поднять его из фона нельзя. Для QUERY это норма:
            // значит туннель остановлен, и состояние уже равно «выключен».
            Log.w(TAG, "$action не отправлен", t)
            return false
        }
    }

    /**
     * Ссылка `tg://proxy` — её понимают AyuGram, Plus Messenger, NekoGram,
     * Telegram Desktop. Официальный клиент Telegram для Android deep-link
     * НЕ обрабатывает: для него показываем server/port/secret отдельно
     * (см. TgWsActivity).
     */
    fun deepLink(bindIp: String, port: Int, secretFull: String): String =
        "tg://proxy?server=${bindIp}&port=${port}&secret=${secretFull}"
}
