// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn.core.tgws

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import java.security.SecureRandom

/**
 * v4.10.0: настройки Telegram-туннеля (MTProto-WS).
 *
 * ---------------------------------------------------------------------------
 *  ЧТО ЭТО ТАКОЕ И ЧЕМ ОТЛИЧАЕТСЯ ОТ ДВУХ ДРУГИХ РЕЖИМОВ
 * ---------------------------------------------------------------------------
 *  Режимы «VPN-узел» и «Обход DPI» поднимают TUN-интерфейс: весь трафик
 *  телефона идёт через приложение, в статусбаре висит ключик, нужно разрешение
 *  VpnService.
 *
 *  Telegram-туннель устроен иначе и ВООБЩЕ НЕ ТРОГАЕТ VPN. Это локальный
 *  MTProto-прокси на 127.0.0.1:[port]:
 *
 *      Telegram ──TCP──> 127.0.0.1:1443 (наш Rust-натив)
 *                            │
 *                            ├──WSS через CloudFlare──> Telegram DC   (основной путь)
 *                            └──TCP напрямую──────────> Telegram DC   (резерв)
 *
 *  То есть:
 *    * разрешения VpnService не нужно, ключика в статусбаре нет;
 *    * трафик остальных приложений не меняется вовсе;
 *    * прописывать прокси нужно ВНУТРИ Telegram — отсюда кнопка
 *      «Открыть в Telegram» (tg://proxy) и ручной ввод server/port/secret;
 *    * работает одновременно с любым из двух других режимов. Если VPN поднят,
 *      исходящие WSS натива пойдут через туннель (двойная защита); если
 *      выключен — напрямую. И то и другое корректно.
 *
 *  Именно поэтому здесь отдельный сервис и отдельный экран, а не четвёртая
 *  кнопка в переключателе режимов: это не режим туннеля, а независимая функция.
 */
data class TgWsConfig(
    /** Только loopback. Внешний интерфейс означал бы открытый прокси для всей сети. */
    val bindIp: String = DEFAULT_BIND,
    val port: Int = DEFAULT_PORT,
    /** 32 hex-символа. Генерируется один раз и переиспользуется. */
    val secret: String = "",
    /** Пул предварительно открытых WS-соединений, 0..16. */
    val poolSize: Int = DEFAULT_POOL,
    /** Ходить через CloudFlare. Выключать имеет смысл только если CF сам заблокирован. */
    val cfEnabled: Boolean = true,
    /** Свой домен CF-воркера; "" — встроенный список доменов. */
    val cfDomain: String = "",
    /**
     * Ручные адреса DC в формате `1:149.154.175.50,2:149.154.167.51`.
     * "" — авто (в нативе зашиты IP всех DC).
     * Нужно только если провайдер режет конкретные адреса Telegram.
     */
    val dcIps: String = "",
    /** Подробный лог в logcat (тег TgWsProxy). */
    val verbose: Boolean = true,
    /** Держать CPU-wakelock, чтобы прокси не засыпал вместе с телефоном. */
    val keepAwake: Boolean = true,
    /** Поднимать заново после перезагрузки устройства. */
    val autoStart: Boolean = false,
) {
    /** Валидна ли конфигурация настолько, чтобы пробовать стартовать. */
    val valid: Boolean
        get() = port in 1..65535 && bindIp.isNotBlank() && isValidSecret(secret)

    companion object {
        const val DEFAULT_BIND = "127.0.0.1"
        const val DEFAULT_PORT = 1443
        const val DEFAULT_POOL = 4

        /**
         * 1443 — общепринятый порт MTProto-прокси (его пропускает большинство
         * фильтров, в отличие от 1082/8080). Меняется в настройках экрана.
         */
        fun isValidSecret(s: String): Boolean =
            s.length == 32 && s.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }

        fun randomSecret(): String {
            val b = ByteArray(16)
            SecureRandom().nextBytes(b)
            return b.joinToString("") { "%02x".format(it) }
        }
    }
}

/**
 * Хранилище настроек Telegram-туннеля.
 *
 * ПОЧЕМУ ОТДЕЛЬНЫЙ ФАЙЛ, А НЕ [dev.flicker.vpn.util.Prefs].
 * Сервис TgWsService живёт в процессе `:tgws`, а SharedPreferences между
 * процессами НЕ синхронизируются (MODE_MULTI_PROCESS deprecated и не работает
 * надёжно). Поэтому правило такое:
 *   * читает и пишет этот файл ТОЛЬКО основной процесс (UI);
 *   * сервис получает всю конфигурацию extras'ами интента и prefs не трогает;
 *   * обратно состояние уезжает broadcast'ом (TgWsClient).
 * Тогда гонки между процессами невозможны в принципе.
 */
object TgWsPrefs {

    private const val FILE = "flicker_tgws"

    private const val K_PORT = "port"
    private const val K_SECRET = "secret"
    private const val K_POOL = "pool_size"
    private const val K_CF_ENABLED = "cf_enabled"
    private const val K_CF_DOMAIN = "cf_domain"
    private const val K_DC_IPS = "dc_ips"
    private const val K_VERBOSE = "verbose"
    private const val K_KEEP_AWAKE = "keep_awake"
    private const val K_AUTOSTART = "auto_start"
    private const val K_WAS_RUNNING = "was_running"

    private fun p(c: Context): SharedPreferences =
        c.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    /**
     * Читает сохранённое и ГАРАНТИРУЕТ валидный secret: если его нет или он
     * побился — генерирует и сразу сохраняет (commit, не apply: значение нужно
     * в том же процессе прямо сейчас, а не «когда-нибудь»).
     */
    fun load(c: Context): TgWsConfig {
        val sp = p(c)
        var secret = (sp.getString(K_SECRET, "") ?: "").trim()
        if (!TgWsConfig.isValidSecret(secret)) {
            secret = TgWsConfig.randomSecret()
            sp.edit(commit = true) { putString(K_SECRET, secret) }
        }
        return TgWsConfig(
            port = (sp.getInt(K_PORT, TgWsConfig.DEFAULT_PORT)).let {
                if (it in 1..65535) it else TgWsConfig.DEFAULT_PORT
            },
            secret = secret,
            poolSize = sp.getInt(K_POOL, TgWsConfig.DEFAULT_POOL).coerceIn(0, 16),
            cfEnabled = sp.getBoolean(K_CF_ENABLED, true),
            cfDomain = (sp.getString(K_CF_DOMAIN, "") ?: "").trim(),
            dcIps = (sp.getString(K_DC_IPS, "") ?: "").trim(),
            verbose = sp.getBoolean(K_VERBOSE, true),
            keepAwake = sp.getBoolean(K_KEEP_AWAKE, true),
            autoStart = sp.getBoolean(K_AUTOSTART, false),
        )
    }

    fun save(c: Context, cfg: TgWsConfig) = p(c).edit {
        putInt(K_PORT, cfg.port)
        putString(K_SECRET, cfg.secret)
        putInt(K_POOL, cfg.poolSize)
        putBoolean(K_CF_ENABLED, cfg.cfEnabled)
        putString(K_CF_DOMAIN, cfg.cfDomain)
        putString(K_DC_IPS, cfg.dcIps)
        putBoolean(K_VERBOSE, cfg.verbose)
        putBoolean(K_KEEP_AWAKE, cfg.keepAwake)
        putBoolean(K_AUTOSTART, cfg.autoStart)
    }

    fun newSecret(c: Context): String {
        val s = TgWsConfig.randomSecret()
        p(c).edit(commit = true) { putString(K_SECRET, s) }
        return s
    }

    /**
     * Флаг «прокси работал, когда приложение закрыли». Нужен ровно для одного:
     * подсказать UI при следующем открытии, что сервис могли убить системой,
     * и для автозапуска после перезагрузки (BootReceiver).
     */
    fun wasRunning(c: Context): Boolean = p(c).getBoolean(K_WAS_RUNNING, false)

    fun setWasRunning(c: Context, v: Boolean) = p(c).edit { putBoolean(K_WAS_RUNNING, v) }
}
