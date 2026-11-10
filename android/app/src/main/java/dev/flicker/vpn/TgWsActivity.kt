// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import dev.flicker.vpn.core.tgws.TgWsClient
import dev.flicker.vpn.core.tgws.TgWsConfig
import dev.flicker.vpn.core.tgws.TgWsPrefs
import dev.flicker.vpn.core.tgws.TgWsState
import dev.flicker.vpn.databinding.ActivityTgWsBinding
import kotlinx.coroutines.launch
import java.io.File

/**
 * v4.10.0: экран Telegram-туннеля (локальный MTProto-прокси через WebSocket).
 *
 * Экран сам по себе ничего не запускает: вся работа в [dev.flicker.vpn.core.tgws.TgWsService]
 * (процесс `:tgws`). Здесь только ввод настроек, отображение состояния и
 * реквизиты, которые нужно вписать в Telegram.
 *
 * СОСТОЯНИЕ ПРИХОДИТ BROADCAST'ОМ, а не bindService'ом: сервис в другом
 * процессе, и связывать их жизненные циклы незачем. При открытии экрана
 * шлём [TgWsClient.query] — сервис отвечает актуальным снимком, поэтому
 * картина правильная даже если прокси подняли час назад из плитки или
 * из автозапуска.
 */
class TgWsActivity : AppCompatActivity() {

    private lateinit var b: ActivityTgWsBinding
    private var cfg: TgWsConfig = TgWsConfig()

    /** Секрет из натива (`dd…`), если туннель запущен; иначе вычисляем сами. */
    private var current: TgWsState = TgWsState()

    /** Пользователь правит поля — не перезаписывать их пришедшим состоянием. */
    private var editing = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityTgWsBinding.inflate(layoutInflater)
        setContentView(b.root)

        b.toolbar.setNavigationOnClickListener { finish() }

        cfg = TgWsPrefs.load(this)

        b.btnToggle.setOnClickListener { toggle() }
        b.btnRestart.setOnClickListener { restart() }
        b.btnOpenTg.setOnClickListener { openInTelegram() }
        b.btnCopyLink.setOnClickListener { copy(deeplink(), getString(R.string.tgws_btn_copy_link)) }
        b.btnNewSecret.setOnClickListener { newSecret() }
        b.btnApply.setOnClickListener { apply() }
        b.btnCopyLog.setOnClickListener { copyLog() }

        b.copyServer.setOnClickListener { copy(b.valServer.text.toString(), getString(R.string.tgws_lbl_server)) }
        b.copyPort.setOnClickListener { copy(b.valPort.text.toString(), getString(R.string.tgws_lbl_port)) }
        b.copySecret.setOnClickListener { copy(secretFull(), getString(R.string.tgws_lbl_secret)) }

        fillSettings()
        watchEdits()

        // .so могла не доехать в APK (например, сборка под armeabi-v7a, где
        // libflickerbox.so всё равно нет). Проверяем наличием файла, а не
        // загрузкой: грузить 2 МБ Rust-библиотеку в UI-процессе незачем.
        val so = File(applicationInfo.nativeLibraryDir, "libtgwsproxy.so")
        b.missingBanner.visibility = if (so.exists()) View.GONE else View.VISIBLE
        b.tgwsVersion.text = "FlickerVPN ${BuildConfig.VERSION_NAME} · libtgwsproxy: " +
            (if (so.exists()) "найдена" else "ОТСУТСТВУЕТ")

        renderStatic()

        TgWsClient.attach(this)
        lifecycleScope.launch {
            TgWsClient.state.collect { st ->
                current = st
                render(st)
            }
        }
        // Запрашиваем снимок: сервис мог стартовать до того, как мы подписались.
        TgWsClient.query(this)
    }

    override fun onResume() {
        super.onResume()
        TgWsClient.query(this)
    }

    override fun onDestroy() {
        TgWsClient.detach(this)
        super.onDestroy()
    }

    // -----------------------------------------------------------------------
    //  Настройки
    // -----------------------------------------------------------------------

    private fun fillSettings() {
        b.inPort.setText(cfg.port.toString())
        b.inPool.setText(cfg.poolSize.toString())
        b.swCf.isChecked = cfg.cfEnabled
        b.inCfDomain.setText(cfg.cfDomain)
        b.inDcIps.setText(cfg.dcIps)
        b.swAwake.isChecked = cfg.keepAwake
        b.swAutostart.isChecked = cfg.autoStart
        b.swVerbose.isChecked = cfg.verbose
    }

    /**
     * Снимаем флаг «редактирую» через 1,5 с после последней правки.
     *
     * Зачем. Состояние приходит broadcast'ом каждые 5 с, и render() перерисовывает
     * реквизиты прокси. Если в этот момент пользователь печатает порт, поле
     * дёргается. Поэтому пока идёт ввод — реквизиты не трогаем. Полноценный
     * «focus listener на всех полях» здесь избыточен: TextWatcher уже есть,
     * а таймаут снимает блокировку сам, даже если поле потеряло фокус нестандартно.
     */
    private fun watchEdits() {
        val w = object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, a: Int, c: Int, d: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, c: Int, d: Int) {}
            override fun afterTextChanged(s: Editable?) {
                editing = true
                b.root.removeCallbacks(clearEditing)
                b.root.postDelayed(clearEditing, 1_500L)
            }
        }
        b.inPort.addTextChangedListener(w)
        b.inPool.addTextChangedListener(w)
        b.inCfDomain.addTextChangedListener(w)
        b.inDcIps.addTextChangedListener(w)
    }

    private val clearEditing = Runnable { editing = false }

    /** Собрать конфигурацию из полей. @return текст ошибки или null. */
    private fun readFields(): Pair<TgWsConfig?, String?> {
        val port = b.inPort.text.toString().trim().toIntOrNull()
        if (port == null || port !in 1..65535) {
            return null to "Порт должен быть числом от 1 до 65535"
        }
        val pool = b.inPool.text.toString().trim().toIntOrNull()
        if (pool == null || pool !in 0..16) {
            return null to "Пул соединений — число от 0 до 16"
        }
        val dc = b.inDcIps.text.toString().trim()
        if (dc.isNotEmpty() && !dc.matches(Regex("^-?\\d+:[0-9a-fA-F.:,\\s/-]+(,-?\\d+:[0-9a-fA-F.:,\\s/-]+)*$"))) {
            return null to "Адреса DC в формате 1:149.154.175.50,2:149.154.167.51"
        }
        val next = cfg.copy(
            port = port,
            poolSize = pool,
            cfEnabled = b.swCf.isChecked,
            cfDomain = b.inCfDomain.text.toString().trim(),
            dcIps = dc,
            keepAwake = b.swAwake.isChecked,
            autoStart = b.swAutostart.isChecked,
            verbose = b.swVerbose.isChecked,
        )
        return next to null
    }

    private fun apply() {
        val (next, err) = readFields()
        if (next == null) {
            toast(err ?: "Ошибка")
            return
        }
        cfg = next
        TgWsPrefs.save(this, cfg)
        editing = false
        // Перезапускаем только живой туннель: стартовать остановленный значит
        // включить его за спиной пользователя.
        if (current.running) TgWsClient.restart(this, cfg)
        toast(getString(R.string.tgws_saved))
        renderStatic()
    }

    private fun newSecret() {
        val s = TgWsPrefs.newSecret(this)
        cfg = cfg.copy(secret = s)
        toast(getString(R.string.tgws_secret_changed))
        renderStatic()
        if (current.running) TgWsClient.restart(this, cfg)
    }

    // -----------------------------------------------------------------------
    //  Действия
    // -----------------------------------------------------------------------

    private fun toggle() {
        if (current.running) {
            TgWsClient.stop(this)
            b.btnToggle.isEnabled = false
            b.root.postDelayed({ b.btnToggle.isEnabled = true }, 1_200L)
        } else {
            val (next, err) = readFields()
            if (next == null) {
                toast(err ?: "Ошибка")
                return
            }
            cfg = next
            TgWsPrefs.save(this, cfg)
            val e = TgWsClient.start(this, cfg)
            if (e != null) toast(e) else renderStatic()
        }
    }

    private fun restart() {
        val (next, err) = readFields()
        if (next == null) {
            toast(err ?: "Ошибка")
            return
        }
        cfg = next
        TgWsPrefs.save(this, cfg)
        TgWsClient.restart(this, cfg)
        renderStatic()
    }

    /**
     * `tg://proxy?server=…&port=…&secret=…`.
     *
     * Понимают AyuGram, Plus Messenger, NekoGram, Telegram Desktop.
     * Официальный клиент Telegram для Android deep-link НЕ обрабатывает —
     * тогда показываем, куда вписать вручную. Реквизиты при этом остаются
     * на экране, ничего искать не нужно.
     */
    private fun openInTelegram() {
        val uri = Uri.parse(deeplink())
        try {
            startActivity(Intent(Intent.ACTION_VIEW, uri).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        } catch (t: Throwable) {
            showNoTgDialog()
        }
    }

    private fun showNoTgDialog() {
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(R.string.tgws_title)
            .setMessage(R.string.tgws_no_tg)
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    private fun deeplink(): String =
        TgWsClient.deepLink(cfg.bindIp, cfg.port, secretFull())

    /**
     * Secret для Telegram. Приоритет — значение из натива (оно точно
     * соответствует тому, что реально слушает прокси). Пока туннель не запущен,
     * вычисляем сами: наш форк не экспортирует SetFakeTlsDomain, значит
     * fake-TLS выключен всегда и префикс всегда `dd`.
     */
    private fun secretFull(): String {
        val fromNative = current.secretFull
        if (fromNative.isNotBlank()) return fromNative
        return if (TgWsConfig.isValidSecret(cfg.secret)) "dd${cfg.secret}" else "—"
    }

    // -----------------------------------------------------------------------
    //  Отрисовка
    // -----------------------------------------------------------------------

    /** Реквизиты прокси: зависят от настроек, а не от состояния сервиса. */
    private fun renderStatic() {
        b.valServer.text = cfg.bindIp
        b.valPort.text = cfg.port.toString()
        b.valSecret.text = secretFull()
    }

    private fun render(st: TgWsState) {
        val (badge, badgeBg, badgeColor, text) = when {
            st.error.isNotBlank() && !st.verified ->
                Badge(getString(R.string.tgws_badge_err), R.drawable.badge_err, 0xFFFF9DB3.toInt(), st.error)
            st.verified ->
                Badge(getString(R.string.tgws_badge_on), R.drawable.badge_ok, 0xFF0B0F1A.toInt(),
                    getString(R.string.tgws_endpoint, "${cfg.bindIp}:${cfg.port}"))
            st.running ->
                Badge(getString(R.string.tgws_badge_starting), R.drawable.badge_off, 0xFF8A93A8.toInt(),
                    getString(R.string.tgws_starting))
            else ->
                Badge(getString(R.string.tgws_badge_off), R.drawable.badge_off, 0xFF8A93A8.toInt(),
                    getString(R.string.tgws_off_detail, "${cfg.bindIp}:${cfg.port}"))
        }
        b.statusBadge.text = badge
        b.statusBadge.setBackgroundResource(badgeBg)
        b.statusBadge.setTextColor(badgeColor)
        b.statusText.text = text

        val err = if (st.error.isNotBlank() && !st.verified) st.error else ""
        b.errorText.visibility = if (err.isBlank()) View.GONE else View.VISIBLE
        b.errorText.text = err

        b.statsText.text = st.stats.ifBlank { getString(R.string.tgws_stats_empty) }

        b.btnToggle.setText(if (st.running) R.string.tgws_btn_stop else R.string.tgws_btn_start)
        b.btnRestart.isEnabled = st.running
        b.btnOpenTg.isEnabled = st.verified || TgWsConfig.isValidSecret(cfg.secret)

        if (!editing) renderStatic()

        val log = st.log
        val logText = if (log.isEmpty()) getString(R.string.tgws_log_empty) else log.joinToString("\n")
        if (b.logText.text.toString() != logText) {
            b.logText.text = logText
            // прокручиваем вниз: свежее внизу, а смотреть нужно именно его
            b.logScroll.post { b.logScroll.fullScroll(View.FOCUS_DOWN) }
        }
    }

    private data class Badge(val text: String, val bg: Int, val color: Int, val status: String)

    // -----------------------------------------------------------------------

    private fun copy(value: String, label: String) {
        if (value.isBlank() || value == "—") {
            toast(label + ": нечего копировать")
            return
        }
        try {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText(label, value))
            toast(getString(R.string.tgws_copied) + ": " + label)
        } catch (t: Throwable) {
            toast("Не удалось скопировать: ${t.javaClass.simpleName}")
        }
    }

    private fun copyLog() {
        val head = buildString {
            append("FlickerVPN ").append(BuildConfig.VERSION_NAME).append('\n')
            append("Telegram-туннель: ")
            append(
                when {
                    current.verified -> "работает"
                    current.running -> "запускается"
                    else -> "остановлен"
                }
            ).append('\n')
            append("endpoint: ").append(cfg.bindIp).append(':').append(cfg.port).append('\n')
            append("secret: ").append(secretFull()).append('\n')
            append("настройки: pool=").append(cfg.poolSize)
                .append(" cf=").append(cfg.cfEnabled)
                .append(" cfDomain=").append(cfg.cfDomain.ifBlank { "-" })
                .append(" dcIps=").append(cfg.dcIps.ifBlank { "-" })
                .append(" keepAwake=").append(cfg.keepAwake).append('\n')
            append("stats: ").append(current.stats.ifBlank { "-" }).append('\n')
            append("error: ").append(current.error.ifBlank { "-" }).append('\n')
            append("--- журнал ядра (").append(current.log.size).append(" строк) ---\n")
        }
        copy(head + current.log.joinToString("\n"), "tgws-log")
        toast(getString(R.string.tgws_log_copied))
    }

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_SHORT).show()
}
