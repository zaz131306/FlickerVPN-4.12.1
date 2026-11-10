// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn

import android.Manifest
import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.util.Log
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.google.android.material.switchmaterial.SwitchMaterial
import dev.flicker.mobile.Mobile
import dev.flicker.vpn.core.tgws.TgWsClient
import dev.flicker.vpn.core.tgws.TgWsState
import dev.flicker.vpn.databinding.ActivityMainBinding
import dev.flicker.vpn.util.Battery
import dev.flicker.vpn.util.Prefs
import dev.flicker.vpn.util.SourceHealth
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var adapter: ServerAdapter
    private val checkingIds = mutableSetOf<String>()

    /**
     * v4.12.0: запрошен ли системный диалог согласия для ОБХОДА DPI.
     *
     * Колбэк vpnPrepare раньше всегда звал connectNow(), а тому нужен
     * выбранный узел (selectedServerJson ?: return) — в режиме обхода узла
     * нет, и подтверждение согласия молча терялось. Плюс connectBypass()
     * вообще не вызывал VpnService.prepare(): на свежей установке (согласие
     * ещё не дано) establish() в сервисе падал — «проблема с подключением».
     */
    private var pendingBypass = false

    private val vpnPrepare =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                if (pendingBypass) startBypassNow() else connectNow()
            } else {
                pendingBypass = false
                toast(getString(R.string.err_vpn_denied))
                renderUi()
            }
        }

    private val askNotifications =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    private val stateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != TunnelService.BROADCAST_STATE) return
            val connected = intent.getBooleanExtra(TunnelService.EXTRA_CONNECTED, false)
            val message = intent.getStringExtra(TunnelService.EXTRA_MESSAGE)
            // v4.12.0: синхронизация состояния в ЭТОТ (основной) процесс.
            //
            // Обход DPI живёт в процессе :bypass: Repository.setConnected и
            // AppState обновляются ТАМ, а UI читает свои внутрипроцессные
            // копии здесь. Без этой синхронизации подключение обхода никогда
            // не отображалось: кнопка оставалась «Подключить», горела плашка
            // рассинхрона, плитка сбрасывалась в «выключено».
            val name = intent.getStringExtra(TunnelService.EXTRA_NAME)
            if (connected) {
                Repository.setConnected(true, name ?: "")
                dev.flicker.vpn.data.AppState.update(
                    dev.flicker.vpn.data.ServiceStatus.Connected,
                    serverName = name ?: ""
                )
            } else {
                Repository.setConnected(false, "")
                if (!message.isNullOrEmpty()) {
                    dev.flicker.vpn.data.AppState.update(
                        dev.flicker.vpn.data.ServiceStatus.Failed, error = message
                    )
                } else {
                    dev.flicker.vpn.data.AppState.update(
                        dev.flicker.vpn.data.ServiceStatus.Disconnected
                    )
                }
            }
            if (!connected && !message.isNullOrEmpty()) {
                AlertDialog.Builder(this@MainActivity)
                    .setTitle(R.string.dlg_error_title)
                    .setMessage(message)
                    .setPositiveButton(android.R.string.ok, null)
                    .show()
            }
            // v4.2.0: в режиме «Прокси» один раз показываем инструкцию,
            // куда вписать прокси в Telegram.
            if (connected &&
                dev.flicker.vpn.data.AppState.mode == dev.flicker.vpn.data.TunnelMode.Proxy &&
                !proxyHintShown
            ) {
                proxyHintShown = true
                showProxyHint()
            }
            if (!connected) proxyHintShown = false
            renderUi()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)

        adapter = ServerAdapter(
            onClick = { row ->
                Repository.setSelectedId(row.id)
                renderUi()
            },
            onLongClick = { row -> showServerDetails(row) }
        )
        binding.serverList.layoutManager = LinearLayoutManager(this)
        binding.serverList.adapter = adapter

        binding.btnRefresh.setOnClickListener { refreshSubs() }
        binding.btnProbe.setOnClickListener {
            if (Repository.ui.value.connected) {
                toast(getString(R.string.probe_disabled_while_connected))
            } else {
                probeServers()
            }
        }
        binding.btnConnect.setOnClickListener {
            if (Repository.ui.value.connected) disconnect() else connectSelected()
        }
        binding.btnSettings.setOnClickListener { showSettings() }

        // v4.7.0: режимы и аварийное отключение — на главном экране, не в меню.
        binding.btnModeBypass.setOnClickListener { setMode(Prefs.MODE_BYPASS) }
        binding.btnModeVpn.setOnClickListener { setMode(Prefs.MODE_VPN) }
        binding.btnModeProxy.setOnClickListener { setMode(Prefs.MODE_PROXY) }
        binding.btnHardStop.setOnClickListener { confirmHardStop() }
        // v4.10.0: строка Telegram-туннеля открывает его экран. Туннель
        // независим от VPN, поэтому здесь именно переход на экран, а не
        // переключение режима.
        binding.tgwsRow.setOnClickListener { openTgWs() }
        // v4.7.1: строка «Пресет: …» в карточке состояния — кликабельна, но
        // только в режиме обхода DPI. Так выбор стратегии обнаруживается с
        // главного экрана, без похода в настройки.
        binding.targetText.setOnClickListener {
            if (Prefs.mode(this) == Prefs.MODE_BYPASS) showPresetDialog()
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            askNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

        // Прошлая сессия не завершилась штатно -> процесс убили.
        // Показываем один раз, чтобы пользователь знал: крах был, и есть где
        // посмотреть причину. Маркер снимается сразу, иначе диалог вылезал бы
        // при каждом запуске.
        if (CrashLog.previousSessionCrashed(this)) {
            CrashLog.markCleanExit(this)
            AlertDialog.Builder(this)
                .setTitle(R.string.crash_detected_title)
                .setMessage(R.string.crash_detected_message)
                .setPositiveButton(R.string.crash_log_title) { _, _ -> showCrashLog() }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        }

        if (!FlickerApp.nativeReady) {
            // Показываем причину, а не абстрактное «ядро не загружено».
            // Native.failureReason содержит конкретику: нет .so под эту ABI,
            // dlopen отклонил библиотеку, 16KB-выравнивание и т.д.
            AlertDialog.Builder(this)
                .setTitle(R.string.dlg_error_title)
                .setMessage(Native.userVisibleError ?: getString(R.string.err_native_missing))
                .setPositiveButton(android.R.string.ok, null)
                .show()
            // ВАЖНО: при неготовом ядре не запускаем автообновление.
            // Раньше код показывал диалог и СРАЗУ ПОСЛЕ этого вызывал
            // refreshSubs() → Repository.refresh() → Mobile.normalizeSources(),
            // то есть native-вызов при незагруженной библиотеке. Диалог не успевал
            // отрисоваться — процесс падал. Теперь refresh() защищён и внутри,
            // но нет смысла вообще дёргать сеть, если ядра нет.
            renderUi()
            return
        }

        lifecycleScope.launch {
            combine(Repository.servers, Repository.ui) { s, u -> Pair(s, u) }
                .collect { renderUi() }
        }

        // v4.8.1: в режиме обхода DPI подписки и узлы не используются вовсе,
        // поэтому тянуть списки серверов при старте незачем — это лишний
        // трафик и батарея ради данных, которые в этом режиме никто не читает.
        if (Prefs.mode(this) != Prefs.MODE_BYPASS &&
            Repository.autoRefresh && Repository.rawServers() == "[]"
        ) {
            refreshSubs()
        }
        renderUi()
    }

    override fun onResume() {
        super.onResume()
        ContextCompat.registerReceiver(
            this, stateReceiver,
            IntentFilter(TunnelService.BROADCAST_STATE),
            ContextCompat.RECEIVER_NOT_EXPORTED
        )
        // v4.10.0: состояние Telegram-туннеля приходит из процесса ":tgws"
        // broadcast'ом. Подписываемся здесь и сразу просим снимок: прокси мог
        // быть поднят давно (из уведомления или автозапуска), а кэш в этом
        // процессе пуст.
        TgWsClient.attach(this)
        TgWsClient.query(this)
        tgwsJob?.cancel()
        tgwsJob = lifecycleScope.launch { TgWsClient.state.collect { renderTgws(it) } }
        // v4.12.0: догнать состояние обхода DPI, если UI перезапустился,
        // а туннель в :bypass жив (broadcast уже не придёт).
        syncBypassState()
        renderUi()
        // v4.7.0: счётчики трафика приходят из ядра раз в 2 с
        // (Libbox.CommandStatus), а broadcast о них не рассылается — поэтому
        // просто перечитываем их, пока экран виден. Тикер снимается в onPause,
        // чтобы не будить UI в фоне.
        binding.root.removeCallbacks(trafficTicker)
        binding.root.postDelayed(trafficTicker, TRAFFIC_REFRESH_MS)
    }

    override fun onPause() {
        super.onPause()
        binding.root.removeCallbacks(trafficTicker)
        // v4.10.0: подписка на состояние туннеля живёт на отдельном Job, а не
        // на голом lifecycleScope: сам lifecycleScope отменяется только в
        // onDestroy, а обновлять строку на невидимом экране незачем.
        tgwsJob?.cancel()
        tgwsJob = null
        TgWsClient.detach(this)
        try {
            unregisterReceiver(stateReceiver)
        } catch (_: Exception) {
        }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.menu_main, menu)
        val searchItem = menu.findItem(R.id.action_search)
        val searchView = searchItem?.actionView as? androidx.appcompat.widget.SearchView
        searchView?.queryHint = getString(R.string.action_search)
        searchView?.setOnQueryTextListener(object : androidx.appcompat.widget.SearchView.OnQueryTextListener {
            override fun onQueryTextSubmit(query: String?): Boolean {
                adapter.filter(query.orEmpty())
                return true
            }
            override fun onQueryTextChange(newText: String?): Boolean {
                adapter.filter(newText.orEmpty())
                return true
            }
        })
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            R.id.action_about -> {
                showAbout()
                return true
            }
            R.id.action_crash_log -> {
                showCrashLog()
                return true
            }
            R.id.action_diagnostics -> {
                showDiagnostics()
                return true
            }
            R.id.action_mode -> {
                showModeDialog()
                return true
            }
            R.id.action_netcheck -> {
                runInternetCheck()
                return true
            }
            R.id.action_hard_stop -> {
                confirmHardStop()
                return true
            }
            R.id.action_strategy_test -> {
                runStrategyTest()
                return true
            }
            R.id.action_tgws -> {
                openTgWs()
                return true
            }
            R.id.action_settings -> {
                showSettings()
                return true
            }
            R.id.action_update_subs -> {
                refreshSubs()
                return true
            }
            R.id.action_exit -> {
                confirmExit()
                return true
            }
        }
        return super.onOptionsItemSelected(item)
    }

    /**
     * Диагностический дамп: устройство, состояние ядра, разрешение VPN, сеть
     * и — главное — сгенерированный конфиг sing-box с вычищенными секретами.
     *
     * Зачем: молчаливый краш при подключении нельзя воспроизвести без телефона,
     * а конфиг можно провалидировать офлайн по исходникам option/<имя>.go нужной
     * версии sing-box. Именно так были найдены ошибки `dns.servers[].address`
     * и `sniff` на tun-inbound — обе давали фатальный отказ разбора конфига.
     */
    private fun showDiagnostics() {
        val dump = try {
            Diagnostics.collect(this)
        } catch (e: Throwable) {
            "не удалось собрать диагностику: ${e.javaClass.simpleName}: ${e.message}"
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.diagnostics_title)
            // Дамп длинный, в диалоге его не прочитать целиком — поэтому
            // основное действие «Копировать», а текст показываем хвостом.
            .setMessage(getString(R.string.diagnostics_hint) + "\n\n" +
                (if (dump.length > 2500) "…" + dump.takeLast(2500) else dump))
            .setPositiveButton(R.string.diagnostics_copy) { _, _ ->
                val cm = getSystemService(Context.CLIPBOARD_SERVICE)
                    as? android.content.ClipboardManager
                cm?.setPrimaryClip(android.content.ClipData.newPlainText("flicker-diagnostics", dump))
                toast(getString(R.string.diagnostics_saved))
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * Журнал сбоев — прямо на телефоне, без adb.
     *
     * Нужен потому, что приложение закрывалось при подключении БЕЗ диалога:
     * ни краш-репорта, ни внятной причины. Теперь Java-исключения пишутся
     * в filesDir/crash.log (CrashLog), а здесь их можно прочитать и скопировать.
     *
     * Если журнал ПУСТ, а приложение всё равно закрылось — значит крах нативный
     * (SIGSEGV/SIGABRT внутри libflickerbox.so) либо исключение улетело из
     * JNI-колбэка обратно в Go. Java-обработчик такое не ловит по определению;
     * тогда нужен logcat (команды в docs/06-TESTING.md).
     */
    private fun showCrashLog() {
        // v4.0.8: перед показом заново выгребаем системный crash-буфер —
        // tombstone дописывается системой 1-3 секунды ПОСЛЕ «Fatal signal»,
        // и слив по горячим следам его обрезал. Теперь буфер содержит полный
        // набор кадров и Abort message.
        CrashLog.dumpCrashBufferSync(this)
        val text = CrashLog.read(this, 60000, 30000)
        // Показываем ОБА пути: наш Java-журнал и файл, куда libbox
        // перенаправил stderr процесса. Второй — главный при нативном крахе:
        // Go-паника в libflickerbox.so попадает только туда.
        val paths = getString(R.string.crash_log_path, CrashLog.path(this)) +
            "\n" + getString(R.string.crash_log_path, Native.nativeCrashReport(this).absolutePath)
        val body = if (!CrashLog.hasAnyRecord(this)) {
            getString(R.string.crash_log_empty) + "\n\n" + paths
        } else {
            // v4.1.0: показываем и НАЧАЛО (раздел «ПРИЧИНА (кратко)» — там строка паники), и хвост (свежие записи).
            val shown = if (text.length > 9000)
                text.take(5000) + "\n…(середина обрезана — полный текст в «Поделиться»/«Копировать»)…\n" + text.takeLast(3500)
            else text
            shown + "\n\n" + paths
        }
        // v4.0.5: диалог с собственным набором кнопок — «Копировать»,
        // «Поделиться» (системный ACTION_SEND: Telegram, почта, заметки —
        // лог можно отправить прямо с телефона без ПК), «Очистить», «Закрыть».
        val pad = (14 * resources.displayMetrics.density).toInt()
        val container = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(pad, pad / 2, pad, 0)
        }
        val scroll = android.widget.ScrollView(this).apply {
            addView(android.widget.TextView(context).apply {
                this.text = body
                setTextIsSelectable(true)
                typeface = android.graphics.Typeface.MONOSPACE
                textSize = 10f
            })
            layoutParams = android.widget.LinearLayout.LayoutParams(
                android.widget.LinearLayout.LayoutParams.MATCH_PARENT,
                (300 * resources.displayMetrics.density).toInt()
            )
        }
        container.addView(scroll)
        val buttons = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.HORIZONTAL
            setPadding(0, pad / 2, 0, pad / 2)
        }
        val dlg = AlertDialog.Builder(this)
            .setTitle(R.string.crash_log_title)
            .setView(container)
            .create()
        fun mkBtn(label: String, action: () -> Unit) {
            buttons.addView(android.widget.Button(this).apply {
                this.text = label
                setAllCaps(false)
                textSize = 12f
                setOnClickListener { action() }
                layoutParams = android.widget.LinearLayout.LayoutParams(
                    0, android.widget.LinearLayout.LayoutParams.WRAP_CONTENT, 1f
                )
            })
        }
        mkBtn("Копировать") {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as? android.content.ClipboardManager
            cm?.setPrimaryClip(android.content.ClipData.newPlainText("crash.log", text))
            toast("Скопировано в буфер")
        }
        mkBtn("Поделиться") {
            try {
                val send = android.content.Intent(android.content.Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(android.content.Intent.EXTRA_SUBJECT, "FlickerVPN — журнал сбоев")
                    putExtra(android.content.Intent.EXTRA_TEXT, text)
                }
                startActivity(android.content.Intent.createChooser(send, "Отправить журнал"))
            } catch (e: Throwable) {
                toast("Не удалось открыть «Поделиться»: " + e.message)
            }
        }
        mkBtn("Очистить") {
            CrashLog.clear(this)
            dlg.dismiss()
            toast("Журнал очищен")
        }
        mkBtn("Закрыть") { dlg.dismiss() }
        container.addView(buttons)
        dlg.show()
    }

    // ---------- v4.2.0: режим подключения и проверка интернета ----------

    private var proxyHintShown = false

    private fun showModeDialog() {
        // v4.7.1: три режима, и выбор идёт через setMode() — там же проверка
        // «туннель поднят, нужно переподключиться». Раньше этот диалог писал
        // Prefs.setMode() напрямую, минуя проверку.
        val modes = arrayOf(
            "Обход DPI (без сервера, подмена пакетов — как ByeByeDPI)",
            "VPN-туннель через узел (весь трафик телефона)",
            "Локальный прокси (SOCKS5 для Telegram)"
        )
        val current = when (dev.flicker.vpn.util.Prefs.mode(this)) {
            dev.flicker.vpn.util.Prefs.MODE_BYPASS -> 0
            dev.flicker.vpn.util.Prefs.MODE_PROXY -> 2
            else -> 1
        }
        AlertDialog.Builder(this)
            .setTitle("Режим подключения")
            // v4.8.1: объяснение разницы. Без него два режима выглядят
            // одинаково («и то и другое включает ключик»), и непонятно,
            // зачем они оба.
            .setMessage(
                "Обход DPI — трафик идёт НАПРЯМУЮ к сайту, пакеты искажаются, " +
                    "чтобы фильтр не узнал запрос. Сервер и подписка не нужны, " +
                    "скорость полная. Не спасает, если блокировка по IP, а не по сигнатуре.\n\n" +
                    "VPN-узел — трафик идёт через зарубежный сервер. Обходит ЛЮБУЮ " +
                    "блокировку, включая по IP, и скрывает от провайдера, куда вы " +
                    "ходите. Нужен живой узел, скорость ниже.\n\n" +
                    "Прокси — локальный SOCKS5 без системного VPN: прописывается " +
                    "внутри приложения (например, в настройках Telegram)."
            )
            .setSingleChoiceItems(modes, current) { d, which ->
                d.dismiss()
                setMode(
                    when (which) {
                        0 -> dev.flicker.vpn.util.Prefs.MODE_BYPASS
                        2 -> dev.flicker.vpn.util.Prefs.MODE_PROXY
                        else -> dev.flicker.vpn.util.Prefs.MODE_VPN
                    }
                )
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun showProxyHint() {
        AlertDialog.Builder(this)
            .setTitle("Локальный прокси запущен")
            .setMessage(
                "SOCKS5-прокси: 127.0.0.1, порт ${TunnelService.PROXY_PORT}\n\n" +
                    "Чтобы Telegram ходил через него:\n" +
                    "Telegram → Настройки → Данные и память → Прокси →\n" +
                    "«Использовать прокси» → Добавить → SOCKS5\n" +
                    "Сервер: 127.0.0.1\nПорт: ${TunnelService.PROXY_PORT}\n\n" +
                    "Instagram внутриприложенческий прокси не поддерживает —\n" +
                    "для него используйте режим VPN-туннеля."
            )
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    private fun runInternetCheck() {
        val progress = AlertDialog.Builder(this)
            .setTitle("Проверка интернета")
            .setMessage("Измеряю: выходной IP → Telegram API → Instagram…")
            .setCancelable(false)
            .show()
        lifecycleScope.launch {
            val report = withContext(Dispatchers.IO) { netCheck() }
            progress.dismiss()
            CrashLog.note(this@MainActivity, "Проверка интернета:\n" + report)
            AlertDialog.Builder(this@MainActivity)
                .setTitle("Проверка интернета")
                .setMessage(report)
                .setPositiveButton(android.R.string.ok, null)
                .setNeutralButton("Копировать") { _, _ ->
                    val cm = getSystemService(Context.CLIPBOARD_SERVICE) as? android.content.ClipboardManager
                    cm?.setPrimaryClip(android.content.ClipData.newPlainText("netcheck", report))
                    toast("Скопировано — можно переслать")
                }
                .show()
        }
    }

    /**
     * Самодиагностика туннеля: три контрольных запроса ПОСЛЕ подключения.
     * Отвечает на главный вопрос удалённой отладки: трафик вообще ходит
     * через узел или нет, и доступны ли с узла целевые сервисы.
     */
    private fun netCheck(): String {
        val sb = StringBuilder()
        sb.append("FlickerVPN v").append(BuildConfig.VERSION_NAME)
            .append(" (").append(BuildConfig.VERSION_CODE).append(")\n")
        sb.append("Режим: ")
            .append(if (dev.flicker.vpn.util.Prefs.mode(this) == "proxy") "ПРОКСИ (замеры идут МИМО прокси — они для VPN-режима)" else "VPN")
            .append("\n")
        sb.append("Статус: ").append(dev.flicker.vpn.data.AppState.status).append("\n")
        sb.append("Узел: ").append(Repository.selectedServer()?.name ?: "—").append("\n\n")

        fun fetch(url: String, wantBody: Boolean): String = try {
            val c = java.net.URL(url).openConnection() as java.net.HttpURLConnection
            c.connectTimeout = 10000
            c.readTimeout = 12000
            c.instanceFollowRedirects = false
            val code = c.responseCode
            var body = ""
            if (wantBody) {
                body = try {
                    (c.inputStream ?: c.errorStream)?.bufferedReader()?.readText()?.take(60) ?: ""
                } catch (_: Throwable) { "" }
            }
            c.disconnect()
            if (wantBody) body.ifBlank { "HTTP $code" } else "HTTP $code"
        } catch (t: Throwable) {
            "ОШИБКА: ${t.javaClass.simpleName}"
        }

        sb.append("1) Выходной IP: ").append(fetch("https://api.ipify.org", true)).append("\n")
        sb.append("2) Telegram API (доступен = HTTP 401/404): ")
            .append(fetch("https://api.telegram.org/getMe", false)).append("\n")
        sb.append("3) Instagram (доступен = HTTP 200/301/302): ")
            .append(fetch("https://www.instagram.com/", false)).append("\n\n")
        sb.append("Выводы:\n")
        sb.append("· другие VPN-приложения (ByeByeDPI и т.п.) должны быть ВЫКЛЮЧЕНЫ:\n  в Android работает только один VPN, два вместе = чёрная дыра для трафика;\n")
        sb.append("· п.1 = ваш домашний IP или ошибка → трафик НЕ идёт через туннель;\n")
        sb.append("· п.1 = иностранный IP, п.2/3 ошибки → узел не выпускает трафик, смените узел;\n")
        sb.append("· всё HTTP → туннель полностью рабочий.")
        return sb.toString()
    }

    // ---------- отрисовка ----------

    // ------------------------------------------------------------------
    //  v4.10.0: Telegram-туннель на главном экране
    // ------------------------------------------------------------------

    /**
     * Job подписки на состояние Telegram-туннеля. Отдельный от lifecycleScope
     * запуск нужен, чтобы снимать подписку в onPause: сам lifecycleScope
     * отменяется только в onDestroy, а обновлять строку на невидимом экране
     * незачем.
     */
    private var tgwsJob: kotlinx.coroutines.Job? = null

    private fun openTgWs() {
        try {
            startActivity(Intent(this, TgWsActivity::class.java))
        } catch (t: Throwable) {
            Log.e(FlickerApp.TAG, "не удалось открыть экран Telegram-туннеля", t)
            toast("Не удалось открыть экран: ${t.javaClass.simpleName}")
        }
    }

    /**
     * Строка Telegram-туннеля под переключателем режимов.
     *
     * Показываем именно СОСТОЯНИЕ, а не намерение: если сервис поднят, но
     * натив ещё не занял порт (он тянет список доменов CloudFlare), пишем
     * «запуск…». Тот же принцип, что в renderDesyncBanner() — не врать
     * пользователю про «работает».
     */
    private fun renderTgws(st: TgWsState) {
        val dot = when {
            st.verified -> R.drawable.dot_ok
            st.error.isNotBlank() -> R.drawable.dot_dead
            st.running -> R.drawable.dot_warn
            else -> R.drawable.dot_unknown
        }
        binding.tgwsDot.setBackgroundResource(dot)

        // Адрес берём ИЗ СОСТОЯНИЯ, а не из настроек: TgWsPrefs.load() при
        // пустом секрете генерирует и сохраняет новый, то есть имеет побочный
        // эффект. Звать её из функции отрисовки, которая срабатывает каждые
        // 5 секунд, — значит писать в SharedPreferences на ровном месте.
        val endpoint = st.endpoint.ifBlank { "127.0.0.1" }
        val text = when {
            st.error.isNotBlank() && !st.verified -> getString(R.string.tgws_main_row_err)
            st.verified -> getString(R.string.tgws_main_row_on_short, endpoint)
            st.running -> getString(R.string.tgws_main_row_starting)
            else -> getString(R.string.tgws_main_row_off_short)
        }
        binding.tgwsText.text = text
        binding.tgwsText.setTextColor(
            if (st.verified) 0xFFE8ECF5.toInt() else 0xFF8A93A8.toInt()
        )
    }

    private fun renderUi() {
        val ui = Repository.ui.value
        val rows = Repository.servers.value
        adapter.submit(rows, Repository.selectedId, checkingIds)
        binding.emptyHint.visibility = if (rows.isEmpty()) View.VISIBLE else View.GONE
        binding.progress.visibility =
            if (ui.refreshing || ui.probing) View.VISIBLE else View.INVISIBLE

        binding.btnRefresh.isEnabled = !ui.refreshing && !ui.probing
        binding.btnProbe.isEnabled = !ui.refreshing && !ui.probing && rows.isNotEmpty() && !ui.connected
        binding.btnConnect.isEnabled = !ui.refreshing

        val selected = Repository.selectedServer()
        if (ui.connected) {
            binding.statusBadge.setText(R.string.status_connected)
            binding.statusBadge.setBackgroundResource(R.drawable.badge_ok)
            binding.statusText.text = getString(R.string.status_connected_to, ui.connectedName)
            binding.btnConnect.setText(R.string.btn_disconnect)
        } else {
            binding.statusBadge.setText(R.string.status_disconnected)
            binding.statusBadge.setBackgroundResource(R.drawable.badge_off)
            binding.statusText.text = selected?.let {
                getString(R.string.status_selected, it.name)
            } ?: getString(R.string.status_no_selection)
            binding.btnConnect.setText(R.string.btn_connect)
        }

        // v4.7.0: вызываем ПОСЛЕ основного блока — renderModeButtons()
        // переопределяет видимость списка и доступность кнопок, и его слово
        // должно быть последним.
        renderStateCard(ui, selected)
        renderDesyncBanner()
        renderModeButtons()
    }

    // ------------------------------------------------------------------
    //  v4.7.0: карточка состояния, режимы, рассинхрон
    // ------------------------------------------------------------------

    /** Период перечитывания счётчиков трафика. Ядро отдаёт их раз в 2 с. */
    private val TRAFFIC_REFRESH_MS = 1_500L

    private val trafficTicker = object : Runnable {
        override fun run() {
            renderTraffic()
            binding.root.postDelayed(this, TRAFFIC_REFRESH_MS)
        }
    }

    /**
     * v4.12.0: живой ли туннель — с учётом обхода DPI.
     *
     * [TunnelService.isLive] (instance?.started) видит только сервис СВОЕГО
     * процесса, а обход работает в :bypass — отсюда вечно false и ложная
     * плашка рассинхрона. Для режима обхода источник правды — наличие
     * VPN-интерфейса в системе (см. TunnelService.isVpnInterfaceUp).
     */
    private fun tunnelLive(): Boolean =
        TunnelService.isLive ||
            (Prefs.mode(this) == Prefs.MODE_BYPASS && TunnelService.isVpnInterfaceUp(this))

    /**
     * v4.12.0: холодная синхронизация состояния обхода DPI.
     *
     * Если приложение перезапущено, а обход жив (:bypass пережил рестарт UI),
     * восстановить «подключено» в этом процессе: из broadcast'а состояние уже
     * не придёт (он одноразовый), а VPN-интерфейс система видит всегда.
     */
    private fun syncBypassState() {
        if (Prefs.mode(this) != Prefs.MODE_BYPASS) return
        if (Repository.ui.value.connected) return
        if (!TunnelService.isVpnInterfaceUp(this)) return
        val name = if (Prefs.byedpiCommand(this).isNotBlank()) {
            "Обход DPI · своя командная строка"
        } else {
            "Обход DPI · ${dev.flicker.vpn.core.ByeDpiArgs.preset(Prefs.byedpiPreset(this)).title}"
        }
        Repository.setConnected(true, name)
        dev.flicker.vpn.data.AppState.update(
            dev.flicker.vpn.data.ServiceStatus.Connected,
            serverName = name
        )
    }

    private fun modeTitle(mode: String): String = when (mode) {
        Prefs.MODE_BYPASS -> getString(R.string.mode_bypass)
        Prefs.MODE_PROXY -> getString(R.string.mode_proxy_local)
        else -> getString(R.string.mode_vpn_node)
    }

    /** Режим + цель (узел ИЛИ пресет обхода) + трафик. */
    private fun renderStateCard(ui: Repository.UiState, selected: Repository.ServerRow?) {
        val mode = Prefs.mode(this)
        binding.modeText.text = getString(R.string.status_mode, modeTitle(mode))
        binding.targetText.text = if (mode == Prefs.MODE_BYPASS) {
            getString(
                R.string.status_target_preset,
                dev.flicker.vpn.core.ByeDpiArgs.preset(Prefs.byedpiPreset(this)).title
            )
        } else {
            val name = if (ui.connected) ui.connectedName else selected?.name.orEmpty()
            if (name.isBlank()) getString(R.string.status_target_none)
            else getString(R.string.status_target_node, name)
        }
        renderTraffic()
    }

    private fun renderTraffic() {
        val svc = TunnelService.instance
        if (svc == null || !TunnelService.isLive) {
            binding.trafficText.setText(R.string.traffic_idle)
            return
        }
        val upTotal = svc.statUplinkTotal
        val downTotal = svc.statDownlinkTotal
        if (upTotal == 0L && downTotal == 0L && svc.statConnectionsIn == 0L) {
            binding.trafficText.setText(R.string.traffic_idle)
            return
        }
        binding.trafficText.text = getString(
            R.string.traffic_line,
            formatBytes(svc.statUplink), formatBytes(svc.statDownlink),
            formatBytes(upTotal), formatBytes(downTotal)
        )
    }

    private fun formatBytes(v: Long): String = when {
        v < 1024L -> "$v Б"
        v < 1024L * 1024 -> String.format(java.util.Locale.US, "%.1f КБ", v / 1024.0)
        v < 1024L * 1024 * 1024 -> String.format(java.util.Locale.US, "%.1f МБ", v / (1024.0 * 1024))
        else -> String.format(java.util.Locale.US, "%.2f ГБ", v / (1024.0 * 1024 * 1024))
    }

    /**
     * Красная плашка: UI утверждает, что подключено, а живого сервиса нет.
     *
     * Это ровно та ситуация, при которой ключик в статусбаре висит, а кнопка
     * «Отключить» ничего не делает: состояние хранимое, обновлять его было
     * некому. Сверяем с [TunnelService.isLive] — вычисляемым состоянием
     * (принцип Intra `VpnController.getState()` и v2rayNG `isRunning()`).
     */
    private fun renderDesyncBanner() {
        val claimsConnected = Repository.ui.value.connected ||
            dev.flicker.vpn.data.AppState.status == dev.flicker.vpn.data.ServiceStatus.Connected
        val desync = claimsConnected && !tunnelLive()
        binding.desyncBanner.visibility = if (desync) View.VISIBLE else View.GONE
        // НАМЕРЕННО без побочных эффектов.
        //
        // Соблазн «сразу сбросить залипшее состояние» здесь вреден по двум
        // причинам:
        //   1. на Repository.ui подписан `combine(...).collect { renderUi() }`
        //      (onCreate), то есть setUi() внутри renderUi() запускает новый
        //      проход рендера. Сошлось бы за два круга, но менять состояние
        //      из функции отрисовки — лишний риск;
        //   2. плашка исчезла бы мгновенно, а она ДОЛЖНА висеть, пока
        //      пользователь не нажмёт «Снять» — это единственное видимое
        //      свидетельство того, что ключик в статусбаре не соответствует
        //      реальности.
        // Сброс происходит сам: hardStop() завершает процесс, а при следующем
        // запуске AppState и Repository.ui стартуют с чистыми значениями.
    }

    private fun renderModeButtons() {
        val mode = Prefs.mode(this)
        fun paint(v: View, on: Boolean) {
            v.setBackgroundResource(if (on) R.drawable.mode_btn_sel else R.drawable.mode_btn)
            if (v is android.widget.TextView) {
                v.setTextColor(if (on) 0xFF0B0F1A.toInt() else 0xFFE8ECF5.toInt())
            }
        }
        paint(binding.btnModeBypass, mode == Prefs.MODE_BYPASS)
        paint(binding.btnModeVpn, mode == Prefs.MODE_VPN)
        paint(binding.btnModeProxy, mode == Prefs.MODE_PROXY)

        // В режиме обхода DPI список узлов и подписки не используются:
        // внешнего сервера там нет. Скрываем, чтобы не вводить в заблуждение.
        val bypass = mode == Prefs.MODE_BYPASS
        val ui = Repository.ui.value
        binding.serverList.visibility = if (bypass) View.GONE else View.VISIBLE
        binding.emptyHint.visibility =
            if (!bypass && Repository.servers.value.isEmpty()) View.VISIBLE else View.GONE
        binding.btnRefresh.isEnabled = !bypass && !ui.refreshing && !ui.probing
        binding.btnProbe.isEnabled = !bypass && !ui.refreshing && !ui.probing && !ui.connected
    }

    private fun setMode(mode: String) {
        if (Prefs.mode(this) == mode) return

        if (tunnelLive()) {
            // Конфиг туннеля зависит от режима, поэтому на живом туннеле его
            // нужно пересобрать. Проще и честнее остановить и включить заново,
            // чем перезапускать ядро под пользователем.
            AlertDialog.Builder(this)
                .setTitle("Сменить режим")
                .setMessage("Туннель сейчас поднят. Для смены режима его нужно отключить и включить заново. Отключить?")
                .setPositiveButton("Отключить и сменить") { _, _ ->
                    Prefs.setMode(this, mode)
                    disconnect()
                    toast("Режим: ${modeTitle(mode)}. Нажмите «Подключить».")
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
            return
        }

        Prefs.setMode(this, mode)
        renderUi()
        toast("Режим: ${modeTitle(mode)}")
    }

    // ---------- действия ----------

    private fun refreshSubs() {
        Repository.refresh(
            onProgress = { text ->
                runOnUiThread {
                    binding.statusText.text = text
                }
            },
            onDone = { _, text ->
                runOnUiThread {
                    Repository.setUi { it.copy(refreshing = false, statusText = "") }
                    toast(text)
                    renderUi()
                }
            }
        )
    }

    private fun probeServers() {
        checkingIds.clear()
        // probeSpecsFromServers — native: Go парсит весь список узлов и строит
        // JSON-спеки. На подписке из сотен серверов это заметно, а вызов идёт
        // из обработчика клика, то есть с главного потока. Уводим в IO.
        lifecycleScope.launch {
            val specs = withContext(Dispatchers.IO) {
                // Throwable, а не Exception: при незагруженной .so прилетает
                // UnsatisfiedLinkError (это Error), и catch(Exception) его пропускает.
                if (!Native.ready) JSONArray() else try {
                    JSONArray(Mobile.probeSpecsFromServers(Repository.rawServers(), Repository.allowHY2))
                } catch (e: Throwable) {
                    Log.w(FlickerApp.TAG, "probeSpecsFromServers", e)
                    JSONArray()
                }
            }
            startProbing(specs)
        }
    }

    /** Продолжение [probeServers] после того, как спеки построены в фоне. */
    private fun startProbing(specs: JSONArray) {
        val total = specs.length()
        if (total == 0) {
            toast(getString(R.string.err_nothing_to_probe))
            return
        }
        var done = 0
        Repository.probeAll(
            onStage = { id, stage ->
                val name = stage.optString("stage")
                val terminal = stage.optBoolean("fatal") || name == "geoip" ||
                    (name == "http" && !stage.optBoolean("ok"))
                if (terminal && checkingIds.add(id)) {
                    done++
                    runOnUiThread {
                        binding.statusText.text = getString(R.string.status_probing, done, total)
                        adapter.setChecking(checkingIds)
                    }
                }
            },
            onDone = { text ->
                runOnUiThread {
                    checkingIds.clear()
                    Repository.setUi { it.copy(probing = false, statusText = "") }
                    if (text.isNotBlank()) toast(text)
                    renderUi()
                }
            }
        )
    }

    private fun connectSelected() {
        // v4.7.1: режим «Обход DPI» — внешнего сервера нет вообще, трафик идёт
        // напрямую с искажением пакетов (byedpi). Требовать выбранный узел
        // здесь нельзя, иначе режим невозможно включить.
        if (Prefs.mode(this) == Prefs.MODE_BYPASS) {
            connectBypass()
            return
        }

        // v4.5.0: если выбранного узла больше нет (его вычистили как узел
        // белого списка или он устарел), НЕ отказываем, а берём лучший
        // встроенный и сразу его выбираем — пользователь видит, чем подключается.
        var row = Repository.selectedServer()
        if (row == null) {
            val fallback = Repository.firstBootstrap()
            if (fallback != null) {
                Repository.setSelectedId(fallback.id)
                row = fallback
                toast("Выбран узел: ${fallback.name}")
                renderUi()
            }
        }
        if (row == null) {
            toast(getString(R.string.err_no_server))
            return
        }
        if (row.demo) {
            toast(getString(R.string.err_demo_server))
            return
        }
        // v4.2.0: в режиме «Прокси» системный VPN не поднимается —
        // ни разрешения ОС, ни диалога согласия не нужно (метод ByeByeDPI).
        if (dev.flicker.vpn.util.Prefs.mode(this) == "proxy") {
            connectNow()
            return
        }
        // v4.7.1: в режиме обхода DPI TUN поднимается, поэтому диалог согласия
        // обязателен — дальше по коду, общим путём через VpnService.prepare().
        val prepare = VpnService.prepare(this)
        if (prepare != null) {
            vpnPrepare.launch(prepare)
        } else {
            connectNow()
        }
    }

    private fun connectNow() {
        val json = Repository.selectedServerJson() ?: return
        binding.statusText.text = getString(R.string.status_connecting)
        if (!Native.ready) {
            AlertDialog.Builder(this)
                .setTitle(R.string.dlg_error_title)
                .setMessage(Native.userVisibleError ?: getString(R.string.err_native_missing))
                .setPositiveButton(android.R.string.ok, null)
                .show()
            renderUi()
            return
        }
        // Ранняя валидация конфига — ошибки показываем до запуска сервиса.
        // Мигрируем ДО проверки, иначе checkTunConfig отвергнет конфиг по той
        // же причине, что и ядро, и пользователь увидит ошибку, хотя
        // подключение на самом деле прошло бы.
        //
        // ОБА вызова — native (Go парсит и валидирует JSON). БЫЛО: они шли
        // прямо в обработчике клика, то есть на ГЛАВНОМ потоке. На большом
        // списке узлов или медленном устройстве это блокировка UI, а при
        // зависании ядра — ANR с убийством процесса без внятного диалога.
        // Тот же антипаттерн, что был в TunnelService.startTunnel.
        lifecycleScope.launch {
            val error = withContext(Dispatchers.IO) {
                try {
                    Mobile.checkTunConfig(
                        ConfigMigrate.migrate(Mobile.buildTunConfig(json, Repository.tunParamsJson()))
                    )
                    null
                } catch (e: Throwable) {   // Throwable: buildTunConfig — native
                    e.message ?: e.javaClass.simpleName
                }
            }
            if (error != null) {
                AlertDialog.Builder(this@MainActivity)
                    .setTitle(R.string.dlg_error_title)
                    .setMessage(error)
                    .setPositiveButton(android.R.string.ok, null)
                    .show()
                renderUi()
                return@launch
            }
            TunnelService.start(this@MainActivity, json)
        }
    }

    /**
     * v4.12.0: подключение в режиме обхода DPI — схема эталона ByeByeDPI-x-tg.
     *
     * Что изменилось по сравнению с 4.11.0:
     *   * движок обхода больше НЕ зависит от Go-ядра (libflickerbox.so):
     *     проверка Native.ready и валидация BypassConfig через
     *     Mobile.checkTunConfig убраны — вместо них проверяются libbyedpi.so
     *     и libhev-socks5-tunnel.so, которые реально нужны сервису;
     *   * ОБЯЗАТЕЛЬНЫЙ VpnService.prepare(): TUN поднимается, значит системное
     *     согласие необходимо. Раньше prepare() не вызывался вовсе, и на
     *     свежей установке establish() в сервисе получал отказ — пользователь
     *     видел «не подключается».
     */
    private fun connectBypass() {
        val byedpiOk = dev.flicker.vpn.core.ByeDpiProxy.nativeReady
        val tproxyOk = dev.flicker.vpn.core.TProxyService.nativeReady
        if (!byedpiOk || !tproxyOk) {
            val details = buildString {
                if (!byedpiOk) appendLine("libbyedpi.so: ${dev.flicker.vpn.core.ByeDpiProxy.loadError ?: "?"}")
                if (!tproxyOk) appendLine("libhev-socks5-tunnel.so: ${dev.flicker.vpn.core.TProxyService.loadError ?: "?"}")
            }
            AlertDialog.Builder(this)
                .setTitle(R.string.dlg_error_title)
                .setMessage(
                    "Обход DPI недоступен: нативные библиотеки движка не загружены.\n\n" +
                        details + "\nПересоберите APK с установленными NDK и CMake " +
                        "(BUILD-ANDROID.md: externalNativeBuild + runNdkBuild)."
                )
                .setPositiveButton(android.R.string.ok, null)
                .show()
            renderUi()
            return
        }
        binding.statusText.text = getString(R.string.status_connecting)
        val prepare = VpnService.prepare(this)
        if (prepare != null) {
            pendingBypass = true
            vpnPrepare.launch(prepare)
        } else {
            startBypassNow()
        }
    }

    /** Согласие VPN получено (или уже было) — поднимаем обход. */
    private fun startBypassNow() {
        pendingBypass = false
        binding.statusText.text = getString(R.string.status_connecting)
        TunnelService.start(this@MainActivity, TunnelService.BYPASS_NO_SERVER)
    }

    /**
     * v4.7.1: выбор стратегии обхода DPI.
     *
     * Показываем все пресеты с пояснением, зачем каждый нужен: подбирать
     * параметры byedpi вслепую бессмысленно, а подпись «OOB / Split / Fake»
     * без объяснения пользователю ничего не говорит.
     *
     * Если туннель поднят — предупреждаем, что пресет применится только после
     * переподключения (движок byedpi одноразовый на процесс: смена параметров
     * это остановка и новый запуск).
     */
    private fun showPresetDialog() {
        val presets = dev.flicker.vpn.core.ByeDpiArgs.PRESETS
        val currentId = Prefs.byedpiPreset(this)
        val current = presets.indexOfFirst { it.id == currentId }.coerceAtLeast(0)
        val titles = presets.map { it.title }.toTypedArray()

        AlertDialog.Builder(this)
            .setTitle("Стратегия обхода DPI")
            .setSingleChoiceItems(titles, current) { d, which ->
                val preset = presets[which]
                Prefs.setByedpiPreset(this, preset.id)
                d.dismiss()
                renderUi()
                AlertDialog.Builder(this)
                    .setTitle(preset.title)
                    .setMessage(
                        preset.note + "\n\nКомандная строка:\n" + preset.command +
                            if (tunnelLive())
                                "\n\nТуннель поднят — пресет применится после переподключения."
                            else ""
                    )
                    .setPositiveButton(android.R.string.ok, null)
                    .show()
            }
            .setNeutralButton("Своя строка…") { _, _ -> showCustomArgsDialog() }
            .setNegativeButton(android.R.string.cancel, null)
            // v4.8.0: автоподбор. Отдельная кнопка в меню, чтобы её было видно
            // и из диалога пресетов тоже.
            .setPositiveButton("Подобрать автоматически") { _, _ -> runStrategyTest() }
            .show()
    }

    /** v4.7.1: произвольная командная строка byedpi (пустая = вернуться к пресету). */
    private fun showCustomArgsDialog() {
        val input = EditText(this).apply {
            setText(Prefs.byedpiCommand(this@MainActivity))
            hint = "-Kt,h -o1 -e a -An -Ku -a1"
            setSingleLine(false)
            minLines = 2
        }
        AlertDialog.Builder(this)
            .setTitle("Своя командная строка byedpi")
            .setMessage(
                "argv[0], --ip и --port подставятся сами. Пустая строка — вернуться к пресету.\n" +
                    "Список опций: cpp/byedpi/README.md"
            )
            .setView(input)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                Prefs.setByedpiCommand(this, input.text.toString().trim())
                toast(if (Prefs.byedpiCommand(this).isEmpty()) "Своя строка очищена — используется пресет"
                       else "Своя командная строка сохранена")
                renderUi()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    // ------------------------------------------------------------------
    //  v4.8.0: автоподбор рабочей стратегии обхода DPI
    // ------------------------------------------------------------------

    private var tester: dev.flicker.vpn.core.StrategyTester? = null
    private var testDialog: AlertDialog? = null
    private var testText: android.widget.TextView? = null
    private var testBaselineOk = 0
    private var testBaselineTotal = 0

    private fun setTestProgress(text: String) {
        runOnUiThread { testText?.text = text }
    }

    /**
     * Прогон подборщика стратегий.
     *
     * VPN для теста НЕ нужен: byedpi — обычный SOCKS5 на 127.0.0.1, и тестер
     * ходит через него напрямую, минуя TUN и sing-box. Поэтому запускать можно
     * в любом состоянии, и тест проверяет именно обход DPI, а не всю цепочку.
     *
     * Занимает 2-4 минуты (9 пресетов × 5 сайтов, на каждый пресет — перезапуск
     * процесса :byedpi). Прогресс показываем обязательно: без него выглядит как
     * зависание, и пользователь убивает приложение посередине.
     */
    private fun runStrategyTest() {
        if (tester != null) {
            toast("Подбор уже идёт")
            return
        }
        val t = dev.flicker.vpn.core.StrategyTester(this)
        tester = t
        testBaselineOk = 0
        testBaselineTotal = 0

        val tv = android.widget.TextView(this).apply {
            setPadding(56, 44, 56, 28)
            textSize = 13f
            text = "Готовлюсь…"
        }
        testText = tv
        testDialog = AlertDialog.Builder(this)
            .setTitle("Подбор стратегии обхода")
            .setView(tv)
            .setCancelable(false)
            .setNegativeButton("Отмена") { _, _ -> t.cancel() }
            .show()

        lifecycleScope.launch {
            val sites = dev.flicker.vpn.core.StrategyTester.DEFAULT_SITES
            val results = try {
                t.run(
                    presets = dev.flicker.vpn.core.ByeDpiArgs.PRESETS,
                    sites = sites,
                    listener = object : dev.flicker.vpn.core.StrategyTester.Listener {
                        override fun onBaselineStart(total: Int) {
                            testBaselineTotal = total
                            setTestProgress("Шаг 1/2: базовая линия (сайты БЕЗ обхода) — 0/$total\n" +
                                "Нужно, чтобы отличать «заблокировано» от «не работает тест».")
                        }

                        override fun onBaselineSite(r: dev.flicker.vpn.core.StrategyTester.SiteResult) {
                            testBaselineOk += if (r.ok) 1 else 0
                            setTestProgress(
                                "Шаг 1/2: базовая линия — $testBaselineOk/$testBaselineTotal открылось\n" +
                                    "Текущий: ${r.site}\n  ${if (r.ok) "✓" else "✗"} ${r.detail}"
                            )
                        }

                        override fun onPresetStart(index: Int, total: Int, title: String) {
                            setTestProgress("Шаг 2/2: пресет $index/$total — «$title»\nПоднимаю byedpi…")
                        }

                        override fun onPresetSite(
                            title: String,
                            r: dev.flicker.vpn.core.StrategyTester.SiteResult
                        ) {
                            setTestProgress(
                                "Шаг 2/2: «$title»\n${r.site}\n  ${if (r.ok) "✓" else "✗"} ${r.detail} (${r.ms} мс)"
                            )
                        }

                        override fun onPresetDone(r: dev.flicker.vpn.core.StrategyTester.PresetResult) {
                            setTestProgress(
                                "«${r.title}»: ${r.score} из ${sites.size}, новых +${r.gained}" +
                                    if (!r.controlOk) "\n⚠ контрольный сайт не открылся" else ""
                            )
                        }

                        override fun onPresetFailed(title: String, error: String) {
                            setTestProgress("«$title»: движок не поднялся — $error\nПропускаю.")
                        }
                    }
                )
            } catch (ce: kotlinx.coroutines.CancellationException) {
                emptyList()
            } catch (e: Throwable) {
                Log.e(FlickerApp.TAG, "подбор стратегий", e)
                emptyList()
            }
            tester = null
            showTestResults(results, t)
        }
    }

    private fun showTestResults(
        results: List<dev.flicker.vpn.core.StrategyTester.PresetResult>,
        t: dev.flicker.vpn.core.StrategyTester,
    ) {
        testDialog?.dismiss()
        testDialog = null
        testText = null

        if (results.isEmpty()) {
            toast("Подбор отменён или не дал результатов")
            renderUi()
            return
        }
        val ranked = t.rank(results)
        val report = t.report(results)
        CrashLog.note(this, report)

        val best = ranked.firstOrNull { it.controlOk && it.gained > 0 }
            ?: ranked.firstOrNull { it.controlOk }
            ?: ranked.firstOrNull()

        val lines = ranked.mapIndexed { i, r ->
            "${i + 1}. ${r.title} — ${r.score}/${r.throughProxy.size}, новых +${r.gained}" +
                if (!r.controlOk) "  ⚠" else ""
        }
        val message = buildString {
            if (best == null) {
                append("Ни один пресет не дал валидного результата.\n\n")
            } else if (best.gained > 0) {
                append("Лучший: «${best.title}» — открыл ${best.gained} сайт(ов), ")
                append("которые без обхода не открывались.\n\n")
            } else {
                append("Обход НЕ помог: все сайты, открывшиеся через byedpi, ")
                append("открывались и напрямую.\n\n")
                append("Возможные причины:\n")
                append("• провайдер блокирует не по SNI/ClientHello — тогда нужен ")
                append("серверный режим (VPN-узел);\n")
                append("• не работает DNS (в отчёте будут UnknownHostException);\n")
                append("• тест шёл при включённом VPN и сокеты петляли.\n\n")
            }
            append(lines.joinToString("\n"))
            append("\n\nПолный отчёт сохранён в журнал сбоев (меню ⋮ → «Журнал сбоев»).")
        }

        AlertDialog.Builder(this)
            .setTitle("Результаты подбора")
            .setMessage(message)
            .setPositiveButton(
                if (best != null) "Применить «${best.title}»" else "Закрыть"
            ) { _, _ ->
                if (best != null) {
                    Prefs.setByedpiPreset(this, best.presetId)
                    // Своя командная строка переопределяет пресет — чистим,
                    // иначе выбор не применится.
                    if (Prefs.byedpiCommand(this).isNotEmpty()) {
                        Prefs.setByedpiCommand(this, "")
                    }
                    toast("Пресет «${best.title}» выбран. Переподключитесь.")
                }
                renderUi()
            }
            .setNeutralButton("Скопировать отчёт") { _, _ ->
                val cm = getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager
                cm.setPrimaryClip(android.content.ClipData.newPlainText("FlickerVPN подбор DPI", report))
                toast("Отчёт в буфере обмена")
            }
            .setNegativeButton("Закрыть") { _, _ -> renderUi() }
            .show()
    }

    private fun disconnect() {
        TunnelService.stop(this)
        renderUi()
    }

    /**
     * v4.7.0: аварийное отключение — «ключик висит и не убирается».
     *
     * Предупреждаем, что приложение будет закрыто: [TunnelService.hardStop]
     * в худшем случае завершает процесс, а это весь наш процесс, включая UI.
     * Настройки и список узлов не теряются (SharedPreferences пишутся
     * синхронно), но несохранённого в интерфейсе состояния не останется.
     */

    /**
     * v4.12.1: выход из приложения. Останавливает туннель штатно
     * (без hardStop) и закрывает все активности.
     */
    private fun confirmExit() {
        AlertDialog.Builder(this)
            .setTitle("Выйти из приложения?")
            .setMessage("VPN-туннель будет отключён, приложение закроется.")
            .setPositiveButton("Выйти") { _, _ ->
                TunnelService.stop(this)
                try {
                    stopService(Intent(this, Class.forName("dev.flicker.vpn.BypassVpnService")))
                } catch (_: Throwable) {}
                finishAffinity()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun confirmHardStop() {
        AlertDialog.Builder(this)
            .setTitle("Экстренно выключить VPN")
            .setMessage(
                "Снять туннель принудительно.\n\n" +
                    "Используйте, если обычное «Отключить» не убрало ключик из статусбара.\n\n" +
                    "Приложение закроется и перезапустится с чистым состоянием. " +
                    "Настройки и список узлов сохранятся."
            )
            .setPositiveButton("Выключить принудительно") { _, _ ->
                toast("Принудительное отключение…")
                TunnelService.hardStop(this)
                // UI закроется вместе с процессом; если процесс выживет —
                // просто перерисуем состояние.
                binding.root.postDelayed({ renderUi() }, 500)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun showServerDetails(row: Repository.ServerRow) {
        val parts = mutableListOf<String>()
        parts += "${row.protocolLabel} · ${row.host}:${row.port}"
        if (row.country.isNotEmpty()) parts += "Страна: ${row.country}"
        val obj = try {
            JSONObject(row.json)
        } catch (e: Exception) {
            null
        }
        obj?.let {
            if (it.optString("exitIp").isNotEmpty()) parts += "Выходной IP: ${it.optString("exitIp")}"
            val ok = it.optInt("checksOk")
            val total = it.optInt("checksTotal")
            if (total > 0) parts += "Успех проверок: $ok/$total"
            if (it.optString("lastError").isNotEmpty()) parts += "Ошибка: ${it.optString("lastError")}"
        }
        AlertDialog.Builder(this)
            .setTitle("${row.flag} ${row.name}")
            .setItems(parts.toTypedArray(), null)
            .setNeutralButton(R.string.action_connect_here) { _, _ ->
                Repository.setSelectedId(row.id)
                connectSelected()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    // ---------- настройки ----------

    private fun showSettings() {
        val view = layoutInflater.inflate(R.layout.dialog_settings, null)
        val swAutoRefresh = view.findViewById<SwitchMaterial>(R.id.sw_auto_refresh)
        val swHy2 = view.findViewById<SwitchMaterial>(R.id.sw_hy2)
        val edDns = view.findViewById<EditText>(R.id.ed_dns)
        val edSource = view.findViewById<EditText>(R.id.ed_source)
        val btnAddSource = view.findViewById<Button>(R.id.btn_add_source)
        val btnManageSources = view.findViewById<Button>(R.id.btn_manage_sources)

        val swAutostart = view.findViewById<SwitchMaterial>(R.id.sw_autostart)
        val swAutoReconnect = view.findViewById<SwitchMaterial>(R.id.sw_auto_reconnect)
        val btnBattery = view.findViewById<Button>(R.id.btn_battery)
        val btnSourcesHealth = view.findViewById<Button>(R.id.btn_sources_health)
        val btnSourcesReset = view.findViewById<Button>(R.id.btn_sources_reset)

        swAutoRefresh.isChecked = Repository.autoRefresh
        swHy2.isChecked = Repository.allowHY2
        edDns.setText(Repository.dnsServer)

        swAutostart.isChecked = Prefs.autoStart(this)
        swAutoReconnect.isChecked = Prefs.autoReconnect(this)

        // Если исключение из оптимизации уже получено — кнопку гасим,
        // чтобы не предлагать одно и то же каждый раз.
        btnBattery.isEnabled = Battery.shouldAsk(this)
        btnBattery.alpha = if (btnBattery.isEnabled) 1f else 0.4f

        val dialog = AlertDialog.Builder(this)
            .setTitle(R.string.settings_title)
            .setView(view)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                Repository.setAutoRefresh(swAutoRefresh.isChecked)
                Repository.setAllowHY2(swHy2.isChecked)
                try {
                    val dns = edDns.text.toString()
                    Repository.setDnsServer(dns)
                    // v4.12.1: один DNS и для VPN, и для обхода DPI
                    Prefs.setBypassDns(this@MainActivity, dns.trim().ifBlank { "1.1.1.1" })
                } catch (e: IllegalArgumentException) {
                    toast(getString(R.string.err_invalid_dns))
                }
                Prefs.setAutoStart(this@MainActivity, swAutostart.isChecked)
                Prefs.setAutoReconnect(this@MainActivity, swAutoReconnect.isChecked)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .create()

        btnAddSource.setOnClickListener {
            val url = edSource.text.toString().trim()
            if (Repository.addSource(url)) {
                edSource.setText("")
                toast(getString(R.string.msg_source_added))
            } else {
                toast(getString(R.string.err_source_invalid))
            }
        }
        btnManageSources.setOnClickListener { showSourcesDialog() }

        btnBattery.setOnClickListener { showBatteryDialog() }
        btnSourcesHealth.setOnClickListener { showSourcesHealth() }
        btnSourcesReset.setOnClickListener {
            SourceHealth.reset(this)
            toast(getString(R.string.pref_sources_reset))
            showSourcesHealth()
        }

        dialog.show()
    }

    /**
     * Диалог про оптимизацию батареи.
     *
     * Показываем только если исключение ещё не получено. Отдельный диалог, а не
     * прямой переход в системные настройки, потому что на китайских прошивках
     * системного диалога часто нет — тогда предлагаем OEM-экран автозапуска.
     */
    private fun showBatteryDialog() {
        if (!Battery.shouldAsk(this)) {
            toast(getString(R.string.pref_battery_summary))
            return
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.battery_dialog_title)
            .setMessage(R.string.battery_dialog_message)
            .setPositiveButton(R.string.battery_dialog_ok) { _, _ ->
                Prefs.setBatteryAsked(this)
                // Сначала пробуем системный диалог; если прошивка его не даёт —
                // открываем OEM-экран автозапуска, а уже если и его нет —
                // общий список приложений с оптимизацией.
                if (!Battery.requestIgnore(this)) {
                    if (!Battery.openVendorAutostart(this)) {
                        Battery.openBatterySettings(this)
                    }
                }
            }
            .setNegativeButton(R.string.battery_dialog_later) { _, _ ->
                Prefs.setBatteryAsked(this)
            }
            .show()
    }

    /**
     * Состояние circuit breaker'а источников подписок: кто заморожен, на сколько
     * и с какой ошибкой. Без этого экрана SourceHealth работает «в стол» —
     * пользователь видит только «источников стало меньше», но не понимает почему.
     */
    private fun showSourcesHealth() {
        val lines = SourceHealth.describe(this)
        val text = if (lines.isEmpty()) {
            getString(R.string.pref_sources_health) + ":—"
        } else {
            lines.joinToString("\n")
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.pref_sources_health)
            .setMessage(text)
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    private fun showSourcesDialog() {
        val arr = Repository.sources()
        val names = ArrayList<String>()
        val checked = ArrayList<Boolean>()
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            names += o.optString("name").ifEmpty { o.optString("url") }
            checked += o.optBoolean("enabled", true)
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.pref_sources)
            .setMultiChoiceItems(names.toTypedArray(), checked.toBooleanArray()) { _, which, isChecked ->
                checked[which] = isChecked
            }
            .setPositiveButton(android.R.string.ok) { _, _ ->
                for (i in 0 until arr.length()) {
                    Repository.setSourceEnabled(arr.getJSONObject(i).optString("id"), checked[i])
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun showAbout() {
        val coreVersion = Native.call("version", fallback = "—") { Mobile.version() ?: "—" }
        AlertDialog.Builder(this)
            .setTitle(R.string.about_title)
            .setMessage(getString(R.string.about_text, BuildConfig.VERSION_NAME, coreVersion))
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    private fun toast(text: String) {
        Toast.makeText(this, text, Toast.LENGTH_LONG).show()
    }
}
