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

        binding.btnModeBypass.setOnClickListener { setMode(Prefs.MODE_BYPASS) }
        binding.btnModeVpn.setOnClickListener { setMode(Prefs.MODE_VPN) }
        binding.btnModeProxy.setOnClickListener { setMode(Prefs.MODE_PROXY) }
        binding.btnHardStop.setOnClickListener { confirmHardStop() }
        binding.tgwsRow.setOnClickListener { openTgWs() }
        binding.targetText.setOnClickListener {
            if (Prefs.mode(this) == Prefs.MODE_BYPASS) showPresetDialog()
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            askNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

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
            AlertDialog.Builder(this)
                .setTitle(R.string.dlg_error_title)
                .setMessage(Native.userVisibleError ?: getString(R.string.err_native_missing))
                .setPositiveButton(android.R.string.ok, null)
                .show()
            renderUi()
            return
        }

        lifecycleScope.launch {
            combine(Repository.servers, Repository.ui) { s, u -> Pair(s, u) }
                .collect { renderUi() }
        }

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
        TgWsClient.attach(this)
        TgWsClient.query(this)
        tgwsJob?.cancel()
        tgwsJob = lifecycleScope.launch { TgWsClient.state.collect { renderTgws(it) } }
        syncBypassState()
        renderUi()
        binding.root.removeCallbacks(trafficTicker)
        binding.root.postDelayed(trafficTicker, TRAFFIC_REFRESH_MS)
    }

    override fun onPause() {
        super.onPause()
        binding.root.removeCallbacks(trafficTicker)
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
            // v4.12.2: пункт action_mode убран — режим переключается кнопками
            // на главном экране (btnModeBypass / btnModeVpn / btnModeProxy).
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

    private fun showDiagnostics() {
        val dump = try {
            Diagnostics.collect(this)
        } catch (e: Throwable) {
            "не удалось собрать диагностику: ${e.javaClass.simpleName}: ${e.message}"
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.diagnostics_title)
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

    private fun showCrashLog() {
        CrashLog.dumpCrashBufferSync(this)
        val text = CrashLog.read(this, 60000, 30000)
        val paths = getString(R.string.crash_log_path, CrashLog.path(this)) +
            "\n" + getString(R.string.crash_log_path, Native.nativeCrashReport(this).absolutePath)
        val body = if (!CrashLog.hasAnyRecord(this)) {
            getString(R.string.crash_log_empty) + "\n\n" + paths
        } else {
            val shown = if (text.length > 9000)
                text.take(5000) + "\n…(середина обрезана — полный текст в «Поделиться»/«Копировать»)…\n" + text.takeLast(3500)
            else text
            shown + "\n\n" + paths
        }
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

    private var proxyHintShown = false

    private fun showModeDialog() {
        val modes = arrayOf(
            "Обход DPI (без сервера, подмена пакетов — как ByeByeDPI)",
            "VPN-туннель через узел (весь трафик телефона)",
            "Локальный прокси (SOCKS5 для Telegram)"
        )
        val current = when (Prefs.mode(this)) {
            Prefs.MODE_BYPASS -> 0
            Prefs.MODE_PROXY -> 2
            else -> 1
        }
        AlertDialog.Builder(this)
            .setTitle("Режим подключения")
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
                        0 -> Prefs.MODE_BYPASS
                        2 -> Prefs.MODE_PROXY
                        else -> Prefs.MODE_VPN
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

    private fun netCheck(): String {
        val sb = StringBuilder()
        sb.append("FlickerVPN v").append(BuildConfig.VERSION_NAME)
            .append(" (").append(BuildConfig.VERSION_CODE).append(")\n")
        sb.append("Режим: ")
            .append(if (Prefs.mode(this) == "proxy") "ПРОКСИ (замеры идут МИМО прокси — они для VPN-режима)" else "VPN")
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

    private var tgwsJob: kotlinx.coroutines.Job? = null

    private fun openTgWs() {
        try {
            startActivity(Intent(this, TgWsActivity::class.java))
        } catch (t: Throwable) {
            Log.e(FlickerApp.TAG, "не удалось открыть экран Telegram-туннеля", t)
            toast("Не удалось открыть экран: ${t.javaClass.simpleName}")
        }
    }

    private fun renderTgws(st: TgWsState) {
        val dot = when {
            st.verified -> R.drawable.dot_ok
            st.error.isNotBlank() -> R.drawable.dot_dead
            st.running -> R.drawable.dot_warn
            else -> R.drawable.dot_unknown
        }
        binding.tgwsDot.setBackgroundResource(dot)
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

        renderStateCard(ui, selected)
        renderDesyncBanner()
        renderModeButtons()
    }

    private val TRAFFIC_REFRESH_MS = 1_500L

    private val trafficTicker = object : Runnable {
        override fun run() {
            renderTraffic()
            binding.root.postDelayed(this, TRAFFIC_REFRESH_MS)
        }
    }

    private fun tunnelLive(): Boolean =
        TunnelService.isLive ||
            (Prefs.mode(this) == Prefs.MODE_BYPASS && TunnelService.isVpnInterfaceUp(this))

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

    private fun renderDesyncBanner() {
        val claimsConnected = Repository.ui.value.connected ||
            dev.flicker.vpn.data.AppState.status == dev.flicker.vpn.data.ServiceStatus.Connected
        val desync = claimsConnected && !tunnelLive()
        binding.desyncBanner.visibility = if (desync) View.VISIBLE else View.GONE
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
        lifecycleScope.launch {
            val specs = withContext(Dispatchers.IO) {
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
        if (Prefs.mode(this) == Prefs.MODE_BYPASS) {
            connectBypass()
            return
        }

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
        if (Prefs.mode(this) == "proxy") {
            connectNow()
            return
        }
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
        lifecycleScope.launch {
            val error = withContext(Dispatchers.IO) {
                try {
                    Mobile.checkTunConfig(
                        ConfigMigrate.migrate(Mobile.buildTunConfig(json, Repository.tunParamsJson()))
                    )
                    null
                } catch (e: Throwable) {
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

    private fun startBypassNow() {
        pendingBypass = false
        binding.statusText.text = getString(R.string.status_connecting)
        TunnelService.start(this@MainActivity, TunnelService.BYPASS_NO_SERVER)
    }

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
            .setPositiveButton("Подобрать автоматически") { _, _ -> runStrategyTest() }
            .show()
    }

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

    private var tester: dev.flicker.vpn.core.StrategyTester? = null
    private var testDialog: AlertDialog? = null
    private var testText: android.widget.TextView? = null
    private var testBaselineOk = 0
    private var testBaselineTotal = 0

    private fun setTestProgress(text: String) {
        runOnUiThread { testText?.text = text }
    }

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
