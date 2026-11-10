// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn.util

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import android.util.Log

/**
 * Оптимизация батареи и OEM-автозапуск.
 *
 * ЗАЧЕМ: на MIUI/HyperOS, EMUI, ColorOS, OriginOS, One UI foreground-сервис VPN
 * всё равно убивают через несколько минут, если приложение не в исключениях.
 * Симптом — «подключился, поработало и отвалилось», при этом в логах приложения
 * чисто: процесс просто убит системой.
 *
 * ПРО РАЗРЕШЕНИЕ: REQUEST_IGNORE_BATTERY_OPTIMIZATIONS нужно объявить в
 * манифесте. Google Play разрешает его не всем, но VPN-клиенты входят в перечень
 * допустимых кейсов — это одно из явно разрешённых исключений.
 *
 * ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS без объявленного разрешения на
 * Android 12+ кидает SecurityException, поэтому все вызовы обёрнуты.
 */
object Battery {

    private const val TAG = "FlickerBattery"

    fun isIgnoring(context: Context): Boolean {
        val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return true
        return try {
            pm.isIgnoringBatteryOptimizations(context.packageName)
        } catch (e: Exception) {
            Log.w(TAG, "isIgnoringBatteryOptimizations", e)
            true
        }
    }

    /** Стоит ли вообще предлагать пользователю исключение. */
    fun shouldAsk(context: Context): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && !isIgnoring(context)

    /** Системный диалог «Разрешить работу в фоне?». false — если показать не удалось. */
    fun requestIgnore(activity: Activity): Boolean {
        if (isIgnoring(activity)) return true
        val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
            data = Uri.parse("package:${activity.packageName}")
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        return try {
            activity.startActivity(intent)
            true
        } catch (e: Exception) {
            Log.w(TAG, "диалог батареи недоступен, открываю общий список", e)
            openSettings(activity, Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
        }
    }

    fun openBatterySettings(context: Context): Boolean =
        openSettings(context, Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)

    /**
     * Автозапуск у китайских OEM. Единого API нет, поэтому перебираем известные
     * компоненты и открываем первый откликнувшийся.
     */
    fun openVendorAutostart(context: Context): Boolean {
        val candidates = listOf(
            "com.miui.securitycenter/com.miui.permcenter.autostart.AutoStartManagementActivity",
            "com.huawei.systemmanager/com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity",
            "com.huawei.systemmanager/com.huawei.systemmanager.appcontrol.activity.StartupAppControlActivity",
            "com.coloros.safecenter/com.coloros.safecenter.permission.startup.StartupAppListActivity",
            "com.oppo.safe/com.oppo.safe.permission.startup.StartupAppListActivity",
            "com.vivo.permissionmanager/com.vivo.permissionmanager.activity.BgStartUpManagerActivity",
            "com.iqoo.secure/com.iqoo.secure.ui.phoneoptimize.BgStartUpManager",
            "com.samsung.android.lool/com.samsung.android.sm.ui.battery.BatteryActivity",
            "com.oneplus.security/com.oneplus.security.chainlaunch.view.ChainLaunchAppListActivity",
        )
        for (c in candidates) {
            val (pkg, cls) = c.split("/", limit = 2)
            try {
                context.startActivity(
                    Intent().setClassName(pkg, cls).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                )
                Log.i(TAG, "открыт автозапуск: $pkg")
                return true
            } catch (_: Exception) {
                // компонент не найден — пробуем следующий
            }
        }
        return openBatterySettings(context)
    }

    private fun openSettings(context: Context, action: String): Boolean = try {
        context.startActivity(Intent(action).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        true
    } catch (e: Exception) {
        Log.w(TAG, "не открыть $action", e)
        false
    }
}
