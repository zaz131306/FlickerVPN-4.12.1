// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn.util

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.core.app.NotificationCompat
import dev.flicker.vpn.FlickerApp
import dev.flicker.vpn.MainActivity
import dev.flicker.vpn.R
import dev.flicker.vpn.TunnelService
import dev.flicker.vpn.data.AppState
import dev.flicker.vpn.data.TunnelMode

/**
 * Уведомления туннеля.
 *
 * ЗАМЕЧАНИЯ ПО ПЛАТФОРМЕ, ИЗ-ЗА КОТОРЫХ ЭТО ВЫНЕСЕНО ОТДЕЛЬНО:
 *
 *  1. FLAG_IMMUTABLE у всех PendingIntent — обязателен с API 31. Без него на
 *     Android 12+ при создании уведомления кидает IllegalArgumentException.
 *     Симптом: «включаю VPN — приложение вылетает».
 *  2. Разные requestCode у каждого PendingIntent. Если он один, Android
 *     переиспользует объект, и кнопка «Пауза» начинает выполнять «Отключить».
 *  3. setSilent + setOnlyAlertOnce + IMPORTANCE_LOW: уведомление обновляется
 *     периодически, и без этого телефон вибрирует на каждом обновлении.
 *  4. FOREGROUND_SERVICE_IMMEDIATE — на Android 12 уведомление FGS по умолчанию
 *     показывается с задержкой до 10 с; для VPN это выглядит как «включил, а
 *     ничего не произошло».
 *  5. VISIBILITY_SECRET — имя узла не светится на заблокированном экране.
 *  6. notify() обёрнут в try: на части прошивок кидает при отключённом канале,
 *     и ронять из-за этого туннель недопустимо.
 */
object Notifications {

    private const val TAG = FlickerApp.TAG

    /** Совпадает с TunnelService.NOTIF_ID */
    const val TUNNEL_ID = 1

    /** «Приостановлено» — отдельный id, чтобы его можно было смахнуть. */
    const val PAUSE_ID = 3

    /** Ошибка подключения. */
    const val ERROR_ID = 4

    private const val RC_OPEN = 100
    private const val RC_PAUSE = 101
    private const val RC_STOP = 102
    private const val RC_RESUME = 103

    fun buildTunnel(context: Context, serverName: String?): Notification {
        val modeLabel = when (AppState.mode) {
            TunnelMode.Vpn -> context.getString(R.string.mode_vpn)
            TunnelMode.Proxy -> context.getString(R.string.mode_proxy)
        }
        val text = if (serverName.isNullOrBlank()) modeLabel else "$modeLabel · $serverName"
        return NotificationCompat.Builder(context, FlickerApp.CHANNEL_TUNNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(context.getString(R.string.app_name))
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setOngoing(true)
            .setSilent(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setContentIntent(openApp(context))
            .addAction(0, context.getString(R.string.action_pause), svc(context, TunnelService.ACTION_PAUSE, RC_PAUSE))
            .addAction(0, context.getString(R.string.action_disconnect), svc(context, TunnelService.ACTION_DISCONNECT, RC_STOP))
            .build()
    }

    fun buildPause(context: Context): Notification =
        NotificationCompat.Builder(context, FlickerApp.CHANNEL_TUNNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(context.getString(R.string.app_name))
            .setContentText(context.getString(R.string.status_paused))
            .setSilent(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(openApp(context))
            .addAction(0, context.getString(R.string.action_resume), svc(context, TunnelService.ACTION_RESUME, RC_RESUME))
            // v4.2.1: «Отключить» прямо из состояния паузы. Раньше из уведомления
            // паузы можно было только «возобновить» — сервис оставался висеть
            // в шторке, и пользователь не мог его выключить, не заходя в приложение.
            .addAction(0, context.getString(R.string.action_disconnect), svc(context, TunnelService.ACTION_DISCONNECT, RC_STOP))
            .build()

    fun buildError(context: Context, message: String): Notification =
        NotificationCompat.Builder(context, FlickerApp.CHANNEL_STATUS)
            .setSmallIcon(R.drawable.ic_notification)
            // Заголовок — «Не удалось подключиться», а не имя приложения:
            // в шторке и так видно, чьё это уведомление, а вот причину надо
            // показывать сразу, не заставляя раскрывать шторку.
            .setContentTitle(context.getString(R.string.status_error))
            .setContentText(message)
            .setStyle(NotificationCompat.BigTextStyle().bigText(message))
            .setAutoCancel(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(openApp(context))
            .build()

    fun notify(context: Context, id: Int, n: Notification) {
        try {
            context.getSystemService(NotificationManager::class.java)?.notify(id, n)
        } catch (e: Exception) {
            Log.w(TAG, "notify($id) не удался", e)
        }
    }

    fun cancel(context: Context, id: Int) {
        try {
            context.getSystemService(NotificationManager::class.java)?.cancel(id)
        } catch (e: Exception) {
            Log.w(TAG, "cancel($id) не удался", e)
        }
    }

    private fun piFlags() = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE

    private fun openApp(context: Context) = PendingIntent.getActivity(
        context, RC_OPEN,
        Intent(context, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
        piFlags(),
    )

    private fun svc(context: Context, action: String, rc: Int) = PendingIntent.getService(
        context, rc,
        Intent(context, TunnelService.targetClass(context)).setAction(action),
        piFlags(),
    )
}
