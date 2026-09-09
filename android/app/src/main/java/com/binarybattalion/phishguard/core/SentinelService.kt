package com.binarybattalion.phishguard.core

import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.binarybattalion.phishguard.MainActivity
import com.binarybattalion.phishguard.PhishGuardApplication
import com.binarybattalion.phishguard.R

class SentinelService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            isServiceRunning = false
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }

        isServiceRunning = true
        startForegroundNotification()
        return START_STICKY
    }

    private fun startForegroundNotification() {
        val appIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            appIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(this, PhishGuardApplication.SENTINEL_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle("🛡️ PhishGuard Sentinel Active")
            .setContentText("Autonomous background defense active. Monitoring carrier SMS in real time.")
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    override fun onDestroy() {
        isServiceRunning = false
        super.onDestroy()
    }

    companion object {
        const val NOTIFICATION_ID = 20261
        const val ACTION_START = "com.binarybattalion.phishguard.START_SENTINEL"
        const val ACTION_STOP = "com.binarybattalion.phishguard.STOP_SENTINEL"

        var isServiceRunning = false
            private set

        fun startSentinel(context: Context) {
            val intent = Intent(context, SentinelService::class.java).apply {
                action = ACTION_START
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stopSentinel(context: Context) {
            val intent = Intent(context, SentinelService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }
    }
}
