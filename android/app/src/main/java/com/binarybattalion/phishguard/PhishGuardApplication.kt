package com.binarybattalion.phishguard

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build

class PhishGuardApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        createNotificationChannels()
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val name = getString(R.string.notification_channel_name)
            val descriptionText = getString(R.string.notification_channel_desc)
            val importance = NotificationManager.IMPORTANCE_HIGH
            val channel = NotificationChannel(THREAT_CHANNEL_ID, name, importance).apply {
                description = descriptionText
                enableVibration(true)
                enableLights(true)
            }
            val notificationManager: NotificationManager =
                getSystemService(NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)

            // Sentinel Foreground Service Persistent Notification Channel
            val sentinelChannel = NotificationChannel(
                SENTINEL_CHANNEL_ID,
                "PhishGuard 24/7 Background Sentinel",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Keeps PhishGuard active in background to monitor incoming carrier SMS for scam links and DLT violations."
                setShowBadge(false)
            }
            notificationManager.createNotificationChannel(sentinelChannel)
        }
    }

    companion object {
        const val THREAT_CHANNEL_ID = "phishguard_threat_alerts_channel"
        const val SENTINEL_CHANNEL_ID = "phishguard_sentinel_channel"
    }
}
