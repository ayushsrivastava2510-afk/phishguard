package com.binarybattalion.phishguard

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.media.AudioAttributes
import android.net.Uri
import android.os.Build

class PhishGuardApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        createNotificationChannels()
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val notificationManager: NotificationManager =
                getSystemService(NOTIFICATION_SERVICE) as NotificationManager

            val name = getString(R.string.notification_channel_name)
            val descriptionText = getString(R.string.notification_channel_desc)
            val importance = NotificationManager.IMPORTANCE_HIGH
            val channel = NotificationChannel(THREAT_CHANNEL_ID, name, importance).apply {
                description = descriptionText
                enableVibration(true)
                enableLights(true)
            }
            notificationManager.createNotificationChannel(channel)

            // 🚨 Critical Siren Notification Channel for Threat Factor > 90
            val sirenUri = Uri.parse("android.resource://${packageName}/${R.raw.threat_siren_5s}")
            val audioAttributes = AudioAttributes.Builder()
                .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                .setUsage(AudioAttributes.USAGE_ALARM)
                .build()

            val sirenChannel = NotificationChannel(
                CRITICAL_SIREN_CHANNEL_ID,
                "🚨 Critical Threat Siren Alert (>90 Score)",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "High-urgency 5-second emergency siren notification for critical SMS threats with risk score exceeding 90/100"
                setSound(sirenUri, audioAttributes)
                enableVibration(true)
                vibrationPattern = longArrayOf(
                    0, 350, 150, 350, 150, 350, 150, 350, 150, 350,
                    150, 350, 150, 350, 150, 350, 150, 350, 150, 350
                )
                enableLights(true)
                lightColor = android.graphics.Color.RED
                setShowBadge(true)
            }
            notificationManager.createNotificationChannel(sirenChannel)

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
        const val CRITICAL_SIREN_CHANNEL_ID = "phishguard_critical_siren_channel"
        const val SENTINEL_CHANNEL_ID = "phishguard_sentinel_channel"
    }
}
