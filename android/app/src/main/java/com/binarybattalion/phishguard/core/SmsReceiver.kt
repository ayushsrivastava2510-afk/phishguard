package com.binarybattalion.phishguard.core

import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import androidx.core.app.NotificationCompat
import com.binarybattalion.phishguard.MainActivity
import com.binarybattalion.phishguard.PhishGuardApplication
import com.binarybattalion.phishguard.R
import com.binarybattalion.phishguard.ui.activities.ThreatAlertActivity

class SmsReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        var sender = ""
        var body = ""

        if (intent.action == Telephony.Sms.Intents.SMS_RECEIVED_ACTION) {
            val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
            if (messages.isNullOrEmpty()) return

            sender = messages[0].originatingAddress ?: "Unknown"
            body = messages.joinToString(separator = "") { it.messageBody ?: "" }
        } else if (intent.action == ACTION_SIMULATE_SMS) {
            sender = intent.getStringExtra(EXTRA_SIMULATED_SENDER) ?: "+91 98112 34567"
            body = intent.getStringExtra(EXTRA_SIMULATED_MESSAGE) ?: "प्रिय उपभोक्ता, आपका बिजली बिल अपडेट नहीं हुआ है। आज रात 9:30 बजे आपकी बिजली काट दी जाएगी। तुरंत संपर्क करें: bit.ly/bijli-bill-update"
        } else {
            return
        }

        if (body.isBlank()) return

        // Execute on-device native Smishing forensics
        val analysis = SmishingAnalyzer.analyzeSmishingMessage(sender, body)

        // 0. Trigger 5-second emergency siren voice/sound alarm if threat factor exceeds 90
        if (analysis.riskScore > 90) {
            ThreatSirenPlayer.playSiren(context, 5000L)
        }

        // 1. Launch floating side-by-side analysis popup immediately
        try {
            ThreatAlertActivity.launch(context, analysis.senderId, analysis.rawMessage)
        } catch (e: Exception) {
            e.printStackTrace()
        }

        // 2. Post high-priority Heads-up Notification alongside the system SMS notification
        showSmishingAlertNotification(context, analysis)
    }

    private fun showSmishingAlertNotification(context: Context, record: SmishingRecord) {
        val tapIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra("EXTRA_INCOMING_CASE_ID", record.caseId)
            putExtra("EXTRA_INCOMING_SENDER", record.senderId)
            putExtra("EXTRA_INCOMING_MESSAGE", record.rawMessage)
        }

        val pendingIntent = PendingIntent.getActivity(
            context,
            record.caseId.hashCode(),
            tapIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        // Floating full-screen intent for instant pop-up
        val alertIntent = Intent(context, ThreatAlertActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(ThreatAlertActivity.EXTRA_SENDER, record.senderId)
            putExtra(ThreatAlertActivity.EXTRA_MESSAGE, record.rawMessage)
        }
        val alertPendingIntent = PendingIntent.getActivity(
            context,
            record.caseId.hashCode() + 1,
            alertIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val isThreat = record.riskScore >= 35
        val isCriticalSiren = record.riskScore > 90

        val channelId = if (isCriticalSiren) {
            PhishGuardApplication.CRITICAL_SIREN_CHANNEL_ID
        } else {
            PhishGuardApplication.THREAT_CHANNEL_ID
        }

        val alertTitle = if (isCriticalSiren) {
            "🚨 CRITICAL SIREN ALARM (>90): ${record.senderId}"
        } else if (record.riskScore >= 70) {
            "🚨 CRITICAL SMISHING DETECTED: ${record.senderId}"
        } else if (isThreat) {
            "⚠️ SUSPICIOUS SMS FLAGGED: ${record.senderId}"
        } else {
            "🟢 VERIFIED SAFE SMS: ${record.senderId}"
        }

        val builder = NotificationCompat.Builder(context, channelId)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle(alertTitle)
            .setContentText(
                if (isCriticalSiren) {
                    "🚨 5-SECOND EMERGENCY SIREN TRIGGERED! ${record.threatCategory} (${record.riskScore}/100 Risk)."
                } else {
                    "${record.threatCategory} (${record.riskScore}/100 Risk). Tap to inspect evidence."
                }
            )
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .bigText(
                        "Risk Score: ${record.riskScore}/100 (${record.verdict})\n" +
                        "Sender: ${record.senderId} (${record.senderInfo.senderType})\n" +
                        "Category: ${record.threatCategory}\n" +
                        (if (record.vernacularInfo.isVernacular) "Language: ${record.vernacularInfo.detectedLanguage}\n" else "") +
                        "Advisory: ${record.actionMsg}\n" +
                        "Message: \"${record.rawMessage}\""
                    )
            )
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .setFullScreenIntent(alertPendingIntent, true)
            .addAction(
                R.drawable.ic_launcher_foreground,
                "🔬 Inspect Forensics",
                pendingIntent
            )

        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(record.caseId.hashCode(), builder.build())
    }

    companion object {
        const val ACTION_SIMULATE_SMS = "com.binarybattalion.phishguard.SIMULATE_SMS"
        const val EXTRA_SIMULATED_SENDER = "EXTRA_SIMULATED_SENDER"
        const val EXTRA_SIMULATED_MESSAGE = "EXTRA_SIMULATED_MESSAGE"
    }
}
