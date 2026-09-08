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

class SmsReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Telephony.Sms.Intents.SMS_RECEIVED_ACTION) {
            val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
            if (messages.isNullOrEmpty()) return

            val sender = messages[0].originatingAddress ?: "Unknown"
            val body = messages.joinToString(separator = "") { it.messageBody ?: "" }

            // Execute on-device native Smishing forensics
            val analysis = SmishingAnalyzer.analyzeSmishingMessage(sender, body)

            // If assessed risk is high or critical, trigger heads-up warning notification
            if (analysis.riskScore >= 70) {
                showSmishingAlertNotification(context, analysis)
            }
        }
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

        val notification = NotificationCompat.Builder(context, PhishGuardApplication.THREAT_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle("🚨 Critical Smishing Alert: ${record.senderId}")
            .setContentText("${record.threatCategory} (${record.riskScore}/100 Risk). Tap to inspect evidence.")
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .bigText(
                        "Sender: ${record.senderId}\n" +
                        "Category: ${record.threatCategory}\n" +
                        "Action: ${record.actionMsg}\n" +
                        "Message: \"${record.rawMessage}\""
                    )
            )
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(record.caseId.hashCode(), notification)
    }
}
