package com.binarybattalion.phishguard.core

import android.content.Context
import android.database.Cursor
import android.provider.Telephony
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class ScannedInboxSms(
    val id: String,
    val sender: String,
    val body: String,
    val timestamp: Long,
    val formattedDate: String,
    val record: SmishingRecord
)

data class InboxScanSummary(
    val totalScanned: Int,
    val criticalThreats: Int,
    val suspiciousCount: Int,
    val safeCount: Int,
    val items: List<ScannedInboxSms>
)

object InboxSmsScanner {

    fun scanDeviceInbox(context: Context, limit: Int = 50): InboxScanSummary {
        val items = mutableListOf<ScannedInboxSms>()
        val contentResolver = context.contentResolver
        val uri = Telephony.Sms.Inbox.CONTENT_URI
        val projection = arrayOf(
            Telephony.Sms._ID,
            Telephony.Sms.ADDRESS,
            Telephony.Sms.BODY,
            Telephony.Sms.DATE
        )
        val sortOrder = "${Telephony.Sms.DATE} DESC"

        var cursor: Cursor? = null
        try {
            cursor = contentResolver.query(uri, projection, null, null, sortOrder)
            if (cursor != null && cursor.moveToFirst()) {
                val idCol = cursor.getColumnIndex(Telephony.Sms._ID)
                val addressCol = cursor.getColumnIndex(Telephony.Sms.ADDRESS)
                val bodyCol = cursor.getColumnIndex(Telephony.Sms.BODY)
                val dateCol = cursor.getColumnIndex(Telephony.Sms.DATE)

                var count = 0
                val dateFormat = SimpleDateFormat("dd MMM yyyy, hh:mm a", Locale.getDefault())

                do {
                    val id = if (idCol >= 0) cursor.getString(idCol) ?: count.toString() else count.toString()
                    val sender = if (addressCol >= 0) cursor.getString(addressCol) ?: "Unknown" else "Unknown"
                    val body = if (bodyCol >= 0) cursor.getString(bodyCol) ?: "" else ""
                    val dateMillis = if (dateCol >= 0) cursor.getLong(dateCol) else System.currentTimeMillis()

                    if (body.isNotBlank()) {
                        val record = SmishingAnalyzer.analyzeSmishingMessage(sender, body)
                        items.add(
                            ScannedInboxSms(
                                id = id,
                                sender = sender,
                                body = body,
                                timestamp = dateMillis,
                                formattedDate = dateFormat.format(Date(dateMillis)),
                                record = record
                            )
                        )
                    }
                    count++
                } while (cursor.moveToNext() && count < limit)
            }
        } catch (e: Exception) {
            e.printStackTrace()
        } finally {
            cursor?.close()
        }

        val critical = items.count { it.record.riskScore >= 70 }
        val suspicious = items.count { it.record.riskScore in 35..69 }
        val safe = items.count { it.record.riskScore < 35 }

        return InboxScanSummary(
            totalScanned = items.size,
            criticalThreats = critical,
            suspiciousCount = suspicious,
            safeCount = safe,
            items = items
        )
    }

    fun getFallbackSampleInbox(): InboxScanSummary {
        val samples = listOf(
            Pair("+91 98234 11223", "Dear SBI Customer, your YONO account is blocked today due to pending KYC. Please update your PAN immediately to avoid account closure: bit.ly/sbi-yono-kyc-update"),
            Pair("+91 91234 56789", "Dear consumer, your electricity power will be disconnected tonight at 9:30 PM because your previous month bill was not updated. Call officer immediately or download mahadiscom.apk: bit.ly/bijli-bill-pay"),
            Pair("VK-HDFCBK", "748291 is your OTP for purchase of Rs. 4,500.00 at AMAZON INDIA with your HDFC Bank Card ending 4092. Valid for 10 mins. Never share OTP with anyone.")
        )
        val dateFormat = SimpleDateFormat("dd MMM yyyy, hh:mm a", Locale.getDefault())
        val now = System.currentTimeMillis()
        val items = samples.mapIndexed { idx, (sender, body) ->
            val record = SmishingAnalyzer.analyzeSmishingMessage(sender, body)
            val time = now - (idx * 3600000L * 4)
            ScannedInboxSms(
                id = "sample_$idx",
                sender = sender,
                body = body,
                timestamp = time,
                formattedDate = dateFormat.format(Date(time)),
                record = record
            )
        }
        val critical = items.count { it.record.riskScore >= 70 }
        val suspicious = items.count { it.record.riskScore in 35..69 }
        val safe = items.count { it.record.riskScore < 35 }

        return InboxScanSummary(
            totalScanned = items.size,
            criticalThreats = critical,
            suspiciousCount = suspicious,
            safeCount = safe,
            items = items
        )
    }
}
