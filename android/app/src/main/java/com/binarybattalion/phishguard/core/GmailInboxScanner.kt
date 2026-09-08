package com.binarybattalion.phishguard.core

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.io.PrintWriter
import java.net.HttpURLConnection
import java.net.Socket
import java.net.URL
import java.text.SimpleDateFormat
import java.util.*
import javax.net.ssl.SSLSocketFactory

object GmailInboxScanner {

    /**
     * Connects to Google's Gmail API or IMAP over SSL
     * to retrieve unread or recent inbox emails, extracts sender, subject,
     * and snippet, and audits each message with EmailAnalyzer.
     */
    suspend fun scanLiveGmail(
        tokenOrPassword: String,
        limit: Int = 15,
        accountEmail: String = "me"
    ): EmailInboxScanSummary = withContext(Dispatchers.IO) {
        val items = mutableListOf<ScannedInboxEmail>()
        val trimmedKey = tokenOrPassword.trim()
        val cleanEmail = accountEmail.trim()
        var errorMsg: String? = null

        if (trimmedKey.isNotBlank()) {
            // Mode 1: Google App Password -> IMAP over SSL (imap.gmail.com:993)
            val isLikelyAppPassword = !trimmedKey.startsWith("ya29") && (trimmedKey.replace(" ", "").length in 8..32)
            if (isLikelyAppPassword && cleanEmail.contains("@")) {
                val (imapItems, imapErr) = fetchViaImap(cleanEmail, trimmedKey, limit)
                if (imapItems.isNotEmpty()) {
                    items.addAll(imapItems)
                } else {
                    errorMsg = imapErr
                }
            }

            // Mode 2: OAuth2 Access Token -> Google Gmail REST API
            if (items.isEmpty() && (trimmedKey.startsWith("ya29") || !isLikelyAppPassword)) {
                try {
                    val restItems = fetchViaRestApi(trimmedKey, limit)
                    if (restItems.isNotEmpty()) {
                        items.addAll(restItems)
                    } else if (errorMsg == null) {
                        errorMsg = "Google API token expired or invalid scope (need gmail.readonly)."
                    }
                } catch (e: Exception) {
                    errorMsg = e.message ?: "Network error connecting to Gmail API"
                }
            }
        }

        // If real emails were successfully fetched
        if (items.isNotEmpty()) {
            val critical = items.count { it.record.riskScore >= 70 }
            val suspicious = items.count { it.record.riskScore in 35..69 }
            val safe = items.count { it.record.riskScore < 35 }

            return@withContext EmailInboxScanSummary(
                accountEmail = cleanEmail,
                totalScanned = items.size,
                criticalThreats = critical,
                suspiciousCount = suspicious,
                safeCount = safe,
                items = items,
                statusMessage = "Live Gmail Sync Active: ${items.size} messages audited from your personal inbox.",
                isLiveSync = true
            )
        }

        // Fallback to sample threat benchmark feed with informative status
        val fallback = getSampleGmailInbox(cleanEmail)
        val finalStatus = when {
            trimmedKey.isBlank() -> "Simulated Live Feed: Enter your 16-letter Google App Password above to audit your personal inbox."
            errorMsg != null -> "Auth Error ($errorMsg). Showing benchmark threat cases below."
            else -> "Could not connect to Gmail. Ensure IMAP is enabled in Gmail settings. Showing benchmark threat cases."
        }

        EmailInboxScanSummary(
            accountEmail = cleanEmail,
            totalScanned = fallback.totalScanned,
            criticalThreats = fallback.criticalThreats,
            suspiciousCount = fallback.suspiciousCount,
            safeCount = fallback.safeCount,
            items = fallback.items,
            statusMessage = finalStatus,
            isLiveSync = false
        )
    }

    /**
     * Direct IMAP over SSL (port 993) engine for Google App Passwords
     */
    private fun fetchViaImap(accountEmail: String, appPassword: String, limit: Int): Pair<List<ScannedInboxEmail>, String?> {
        val items = mutableListOf<ScannedInboxEmail>()
        val cleanPass = appPassword.replace(" ", "").trim()
        val cleanEmail = accountEmail.trim()
        val dateFormat = SimpleDateFormat("dd MMM yyyy, hh:mm a", Locale.getDefault())
        var errorDetail: String? = null

        var socket: Socket? = null
        try {
            val sslFactory = SSLSocketFactory.getDefault()
            socket = sslFactory.createSocket("imap.gmail.com", 993)
            socket.soTimeout = 12000

            val reader = BufferedReader(InputStreamReader(socket.getInputStream(), "UTF-8"))
            val writer = PrintWriter(OutputStreamWriter(socket.getOutputStream(), "UTF-8"), true)

            // 1. Read Greeting
            reader.readLine()

            // 2. Login
            writer.println("A01 LOGIN $cleanEmail $cleanPass")
            var loginSuccess = false
            while (true) {
                val line = reader.readLine() ?: break
                if (line.startsWith("A01 OK", ignoreCase = true)) {
                    loginSuccess = true
                    break
                } else if (line.startsWith("A01 NO", ignoreCase = true) || line.startsWith("A01 BAD", ignoreCase = true)) {
                    errorDetail = if (line.contains("AUTHENTICATIONFAILED", ignoreCase = true)) {
                        "Invalid App Password. Please generate a new 16-letter code at myaccount.google.com/apppasswords"
                    } else if (line.contains("ALERT", ignoreCase = true)) {
                        "IMAP is disabled in your Gmail settings. Open Gmail on web -> Settings -> Forwarding and POP/IMAP -> Enable IMAP."
                    } else {
                        "Gmail IMAP rejected login: ${line.substringAfter("A01 NO").trim()}"
                    }
                    break
                }
            }

            if (!loginSuccess) {
                return Pair(emptyList(), errorDetail ?: "Authentication failed")
            }

            // 3. Select Inbox
            writer.println("A02 SELECT INBOX")
            var existsCount = 0
            while (true) {
                val line = reader.readLine() ?: break
                if (line.contains("EXISTS", ignoreCase = true)) {
                    val parts = line.trim().split(" ")
                    if (parts.size >= 2) {
                        existsCount = parts[1].toIntOrNull() ?: existsCount
                    }
                }
                if (line.startsWith("A02 OK", ignoreCase = true) || line.startsWith("A02 NO", ignoreCase = true) || line.startsWith("A02 BAD", ignoreCase = true)) {
                    break
                }
            }

            if (existsCount > 0) {
                val startMsg = maxOf(1, existsCount - limit + 1)
                val endMsg = existsCount

                // 4. Fetch headers for recent messages
                for (msgNum in endMsg downTo startMsg) {
                    val tag = "F$msgNum"
                    writer.println("$tag FETCH $msgNum (BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE)])")
                    var subject = "No Subject"
                    var fromSender = cleanEmail
                    var dateStr = ""
                    var readingHeaders = false

                    while (true) {
                        val line = reader.readLine() ?: break
                        if (line.startsWith("$tag OK", ignoreCase = true) || line.startsWith("$tag NO", ignoreCase = true) || line.startsWith("$tag BAD", ignoreCase = true)) {
                            break
                        }
                        if (line.startsWith("* $msgNum FETCH") && line.contains("HEADER.FIELDS")) {
                            readingHeaders = true
                            continue
                        }
                        if (readingHeaders) {
                            if (line.startsWith("Subject:", ignoreCase = true)) {
                                subject = decodeMimeWord(line.substring(8).trim())
                            } else if (line.startsWith("From:", ignoreCase = true)) {
                                fromSender = decodeMimeWord(line.substring(5).trim())
                            } else if (line.startsWith("Date:", ignoreCase = true)) {
                                dateStr = line.substring(5).trim()
                            } else if (line.trim().isEmpty() || line.startsWith(")")) {
                                readingHeaders = false
                            }
                        }
                    }

                    if (subject.isNotBlank() && subject != "No Subject") {
                        val record = EmailAnalyzer.analyzeEmail(subject, fromSender, subject)
                        val now = System.currentTimeMillis() - ((existsCount - msgNum) * 1000L * 60 * 15)

                        items.add(
                            ScannedInboxEmail(
                                id = "imap-$msgNum",
                                subject = subject,
                                sender = fromSender,
                                bodySnippet = "Dispatched from $fromSender. Date: $dateStr",
                                timestamp = now,
                                formattedDate = dateFormat.format(Date(now)),
                                record = record
                            )
                        )
                    }
                }
            }

            // Logout
            writer.println("A04 LOGOUT")
        } catch (e: Exception) {
            e.printStackTrace()
            errorDetail = e.localizedMessage ?: "Socket timeout connecting to imap.gmail.com"
        } finally {
            try {
                socket?.close()
            } catch (_: Exception) {}
        }
        return Pair(items, errorDetail)
    }

    /**
     * REST API fetcher for Google OAuth2 Tokens
     */
    private fun fetchViaRestApi(accessToken: String, limit: Int): List<ScannedInboxEmail> {
        val items = mutableListOf<ScannedInboxEmail>()
        val dateFormat = SimpleDateFormat("dd MMM yyyy, hh:mm a", Locale.getDefault())

        val listUrl = URL("https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=$limit&q=in:inbox")
        val conn = listUrl.openConnection() as HttpURLConnection
        conn.requestMethod = "GET"
        conn.setRequestProperty("Authorization", "Bearer $accessToken")
        conn.setRequestProperty("Accept", "application/json")
        conn.connectTimeout = 8000
        conn.readTimeout = 8000

        if (conn.responseCode == 200) {
            val reader = BufferedReader(InputStreamReader(conn.inputStream))
            val responseStr = reader.readText()
            reader.close()

            val json = JSONObject(responseStr)
            val messagesArray = json.optJSONArray("messages")

            if (messagesArray != null) {
                for (i in 0 until messagesArray.length()) {
                    val msgObj = messagesArray.getJSONObject(i)
                    val msgId = msgObj.getString("id")

                    val detailUrl = URL("https://gmail.googleapis.com/gmail/v1/users/me/messages/$msgId?format=full")
                    val dConn = detailUrl.openConnection() as HttpURLConnection
                    dConn.requestMethod = "GET"
                    dConn.setRequestProperty("Authorization", "Bearer $accessToken")
                    dConn.connectTimeout = 5000
                    dConn.readTimeout = 5000

                    if (dConn.responseCode == 200) {
                        val dReader = BufferedReader(InputStreamReader(dConn.inputStream))
                        val dStr = dReader.readText()
                        dReader.close()

                        val dJson = JSONObject(dStr)
                        val snippet = dJson.optString("snippet", "")
                        val internalDate = dJson.optLong("internalDate", System.currentTimeMillis())

                        val payload = dJson.optJSONObject("payload")
                        val headers = payload?.optJSONArray("headers")
                        var subject = "No Subject"
                        var fromSender = "Unknown"

                        if (headers != null) {
                            for (h in 0 until headers.length()) {
                                val header = headers.getJSONObject(h)
                                val name = header.optString("name", "")
                                if (name.equals("Subject", ignoreCase = true)) {
                                    subject = decodeMimeWord(header.optString("value", subject))
                                } else if (name.equals("From", ignoreCase = true)) {
                                    fromSender = decodeMimeWord(header.optString("value", fromSender))
                                }
                            }
                        }

                        val auditRecord = EmailAnalyzer.analyzeEmail(subject, fromSender, snippet)
                        items.add(
                            ScannedInboxEmail(
                                id = msgId,
                                subject = subject,
                                sender = fromSender,
                                bodySnippet = snippet,
                                timestamp = internalDate,
                                formattedDate = dateFormat.format(Date(internalDate)),
                                record = auditRecord
                            )
                        )
                    }
                }
            }
        }
        return items
    }

    /**
     * Decodes MIME encoded-words (e.g. =?UTF-8?B?...?= or =?UTF-8?Q?...?=)
     */
    private fun decodeMimeWord(input: String): String {
        val regex = Regex("=\\?([^?]+)\\?([BQbq])\\?([^?]+)\\?=")
        return regex.replace(input) { match ->
            try {
                val charset = match.groupValues[1]
                val encoding = match.groupValues[2].uppercase()
                val encodedData = match.groupValues[3]
                if (encoding == "B") {
                    val bytes = android.util.Base64.decode(encodedData, android.util.Base64.DEFAULT)
                    String(bytes, java.nio.charset.Charset.forName(charset))
                } else if (encoding == "Q") {
                    val decoded = encodedData.replace("_", " ")
                    val qRegex = Regex("=([0-9A-Fa-f]{2})")
                    qRegex.replace(decoded) { m ->
                        val hex = m.groupValues[1].toInt(16).toChar()
                        hex.toString()
                    }
                } else {
                    match.value
                }
            } catch (_: Exception) {
                match.value
            }
        }.replace("\r", "").replace("\n", " ").trim()
    }

    /**
     * High-fidelity multi-threat fallback sample feed
     */
    fun getSampleGmailInbox(accountEmail: String = "ayushsrivastava2510@gmail.com"): EmailInboxScanSummary {
        val dateFormat = SimpleDateFormat("dd MMM yyyy, hh:mm a", Locale.getDefault())
        val now = System.currentTimeMillis()

        val sampleList = listOf(
            Triple(
                "Urgent: Mandated KYC Verification Notice for State Bank Account",
                "alert-services@sbi-online-portal.in",
                "Dear Customer, your internet banking and UPI access will be permanently deactivated in 24 hours due to unverified PAN card. Verify immediately: http://sbi-kyc-update.online/auth"
            ),
            Triple(
                "Unauthorized Login Attempt Detected on Your PayPal Account",
                "security-alert@paypa1.com",
                "We noticed suspicious access from an unknown IP in Moscow, Russia. Confirm your login credentials within 24 hours at http://paypa1-security.com or account funds will be frozen."
            ),
            Triple(
                "STRICTLY CONFIDENTIAL: Immediate Acquisition Wire Transfer Required",
                "cfo-office@partner-corp.xyz",
                "Please process an urgent wire transfer of $45,000 before bank cut-off today. Do not discuss with anyone in the office as this transaction is subject to strict NDA. Revised wire instructions attached."
            ),
            Triple(
                "Security alert for your linked Google Account",
                "no-reply@accounts.google.com",
                "A new sign-in was detected on Windows 11 device in Bangalore, India. If this was you, you don't need to take any action. If not, check your account activity."
            ),
            Triple(
                "Your Amazon Prime Membership Renewal Notice - Invoice #89211",
                "billing-update@amaz0n-prime-service.top",
                "Your card was charged Rs 1,499 for annual renewal. If you did not authorize this charge, click immediately to cancel subscription and refund payment."
            ),
            Triple(
                "Quarterly Business Review: Meeting Agenda & Q3 Performance",
                "sarah.jenkins@enterprise-partner.com",
                "Hi team, please find attached the agenda for tomorrow's 10:00 AM QBR. Looking forward to reviewing the quarterly performance metrics and roadmap."
            )
        )

        val items = sampleList.mapIndexed { index, (subj, sender, body) ->
            val timestamp = now - (index * 1000L * 60 * 42)
            val record = EmailAnalyzer.analyzeEmail(subj, sender, body)
            ScannedInboxEmail(
                id = "gmail-msg-${1000 + index}",
                subject = subj,
                sender = sender,
                bodySnippet = body,
                timestamp = timestamp,
                formattedDate = dateFormat.format(Date(timestamp)),
                record = record
            )
        }

        val critical = items.count { it.record.riskScore >= 70 }
        val suspicious = items.count { it.record.riskScore in 35..69 }
        val safe = items.count { it.record.riskScore < 35 }

        return EmailInboxScanSummary(
            accountEmail = accountEmail,
            totalScanned = items.size,
            criticalThreats = critical,
            suspiciousCount = suspicious,
            safeCount = safe,
            items = items,
            statusMessage = "Simulated Live Feed: Showing benchmark threat cases.",
            isLiveSync = false
        )
    }
}
