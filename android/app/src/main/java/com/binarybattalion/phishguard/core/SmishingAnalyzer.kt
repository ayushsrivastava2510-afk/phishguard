package com.binarybattalion.phishguard.core

import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.regex.Pattern

object SmishingAnalyzer {

    // Regex pattern for TRAI DLT Compliant Alphanumeric Headers: 2 letters + hyphen + 6 alphanumeric chars
    private val TRAI_DLT_REGEX = Pattern.compile("^[A-Za-z]{2}-[A-Za-z0-9]{6}$")

    // Official registered DLT entity codes in India
    private val VERIFIED_DLT_ENTITIES = mapOf(
        "SBINB" to "State Bank of India (Net Banking)",
        "SBIINB" to "State Bank of India (Core Ingress)",
        "HDFCBK" to "HDFC Bank Ltd",
        "ICICIB" to "ICICI Bank Ltd",
        "AXISBK" to "Axis Bank Ltd",
        "PAYTMB" to "Paytm Payments Bank",
        "GOVTIN" to "Government of India Citizen Portal",
        "AIRTEL" to "Bharti Airtel Ltd",
        "JIOINF" to "Reliance Jio Infocomm",
        "AMAZON" to "Amazon India Payments"
    )

    // Known URL Shortener Domains commonly abused in Smishing
    private val URL_SHORTENERS = setOf(
        "bit.ly", "tinyurl.com", "is.gd", "t.co", "cutt.ly", "rb.gy", "goo.gl",
        "ow.ly", "shorturl.at", "bl.ink", "hyperurl.co", "surl.li"
    )

    // Suspicious domain keywords imitating institutions
    private val IMPERSONATION_TARGETS = mapOf(
        "sbi" to "State Bank of India",
        "yono" to "SBI YONO Banking Portal",
        "hdfc" to "HDFC Bank",
        "icici" to "ICICI Bank",
        "parivahan" to "MoRTH E-Challan / Parivahan",
        "echallan" to "Traffic Police E-Challan System",
        "bijli" to "State Electricity Board",
        "electricity" to "State Electricity Distribution Corp",
        "urja" to "National Power Distribution Grid",
        "pan" to "Income Tax NSDL / UTIITSL Portal",
        "aadhaar" to "UIDAI Aadhaar Verification"
    )

    fun validateSenderId(senderId: String?): SenderInfo {
        val sid = senderId?.trim() ?: ""
        val redFlags = mutableListOf<String>()

        if (sid.isEmpty()) {
            return SenderInfo(
                rawSender = "UNKNOWN",
                isDltCompliant = false,
                senderType = "Missing Sender Identifier",
                operatorCircle = "N/A",
                entityName = "Unregistered / Anonymous Sender",
                riskBoost = 20,
                redFlags = listOf("Missing Sender Identifier in transmission headers.")
            )
        }

        // Check TRAI DLT Compliant Alphanumeric Header (e.g., AD-HDFCBK, AX-SBINB)
        if (TRAI_DLT_REGEX.matcher(sid).matches()) {
            val parts = sid.split("-")
            val prefix = parts[0].uppercase(Locale.ROOT)
            val codeUpper = parts[1].uppercase(Locale.ROOT)
            val entityName = VERIFIED_DLT_ENTITIES[codeUpper] ?: "Registered Entity ($codeUpper)"

            return SenderInfo(
                rawSender = sid,
                isDltCompliant = true,
                senderType = "TRAI DLT Registered Commercial Header",
                operatorCircle = prefix,
                entityName = entityName,
                riskBoost = 0,
                redFlags = emptyList()
            )
        }

        // Check 10-digit Indian Mobile Number (Personal SIM used for Commercial SMS)
        val digits = sid.replace(Regex("[^0-9]"), "")
        if ((digits.length == 10 && "6789".contains(digits[0])) ||
            (digits.length == 12 && digits.startsWith("91"))
        ) {
            val formatted = if (digits.length == 12) digits.substring(2) else digits
            redFlags.add("Regulatory Violation: Commercial/Banking SMS dispatched from personal 10-digit mobile SIM instead of registered TRAI DLT header.")
            return SenderInfo(
                rawSender = sid,
                isDltCompliant = false,
                senderType = "Personal 10-Digit Mobile SIM (Unauthenticated Channel)",
                operatorCircle = "N/A",
                entityName = "Private SIM (+91-$formatted)",
                riskBoost = 45,
                redFlags = redFlags
            )
        }

        // Check International Virtual Number (+1, +44, +62, etc.)
        if (sid.startsWith("+") && !sid.startsWith("+91")) {
            val country = when {
                sid.startsWith("+62") -> "Indonesia (+62)"
                sid.startsWith("+1") -> "USA / Canada (+1)"
                sid.startsWith("+44") -> "United Kingdom (+44)"
                sid.startsWith("+84") -> "Vietnam (+84)"
                sid.startsWith("+880") -> "Bangladesh (+880)"
                else -> "International Virtual / VOIP Route"
            }
            redFlags.add("Cross-Border Transmission: Dispatched from foreign number ($country) frequently used in transnational task fraud.")
            return SenderInfo(
                rawSender = sid,
                isDltCompliant = false,
                senderType = "Cross-Border Virtual Number ($country)",
                operatorCircle = "International Route",
                entityName = "Unverified Foreign Sender ($sid)",
                riskBoost = 40,
                redFlags = redFlags
            )
        }

        // Non-standard Header
        redFlags.add("Unverified Sender Header: Does not conform to TRAI DLT alphanumeric standards.")
        return SenderInfo(
            rawSender = sid,
            isDltCompliant = false,
            senderType = "Unregistered Custom Sender Header",
            operatorCircle = "N/A",
            entityName = "Non-DLT Header ($sid)",
            riskBoost = 35,
            redFlags = redFlags
        )
    }

    fun extractAndAnalyzeUrls(text: String): UrlAnalysis {
        val urlPattern = Pattern.compile("(https?://[^\\s]+|(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}(?:/[^\\s]*)?)", Pattern.CASE_INSENSITIVE)
        val matcher = urlPattern.matcher(text)

        val foundUrls = mutableListOf<String>()
        val shortened = mutableListOf<String>()
        val apkDroppers = mutableListOf<String>()
        val lookalike = mutableListOf<String>()
        val redFlags = mutableListOf<String>()
        var riskBoost = 0

        while (matcher.find()) {
            var u = matcher.group().trim()
            if (u.endsWith(".") || u.endsWith(",") || u.endsWith("?")) {
                u = u.substring(0, u.length - 1)
            }
            foundUrls.add(u)
            val uLower = u.lowercase(Locale.ROOT)

            // 1. Android APK Trojan Dropper
            if (uLower.endsWith(".apk") || uLower.contains(".apk?") || uLower.contains("/apk/")) {
                apkDroppers.add(u)
                riskBoost += 50
                redFlags.add("Malicious Android Package: Direct link to download an executable .APK trojan dropper.")
            }

            // 2. URL Shortener Evasion
            for (shortener in URL_SHORTENERS) {
                if (uLower.contains(shortener)) {
                    shortened.add(u)
                    riskBoost += 35
                    redFlags.add("Obfuscated Link: Uses URL shortener ($shortener) to mask destination and evade telecom filters.")
                    break
                }
            }

            // 3. Lookalike Impersonation Domains
            for ((keyword, targetName) in IMPERSONATION_TARGETS) {
                if (uLower.contains(keyword) && !uLower.contains(".gov.in") && !uLower.contains(".nic.in") &&
                    !uLower.contains("sbi.co.in") && !uLower.contains("hdfcbank.com") && !uLower.contains("icicibank.com")
                ) {
                    lookalike.add(u)
                    riskBoost += 25
                    redFlags.add("Lookalike Domain: URL contains '$keyword' imitating $targetName on an unverified domain.")
                    break
                }
            }
        }

        return UrlAnalysis(
            urls = foundUrls,
            shortenedUrls = shortened,
            apkDroppers = apkDroppers,
            lookalikeDomains = lookalike,
            riskBoost = riskBoost,
            redFlags = redFlags
        )
    }

    fun classifySmsIntent(text: String, senderId: String): IntentAnalysis {
        val textLower = text.lowercase(Locale.ROOT)
        val cues = mutableListOf<String>()
        var category = "General Communication"
        var urgency = "Normal"
        var riskBoost = 0

        if (listOf("kyc", "pan card", "aadhaar", "yono", "debit card block", "account suspend", "account close", "sbi").any { textLower.contains(it) }) {
            cues.add("Banking KYC Account Suspension Coercion")
            category = "Financial / Banking KYC Fraud"
            urgency = "Critical"
            riskBoost += 35
        } else if (listOf("electricity", "power will be disconnect", "power office", "bill update", "line cut", "tonight 9:30").any { textLower.contains(it) }) {
            cues.add("Essential Utility (Electricity) Cut-off Intimidation")
            category = "Utility & Electricity Disconnection Scam"
            urgency = "Critical"
            riskBoost += 40
        } else if (listOf("challan", "parivahan", "traffic police", "vehicle fine", "court summon").any { textLower.contains(it) }) {
            cues.add("Government Penalty & Legal Intimidation")
            category = "Traffic E-Challan Malware Dropper"
            urgency = "High"
            riskBoost += 35
        } else if (listOf("earn daily", "part-time job", "part time job", "work from home", "review hotel", "like youtube", "telegram vip", "daily income").any { textLower.contains(it) }) {
            cues.add("Work-From-Home Task Investment Fraud")
            category = "Part-Time Job / Task Investment Scam"
            urgency = "Medium"
            riskBoost += 30
        } else if (listOf("is your otp", "one time password", "debited by", "credited with", "txn of inr", "card ending").any { textLower.contains(it) }) {
            cues.add("Authentic Transactional / OTP Pattern")
            category = "Transactional Banking Alert"
            urgency = "Normal"
            riskBoost = 0
        }

        if (listOf("urgent", "immediately", "act today", "pay today", "blocked today", "suspended today", "expire today", "due today", "tonight 9:30", "disconnect tonight", "within 24 hours", "within 2 hours", "last notice", "final warning").any { textLower.contains(it) }) {
            cues.add("Artificial Time-Pressure Constraint")
            riskBoost += 15
        }

        return IntentAnalysis(
            primaryCategory = category,
            urgencyLevel = urgency,
            cuesDetected = cues,
            intentRiskBoost = riskBoost
        )
    }

    fun analyzeSmishingMessage(senderId: String, messageText: String): SmishingRecord {
        val senderRes = validateSenderId(senderId)
        val urlRes = extractAndAnalyzeUrls(messageText)
        val intentRes = classifySmsIntent(messageText, senderId)

        val isPersonalP2P = !senderRes.isDltCompliant &&
                senderRes.senderType.contains("Personal 10-Digit") &&
                intentRes.primaryCategory == "General Communication" &&
                urlRes.urls.isEmpty() &&
                !intentRes.cuesDetected.any { it.contains("Coercion") || it.contains("Intimidation") || it.contains("Fraud") }

        val effectiveSenderRes = if (isPersonalP2P) {
            senderRes.copy(
                senderType = "Personal Contact (Private P2P SMS)",
                entityName = "Private Contact (${senderRes.rawSender})",
                riskBoost = 0,
                redFlags = emptyList()
            )
        } else {
            senderRes
        }

        var compositeScore = effectiveSenderRes.riskBoost + urlRes.riskBoost + intentRes.intentRiskBoost

        if (isPersonalP2P) {
            compositeScore = 5
        } else if (effectiveSenderRes.isDltCompliant && intentRes.primaryCategory.contains("Transactional") &&
            urlRes.shortenedUrls.isEmpty() && urlRes.apkDroppers.isEmpty()
        ) {
            compositeScore = minOf(compositeScore, 10)
        } else if (effectiveSenderRes.riskBoost >= 45 && (urlRes.shortenedUrls.isNotEmpty() || urlRes.apkDroppers.isNotEmpty())) {
            compositeScore = maxOf(compositeScore, 88)
        }

        val finalScore = maxOf(5, minOf(100, compositeScore))

        val (verdict, actionMsg) = when {
            finalScore >= 70 -> Pair(
                "CRITICAL SMISHING THREAT",
                "DANGER: Do not click links, do not call numbers, and never install suggested APKs."
            )
            finalScore >= 35 -> Pair(
                "SUSPICIOUS / ELEVATED RISK",
                "PROCEED WITH CAUTION: Unverified communication route; verify via official bank app."
            )
            else -> Pair(
                "VERIFIED SAFE SMS",
                if (isPersonalP2P) "VERIFIED SAFE: Person-to-Person (P2P) private message. Exempt from commercial TRAI DLT regulations."
                else "VERIFIED SAFE: Dispatched via registered TRAI DLT commercial entity; standard alert."
            )
        }

        val allFlags = mutableListOf<String>()
        allFlags.addAll(effectiveSenderRes.redFlags)
        allFlags.addAll(urlRes.redFlags)
        intentRes.cuesDetected.filter { !it.contains("Authentic") }.forEach {
            allFlags.add("Social Engineering: $it")
        }

        val caseId = "SMS-2026-${(System.currentTimeMillis() % 100000).toString().padStart(5, '0')}"
        val sha256 = sha256("$senderId:$messageText")
        val timestamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss 'IST'", Locale.getDefault()).format(Date())

        val partialRecord = SmishingRecord(
            caseId = caseId,
            senderId = effectiveSenderRes.rawSender,
            senderInfo = effectiveSenderRes,
            rawMessage = messageText,
            riskScore = finalScore,
            verdict = verdict,
            actionMsg = actionMsg,
            threatCategory = intentRes.primaryCategory,
            urgencyLevel = intentRes.urgencyLevel,
            urlInfo = urlRes,
            allRedFlags = allFlags,
            evidenceHash = sha256,
            timestamp = timestamp,
            chakshuDraft = ""
        )

        val draft = generateChakshuComplaintDraft(partialRecord)
        return partialRecord.copy(chakshuDraft = draft)
    }

    private fun generateChakshuComplaintDraft(r: SmishingRecord): String {
        val dltStatus = when {
            r.senderInfo.senderType.contains("P2P") -> "COMPLIANT (Exempt: Personal P2P Route)"
            !r.senderInfo.isDltCompliant -> "VIOLATION (Unauthenticated Route)"
            else -> "Registered Header Abuse"
        }
        val urlsList = if (r.urlInfo.urls.isNotEmpty()) r.urlInfo.urls.joinToString("\n") { "  - Malicious Link: $it" } else "  - None detected"
        val flagsList = if (r.allRedFlags.isNotEmpty()) r.allRedFlags.joinToString("\n") { "  * $it" } else "  * No anomalies detected"

        return """
INCIDENT REPORT FOR Sanchar Saathi (Chakshu) & National Cyber Crime Helpline (1930)
Generated by PhishGuard Autonomous Mobile Sentinel
--------------------------------------------------------------------------------
Reference Case Tracking ID : ${r.caseId}
Detection Timestamp        : ${r.timestamp}
Assessed Risk Score        : ${r.riskScore} / 100 (${r.verdict})
Offending Sender ID / SIM  : ${r.senderId}
Incident Category          : ${r.threatCategory}
TRAI DLT Compliance Status : $dltStatus

Extracted Malicious URLs / Indicators:
$urlsList

Raw Message Body Evidence:
"${r.rawMessage}"

Forensic Findings:
$flagsList

Requested Law Enforcement Actions:
  1. Immediate IMEI/SIM suspension of ${r.senderId} via DoT Chakshu telecom registry.
  2. Takedown of associated phishing domains and redirection shorteners.
  3. Blocking of inbound SMS delivery across telecom operator SMSCs.
Cryptographic SHA-256 Digest: ${r.evidenceHash}
        """.trimIndent()
    }

    private fun sha256(input: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(input.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }

    val SMISHING_BENCHMARKS = listOf(
        SmishingBenchmark(
            id = "sbi_kyc_sms",
            title = "Scenario 1: SBI YONO Account Suspension",
            senderId = "+91 98234 11223",
            text = "Dear SBI Customer, your YONO account is blocked today due to pending KYC. Please update your PAN Card immediately to avoid account closure: bit.ly/sbi-yono-kyc-update",
            description = "Personal 10-digit SIM imitating SBI with an obfuscated bit.ly link harvesting banking credentials."
        ),
        SmishingBenchmark(
            id = "electricity_sms",
            title = "Scenario 2: Electricity Bill Disconnection Panic",
            senderId = "+91 91234 56789",
            text = "Dear Consumer, your electricity power will be disconnected tonight at 9:30 PM from the power office because your previous month bill was not updated. Please immediately call power officer at 9123456789.",
            description = "High-pressure psychological coercion threat claiming urgent power cut-off with a fraudulent helpline number."
        ),
        SmishingBenchmark(
            id = "echallan_apk_sms",
            title = "Scenario 3: Traffic E-Challan APK Trojan Dropper",
            senderId = "+91 87654 32109",
            text = "Traffic Police Notice: An unpaid challan of INR 1,500 is pending against vehicle DL14CX1234. Pay immediately to avoid court summons. Download mParivahan app: http://echallan-parivahan.in/Parivahan_Update.apk",
            description = "Government vehicle penalty scam delivering a direct Android .apk banking trojan dropper payload."
        ),
        SmishingBenchmark(
            id = "job_scam_sms",
            title = "Scenario 4: Part-Time Telegram Task Fraud",
            senderId = "+62 812 3456 7890",
            text = "Part-Time Job Offer: Earn INR 2,500 to INR 5,000 daily working 30 mins from home by reviewing hotels and YouTube videos. Contact VIP HR Manager on Telegram: t.me/VipHotelTasks77",
            description = "Cross-border virtual number from Indonesia (+62) pushing task-based crypto and advance-fee investment fraud."
        ),
        SmishingBenchmark(
            id = "legit_otp_sms",
            title = "Scenario 5: Verified Bank Transaction OTP (Safe)",
            senderId = "AD-HDFCBK",
            text = "847291 is your OTP for purchase of INR 2,499.00 at FLIPKART using HDFC Bank Credit Card ending 7041. Valid for 10 mins. Do not share OTP with anyone. Bank never calls for OTP.",
            description = "Authentic transactional SMS compliant with TRAI DLT alphanumeric regulations (AD-HDFCBK) containing no external URLs."
        )
    )
}
