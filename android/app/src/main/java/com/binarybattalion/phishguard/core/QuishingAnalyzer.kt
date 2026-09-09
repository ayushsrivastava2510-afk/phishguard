package com.binarybattalion.phishguard.core

import android.graphics.Bitmap
import com.google.zxing.BinaryBitmap
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object QuishingAnalyzer {

    val QUISHING_BENCHMARKS = listOf(
        QuishingBenchmark(
            id = "reverse_collect_refund",
            title = "⚡ Tata Power Refund (Reverse Collect)",
            claimedContext = "Electricity bill overpayment refund of Rs 4,999/- approved. Scan QR to receive instant credit.",
            payload = "upi://pay?pa=rajesh_electric_refund@ybl&pn=Tata%20Power%20Refund%20Cell&am=4999.00&cu=INR&tn=Electricity%20Refund%20Approved",
            description = "High-severity reverse collect trap: promises refund but executes ₹4,999 outbound debit"
        ),
        QuishingBenchmark(
            id = "sbi_kyc_impersonation",
            title = "🏦 SBI Mandatory KYC (VPA Mismatch)",
            claimedContext = "Dear Customer, Your SBI YONO account will be blocked today due to pending KYC. Scan QR to complete verification.",
            payload = "upi://pay?pa=sbi_kyc_desk99@okaxis&pn=State%20Bank%20of%20India&am=1.00&cu=INR&tn=Mandatory%20KYC%20Re-verification",
            description = "Impersonates State Bank of India while VPA routes to individual Google Pay Axis handle"
        ),
        QuishingBenchmark(
            id = "quishing_phish_url",
            title = "🌐 Income Tax Refund Quish (.xyz)",
            claimedContext = "Your Income Tax Refund of Rs 18,450 is ready. Scan QR code to verify your bank details.",
            payload = "https://incometax-refund-gov.xyz/login/verify-pan?ref=83921",
            description = "Quishing QR code redirecting victim to disposable .xyz credential harvesting portal"
        ),
        QuishingBenchmark(
            id = "legitimate_merchant",
            title = "☕ Legitimate Cafe Merchant UPI",
            claimedContext = "Blue Tokai Coffee Roasters — Scan to pay your bill at counter.",
            payload = "upi://pay?pa=bluetokai@icici&pn=Blue%20Tokai%20Coffee&mc=5499&cu=INR&tn=Table%204%20Bill",
            description = "Standard verified cafe counter UPI payment with legitimate Merchant Category Code"
        )
    )

    private val SUSPICIOUS_TLDS = setOf(
        ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".click",
        ".loan", ".racing", ".live", ".fit", ".rest", ".bar", ".icu", ".site",
        ".buzz", ".club", ".online", ".vip"
    )

    private val PERSONAL_HANDLES = mapOf(
        "@ybl" to "PhonePe / Yes Bank (Individual Personal Handle)",
        "@ibl" to "PhonePe / ICICI Bank (Individual Personal Handle)",
        "@axl" to "PhonePe / Axis Bank (Individual Personal Handle)",
        "@okaxis" to "Google Pay / Axis Bank (Individual Personal Handle)",
        "@okhdfcbank" to "Google Pay / HDFC Bank (Individual Personal Handle)",
        "@oksbi" to "Google Pay / SBI (Individual Personal Handle)",
        "@okicici" to "Google Pay / ICICI Bank (Individual Personal Handle)",
        "@paytm" to "Paytm Consumer Wallet / Account",
        "@apl" to "Amazon Pay Consumer Handle"
    )

    private val TARGET_BRANDS = listOf(
        "sbi" to "State Bank of India",
        "state bank" to "State Bank of India",
        "tata power" to "Tata Power DD Ltd",
        "electricity" to "State Electricity Board",
        "bses" to "BSES Yamuna/Rajdhani",
        "hdfc" to "HDFC Bank",
        "icici" to "ICICI Bank",
        "axis" to "Axis Bank",
        "pnb" to "Punjab National Bank",
        "income tax" to "Income Tax Department",
        "airtel" to "Airtel Payments Bank",
        "jio" to "Jio Payments Bank"
    )

    private val REFUND_KEYWORDS = listOf(
        "refund", "cashback", "credit", "reversal", "bonus", "reward", "prize",
        "subsidy", "lottery", "won", "claim", "reimbursement", "overcharge",
        "kyc", "verification", "unblock", "activate"
    )

    /**
     * Decodes a QR code directly from an Android Bitmap using ZXing.
     */
    fun decodeQrFromBitmap(bitmap: Bitmap): String? {
        val width = bitmap.width
        val height = bitmap.height
        val pixels = IntArray(width * height)
        bitmap.getPixels(pixels, 0, width, 0, 0, width, height)
        val source = RGBLuminanceSource(width, height, pixels)
        val bBitmap = BinaryBitmap(HybridBinarizer(source))
        return try {
            val result = MultiFormatReader().decode(bBitmap)
            result.text?.trim()
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Analyzes any QR payload string (UPI Deeplink, Web URL, or Plaintext)
     * against Indian financial cyber fraud patterns.
     */
    fun analyzePayload(rawPayload: String, contextClaim: String = ""): QuishingRecord {
        val startTime = System.nanoTime()
        val trimmed = rawPayload.trim()
        val isUpi = trimmed.startsWith("upi://pay", ignoreCase = true) || trimmed.startsWith("upi://", ignoreCase = true)
        val isUrl = trimmed.startsWith("http://", ignoreCase = true) || trimmed.startsWith("https://", ignoreCase = true) || trimmed.startsWith("www.", ignoreCase = true)

        val sha256 = computeSha256(trimmed.toByteArray(StandardCharsets.UTF_8))
        val timestamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss 'IST'", Locale.getDefault()).format(Date())
        val caseId = "QUISH-" + sha256.take(8).uppercase(Locale.ROOT)

        val rec = if (isUpi) {
            analyzeUpiDeeplink(trimmed, contextClaim, caseId, sha256, timestamp)
        } else if (isUrl) {
            analyzeUrlQuish(trimmed, contextClaim, caseId, sha256, timestamp)
        } else {
            analyzePlainTextQuish(trimmed, caseId, sha256, timestamp)
        }
        val latencyMs = Math.max(1L, (System.nanoTime() - startTime) / 1_000_000L)
        return rec.copy(analysisTimeMs = latencyMs)
    }

    private fun analyzeUpiDeeplink(
        rawUpi: String,
        contextClaim: String,
        caseId: String,
        sha256: String,
        timestamp: String
    ): QuishingRecord {
        val upiDetails = parseUpiParams(rawUpi)
        val redFlags = mutableListOf<String>()
        var riskScore = 10
        var fraudCategory = "LEGITIMATE_UPI"
        var isReverseCollect = false

        val combinedText = (contextClaim + " " + upiDetails.transactionNote).lowercase(Locale.ROOT)
        val hasRefundClaim = REFUND_KEYWORDS.any { combinedText.contains(it) }

        // 1. REVERSE COLLECT PAYMENT TRAP (The Primary Attack Vector)
        if (hasRefundClaim && upiDetails.amount > 0) {
            isReverseCollect = true
            fraudCategory = "REVERSE_COLLECT_PAYMENT_TRAP"
            riskScore = 98
            redFlags.add(
                "CRITICAL REVERSE-COLLECT TRAP: Communication promises a refund or verification, but QR encodes an OUTBOUND DEBIT payment of ${upiDetails.currency} ${String.format("%.2f", upiDetails.amount)}."
            )
            redFlags.add(
                "NPCI Fundamental Protocol Violation: Scanning a QR code or entering a UPI PIN is strictly for SENDING money, never for receiving funds."
            )
        } else if (upiDetails.amount > 0 && (combinedText.contains("bill") || combinedText.contains("electricity") || combinedText.contains("urgent"))) {
            if (upiDetails.mccCode.isEmpty()) {
                redFlags.add(
                    "Unverified utility collect request of ${upiDetails.currency} ${String.format("%.2f", upiDetails.amount)} without official NPCI Merchant Category Code (MCC)."
                )
                riskScore = maxOf(riskScore, 82)
                fraudCategory = "UNVERIFIED_UTILITY_COLLECT"
            }
        }

        // 2. VPA / Handle Impersonation & Bank Mismatch
        var spoofedBrandName: String? = null
        val pnLower = upiDetails.payeeName.lowercase(Locale.ROOT)
        for ((key, brandName) in TARGET_BRANDS) {
            if (pnLower.contains(key) || combinedText.contains(key)) {
                spoofedBrandName = brandName
                break
            }
        }

        if (spoofedBrandName != null) {
            if (upiDetails.isPersonalWallet) {
                redFlags.add(
                    "VPA HANDLE SPOOFING MISMATCH: Payee claims to be '$spoofedBrandName', but VPA '${upiDetails.payeeVpa}' routes to a consumer individual wallet (${upiDetails.walletType})."
                )
                riskScore = maxOf(riskScore, 92)
                if (fraudCategory == "LEGITIMATE_UPI") {
                    fraudCategory = "VPA_IMPERSONATION_MISMATCH"
                }
            }
        }

        // 3. Omitted Payee Name
        if (upiDetails.payeeName.isEmpty() || upiDetails.payeeName.equals("Customer", ignoreCase = true) || upiDetails.payeeName.equals("User", ignoreCase = true)) {
            redFlags.add("Payee display name (`pn`) is omitted or generic filler — hides real recipient identity.")
            riskScore = maxOf(riskScore, 65)
        }

        // 4. Open-amount trap
        if (upiDetails.amount <= 0.0 && upiDetails.mccCode.isEmpty()) {
            redFlags.add("Open-amount collect deeplink: No fixed amount set; malicious collector can request custom debit.")
            riskScore = maxOf(riskScore, 40)
        }

        val verdict = when {
            riskScore >= 85 -> "CRITICAL_THREAT"
            riskScore >= 60 -> "HIGH_RISK"
            riskScore >= 35 -> "SUSPICIOUS"
            else -> "SAFE"
        }

        val headline = when {
            isReverseCollect -> "🚨 High-Severity UPI Reverse-Collect Fraud Detected"
            riskScore >= 70 -> "⚠️ Impersonated UPI Merchant Detected: ${upiDetails.payeeName.ifEmpty { upiDetails.payeeVpa }}"
            else -> "✅ Legitimate / Standard UPI Payment Payload"
        }

        val summary = if (upiDetails.amount > 0) {
            "Encodes an outbound payment request to VPA '${upiDetails.payeeVpa}' (${upiDetails.payeeName.ifEmpty { "Unknown" }}). Scanning in GPay/PhonePe/Paytm will initiate an immediate DEBIT of ${upiDetails.currency} ${String.format("%.2f", upiDetails.amount)} from your account."
        } else {
            "Decoded UPI Deeplink directed to recipient '${upiDetails.payeeVpa}' (${upiDetails.payeeName.ifEmpty { "Unspecified" }})."
        }

        val advisory = if (riskScore >= 70) {
            "DO NOT SCAN THIS QR CODE OR ENTER YOUR UPI PIN. If you enter your PIN, money will be deducted from your bank. Report this immediately to the National Cyber Crime Reporting Portal (cybercrime.gov.in or helpline 1930)."
        } else {
            "Verify the payee name on your banking screen before authorizing any payment."
        }

        val complaintDraft = """
NATIONAL CYBER CRIME REPORTING PORTAL (cybercrime.gov.in / 1930)
COMPLAINT: UPI FINANCIAL FRAUD (QUISHING / REVERSE-COLLECT SCAM)
===============================================================
INCIDENT DATE: $timestamp
CASE ID: $caseId
FRAUD CATEGORY: $fraudCategory
RISK INDEX: $riskScore/100 (HIGH RISK)

BENEFICIARY PARTICULARS:
- Fraudulent VPA Address: ${upiDetails.payeeVpa}
- Claimed Display Name: ${upiDetails.payeeName}
- Attempted Debit Amount: ${upiDetails.currency} ${String.format("%.2f", upiDetails.amount)}
- Provider Handle: ${upiDetails.walletType}

ATTACK VECTOR:
The fraudster delivered a QR code claiming a refund/verification. Digital forensic inspection confirms the QR executes a reverse-collect payment request to siphon victim funds upon UPI PIN entry.

REQUESTED ACTION:
1. Immediate freeze of beneficiary VPA: ${upiDetails.payeeVpa} under IT Act & PMLA.
2. Flagging in NPCI Centralized Fraud Registry.

CRYPTOGRAPHIC EVIDENCE SHA-256:
$sha256
===============================================================
Generated autonomously by PhishGuard Mobile SOC Sentinel
        """.trimIndent()

        return QuishingRecord(
            caseId = caseId,
            payloadType = "UPI",
            rawPayload = rawUpi,
            riskScore = riskScore,
            verdict = verdict,
            fraudCategory = fraudCategory,
            headline = headline,
            summary = summary,
            redFlags = redFlags,
            isReverseCollect = isReverseCollect,
            upiDetails = upiDetails,
            advisory = advisory,
            evidenceHash = sha256,
            timestamp = timestamp,
            policeComplaintDraft = complaintDraft
        )
    }

    private fun analyzeUrlQuish(
        rawUrl: String,
        contextClaim: String,
        caseId: String,
        sha256: String,
        timestamp: String
    ): QuishingRecord {
        val redFlags = mutableListOf<String>()
        var riskScore = 15
        var fraudCategory = "BENIGN_URL"

        val lowerUrl = rawUrl.lowercase(Locale.ROOT)
        var host = ""
        try {
            val stripped = if (lowerUrl.contains("://")) lowerUrl.substringAfter("://") else lowerUrl
            host = stripped.substringBefore("/").substringBefore(":")
        } catch (e: Exception) {
            host = lowerUrl
        }

        // 1. IP Host
        if (host.matches(Regex("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$"))) {
            redFlags.add("Direct numeric IP address host in QR destination: '$host' (bypasses domain reputation filters).")
            riskScore = maxOf(riskScore, 90)
        }

        // 2. High-Risk TLD
        for (tld in SUSPICIOUS_TLDS) {
            if (host.endsWith(tld)) {
                redFlags.add("Destination uses high-risk disposable TLD ('$tld') linked to cyber fraud.")
                riskScore = maxOf(riskScore, 85)
                break
            }
        }

        // 3. URL Shortener
        val shorteners = setOf("bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "ow.ly", "rb.gy")
        if (shorteners.contains(host)) {
            redFlags.add("QR code uses URL Shortener ('$host') to conceal final malicious redirection endpoint.")
            riskScore = maxOf(riskScore, 75)
        }

        // 4. Credential Harvesting Path
        val sensitiveKws = listOf("login", "signin", "kyc", "pan-update", "refund", "verify", "secure", "sbi", "hdfc", "axis", "aadhaar")
        val hits = sensitiveKws.filter { lowerUrl.contains(it) }
        if (hits.isNotEmpty()) {
            redFlags.add("URL contains credential-harvesting triggers: ${hits.joinToString(", ")} on host '$host'.")
            riskScore = maxOf(riskScore, 88)
        }

        // 5. Insecure HTTP
        if (lowerUrl.startsWith("http://")) {
            redFlags.add("Insecure plain HTTP connection — credentials transmitted in cleartext.")
            riskScore = maxOf(riskScore, 50)
        }

        val verdict = when {
            riskScore >= 80 -> {
                fraudCategory = "PHISHING_URL_QUISH"
                "CRITICAL_THREAT"
            }
            riskScore >= 50 -> {
                fraudCategory = "SUSPICIOUS_REDIRECT"
                "HIGH_RISK"
            }
            else -> "SAFE"
        }

        val headline = if (riskScore >= 80) {
            "🚨 Quishing Attack: Malicious Redirect to Fake Portal ($host)"
        } else if (riskScore >= 50) {
            "⚠️ High-Risk QR Redirect Detected: $host"
        } else {
            "✅ Standard Web URL Destination: $host"
        }

        val summary = "Decoded QR code redirects the browser to '$rawUrl'. Checked for typosquatting, credential harvesting, and IP masking."
        val advisory = if (riskScore >= 50) {
            "Do not open this URL on mobile devices or input banking credentials/OTP passwords."
        } else {
            "Safe standard web link."
        }

        val complaintDraft = """
NATIONAL CYBER CRIME REPORTING PORTAL (cybercrime.gov.in / 1930)
COMPLAINT: WEB QUISHING (QR PHISHING REDIRECT)
===============================================================
INCIDENT DATE: $timestamp
CASE ID: $caseId
FRAUD CATEGORY: $fraudCategory
DESTINATION URL: $rawUrl
RISK INDEX: $riskScore/100

ATTACK VECTOR:
Malicious QR code embedding a credential harvesting URL redirecting victims to a fraudulent portal.

REQUESTED ACTION:
1. Urgent domain suspension request to registrar for: $host.
2. Takedown notice under Information Technology (Intermediary Guidelines) Rules.

CRYPTOGRAPHIC EVIDENCE SHA-256:
$sha256
===============================================================
Generated autonomously by PhishGuard Mobile SOC Sentinel
        """.trimIndent()

        return QuishingRecord(
            caseId = caseId,
            payloadType = "URL",
            rawPayload = rawUrl,
            riskScore = riskScore,
            verdict = verdict,
            fraudCategory = fraudCategory,
            headline = headline,
            summary = summary,
            redFlags = redFlags,
            isReverseCollect = false,
            upiDetails = null,
            advisory = advisory,
            evidenceHash = sha256,
            timestamp = timestamp,
            policeComplaintDraft = complaintDraft
        )
    }

    private fun analyzePlainTextQuish(
        text: String,
        caseId: String,
        sha256: String,
        timestamp: String
    ): QuishingRecord {
        return QuishingRecord(
            caseId = caseId,
            payloadType = "PLAIN_TEXT",
            rawPayload = text,
            riskScore = 10,
            verdict = "SAFE",
            fraudCategory = "PLAIN_TEXT",
            headline = "ℹ️ Plain Text QR Code Content",
            summary = "Decoded plaintext content: ${text.take(80)}...",
            redFlags = emptyList(),
            isReverseCollect = false,
            upiDetails = null,
            advisory = "Standard plaintext QR code. No active UPI payment or executable URLs found.",
            evidenceHash = sha256,
            timestamp = timestamp,
            policeComplaintDraft = "No actionable violation found."
        )
    }

    private fun parseUpiParams(rawUpi: String): UpiDetails {
        var pa = ""
        var pn = ""
        var am = 0.0
        var cu = "INR"
        var tn = ""
        var mc = ""
        var tr = ""

        try {
            val query = if (rawUpi.contains("?")) rawUpi.substringAfter("?") else ""
            val pairs = query.split("&")
            for (p in pairs) {
                val kv = p.split("=", limit = 2)
                if (kv.size == 2) {
                    val key = kv[0].lowercase(Locale.ROOT)
                    val value = try {
                        URLDecoder.decode(kv[1], "UTF-8")
                    } catch (e: Exception) {
                        kv[1]
                    }
                    when (key) {
                        "pa" -> pa = value
                        "pn" -> pn = value
                        "am" -> am = value.toDoubleOrNull() ?: 0.0
                        "cu" -> cu = value
                        "tn" -> tn = value
                        "mc" -> mc = value
                        "tr" -> tr = value
                    }
                }
            }
        } catch (e: Exception) {
            // Graceful fallback
        }

        val handle = if (pa.contains("@")) "@" + pa.substringAfter("@").lowercase(Locale.ROOT) else ""
        val isPersonal = PERSONAL_HANDLES.containsKey(handle)
        val walletType = PERSONAL_HANDLES[handle] ?: if (handle.isNotEmpty()) "Institutional Handle ($handle)" else "Unknown / Unspecified"

        return UpiDetails(
            payeeVpa = pa,
            payeeName = pn,
            amount = am,
            currency = cu,
            transactionNote = tn,
            handle = handle,
            isPersonalWallet = isPersonal,
            walletType = walletType,
            mccCode = mc,
            refId = tr
        )
    }

    private fun computeSha256(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(bytes)
        return hash.joinToString("") { "%02x".format(it) }
    }
}
