package com.binarybattalion.phishguard.core

import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object EmailAnalyzer {

    fun analyzeEmail(subject: String, fromSender: String, bodyText: String): EmailAuditRecord {
        val startTime = System.nanoTime()
        val sLower = subject.lowercase(Locale.ROOT)
        val bLower = bodyText.lowercase(Locale.ROOT)
        val fLower = fromSender.lowercase(Locale.ROOT)

        val redFlags = mutableListOf<String>()
        var riskScore = 10
        var category = "Routine Communication"

        // Domain extraction
        val domain = if (fLower.contains("@")) fLower.substringAfter("@").trim() else "unknown.domain"

        // 1. Executive BEC Wire Diversion
        if (sLower.contains("wire transfer") || bLower.contains("wire transfer") || bLower.contains("gift card") ||
            bLower.contains("strictly confidential") || bLower.contains("revised invoice")
        ) {
            category = "Executive BEC Wire Diversion"
            riskScore += 65
            redFlags.add("CEO/Executive Impersonation: Coerces unauthorized fund transfer outside normal procurement.")
        }

        // 2. Financial / Banking Phishing
        if (sLower.contains("kyc") || bLower.contains("kyc") || bLower.contains("pan card") ||
            bLower.contains("bank account blocked") || bLower.contains("aadhaar")
        ) {
            category = "Financial / Banking KYC Fraud"
            riskScore += 75
            redFlags.add("Banking KYC Panic: Falsely threatens account termination to harvest credentials.")
        }

        // 3. Domain Spoofing / Lookalike
        if (domain.contains("paypa1") || domain.contains("amaz0n") || domain.contains("micros0ft") ||
            (domain.endsWith(".xyz") || domain.endsWith(".top") || domain.endsWith(".ru"))
        ) {
            riskScore += 45
            redFlags.add("Spoofed / High-Risk TLD: Domain ($domain) uses typosquatting or untrusted registrar.")
        }

        // 4. Urgency Cues
        if (bLower.contains("immediately") || bLower.contains("within 24 hours") || bLower.contains("act now") ||
            bLower.contains("urgent action")
        ) {
            riskScore += 20
            redFlags.add("Artificial Time Pressure: Intentionally limits response time to bypass logical scrutiny.")
        }

        val finalScore = minOf(100, maxOf(5, riskScore))
        val (verdict, action) = when {
            finalScore >= 70 -> Pair("CRITICAL EMAIL THREAT", "DANGER: Block sender IP, do not click links or open attachments.")
            finalScore >= 35 -> Pair("SUSPICIOUS / ELEVATED RISK", "CAUTION: Verify sender identity via secondary official channel.")
            else -> Pair("VERIFIED SECURE EMAIL", "SAFE: Baseline corporate email with standard security posture.")
        }

        val caseId = "EML-2026-${(System.currentTimeMillis() % 100000).toString().padStart(5, '0')}"
        val sha256 = sha256("$fromSender:$subject:$bodyText")
        val timestamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.US).format(Date())

        return EmailAuditRecord(
            caseId = caseId,
            subject = subject,
            fromSender = fromSender,
            fromDomain = domain,
            riskScore = finalScore,
            threatCategory = category,
            verdict = verdict,
            actionMsg = action,
            redFlags = redFlags,
            evidenceHash = sha256,
            timestamp = timestamp,
            analysisTimeMs = Math.max(1L, (System.nanoTime() - startTime) / 1_000_000L)
        )
    }

    private fun sha256(input: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(input.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
