package com.binarybattalion.phishguard

import com.binarybattalion.phishguard.core.EmailAnalyzer
import com.binarybattalion.phishguard.core.SmishingAnalyzer
import org.junit.Assert.*
import org.junit.Test

class SmishingAnalyzerTest {

    @Test
    fun testSbiYonoKycSmishingDetection() {
        val b = SmishingAnalyzer.SMISHING_BENCHMARKS[0]
        val result = SmishingAnalyzer.analyzeSmishingMessage(b.senderId, b.text)

        assertFalse("10-digit SIM must not be DLT compliant", result.senderInfo.isDltCompliant)
        assertTrue("Must detect shortened URL", result.urlInfo.shortenedUrls.isNotEmpty())
        assertTrue("Must detect banking KYC fraud", result.threatCategory.contains("Financial"))
        assertEquals("CRITICAL SMISHING THREAT", result.verdict)
        assertTrue("Risk score must be high (>=80)", result.riskScore >= 80)
        assertTrue("Chakshu draft must contain sender ID", result.chakshuDraft.contains(b.senderId))
    }

    @Test
    fun testElectricityDisconnectionCoercion() {
        val b = SmishingAnalyzer.SMISHING_BENCHMARKS[1]
        val result = SmishingAnalyzer.analyzeSmishingMessage(b.senderId, b.text)

        assertFalse(result.senderInfo.isDltCompliant)
        assertTrue("Must detect electricity disconnection scam", result.threatCategory.contains("Electricity"))
        assertEquals("CRITICAL SMISHING THREAT", result.verdict)
        assertTrue(result.riskScore >= 80)
    }

    @Test
    fun testEChallanApkTrojanDropper() {
        val b = SmishingAnalyzer.SMISHING_BENCHMARKS[2]
        val result = SmishingAnalyzer.analyzeSmishingMessage(b.senderId, b.text)

        assertTrue("Must detect Android .apk dropper", result.urlInfo.apkDroppers.isNotEmpty())
        assertTrue("Must detect traffic challan category", result.threatCategory.contains("Challan"))
        assertEquals("CRITICAL SMISHING THREAT", result.verdict)
        assertTrue(result.riskScore >= 90)
    }

    @Test
    fun testTaskScamCrossBorderDetection() {
        val b = SmishingAnalyzer.SMISHING_BENCHMARKS[3]
        val result = SmishingAnalyzer.analyzeSmishingMessage(b.senderId, b.text)

        assertTrue("Must detect cross-border Indonesian virtual route", result.senderInfo.senderType.contains("Indonesia"))
        assertTrue("Must classify as part-time task scam", result.threatCategory.contains("Task"))
        assertTrue(result.riskScore >= 70)
    }

    @Test
    fun testLegitimateDltOtpIsSafe() {
        val b = SmishingAnalyzer.SMISHING_BENCHMARKS.first { it.id == "legit_otp_sms" }
        val result = SmishingAnalyzer.analyzeSmishingMessage(b.senderId, b.text)

        assertTrue("AD-HDFCBK must be DLT compliant", result.senderInfo.isDltCompliant)
        assertTrue("Must classify as Transactional Alert", result.threatCategory.contains("Transactional"))
        assertEquals("VERIFIED SAFE SMS", result.verdict)
        assertTrue("Risk score must be low (<=15)", result.riskScore <= 15)
    }

    @Test
    fun testEmailSemanticAnalysis() {
        val result = EmailAnalyzer.analyzeEmail(
            subject = "Urgent: Mandated KYC Verification Notice",
            fromSender = "alert-services@sbi-online-portal.in",
            bodyText = "Dear Customer, complete mandatory KYC immediately to avoid account closure."
        )

        assertTrue("Must detect KYC fraud", result.threatCategory.contains("KYC"))
        assertTrue("Risk score must be elevated (>=70)", result.riskScore >= 70)
        assertNotNull("Must generate SHA-256 evidence hash", result.evidenceHash)
        assertEquals(64, result.evidenceHash.length)
    }
}
