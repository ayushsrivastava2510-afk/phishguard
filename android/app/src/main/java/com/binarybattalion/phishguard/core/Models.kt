package com.binarybattalion.phishguard.core

data class SenderInfo(
    val rawSender: String,
    val isDltCompliant: Boolean,
    val senderType: String,
    val operatorCircle: String,
    val entityName: String,
    val riskBoost: Int,
    val redFlags: List<String>
)

data class UrlAnalysis(
    val urls: List<String>,
    val shortenedUrls: List<String>,
    val apkDroppers: List<String>,
    val lookalikeDomains: List<String>,
    val riskBoost: Int,
    val redFlags: List<String>
)

data class IntentAnalysis(
    val primaryCategory: String,
    val urgencyLevel: String,
    val cuesDetected: List<String>,
    val intentRiskBoost: Int
)

data class SmishingRecord(
    val caseId: String,
    val channel: String = "Mobile SMS (GSM/LTE Telemetry)",
    val senderId: String,
    val senderInfo: SenderInfo,
    val rawMessage: String,
    val riskScore: Int,
    val verdict: String,
    val actionMsg: String,
    val threatCategory: String,
    val urgencyLevel: String,
    val urlInfo: UrlAnalysis,
    val allRedFlags: List<String>,
    val evidenceHash: String,
    val timestamp: String,
    val chakshuDraft: String
)

data class SmishingBenchmark(
    val id: String,
    val title: String,
    val senderId: String,
    val text: String,
    val description: String
)

data class EmailAuditRecord(
    val caseId: String,
    val subject: String,
    val fromSender: String,
    val fromDomain: String,
    val riskScore: Int,
    val threatCategory: String,
    val verdict: String,
    val actionMsg: String,
    val redFlags: List<String>,
    val evidenceHash: String,
    val timestamp: String
)

data class ScannedInboxEmail(
    val id: String,
    val subject: String,
    val sender: String,
    val bodySnippet: String,
    val timestamp: Long,
    val formattedDate: String,
    val record: EmailAuditRecord
)

data class EmailInboxScanSummary(
    val accountEmail: String,
    val totalScanned: Int,
    val criticalThreats: Int,
    val suspiciousCount: Int,
    val safeCount: Int,
    val items: List<ScannedInboxEmail>
)

