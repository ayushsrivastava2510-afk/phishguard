package com.binarybattalion.phishguard.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.binarybattalion.phishguard.core.EmailAnalyzer
import com.binarybattalion.phishguard.core.EmailAuditRecord
import com.binarybattalion.phishguard.core.EmailInboxScanSummary
import com.binarybattalion.phishguard.core.GmailInboxScanner
import com.binarybattalion.phishguard.core.ScannedInboxEmail
import com.binarybattalion.phishguard.ui.components.CircularRiskGauge
import com.binarybattalion.phishguard.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class EmailScenario(
    val id: String,
    val title: String,
    val subject: String,
    val from: String,
    val body: String
)

val EMAIL_BENCHMARKS = listOf(
    EmailScenario(
        id = "sbi_email",
        title = "SBI KYC Fraud",
        subject = "Urgent: Mandated KYC Verification Notice for State Bank Account",
        from = "alert-services@sbi-online-portal.in",
        body = "Dear Customer, your internet banking will be permanently deactivated in 24 hours unless you complete mandatory KYC. Verify immediately: http://sbi-kyc-update.online/auth"
    ),
    EmailScenario(
        id = "paypal_email",
        title = "PayPal Spoof",
        subject = "Unauthorized Login Attempt Detected on Your PayPal Account",
        from = "security@paypa1.com",
        body = "We noticed suspicious access from an unknown IP in Russia. Confirm your identity immediately at http://paypa1-security.com or funds will be locked."
    ),
    EmailScenario(
        id = "bec_email",
        title = "Executive BEC Wire",
        subject = "STRICTLY CONFIDENTIAL: Immediate Acquisition Wire Transfer Required",
        from = "cfo-office@partner-corp.com",
        body = "Please process an urgent wire transfer of $45,000 before bank cut-off. Do not discuss with anyone in the office as this deal is confidential. Wire instructions attached."
    ),
    EmailScenario(
        id = "legit_email",
        title = "Legitimate Partner",
        subject = "Quarterly Business Review: Meeting Agenda & Slide Deck",
        from = "sarah.jenkins@enterprise-partner.com",
        body = "Hi team, please find attached the agenda for tomorrow's 10:00 AM QBR. Looking forward to reviewing the quarterly performance."
    )
)

@Composable
fun EmailScreen(modifier: Modifier = Modifier) {
    val scope = rememberCoroutineScope()

    var activeId by remember { mutableStateOf("") }
    var currentAnalysis by remember {
        mutableStateOf(
            EmailAnalyzer.analyzeEmail(
                EMAIL_BENCHMARKS[0].subject,
                EMAIL_BENCHMARKS[0].from,
                EMAIL_BENCHMARKS[0].body
            )
        )
    }

    // Gmail Sentinel State
    var gmailAccount by remember { mutableStateOf("ayush.security@gmail.com") }
    var gmailAccessToken by remember { mutableStateOf("") }
    var isConfigExpanded by remember { mutableStateOf(false) }
    var inboxScanSummary by remember { mutableStateOf<EmailInboxScanSummary?>(null) }
    var isScanningGmail by remember { mutableStateOf(false) }

    fun runGmailScan() {
        isScanningGmail = true
        scope.launch(Dispatchers.IO) {
            val result = if (gmailAccessToken.isNotBlank()) {
                GmailInboxScanner.scanLiveGmail(gmailAccessToken, limit = 15, accountEmail = gmailAccount)
            } else {
                GmailInboxScanner.getSampleGmailInbox(gmailAccount)
            }
            withContext(Dispatchers.Main) {
                inboxScanSummary = result
                isScanningGmail = false
                if (result.items.isNotEmpty()) {
                    activeId = ""
                    currentAnalysis = result.items[0].record
                }
            }
        }
    }

    // Auto-scan on initial launch
    LaunchedEffect(Unit) {
        if (inboxScanSummary == null) {
            val summary = GmailInboxScanner.getSampleGmailInbox(gmailAccount)
            inboxScanSummary = summary
            if (summary.items.isNotEmpty()) {
                activeId = ""
                currentAnalysis = summary.items[0].record
            }
        }
    }

    // Custom Email State
    var customSubject by remember { mutableStateOf("") }
    var customFrom by remember { mutableStateOf("") }
    var customBody by remember { mutableStateOf("") }
    var isCustomExpanded by remember { mutableStateOf(false) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(BgDark)
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
    ) {
        // 1. LIVE GMAIL SENTINEL CARD
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = CardDark),
            border = BorderStroke(1.dp, PrimaryCobalt.copy(alpha = 0.5f)),
            shape = RoundedCornerShape(14.dp)
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(28.dp)
                                .background(Color(0x33EF4444), RoundedCornerShape(6.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                Icons.Default.Mail,
                                contentDescription = "Gmail",
                                tint = Color(0xFFEF4444),
                                modifier = Modifier.size(16.dp)
                            )
                        }
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "LIVE GMAIL SENTINEL",
                            color = TextPrimary,
                            fontWeight = FontWeight.Bold,
                            fontSize = 13.sp
                        )
                    }

                    Box(
                        modifier = Modifier
                            .background(Color(0x2610B981), RoundedCornerShape(4.dp))
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = "AUTONOMOUS READY",
                            color = RiskCleanLight,
                            fontSize = 8.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }

                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "Directly audits your Gmail inbox for banking scams, executive BEC wire fraud, credential harvesters, and lookalike domains in real-time.",
                    color = TextSecondary,
                    fontSize = 11.sp,
                    lineHeight = 15.sp
                )

                Spacer(modifier = Modifier.height(8.dp))

                // Account Bar
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(CardDarkElevated, RoundedCornerShape(8.dp))
                        .padding(horizontal = 10.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            Icons.Default.AccountCircle,
                            contentDescription = null,
                            tint = PrimaryCobaltLight,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = gmailAccount,
                            color = TextPrimary,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Medium
                        )
                    }

                    Text(
                        text = if (isConfigExpanded) "Done" else "Settings / Token",
                        color = AccentCyan,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.clickable { isConfigExpanded = !isConfigExpanded }
                    )
                }

                if (isConfigExpanded) {
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = gmailAccount,
                        onValueChange = { gmailAccount = it },
                        label = { Text("Gmail Address", fontSize = 11.sp) },
                        modifier = Modifier.fillMaxWidth(),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = PrimaryCobalt,
                            unfocusedBorderColor = BorderDark,
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary
                        ),
                        singleLine = true
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    OutlinedTextField(
                        value = gmailAccessToken,
                        onValueChange = { gmailAccessToken = it },
                        label = { Text("OAuth2 Token / App Password (optional)", fontSize = 11.sp) },
                        modifier = Modifier.fillMaxWidth(),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = PrimaryCobalt,
                            unfocusedBorderColor = BorderDark,
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary
                        ),
                        singleLine = true
                    )
                }

                Spacer(modifier = Modifier.height(10.dp))

                Button(
                    onClick = { runGmailScan() },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = PrimaryCobalt),
                    shape = RoundedCornerShape(8.dp),
                    enabled = !isScanningGmail
                ) {
                    if (isScanningGmail) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(16.dp),
                            color = Color.White,
                            strokeWidth = 2.dp
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Scanning Gmail Inbox...", fontSize = 12.sp, color = Color.White)
                    } else {
                        Icon(
                            Icons.Default.Refresh,
                            contentDescription = "Scan",
                            modifier = Modifier.size(16.dp),
                            tint = Color.White
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "⚡ Auto-Scan Gmail Inbox",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color.White
                        )
                    }
                }

                // Scanned Gmail Summary Feed
                inboxScanSummary?.let { summary ->
                    Spacer(modifier = Modifier.height(12.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        EmailMetricBadge(label = "Scanned", value = "${summary.totalScanned}", color = AccentCyan, modifier = Modifier.weight(1f))
                        EmailMetricBadge(label = "🚨 Threats", value = "${summary.criticalThreats}", color = RiskCritical, modifier = Modifier.weight(1f))
                        EmailMetricBadge(label = "⚠️ Suspicious", value = "${summary.suspiciousCount}", color = RiskWarning, modifier = Modifier.weight(1f))
                        EmailMetricBadge(label = "🟢 Safe", value = "${summary.safeCount}", color = RiskClean, modifier = Modifier.weight(1f))
                    }

                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        text = "TAP ANY GMAIL MESSAGE TO INSPECT FORENSICS:",
                        color = TextTertiary,
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(modifier = Modifier.height(4.dp))

                    Column(
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                        modifier = Modifier
                            .heightIn(max = 240.dp)
                            .verticalScroll(rememberScrollState())
                    ) {
                        summary.items.forEach { item ->
                            val isHighRisk = item.record.riskScore >= 70
                            val isMediumRisk = item.record.riskScore in 35..69
                            val badgeColor = when {
                                isHighRisk -> RiskCritical
                                isMediumRisk -> RiskWarning
                                else -> RiskClean
                            }
                            val badgeTextColor = when {
                                isHighRisk -> RiskCriticalLight
                                isMediumRisk -> Color(0xFFFBBF24)
                                else -> RiskCleanLight
                            }

                            val isSelected = (currentAnalysis.evidenceHash == item.record.evidenceHash)

                            Card(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        activeId = ""
                                        currentAnalysis = item.record
                                    },
                                colors = CardDefaults.cardColors(
                                    containerColor = if (isSelected) Color(0x334D65FF) else CardDarkElevated
                                ),
                                border = BorderStroke(
                                    1.dp,
                                    if (isSelected) PrimaryCobaltLight else BorderDark
                                ),
                                shape = RoundedCornerShape(8.dp)
                            ) {
                                Row(
                                    modifier = Modifier.padding(8.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            Text(
                                                text = item.sender,
                                                color = TextPrimary,
                                                fontWeight = FontWeight.Bold,
                                                fontSize = 12.sp,
                                                maxLines = 1,
                                                overflow = TextOverflow.Ellipsis,
                                                modifier = Modifier.weight(1f, fill = false)
                                            )
                                            Spacer(modifier = Modifier.width(6.dp))
                                            Text(
                                                text = item.formattedDate,
                                                color = TextTertiary,
                                                fontSize = 9.sp
                                            )
                                        }
                                        Spacer(modifier = Modifier.height(2.dp))
                                        Text(
                                            text = item.subject,
                                            color = TextPrimary,
                                            fontSize = 11.sp,
                                            fontWeight = FontWeight.SemiBold,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                        Text(
                                            text = item.bodySnippet,
                                            color = TextSecondary,
                                            fontSize = 10.sp,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                    }

                                    Spacer(modifier = Modifier.width(6.dp))

                                    Box(
                                        modifier = Modifier
                                            .background(badgeColor.copy(alpha = 0.2f), RoundedCornerShape(4.dp))
                                            .padding(horizontal = 6.dp, vertical = 3.dp)
                                    ) {
                                        Text(
                                            text = "${item.record.riskScore}/100",
                                            color = badgeTextColor,
                                            fontSize = 10.sp,
                                            fontWeight = FontWeight.ExtraBold
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // 2. HERO CASE CARD
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, BorderDark, RoundedCornerShape(12.dp)),
            colors = CardDefaults.cardColors(containerColor = CardDarkElevated),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .background(Color(0x264D65FF), RoundedCornerShape(6.dp))
                            .padding(horizontal = 8.dp, vertical = 4.dp)
                    ) {
                        Text("CURRENT FORENSIC TARGET", color = PrimaryCobaltLight, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                    }
                    Text(
                        text = "Case: ${currentAnalysis.caseId}",
                        color = TextSecondary,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))
                Text(currentAnalysis.threatCategory, color = TextPrimary, fontSize = 16.sp, fontWeight = FontWeight.Bold)
                Spacer(modifier = Modifier.height(4.dp))
                Text("Subject: ${currentAnalysis.subject}", color = TextSecondary, fontSize = 12.sp)
                Text("Sender: ${currentAnalysis.fromSender}", color = AccentCyan, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // 3. CIRCULAR RISK GAUGE
        CircularRiskGauge(
            score = currentAnalysis.riskScore,
            verdict = currentAnalysis.verdict
        )

        Spacer(modifier = Modifier.height(14.dp))

        // 4. FINDINGS & SECTION 65B HASH
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = CardDark),
            border = BorderStroke(1.dp, BorderDark),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Text("Section 65B BSA Forensic Evidence", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                Spacer(modifier = Modifier.height(6.dp))
                Text("SHA-256 Digest:", color = TextTertiary, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                Text(currentAnalysis.evidenceHash, color = AccentCyan, fontFamily = FontFamily.Monospace, fontSize = 10.sp)

                Spacer(modifier = Modifier.height(10.dp))
                Text("Forensic Red Flags:", color = TextTertiary, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                if (currentAnalysis.redFlags.isNotEmpty()) {
                    currentAnalysis.redFlags.forEach { flag ->
                        Text("🚩 $flag", color = RiskCriticalLight, fontSize = 11.sp, lineHeight = 16.sp)
                    }
                } else {
                    Text("✅ No malicious intent indicators detected.", color = RiskClean, fontSize = 12.sp)
                }

                Spacer(modifier = Modifier.height(8.dp))
                Text("Recommended Mitigation:", color = TextTertiary, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                Text(currentAnalysis.actionMsg, color = TextSecondary, fontSize = 11.sp, lineHeight = 15.sp)
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // 5. 1-CLICK EMAIL BENCHMARKS (AUXILIARY)
        Text(
            text = "1-CLICK BENCHMARK SCENARIOS",
            color = TextTertiary,
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            letterSpacing = 1.sp
        )

        Spacer(modifier = Modifier.height(8.dp))

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            EMAIL_BENCHMARKS.forEach { scenario ->
                val isSelected = (scenario.id == activeId)
                FilterChip(
                    selected = isSelected,
                    onClick = {
                        activeId = scenario.id
                        currentAnalysis = EmailAnalyzer.analyzeEmail(scenario.subject, scenario.from, scenario.body)
                    },
                    label = {
                        Text(
                            text = scenario.title,
                            fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                            fontSize = 12.sp
                        )
                    },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = PrimaryCobalt,
                        selectedLabelColor = TextPrimary,
                        containerColor = CardDark,
                        labelColor = TextSecondary
                    ),
                    border = FilterChipDefaults.filterChipBorder(
                        enabled = true,
                        selected = isSelected,
                        borderColor = BorderDark,
                        selectedBorderColor = PrimaryCobaltLight
                    )
                )
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // 6. CUSTOM EMAIL AUDIT EXPANDER
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = CardDark),
            border = BorderStroke(1.dp, BorderDark),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.MailOutline, contentDescription = null, tint = AccentCyan, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Audit Custom Email Message", color = TextPrimary, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                    }
                    IconButton(onClick = { isCustomExpanded = !isCustomExpanded }) {
                        Icon(
                            if (isCustomExpanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                            contentDescription = null,
                            tint = TextSecondary
                        )
                    }
                }

                if (isCustomExpanded) {
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = customSubject,
                        onValueChange = { customSubject = it },
                        label = { Text("Subject Line", fontSize = 12.sp) },
                        modifier = Modifier.fillMaxWidth(),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = PrimaryCobalt,
                            unfocusedBorderColor = BorderDark,
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary
                        ),
                        singleLine = true
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = customFrom,
                        onValueChange = { customFrom = it },
                        label = { Text("Sender Email (From)", fontSize = 12.sp) },
                        modifier = Modifier.fillMaxWidth(),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = PrimaryCobalt,
                            unfocusedBorderColor = BorderDark,
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary
                        ),
                        singleLine = true
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = customBody,
                        onValueChange = { customBody = it },
                        label = { Text("Email Content / Body", fontSize = 12.sp) },
                        modifier = Modifier.fillMaxWidth(),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = PrimaryCobalt,
                            unfocusedBorderColor = BorderDark,
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary
                        ),
                        maxLines = 4
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Button(
                        onClick = {
                            if (customBody.isNotBlank()) {
                                activeId = "custom"
                                currentAnalysis = EmailAnalyzer.analyzeEmail(customSubject, customFrom, customBody)
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = PrimaryCobalt),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Text("Analyze Email Content", fontWeight = FontWeight.Bold, fontSize = 13.sp)
                    }
                }
            }
        }
    }
}

@Composable
private fun EmailMetricBadge(label: String, value: String, color: Color, modifier: Modifier = Modifier) {
    Box(
        modifier = modifier
            .background(color.copy(alpha = 0.12f), RoundedCornerShape(6.dp))
            .border(1.dp, color.copy(alpha = 0.3f), RoundedCornerShape(6.dp))
            .padding(vertical = 5.dp),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(value, color = color, fontWeight = FontWeight.ExtraBold, fontSize = 13.sp)
            Text(label, color = color.copy(alpha = 0.9f), fontSize = 8.sp, fontWeight = FontWeight.Bold)
        }
    }
}
