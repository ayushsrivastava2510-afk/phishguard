package com.binarybattalion.phishguard.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.binarybattalion.phishguard.core.EmailAnalyzer
import com.binarybattalion.phishguard.core.EmailAuditRecord
import com.binarybattalion.phishguard.ui.components.CircularRiskGauge
import com.binarybattalion.phishguard.ui.theme.*

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
        body = "Please process an urgent wire transfer of \$45,000 before bank cut-off. Do not discuss with anyone in the office as this deal is confidential. Wire instructions attached."
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
    var activeId by remember { mutableStateOf(EMAIL_BENCHMARKS[0].id) }
    var currentAnalysis by remember {
        mutableStateOf(
            EmailAnalyzer.analyzeEmail(
                EMAIL_BENCHMARKS[0].subject,
                EMAIL_BENCHMARKS[0].from,
                EMAIL_BENCHMARKS[0].body
            )
        )
    }

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
        // 1. 1-Click Email Benchmarks
        Text(
            text = "1-CLICK EMAIL THREAT BENCHMARKS",
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

        // 2. Custom Email Audit Expander
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

        Spacer(modifier = Modifier.height(14.dp))

        // 3. Hero Card
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
                        Text("EMAIL SENTINEL", color = PrimaryCobaltLight, fontSize = 10.sp, fontWeight = FontWeight.Bold)
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
                Text("Domain: ${currentAnalysis.fromDomain}", color = AccentCyan, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // 4. Gauge
        CircularRiskGauge(
            score = currentAnalysis.riskScore,
            verdict = currentAnalysis.verdict
        )

        Spacer(modifier = Modifier.height(14.dp))

        // 5. Findings & Section 65B Hash
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
            }
        }
    }
}
