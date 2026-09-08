package com.binarybattalion.phishguard.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.binarybattalion.phishguard.core.SmishingAnalyzer
import com.binarybattalion.phishguard.core.SmishingRecord
import com.binarybattalion.phishguard.ui.components.CircularRiskGauge
import com.binarybattalion.phishguard.ui.theme.*

@Composable
fun SmishingScreen(
    initialRecord: SmishingRecord? = null,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var activeBenchmarkId by remember { mutableStateOf(SmishingAnalyzer.SMISHING_BENCHMARKS[0].id) }
    var currentAnalysis by remember {
        mutableStateOf(initialRecord ?: SmishingAnalyzer.analyzeSmishingMessage(
            SmishingAnalyzer.SMISHING_BENCHMARKS[0].senderId,
            SmishingAnalyzer.SMISHING_BENCHMARKS[0].text
        ))
    }

    var customSender by remember { mutableStateOf("+91 98234 11223") }
    var customText by remember { mutableStateOf("Dear SBI Customer, your YONO account is blocked today due to pending KYC. Update PAN: bit.ly/sbi-yono-kyc-update") }
    var isCustomExpanded by remember { mutableStateOf(false) }
    var selectedTab by remember { mutableIntStateOf(0) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(BgDark)
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
    ) {
        // 1. 1-Click Attack Scenario Benchmarks
        Text(
            text = "1-CLICK SMISHING ATTACK BENCHMARKS",
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
            SmishingAnalyzer.SMISHING_BENCHMARKS.forEach { benchmark ->
                val isSelected = (benchmark.id == activeBenchmarkId)
                FilterChip(
                    selected = isSelected,
                    onClick = {
                        activeBenchmarkId = benchmark.id
                        currentAnalysis = SmishingAnalyzer.analyzeSmishingMessage(benchmark.senderId, benchmark.text)
                    },
                    label = {
                        Text(
                            text = benchmark.title.substringBefore(":"),
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

        // 2. Custom SMS Ingress Box (Collapsible)
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = CardDark),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Edit, contentDescription = null, tint = AccentCyan, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Audit Custom SMS Message", color = TextPrimary, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
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
                        value = customSender,
                        onValueChange = { customSender = it },
                        label = { Text("Sender ID / Mobile Number", fontSize = 12.sp) },
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
                        value = customText,
                        onValueChange = { customText = it },
                        label = { Text("SMS Message Body", fontSize = 12.sp) },
                        modifier = Modifier.fillMaxWidth(),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = PrimaryCobalt,
                            unfocusedBorderColor = BorderDark,
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary
                        ),
                        maxLines = 3
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Button(
                        onClick = {
                            if (customText.isNotBlank()) {
                                activeBenchmarkId = "custom"
                                currentAnalysis = SmishingAnalyzer.analyzeSmishingMessage(customSender, customText)
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = PrimaryCobalt),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Text("Run On-Device Smishing Forensics", fontWeight = FontWeight.Bold, fontSize = 13.sp)
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // 3. Currently Analyzing Hero Card (GeekPay Theme)
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
                        Text(
                            text = "CURRENTLY ANALYZING",
                            color = PrimaryCobaltLight,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                    Text(
                        text = "Case: ${currentAnalysis.caseId}",
                        color = TextSecondary,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = currentAnalysis.threatCategory,
                    color = TextPrimary,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(6.dp))

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Column {
                        Text("SENDER ID", color = TextTertiary, fontSize = 9.sp, fontWeight = FontWeight.Bold)
                        Text(currentAnalysis.senderId, color = AccentCyan, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                    }
                    Column {
                        Text("TRAI DLT STATUS", color = TextTertiary, fontSize = 9.sp, fontWeight = FontWeight.Bold)
                        val dltText = if (currentAnalysis.senderInfo.isDltCompliant) "DLT COMPLIANT" else "DLT VIOLATION"
                        val dltColor = if (currentAnalysis.senderInfo.isDltCompliant) RiskClean else RiskCritical
                        Text(dltText, color = dltColor, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // 4. Circular Risk Gauge
        CircularRiskGauge(
            score = currentAnalysis.riskScore,
            verdict = currentAnalysis.verdict
        )

        Spacer(modifier = Modifier.height(14.dp))

        // 5. Action Advisory Box
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = if (currentAnalysis.riskScore >= 70) Color(0x26EF4444) else Color(0x2610B981)
            ),
            shape = RoundedCornerShape(12.dp)
        ) {
            Row(
                modifier = Modifier.padding(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    if (currentAnalysis.riskScore >= 70) Icons.Default.Warning else Icons.Default.CheckCircle,
                    contentDescription = null,
                    tint = if (currentAnalysis.riskScore >= 70) RiskCritical else RiskClean,
                    modifier = Modifier.size(24.dp)
                )
                Spacer(modifier = Modifier.width(10.dp))
                Text(
                    text = currentAnalysis.actionMsg,
                    color = TextPrimary,
                    fontSize = 12.sp,
                    lineHeight = 16.sp,
                    fontWeight = FontWeight.Medium
                )
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // 6. Forensic Deep-Dive Tabs
        val tabs = listOf("TRAI DLT", "Links & APKs", "Urgency Cues", "DoT Dossier")
        TabRow(
            selectedTabIndex = selectedTab,
            containerColor = CardDark,
            contentColor = PrimaryCobaltLight
        ) {
            tabs.forEachIndexed { index, title ->
                Tab(
                    selected = selectedTab == index,
                    onClick = { selectedTab = index },
                    text = { Text(title, fontSize = 11.sp, fontWeight = FontWeight.SemiBold) }
                )
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        when (selectedTab) {
            0 -> { // TRAI DLT Tab
                Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = CardDark)) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text("Telecom Header Breakdown", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        Spacer(modifier = Modifier.height(6.dp))
                        Text("Channel Type: ${currentAnalysis.senderInfo.senderType}", color = TextSecondary, fontSize = 12.sp)
                        Text("Attributed Entity: ${currentAnalysis.senderInfo.entityName}", color = TextSecondary, fontSize = 12.sp)
                        Text("Operator / Circle: ${currentAnalysis.senderInfo.operatorCircle}", color = TextSecondary, fontSize = 12.sp)
                        Spacer(modifier = Modifier.height(6.dp))
                        if (currentAnalysis.senderInfo.redFlags.isNotEmpty()) {
                            Text("Carrier Red Flags:", color = RiskCriticalLight, fontWeight = FontWeight.Bold, fontSize = 11.sp)
                            currentAnalysis.senderInfo.redFlags.forEach { flag ->
                                Text("• $flag", color = RiskCriticalLight, fontSize = 11.sp)
                            }
                        }
                    }
                }
            }
            1 -> { // Links & APKs Tab
                Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = CardDark)) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text("Link & Payload Inspection", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        Spacer(modifier = Modifier.height(6.dp))
                        if (currentAnalysis.urlInfo.apkDroppers.isNotEmpty()) {
                            Text("🚨 Android Malware (.APK) Droppers:", color = RiskCritical, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                            currentAnalysis.urlInfo.apkDroppers.forEach { Text("• $it", color = RiskCriticalLight, fontSize = 11.sp) }
                        } else {
                            Text("✅ No executable Android APK payloads detected.", color = RiskClean, fontSize = 12.sp)
                        }
                        Spacer(modifier = Modifier.height(6.dp))
                        if (currentAnalysis.urlInfo.shortenedUrls.isNotEmpty()) {
                            Text("⚠️ URL Shorteners:", color = RiskWarning, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                            currentAnalysis.urlInfo.shortenedUrls.forEach { Text("• $it", color = RiskWarningLight, fontSize = 11.sp) }
                        }
                    }
                }
            }
            2 -> { // Social Engineering Tab
                Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = CardDark)) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text("Message Evidence & Psychology", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        Spacer(modifier = Modifier.height(6.dp))
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(Color(0x40000000), RoundedCornerShape(8.dp))
                                .padding(8.dp)
                        ) {
                            Text(currentAnalysis.rawMessage, color = TextPrimary, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        Text("Red Flags Checklist:", color = TextTertiary, fontWeight = FontWeight.Bold, fontSize = 11.sp)
                        currentAnalysis.allRedFlags.forEach { flag ->
                            Text("🚩 $flag", color = TextSecondary, fontSize = 11.sp, lineHeight = 16.sp)
                        }
                    }
                }
            }
            3 -> { // DoT Chakshu Tab
                Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = CardDark)) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text("Official Chakshu Dossier", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                            IconButton(
                                onClick = {
                                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                    clipboard.setPrimaryClip(ClipData.newPlainText("Chakshu Dossier", currentAnalysis.chakshuDraft))
                                    Toast.makeText(context, "Complaint copied to clipboard!", Toast.LENGTH_SHORT).show()
                                }
                            ) {
                                Icon(Icons.Default.ContentCopy, contentDescription = "Copy", tint = PrimaryCobaltLight)
                            }
                        }
                        Spacer(modifier = Modifier.height(6.dp))
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(Color(0x40000000), RoundedCornerShape(8.dp))
                                .padding(8.dp)
                        ) {
                            Text(
                                text = currentAnalysis.chakshuDraft,
                                color = TextSecondary,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 10.sp,
                                lineHeight = 14.sp
                            )
                        }
                    }
                }
            }
        }
    }
}
