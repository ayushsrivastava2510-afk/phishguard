package com.binarybattalion.phishguard.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.BitmapFactory
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.binarybattalion.phishguard.core.QuishingAnalyzer
import com.binarybattalion.phishguard.core.QuishingRecord
import com.binarybattalion.phishguard.core.UpiReputation
import com.binarybattalion.phishguard.ui.components.CircularRiskGauge
import com.binarybattalion.phishguard.ui.theme.*

@Composable
fun QuishingScreen(
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var selectedSentinelTab by remember { mutableStateOf(0) } // 0: UPI Registry, 1: QR Quishing

    // UPI Registry State
    var upiInputText by remember { mutableStateOf("fake.tatapower@ybl") }
    var activeUpiReputation by remember { mutableStateOf(QuishingAnalyzer.checkUpiReputation("fake.tatapower@ybl")) }
    var activeUpiBenchId by remember { mutableStateOf("fake_tatapower") }

    // QR Quishing State
    var activeBenchmarkId by remember { mutableStateOf(QuishingAnalyzer.QUISHING_BENCHMARKS[0].id) }
    var currentAnalysis by remember {
        mutableStateOf(
            QuishingAnalyzer.analyzePayload(
                QuishingAnalyzer.QUISHING_BENCHMARKS[0].payload,
                QuishingAnalyzer.QUISHING_BENCHMARKS[0].claimedContext
            )
        )
    }

    var customInput by remember { mutableStateOf("upi://pay?pa=refund_desk99@ybl&pn=Tata%20Power%20Refund&am=4999.00&cu=INR&tn=Bill%20Refund%20Approved") }
    var customContext by remember { mutableStateOf("Approved electricity overcharge refund. Scan to receive credit.") }
    var isCustomExpanded by remember { mutableStateOf(false) }

    // Image Picker from Gallery / Files
    val imagePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri != null) {
            try {
                val inputStream = context.contentResolver.openInputStream(uri)
                val bitmap = BitmapFactory.decodeStream(inputStream)
                inputStream?.close()
                if (bitmap != null) {
                    val decodedPayload = QuishingAnalyzer.decodeQrFromBitmap(bitmap)
                    if (decodedPayload != null) {
                        activeBenchmarkId = ""
                        currentAnalysis = QuishingAnalyzer.analyzePayload(
                            decodedPayload,
                            "Scanned QR Code from Device Gallery"
                        )
                        Toast.makeText(context, "QR Decoded Successfully!", Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(context, "No readable QR code found in selected image", Toast.LENGTH_LONG).show()
                    }
                }
            } catch (e: Exception) {
                Toast.makeText(context, "Error decoding image: ${e.message}", Toast.LENGTH_SHORT).show()
            }
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
    ) {
        // Section Header
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "UPI & QR Sentinel",
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold,
                    color = TextPrimary
                )
                Text(
                    text = "1930 Spam Registry • Reverse-Collect • Offline Forensics",
                    fontSize = 11.sp,
                    color = TextSecondary
                )
            }
            Box(
                modifier = Modifier
                    .background(Color(0x224D65FF), RoundedCornerShape(8.dp))
                    .padding(horizontal = 8.dp, vertical = 4.dp)
            ) {
                Text(
                    text = "NPCI CHAKSHU",
                    color = PrimaryCobalt,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold
                )
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Dual Mode Tab Row
        TabRow(
            selectedTabIndex = selectedSentinelTab,
            containerColor = Color(0xFF1E293B),
            contentColor = PrimaryCobaltLight
        ) {
            Tab(
                selected = selectedSentinelTab == 0,
                onClick = { selectedSentinelTab = 0 },
                text = { Text("💳 UPI Spam Registry", fontSize = 11.sp, fontWeight = FontWeight.Bold) }
            )
            Tab(
                selected = selectedSentinelTab == 1,
                onClick = { selectedSentinelTab = 1 },
                text = { Text("📷 QR Quishing", fontSize = 11.sp, fontWeight = FontWeight.Bold) }
            )
        }

        Spacer(modifier = Modifier.height(14.dp))

        if (selectedSentinelTab == 0) {
            // =========================================================================
            // TAB 0: UPI ID SPAM & FRAUD COMPLAINTS REGISTRY SENTINEL
            // =========================================================================
            Text(
                text = "1-CLICK REGISTRY BENCHMARKS",
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                color = TextSecondary
            )
            Spacer(modifier = Modifier.height(6.dp))

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                QuishingAnalyzer.UPI_REGISTRY_BENCHMARKS.forEach { b ->
                    val isSelected = (activeUpiBenchId == b.id)
                    FilterChip(
                        selected = isSelected,
                        onClick = {
                            activeUpiBenchId = b.id
                            upiInputText = b.upiId
                            activeUpiReputation = QuishingAnalyzer.checkUpiReputation(b.upiId)
                        },
                        label = {
                            Text(
                                text = b.label,
                                fontSize = 11.sp,
                                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal
                            )
                        },
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = PrimaryCobalt,
                            selectedLabelColor = Color.White,
                            containerColor = CardDark,
                            labelColor = TextPrimary
                        ),
                        border = FilterChipDefaults.filterChipBorder(
                            enabled = true,
                            selected = isSelected,
                            borderColor = if (isSelected) PrimaryCobalt else BorderDark,
                            selectedBorderColor = PrimaryCobalt
                        )
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Search Bar Input
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedTextField(
                    value = upiInputText,
                    onValueChange = { upiInputText = it },
                    modifier = Modifier.weight(1f),
                    label = { Text("Enter UPI ID / VPA (e.g. fake.tatapower@ybl)", fontSize = 11.sp) },
                    singleLine = true,
                    textStyle = LocalTextStyle.current.copy(fontSize = 12.sp)
                )
                Button(
                    onClick = {
                        if (upiInputText.isNotBlank()) {
                            activeUpiBenchId = ""
                            activeUpiReputation = QuishingAnalyzer.checkUpiReputation(upiInputText.trim())
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = PrimaryCobalt),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Icon(Icons.Default.Search, contentDescription = "Check VPA", modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Check", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // ADAPTIVE THREAT ALERT CARD
            val rep = activeUpiReputation
            val count = rep.complaintCount
            val alertBorder = when {
                count >= 10 -> RiskCritical
                count >= 5 -> RiskWarning
                count >= 1 -> Color(0xFFFDE047)
                else -> RiskClean
            }
            val alertBg = when {
                count >= 10 -> Color(0x33EF4444)
                count >= 5 -> Color(0x33F97316)
                count >= 1 -> Color(0x22FDE047)
                else -> Color(0x2210B981)
            }

            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = alertBg),
                border = BorderStroke(2.dp, alertBorder),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = if (count >= 10) "🚨" else if (count > 0) "⚠️" else "✅",
                            fontSize = 24.sp
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Column {
                            Box(
                                modifier = Modifier
                                    .background(Color(0x44000000), RoundedCornerShape(4.dp))
                                    .padding(horizontal = 6.dp, vertical = 2.dp)
                            ) {
                                Text(
                                    text = rep.statusBadge,
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.ExtraBold,
                                    color = alertBorder
                                )
                            }
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = rep.alertTitle,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color.White
                            )
                        }
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = rep.alertDesc,
                        fontSize = 11.sp,
                        color = Color(0xFFE2E8F0),
                        lineHeight = 15.sp
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(Color(0x33000000), RoundedCornerShape(6.dp))
                            .padding(8.dp)
                    ) {
                        Text(
                            text = "🛡️ Status: ${rep.lawEnforcementStatus}",
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            color = if (count >= 10) RiskCriticalLight else (if (count > 0) Color(0xFFFDE047) else RiskClean)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Circular Risk Gauge Card for UPI
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = CardDark),
                border = BorderStroke(1.dp, BorderDark),
                shape = RoundedCornerShape(14.dp)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "REGISTRY RISK INDEX",
                            fontSize = 10.sp,
                            fontWeight = FontWeight.ExtraBold,
                            color = TextSecondary
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = rep.riskLevel,
                            fontSize = 14.sp,
                            fontWeight = FontWeight.Bold,
                            color = if (count >= 10) RiskCriticalLight else if (count >= 5) RiskWarning else RiskClean
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Total Reported Loss: ${rep.financialLossReported}",
                            fontSize = 11.sp,
                            color = TextSecondary
                        )
                    }
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        CircularRiskGauge(
                            score = rep.riskScore,
                            verdict = rep.riskLevel,
                            modifier = Modifier.size(72.dp)
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "⚡ 1930 Sync",
                            color = AccentCyan,
                            fontSize = 8.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // VPA Parameters Table
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = CardDark),
                border = BorderStroke(1.dp, BorderDark),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text("💳 VPA Registry Telemetry", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
                    Spacer(modifier = Modifier.height(10.dp))

                    ParamRow("UPI Address (VPA)", rep.upiId, isHighlight = count >= 5)
                    ParamRow("Handle Domain", rep.handle)
                    ParamRow("Provider Architecture", rep.providerType)
                    ParamRow("Citizen Complaints", "${rep.complaintCount} Filed", isDebit = count > 0)
                    ParamRow("Repeat Offender", if (rep.isRepeatOffender) "YES (Flagged)" else "No", isHighlight = rep.isRepeatOffender)
                    ParamRow("Enforcement State", if (rep.isBlocked) "Blocked / Frozen" else "Clean Merchant", isHighlight = rep.isBlocked)
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Scam Categories Badges
            if (rep.categories.isNotEmpty()) {
                Text("🏷️ REPORTED SCAM VECTORS", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = TextSecondary)
                Spacer(modifier = Modifier.height(6.dp))
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    rep.categories.forEach { cat ->
                        Box(
                            modifier = Modifier
                                .background(Color(0x22EF4444), RoundedCornerShape(6.dp))
                                .border(1.dp, Color(0x44EF4444), RoundedCornerShape(6.dp))
                                .padding(horizontal = 8.dp, vertical = 4.dp)
                        ) {
                            Text(
                                text = "🚨 $cat",
                                fontSize = 10.sp,
                                color = RiskCriticalLight,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }
                Spacer(modifier = Modifier.height(14.dp))
            }

            // Interactive Action: Report Fraud (+1 Complaint)
            Button(
                onClick = {
                    activeUpiReputation = QuishingAnalyzer.reportUpiFraud(
                        rep.upiId,
                        "Citizen Fraud Grievance",
                        "Reported via PhishGuard Mobile SOC"
                    )
                    Toast.makeText(
                        context,
                        "🚨 Complaint registered! Total complaints updated to ${activeUpiReputation.complaintCount}.",
                        Toast.LENGTH_LONG
                    ).show()
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = RiskCritical),
                shape = RoundedCornerShape(10.dp)
            ) {
                Icon(Icons.Default.ReportProblem, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text("Report Fraud on this UPI ID (+1 Complaint)", fontSize = 12.sp, fontWeight = FontWeight.Bold)
            }

            Spacer(modifier = Modifier.height(20.dp))

        } else {
            // =========================================================================
            // TAB 1: QR QUISHING SCANNER & FORENSICS (EXISTING FULL CODE)
            // =========================================================================
            Text(
                text = "1-CLICK ATTACK BENCHMARKS",
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                color = TextSecondary
            )
            Spacer(modifier = Modifier.height(6.dp))

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                QuishingAnalyzer.QUISHING_BENCHMARKS.forEach { b ->
                    val isSelected = (activeBenchmarkId == b.id)
                    FilterChip(
                        selected = isSelected,
                        onClick = {
                            activeBenchmarkId = b.id
                            currentAnalysis = QuishingAnalyzer.analyzePayload(b.payload, b.claimedContext)
                        },
                        label = {
                            Text(
                                text = b.title,
                                fontSize = 12.sp,
                                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal
                            )
                        },
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = PrimaryCobalt,
                            selectedLabelColor = Color.White,
                            containerColor = CardDark,
                            labelColor = TextPrimary
                        ),
                        border = FilterChipDefaults.filterChipBorder(
                            enabled = true,
                            selected = isSelected,
                            borderColor = if (isSelected) PrimaryCobalt else BorderDark,
                            selectedBorderColor = PrimaryCobalt
                        )
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Action Buttons: Scan Gallery Image & Custom Deeplink
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Button(
                    onClick = { imagePickerLauncher.launch("image/*") },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color(0xFF1E293B),
                        contentColor = Color.White
                    ),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Icon(Icons.Default.QrCodeScanner, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Scan Image QR", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                }

                OutlinedButton(
                    onClick = { isCustomExpanded = !isCustomExpanded },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = PrimaryCobalt
                    ),
                    border = BorderStroke(1.dp, BorderDark),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Icon(
                        if (isCustomExpanded) Icons.Default.ExpandLess else Icons.Default.Edit,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Custom Input", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                }
            }

            // Custom Payload Input Expansion Card
            if (isCustomExpanded) {
                Spacer(modifier = Modifier.height(10.dp))
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = CardDark),
                    border = BorderStroke(1.dp, BorderDark),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text("Audit Custom UPI Deeplink or URL", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
                        Spacer(modifier = Modifier.height(6.dp))
                        OutlinedTextField(
                            value = customInput,
                            onValueChange = { customInput = it },
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text("UPI Link (upi://pay?...) or URL", fontSize = 11.sp) },
                            singleLine = true,
                            textStyle = LocalTextStyle.current.copy(fontSize = 11.sp)
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        OutlinedTextField(
                            value = customContext,
                            onValueChange = { customContext = it },
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text("Context (Claimed message, e.g. refund/kyc)", fontSize = 11.sp) },
                            singleLine = true,
                            textStyle = LocalTextStyle.current.copy(fontSize = 11.sp)
                        )
                        Spacer(modifier = Modifier.height(10.dp))
                        Button(
                            onClick = {
                                if (customInput.isNotBlank()) {
                                    activeBenchmarkId = ""
                                    currentAnalysis = QuishingAnalyzer.analyzePayload(customInput.trim(), customContext.trim())
                                    isCustomExpanded = false
                                }
                            },
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.buttonColors(containerColor = PrimaryCobalt),
                            shape = RoundedCornerShape(8.dp)
                        ) {
                            Text("Analyze Payload", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // ACTIVE ANALYSIS DASHBOARD
            val isReverse = currentAnalysis.isReverseCollect
            val isCritical = currentAnalysis.riskScore >= 70

            // REVERSE COLLECT PULSING WARNING BANNER
            if (isReverse) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = Color(0x33EF4444)),
                    border = BorderStroke(2.dp, RiskCritical),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text("🚨", fontSize = 24.sp)
                            Spacer(modifier = Modifier.width(8.dp))
                            Column {
                                Text(
                                    text = "REVERSE-COLLECT PAYMENT TRAP",
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.ExtraBold,
                                    color = RiskCriticalLight
                                )
                                val upiD = currentAnalysis.upiDetails
                                val amtStr = if (upiD != null && upiD.amount > 0) "${upiD.currency} ${String.format("%.2f", upiD.amount)}" else "an unspecified amount"
                                Text(
                                    text = "Scanning this QR will DEBIT $amtStr from YOUR account!",
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color.White
                                )
                            }
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(Color(0x44000000), RoundedCornerShape(6.dp))
                                .padding(8.dp)
                        ) {
                            Text(
                                text = "🛡️ NPCI Rule: You NEVER need to scan a QR code or enter your UPI PIN to receive money or refunds. UPI PIN is exclusively for paying out.",
                                fontSize = 11.sp,
                                color = Color(0xFFFDE047),
                                lineHeight = 15.sp
                            )
                        }
                    }
                }
                Spacer(modifier = Modifier.height(14.dp))
            }

            // Circular Risk Gauge & Headline Card
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = CardDark),
                border = BorderStroke(1.dp, BorderDark),
                shape = RoundedCornerShape(14.dp)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = currentAnalysis.verdict.replace("_", " "),
                            fontSize = 12.sp,
                            fontWeight = FontWeight.ExtraBold,
                            color = if (isCritical) RiskCriticalLight else (if (currentAnalysis.riskScore >= 40) RiskWarning else RiskClean)
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = currentAnalysis.headline,
                            fontSize = 14.sp,
                            fontWeight = FontWeight.Bold,
                            color = TextPrimary
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = currentAnalysis.summary,
                            fontSize = 11.sp,
                            color = TextSecondary,
                            maxLines = 3,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        CircularRiskGauge(
                            score = currentAnalysis.riskScore,
                            verdict = currentAnalysis.verdict,
                            modifier = Modifier.size(76.dp)
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.Center,
                            modifier = Modifier
                                .background(PrimaryCobalt.copy(alpha = 0.15f), RoundedCornerShape(4.dp))
                                .border(1.dp, PrimaryCobaltLight.copy(alpha = 0.35f), RoundedCornerShape(4.dp))
                                .padding(horizontal = 6.dp, vertical = 2.dp)
                        ) {
                            Text("⚡", fontSize = 8.sp)
                            Spacer(modifier = Modifier.width(2.dp))
                            Text(
                                text = "Analyzed in ${String.format(java.util.Locale.US, "%.2f", currentAnalysis.analysisTimeMs / 1000f)}s",
                                color = AccentCyan,
                                fontSize = 8.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Extracted UPI Parameter Dissection (with reputation badge)
            if (currentAnalysis.upiDetails != null) {
                val u = currentAnalysis.upiDetails!!
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = CardDark),
                    border = BorderStroke(1.dp, BorderDark),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text("💳 UPI Deeplink Forensics", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
                            Text(u.walletType, fontSize = 10.sp, color = AccentCyan, fontWeight = FontWeight.Medium)
                        }
                        Spacer(modifier = Modifier.height(10.dp))

                        ParamRow("Payee VPA (`pa`)", u.payeeVpa.ifEmpty { "N/A" }, isHighlight = u.isPersonalWallet)
                        ParamRow("Display Name (`pn`)", u.payeeName.ifEmpty { "Omitted / Blank" })
                        ParamRow("Debit Amount (`am`)", "${u.currency} ${String.format("%.2f", u.amount)}", isDebit = u.amount > 0)
                        ParamRow("Transaction Note (`tn`)", u.transactionNote.ifEmpty { "None" })
                        ParamRow("Merchant Code (`mc`)", u.mccCode.ifEmpty { "None (P2P Individual)" })

                        if (u.reputation != null) {
                            val rep = u.reputation
                            ParamRow(
                                "Spam Complaints Registry",
                                if (rep.complaintCount > 0) "🚨 ${rep.complaintCount} Complaints Reported" else "✅ 0 Complaints (Clean)",
                                isHighlight = rep.complaintCount > 0
                            )
                            ParamRow(
                                "Enforcement Status",
                                rep.lawEnforcementStatus,
                                isHighlight = rep.isBlocked
                            )
                        }

                        ParamRow("Account Architecture", if (u.isPersonalWallet) "Personal Individual Wallet" else "Institutional / Merchant", isHighlight = u.isPersonalWallet)
                    }
                }
                Spacer(modifier = Modifier.height(14.dp))
            }

            // Red Flags List
            if (currentAnalysis.redFlags.isNotEmpty()) {
                Text("🚩 FORENSIC RED FLAGS", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = TextSecondary)
                Spacer(modifier = Modifier.height(6.dp))
                currentAnalysis.redFlags.forEach { flag ->
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 3.dp),
                        colors = CardDefaults.cardColors(containerColor = Color(0x22EF4444)),
                        border = BorderStroke(1.dp, Color(0x44EF4444)),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Row(
                            modifier = Modifier.padding(10.dp),
                            verticalAlignment = Alignment.Top
                        ) {
                            Text("•", color = RiskCriticalLight, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(flag, color = Color(0xFFFECACA), fontSize = 11.sp, lineHeight = 16.sp)
                        }
                    }
                }
                Spacer(modifier = Modifier.height(14.dp))
            }

            // Raw Payload Viewer
            Text("RAW DECODED PAYLOAD", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = TextSecondary)
            Spacer(modifier = Modifier.height(4.dp))
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color(0xFF0F172A), RoundedCornerShape(8.dp))
                    .padding(12.dp)
            ) {
                Text(
                    text = currentAnalysis.rawPayload,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    color = Color(0xFF94A3B8),
                    lineHeight = 16.sp
                )
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Legal Police / 1930 Complaint Dossier Action
            Button(
                onClick = {
                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    val clip = ClipData.newPlainText("1930 Complaint", currentAnalysis.policeComplaintDraft)
                    clipboard.setPrimaryClip(clip)
                    Toast.makeText(context, "Complaint Dossier Copied to Clipboard!", Toast.LENGTH_LONG).show()
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = PrimaryCobalt
                ),
                shape = RoundedCornerShape(10.dp)
            ) {
                Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text("Copy 1930 / Sanchar Saathi Complaint", fontSize = 12.sp, fontWeight = FontWeight.Bold)
            }

            Spacer(modifier = Modifier.height(20.dp))
        }
    }
}

@Composable
private fun ParamRow(label: String, value: String, isHighlight: Boolean = false, isDebit: Boolean = false) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(label, fontSize = 11.sp, color = TextSecondary)
        Text(
            text = value,
            fontSize = 11.sp,
            fontWeight = if (isHighlight || isDebit) FontWeight.Bold else FontWeight.Medium,
            color = if (isDebit) RiskCriticalLight else (if (isHighlight) Color(0xFFFDE047) else TextPrimary),
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}
