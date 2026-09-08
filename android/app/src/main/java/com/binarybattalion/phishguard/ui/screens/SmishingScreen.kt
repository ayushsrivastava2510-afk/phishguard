package com.binarybattalion.phishguard.ui.screens

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.PackageManager
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
import androidx.core.content.ContextCompat
import com.binarybattalion.phishguard.core.InboxScanSummary
import com.binarybattalion.phishguard.core.InboxSmsScanner
import com.binarybattalion.phishguard.core.SmishingAnalyzer
import com.binarybattalion.phishguard.core.SmishingRecord
import com.binarybattalion.phishguard.ui.components.CircularRiskGauge
import com.binarybattalion.phishguard.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun SmishingScreen(
    initialRecord: SmishingRecord? = null,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

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

    // Real-Time Inbox Scanning State
    var hasReadPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.READ_SMS) == PackageManager.PERMISSION_GRANTED
        )
    }
    var inboxScanSummary by remember { mutableStateOf<InboxScanSummary?>(null) }
    var isScanningInbox by remember { mutableStateOf(false) }

    fun runScan() {
        isScanningInbox = true
        scope.launch(Dispatchers.IO) {
            val result = InboxSmsScanner.scanDeviceInbox(context)
            withContext(Dispatchers.Main) {
                inboxScanSummary = result
                isScanningInbox = false
                if (result.items.isNotEmpty()) {
                    activeBenchmarkId = ""
                    currentAnalysis = result.items[0].record
                }
            }
        }
    }

    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        hasReadPermission = isGranted
        if (isGranted) {
            runScan()
        } else {
            Toast.makeText(context, "SMS permission needed to scan phone inbox", Toast.LENGTH_SHORT).show()
        }
    }

    // Auto-scan on launch if permission already granted
    LaunchedEffect(hasReadPermission) {
        if (hasReadPermission && inboxScanSummary == null) {
            runScan()
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(BgDark)
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
    ) {
        // 1. Live Device Inbox Sentinel Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = CardDark),
            border = BorderStroke(1.dp, if (hasReadPermission) PrimaryCobalt.copy(alpha = 0.5f) else BorderDark),
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
                                .background(Color(0x3338BDF8), RoundedCornerShape(6.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                Icons.Default.MarkEmailRead,
                                contentDescription = "Inbox",
                                tint = AccentCyan,
                                modifier = Modifier.size(16.dp)
                            )
                        }
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "LIVE INBOX SENTINEL",
                            color = TextPrimary,
                            fontWeight = FontWeight.Bold,
                            fontSize = 13.sp
                        )
                    }

                    Box(
                        modifier = Modifier
                            .background(
                                if (hasReadPermission) Color(0x2610B981) else Color(0x26F59E0B),
                                RoundedCornerShape(4.dp)
                            )
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = if (hasReadPermission) "AUTONOMOUS READY" else "NEEDS PERMISSION",
                            color = if (hasReadPermission) RiskCleanLight else Color(0xFFFBBF24),
                            fontSize = 8.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }

                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "Reads messages directly from your device SMS app, auditing for TRAI DLT violations, APK droppers, and banking fraud in real-time.",
                    color = TextSecondary,
                    fontSize = 11.sp,
                    lineHeight = 15.sp
                )

                Spacer(modifier = Modifier.height(10.dp))

                Button(
                    onClick = {
                        if (hasReadPermission) {
                            runScan()
                        } else {
                            permissionLauncher.launch(Manifest.permission.READ_SMS)
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (hasReadPermission) PrimaryCobalt else Color(0xFFD97706)
                    ),
                    shape = RoundedCornerShape(8.dp),
                    enabled = !isScanningInbox
                ) {
                    if (isScanningInbox) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(16.dp),
                            color = TextPrimary,
                            strokeWidth = 2.dp
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Scanning Phone SMS Inbox...", fontSize = 12.sp, color = TextPrimary)
                    } else {
                        Icon(
                            Icons.Default.Refresh,
                            contentDescription = "Scan",
                            modifier = Modifier.size(16.dp),
                            tint = TextPrimary
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = if (hasReadPermission) "⚡ Auto-Scan Phone Inbox" else "Grant SMS Access & Scan",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            color = TextPrimary
                        )
                    }
                }

                // Scanned Inbox Summary Feed
                inboxScanSummary?.let { summary ->
                    Spacer(modifier = Modifier.height(12.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        InboxMetricBadge(label = "Scanned", value = "${summary.totalScanned}", color = AccentCyan, modifier = Modifier.weight(1f))
                        InboxMetricBadge(label = "🚨 Threats", value = "${summary.criticalThreats}", color = RiskCritical, modifier = Modifier.weight(1f))
                        InboxMetricBadge(label = "⚠️ Suspicious", value = "${summary.suspiciousCount}", color = RiskWarning, modifier = Modifier.weight(1f))
                        InboxMetricBadge(label = "🟢 Safe", value = "${summary.safeCount}", color = RiskClean, modifier = Modifier.weight(1f))
                    }

                    if (summary.items.isEmpty()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "No SMS found in phone inbox. Incoming carrier messages will be audited in background automatically!",
                            color = TextTertiary,
                            fontSize = 11.sp,
                            modifier = Modifier.padding(vertical = 4.dp)
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        OutlinedButton(
                            onClick = {
                                val demoSummary = InboxSmsScanner.getFallbackSampleInbox()
                                inboxScanSummary = demoSummary
                                if (demoSummary.items.isNotEmpty()) {
                                    activeBenchmarkId = ""
                                    currentAnalysis = demoSummary.items[0].record
                                }
                            },
                            modifier = Modifier.fillMaxWidth(),
                            border = BorderStroke(1.dp, PrimaryCobaltLight.copy(alpha = 0.6f)),
                            shape = RoundedCornerShape(8.dp)
                        ) {
                            Icon(
                                Icons.Default.Inbox,
                                contentDescription = "Demo",
                                tint = AccentCyan,
                                modifier = Modifier.size(14.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                "Preview Simulated Carrier Inbox (3 Samples)",
                                color = AccentCyan,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.SemiBold
                            )
                        }
                    } else {
                        Spacer(modifier = Modifier.height(10.dp))
                        Text(
                            text = "TAP ANY INBOX MESSAGE TO INSPECT FORENSICS:",
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
                            summary.items.take(20).forEach { item ->
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

                                Card(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable {
                                            activeBenchmarkId = ""
                                            currentAnalysis = item.record
                                        },
                                    colors = CardDefaults.cardColors(
                                        containerColor = if (currentAnalysis.evidenceHash == item.record.evidenceHash)
                                            Color(0x334D65FF) else CardDarkElevated
                                    ),
                                    border = BorderStroke(
                                        1.dp,
                                        if (currentAnalysis.evidenceHash == item.record.evidenceHash)
                                            PrimaryCobaltLight else BorderDark
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
                                                    fontSize = 12.sp
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
                                                text = item.body,
                                                color = TextSecondary,
                                                fontSize = 11.sp,
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
        }

        Spacer(modifier = Modifier.height(14.dp))

        // 2. 1-Click Attack Scenario Benchmarks
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

        // 3. Custom SMS Ingress Box (Collapsible)
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

        // 4. Currently Analyzing Hero Card (GeekPay Theme)
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

        // 5. Circular Risk Gauge
        CircularRiskGauge(
            score = currentAnalysis.riskScore,
            verdict = currentAnalysis.verdict
        )

        Spacer(modifier = Modifier.height(14.dp))

        // 6. Action Banner
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = when {
                    currentAnalysis.riskScore >= 70 -> Color(0x33EF4444)
                    currentAnalysis.riskScore >= 35 -> Color(0x33F59E0B)
                    else -> Color(0x3310B981)
                }
            ),
            shape = RoundedCornerShape(10.dp)
        ) {
            Row(
                modifier = Modifier.padding(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = when {
                        currentAnalysis.riskScore >= 70 -> Icons.Default.Warning
                        currentAnalysis.riskScore >= 35 -> Icons.Default.Info
                        else -> Icons.Default.CheckCircle
                    },
                    contentDescription = null,
                    tint = when {
                        currentAnalysis.riskScore >= 70 -> RiskCriticalLight
                        currentAnalysis.riskScore >= 35 -> Color(0xFFFBBF24)
                        else -> RiskCleanLight
                    }
                )
                Spacer(modifier = Modifier.width(10.dp))
                Text(
                    text = currentAnalysis.actionMsg,
                    color = TextPrimary,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Medium
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // 7. 4 Inspection Tabs
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
                    text = {
                        Text(
                            text = title,
                            fontSize = 11.sp,
                            fontWeight = if (selectedTab == index) FontWeight.Bold else FontWeight.Normal
                        )
                    }
                )
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        when (selectedTab) {
            0 -> { // TRAI DLT Tab
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = CardDark),
                    border = BorderStroke(1.dp, BorderDark),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text("TRAI TCCCPR 2018 Regulatory Header Telemetry", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        Spacer(modifier = Modifier.height(8.dp))
                        DetailRow("Header Category", currentAnalysis.senderInfo.senderType)
                        DetailRow("Operator / Circle", currentAnalysis.senderInfo.operatorCircle)
                        DetailRow("Registered Entity", currentAnalysis.senderInfo.entityName)
                        DetailRow("DLT Compliance", if (currentAnalysis.senderInfo.isDltCompliant) "VERIFIED COMPLIANT" else "UNREGISTERED ROUTE")
                        DetailRow("Risk Penalty", "+${currentAnalysis.senderInfo.riskBoost} Points")
                    }
                }
            }
            1 -> { // Links & APKs Tab
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = CardDark),
                    border = BorderStroke(1.dp, BorderDark),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text("Payload & Malicious Link Interception", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        Spacer(modifier = Modifier.height(8.dp))
                        if (currentAnalysis.urlInfo.apkDroppers.isNotEmpty()) {
                            Text("🚨 Android Trojan APK Droppers:", color = RiskCriticalLight, fontWeight = FontWeight.Bold, fontSize = 11.sp)
                            currentAnalysis.urlInfo.apkDroppers.forEach { Text("• $it", color = RiskCriticalLight, fontSize = 11.sp) }
                            Spacer(modifier = Modifier.height(6.dp))
                        }
                        if (currentAnalysis.urlInfo.shortenedUrls.isNotEmpty()) {
                            Text("⚠️ URL Shorteners Detected:", color = Color(0xFFFBBF24), fontWeight = FontWeight.Bold, fontSize = 11.sp)
                            currentAnalysis.urlInfo.shortenedUrls.forEach { Text("• $it", color = TextSecondary, fontSize = 11.sp) }
                            Spacer(modifier = Modifier.height(6.dp))
                        }
                        if (currentAnalysis.urlInfo.urls.isEmpty()) {
                            Text("✅ No external links or executable APK packages detected.", color = RiskCleanLight, fontSize = 12.sp)
                        }
                    }
                }
            }
            2 -> { // Social Engineering / Urgency Cues Tab
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = CardDark),
                    border = BorderStroke(1.dp, BorderDark),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text("Social Engineering & Panic Vector Analysis", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        Spacer(modifier = Modifier.height(8.dp))
                        DetailRow("Primary Threat Category", currentAnalysis.threatCategory)
                        DetailRow("Urgency Level", currentAnalysis.urgencyLevel)
                        Spacer(modifier = Modifier.height(8.dp))
                        Text("Message Body Under Inspection:", color = TextTertiary, fontWeight = FontWeight.Bold, fontSize = 11.sp)
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(CardDarkElevated, RoundedCornerShape(8.dp))
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
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = CardDark),
                    border = BorderStroke(1.dp, BorderDark),
                    shape = RoundedCornerShape(12.dp)
                ) {
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

@Composable
private fun InboxMetricBadge(label: String, value: String, color: Color, modifier: Modifier = Modifier) {
    Box(
        modifier = modifier
            .background(color.copy(alpha = 0.12f), RoundedCornerShape(6.dp))
            .border(1.dp, color.copy(alpha = 0.3f), RoundedCornerShape(6.dp))
            .padding(vertical = 5.dp),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(text = value, color = color, fontSize = 13.sp, fontWeight = FontWeight.ExtraBold)
            Text(text = label, color = TextSecondary, fontSize = 8.sp)
        }
    }
}

@Composable
private fun DetailRow(title: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(title, color = TextSecondary, fontSize = 11.sp)
        Text(value, color = TextPrimary, fontWeight = FontWeight.SemiBold, fontSize = 11.sp)
    }
}
