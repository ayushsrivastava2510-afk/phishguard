package com.binarybattalion.phishguard.ui.screens

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.binarybattalion.phishguard.core.ChildSafetyAnalyzer
import com.binarybattalion.phishguard.ui.theme.*

@Composable
fun ChildSafetyScreen(
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current

    // Parent Security Gate State (Default PIN: 1234)
    var isParentUnlocked by remember { mutableStateOf(false) }
    var pinInput by remember { mutableStateOf("") }
    var pinError by remember { mutableStateOf(false) }

    // Parental Control Study Mode State
    var isParentalControlActive by remember { mutableStateOf(true) }
    var customBlocklist by remember {
        mutableStateOf(listOf("instagram.com", "youtube.com", "roblox.com", "snapchat.com", "netflix.com"))
    }
    var newWebsiteInput by remember { mutableStateOf("") }

    // Protection Category Policies
    var blockGamingPhishing by remember { mutableStateOf(true) }
    var blockGambling by remember { mutableStateOf(true) }
    var blockAdultContent by remember { mutableStateOf(true) }
    var blockStrangerChat by remember { mutableStateOf(true) }

    // Active URL Audit State
    var activeBenchmarkId by remember { mutableStateOf(ChildSafetyAnalyzer.BENCHMARKS[0].id) }
    var inputUrl by remember { mutableStateOf(ChildSafetyAnalyzer.BENCHMARKS[0].url) }
    var inputContext by remember { mutableStateOf(ChildSafetyAnalyzer.BENCHMARKS[0].context) }
    var currentRecord by remember {
        mutableStateOf(
            ChildSafetyAnalyzer.analyzeUrl(
                ChildSafetyAnalyzer.BENCHMARKS[0].url,
                ChildSafetyAnalyzer.BENCHMARKS[0].context,
                customBlocklist = listOf("instagram.com", "youtube.com", "roblox.com", "snapchat.com", "netflix.com"),
                isParentalControlActive = true
            )
        )
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(BgDark)
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
    ) {
        // 1. Header Card
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
                                .size(32.dp)
                                .background(Color(0x3338BDF8), RoundedCornerShape(8.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                Icons.Default.ChildCare,
                                contentDescription = null,
                                tint = AccentCyan,
                                modifier = Modifier.size(20.dp)
                            )
                        }
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(
                                text = "CHILD SAFE BROWSING SENTINEL",
                                color = TextPrimary,
                                fontWeight = FontWeight.ExtraBold,
                                fontSize = 12.sp,
                                letterSpacing = 0.6.sp
                            )
                            Text(
                                text = "Parental AI Shield & Minor Protection",
                                color = TextSecondary,
                                fontSize = 10.sp
                            )
                        }
                    }

                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .background(
                                    if (isParentalControlActive) Color(0x33A855F7) else Color(0x3364748B),
                                    RoundedCornerShape(4.dp)
                                )
                                .padding(horizontal = 6.dp, vertical = 2.dp)
                        ) {
                            Text(
                                text = if (isParentalControlActive) "🟢 STUDY LOCK ON" else "🟡 PAUSED",
                                color = if (isParentalControlActive) Color(0xFFC084FC) else Color(0xFF94A3B8),
                                fontSize = 8.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                        Spacer(modifier = Modifier.width(6.dp))
                        Box(
                            modifier = Modifier
                                .background(
                                    if (isParentUnlocked) Color(0x2610B981) else Color(0x264D65FF),
                                    RoundedCornerShape(4.dp)
                                )
                                .padding(horizontal = 6.dp, vertical = 2.dp)
                        ) {
                            Text(
                                text = if (isParentUnlocked) "🔓 UNLOCKED" else "🔒 PIN LOCKED",
                                color = if (isParentUnlocked) RiskCleanLight else PrimaryCobaltLight,
                                fontSize = 8.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "Blocks predatory gaming traps, illegal betting apps, and custom distracting websites to help children focus during study hours.",
                    color = TextSecondary,
                    fontSize = 11.sp,
                    lineHeight = 15.sp
                )
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // 2. Parent PIN Gate Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = CardDarkElevated),
            border = BorderStroke(1.dp, if (isParentUnlocked) Color(0x4010B981) else BorderDark),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                if (!isParentUnlocked) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column {
                            Text("Parent Security Lock", color = TextPrimary, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                            Text("Enter 4-digit PIN to toggle Study Mode or edit blocklist (Default: 1234)", color = TextTertiary, fontSize = 9.sp)
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = pinInput,
                            onValueChange = {
                                if (it.length <= 4) {
                                    pinInput = it
                                    pinError = false
                                }
                            },
                            placeholder = { Text("4-Digit PIN", fontSize = 11.sp) },
                            visualTransformation = PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                            singleLine = true,
                            isError = pinError,
                            modifier = Modifier.weight(1f),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = PrimaryCobalt,
                                unfocusedBorderColor = BorderDark,
                                focusedTextColor = TextPrimary,
                                unfocusedTextColor = TextPrimary
                            )
                        )

                        Button(
                            onClick = {
                                if (pinInput == "1234") {
                                    isParentUnlocked = true
                                    pinError = false
                                    Toast.makeText(context, "Parent Access Granted!", Toast.LENGTH_SHORT).show()
                                } else {
                                    pinError = true
                                    Toast.makeText(context, "Incorrect PIN. Default is 1234", Toast.LENGTH_SHORT).show()
                                }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = PrimaryCobalt),
                            shape = RoundedCornerShape(8.dp)
                        ) {
                            Text("Unlock", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                } else {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.LockOpen, contentDescription = null, tint = RiskCleanLight, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Parent Controls Unlocked", color = RiskCleanLight, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                        }

                        OutlinedButton(
                            onClick = {
                                isParentUnlocked = false
                                pinInput = ""
                                Toast.makeText(context, "Parent Settings Locked", Toast.LENGTH_SHORT).show()
                            },
                            border = BorderStroke(1.dp, BorderDark),
                            shape = RoundedCornerShape(6.dp),
                            contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)
                        ) {
                            Text("Lock Now", color = TextSecondary, fontSize = 10.sp)
                        }
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    // Master Study Mode Toggle
                    PolicyToggleRow("🔒 Parental Control / Study Mode (Zero-Tolerance Lock)", isParentalControlActive) {
                        isParentalControlActive = it
                        Toast.makeText(context, if (it) "Study Mode Activated" else "Study Mode Paused", Toast.LENGTH_SHORT).show()
                    }

                    // Policy Toggles
                    PolicyToggleRow("🎮 Block Gaming Currency & Skin Phishing", blockGamingPhishing) { blockGamingPhishing = it }
                    PolicyToggleRow("🎰 Block Youth Betting & Color Prediction Apps", blockGambling) { blockGambling = it }
                    PolicyToggleRow("🔞 Block Explicit Adult Content & Redirection", blockAdultContent) { blockAdultContent = it }
                    PolicyToggleRow("💬 Block Unmonitored Stranger Video Chats", blockStrangerChat) { blockStrangerChat = it }

                    Spacer(modifier = Modifier.height(12.dp))

                    // Custom Website Blocklist Ingress
                    Text("🚫 Blocked Websites during Study Hours", color = TextPrimary, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    Text("Websites listed here cannot be opened under any circumstances while Study Mode is active.", color = TextTertiary, fontSize = 9.sp)
                    Spacer(modifier = Modifier.height(6.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = newWebsiteInput,
                            onValueChange = { newWebsiteInput = it },
                            placeholder = { Text("e.g. discord.com, twitch.tv", fontSize = 11.sp) },
                            singleLine = true,
                            modifier = Modifier.weight(1f),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = PrimaryCobalt,
                                unfocusedBorderColor = BorderDark,
                                focusedTextColor = TextPrimary,
                                unfocusedTextColor = TextPrimary
                            )
                        )
                        Button(
                            onClick = {
                                if (newWebsiteInput.isNotBlank()) {
                                    val clean = newWebsiteInput.trim().lowercase(java.util.Locale.ROOT)
                                        .removePrefix("http://")
                                        .removePrefix("https://")
                                        .substringBefore("/")
                                        .removePrefix("www.")
                                    if (clean.isNotBlank() && !customBlocklist.contains(clean)) {
                                        customBlocklist = customBlocklist + clean
                                        newWebsiteInput = ""
                                        Toast.makeText(context, "Added $clean to study blocklist", Toast.LENGTH_SHORT).show()
                                    }
                                }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = PrimaryCobalt),
                            shape = RoundedCornerShape(8.dp)
                        ) {
                            Text("+ Add", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                        }
                    }

                    Spacer(modifier = Modifier.height(6.dp))
                    Text("Quick Presets:", color = TextTertiary, fontSize = 9.sp)
                    Spacer(modifier = Modifier.height(4.dp))
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        val presets = listOf("instagram.com", "youtube.com", "roblox.com", "snapchat.com", "netflix.com", "discord.com")
                        presets.forEach { domain ->
                            SuggestionChip(
                                onClick = {
                                    if (!customBlocklist.contains(domain)) {
                                        customBlocklist = customBlocklist + domain
                                        Toast.makeText(context, "Added $domain", Toast.LENGTH_SHORT).show()
                                    }
                                },
                                label = { Text("+ $domain", fontSize = 10.sp) },
                                colors = SuggestionChipDefaults.suggestionChipColors(
                                    containerColor = CardDark,
                                    labelColor = if (customBlocklist.contains(domain)) PrimaryCobaltLight else TextSecondary
                                ),
                                border = BorderStroke(1.dp, if (customBlocklist.contains(domain)) PrimaryCobalt else BorderDark)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))
                    Text("Currently Blocked Sites (${customBlocklist.size}):", color = TextSecondary, fontSize = 10.sp, fontWeight = FontWeight.SemiBold)
                    Spacer(modifier = Modifier.height(4.dp))
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        customBlocklist.forEach { domain ->
                            InputChip(
                                selected = true,
                                onClick = {
                                    customBlocklist = customBlocklist.filter { it != domain }
                                    Toast.makeText(context, "Removed $domain", Toast.LENGTH_SHORT).show()
                                },
                                label = { Text(domain, fontSize = 10.sp, color = TextPrimary) },
                                trailingIcon = {
                                    Icon(
                                        Icons.Default.Close,
                                        contentDescription = "Remove",
                                        tint = RiskCriticalLight,
                                        modifier = Modifier.size(14.dp)
                                    )
                                },
                                colors = InputChipDefaults.inputChipColors(
                                    selectedContainerColor = Color(0x33A855F7)
                                ),
                                border = BorderStroke(1.dp, Color(0xFFA855F7))
                            )
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // 3. 1-Click Kid-Safety Benchmarks
        Text(
            text = "1-CLICK CHILD THREAT BENCHMARKS",
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
            ChildSafetyAnalyzer.BENCHMARKS.forEach { bm ->
                val isSelected = (bm.id == activeBenchmarkId)
                val chipLabel = when (bm.id) {
                    "freefire_diamond_scam" -> "🎮 Free Fire Trap"
                    "mahadev_betting_scam" -> "🎰 Mahadev Betting"
                    "stranger_chat_scam" -> "💬 Stranger Chat"
                    "khan_academy_safe" -> "📚 Khan Academy"
                    "parent_study_lock" -> "🚫 Instagram (Study Lock)"
                    else -> bm.title
                }
                FilterChip(
                    selected = isSelected,
                    onClick = {
                        activeBenchmarkId = bm.id
                        inputUrl = bm.url
                        inputContext = bm.context
                        currentRecord = ChildSafetyAnalyzer.analyzeUrl(
                            url = bm.url,
                            contextText = bm.context,
                            customBlocklist = customBlocklist,
                            isParentalControlActive = isParentalControlActive
                        )
                    },
                    label = {
                        Text(
                            text = chipLabel,
                            fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                            fontSize = 11.sp
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

        // 4. Live URL Forensics Input Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = CardDark),
            border = BorderStroke(1.dp, BorderDark),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Text("Audit Any Link for Child Safety", color = TextPrimary, fontSize = 13.sp, fontWeight = FontWeight.Bold)
                Spacer(modifier = Modifier.height(6.dp))

                OutlinedTextField(
                    value = inputUrl,
                    onValueChange = { inputUrl = it },
                    label = { Text("Website Link / Domain Under Audit", fontSize = 11.sp) },
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
                    value = inputContext,
                    onValueChange = { inputContext = it },
                    label = { Text("Ad Headline / Message Context", fontSize = 11.sp) },
                    modifier = Modifier.fillMaxWidth(),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = PrimaryCobalt,
                        unfocusedBorderColor = BorderDark,
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary
                    ),
                    maxLines = 2
                )

                Spacer(modifier = Modifier.height(10.dp))

                Button(
                    onClick = {
                        if (inputUrl.isNotBlank()) {
                            activeBenchmarkId = "custom"
                            currentRecord = ChildSafetyAnalyzer.analyzeUrl(
                                url = inputUrl,
                                contextText = inputContext,
                                customBlocklist = customBlocklist,
                                isParentalControlActive = isParentalControlActive
                            )
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = PrimaryCobalt),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text("Run Child Safety Forensics", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // 5. Forensics Results Display
        val isBlocked = currentRecord.isBlocked
        val isParentBlocked = currentRecord.isParentBlocked
        val bannerBg = when {
            isParentBlocked -> Color(0x33A855F7)
            isBlocked -> Color(0x26EF4444)
            else -> Color(0x2610B981)
        }
        val bannerBorder = when {
            isParentBlocked -> Color(0xFFA855F7)
            isBlocked -> RiskCritical
            else -> RiskClean
        }
        val bannerText = when {
            isParentBlocked -> Color(0xFFC084FC)
            isBlocked -> RiskCriticalLight
            else -> RiskCleanLight
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = bannerBg),
            border = BorderStroke(1.dp, bannerBorder),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = when {
                                isParentBlocked -> Icons.Default.Lock
                                isBlocked -> Icons.Default.Block
                                else -> Icons.Default.CheckCircle
                            },
                            contentDescription = null,
                            tint = bannerText,
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = when {
                                isParentBlocked -> "BLOCKED BY PARENT (STUDY LOCK)"
                                isBlocked -> "SITE BLOCKED FOR CHILD SAFETY"
                                else -> "APPROVED (CHILD SAFE)"
                            },
                            color = bannerText,
                            fontWeight = FontWeight.ExtraBold,
                            fontSize = 12.sp
                        )
                    }

                    Box(
                        modifier = Modifier
                            .background(bannerBorder, RoundedCornerShape(6.dp))
                            .padding(horizontal = 6.dp, vertical = 3.dp)
                    ) {
                        Text(
                            text = if (isParentBlocked) "0/100 (LOCKED)" else "${currentRecord.safetyScore}/100",
                            color = Color.White,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.ExtraBold
                        )
                    }
                }

                Spacer(modifier = Modifier.height(6.dp))

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.Start,
                    modifier = Modifier
                        .background(Color(0x2638BDF8), RoundedCornerShape(6.dp))
                        .border(1.dp, Color(0x4D38BDF8), RoundedCornerShape(6.dp))
                        .padding(horizontal = 8.dp, vertical = 3.dp)
                ) {
                    Text("⚡", fontSize = 10.sp)
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Analyzed in ", color = AccentCyan, fontSize = 10.sp, fontWeight = FontWeight.SemiBold)
                    Text(
                        text = "${String.format(java.util.Locale.US, "%.2f", currentRecord.analysisTimeMs / 1000f)}s",
                        color = TextPrimary,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = " (${currentRecord.analysisTimeMs}ms)",
                        color = AccentCyan.copy(alpha = 0.8f),
                        fontSize = 9.sp
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Column {
                        Text("AGE RATING", color = TextTertiary, fontSize = 9.sp, fontWeight = FontWeight.Bold)
                        Text(currentRecord.ageRating, color = Color(0xFFFBBF24), fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }
                    Column {
                        Text("CATEGORY", color = TextTertiary, fontSize = 9.sp, fontWeight = FontWeight.Bold)
                        Text(currentRecord.primaryCategory, color = TextPrimary, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                    }
                }

                Spacer(modifier = Modifier.height(10.dp))

                Text("Why This Content is Flagged:", color = TextTertiary, fontSize = 9.sp, fontWeight = FontWeight.Bold)
                Text(currentRecord.reason, color = TextPrimary, fontSize = 11.sp, lineHeight = 15.sp)

                Spacer(modifier = Modifier.height(6.dp))

                Text("Parental Action Advisory:", color = TextTertiary, fontSize = 9.sp, fontWeight = FontWeight.Bold)
                Text(currentRecord.recommendedAction, color = if (isBlocked) RiskCriticalLight else RiskCleanLight, fontSize = 11.sp, lineHeight = 15.sp)

                if (currentRecord.matchedCues.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = "Detected Hazard Cues: " + currentRecord.matchedCues.joinToString(", "),
                        color = Color(0xFFFBBF24),
                        fontSize = 10.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // 6. Router-Level Family DNS Shield Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = CardDarkElevated),
            border = BorderStroke(1.dp, BorderDark),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Text("🏠 Whole-Home Router Family DNS Shield", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Configure Cloudflare Families on your Wi-Fi router to block adult and malware content across all kids' phones, tablets, and smart TVs automatically:",
                    color = TextSecondary,
                    fontSize = 10.sp,
                    lineHeight = 14.sp
                )
                Spacer(modifier = Modifier.height(8.dp))
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(Color(0x33000000), RoundedCornerShape(6.dp))
                        .padding(8.dp)
                ) {
                    Text(
                        text = "Cloudflare Family DNS:\nPrimary   : 1.1.1.3\nSecondary : 1.0.0.3\nCleanBrowsing : 185.228.168.168",
                        color = AccentCyan,
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        lineHeight = 14.sp
                    )
                }
            }
        }
    }
}

@Composable
private fun PolicyToggleRow(
    title: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(title, color = TextPrimary, fontSize = 11.sp, modifier = Modifier.weight(1f))
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = SwitchDefaults.colors(
                checkedThumbColor = Color.White,
                checkedTrackColor = PrimaryCobalt
            )
        )
    }
}
