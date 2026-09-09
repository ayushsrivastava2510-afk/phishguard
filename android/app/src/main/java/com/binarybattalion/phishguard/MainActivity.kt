package com.binarybattalion.phishguard

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.LightMode
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.binarybattalion.phishguard.core.SentinelService
import com.binarybattalion.phishguard.core.SmishingAnalyzer
import com.binarybattalion.phishguard.core.SmishingRecord
import com.binarybattalion.phishguard.ui.screens.ChildSafetyScreen
import com.binarybattalion.phishguard.ui.screens.EmailScreen
import com.binarybattalion.phishguard.ui.screens.QuishingScreen
import com.binarybattalion.phishguard.ui.screens.SmishingScreen
import com.binarybattalion.phishguard.ui.theme.*

enum class ThreatVector {
    SMS, EMAIL, QUISHING, CHILD_SAFETY
}

class MainActivity : ComponentActivity() {

    private val liveRecordState = mutableStateOf<SmishingRecord?>(null)

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { grants ->
        val smsGranted = grants[Manifest.permission.RECEIVE_SMS] == true
        if (smsGranted) {
            SentinelService.startSentinel(this)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestRequiredPermissions()

        val incomingSender = intent.getStringExtra("EXTRA_INCOMING_SENDER")
        val incomingMessage = intent.getStringExtra("EXTRA_INCOMING_MESSAGE")
        if (!incomingSender.isNullOrEmpty() && !incomingMessage.isNullOrEmpty()) {
            liveRecordState.value = SmishingAnalyzer.analyzeSmishingMessage(incomingSender, incomingMessage)
        }

        // Start background Sentinel if permission already available
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECEIVE_SMS) == PackageManager.PERMISSION_GRANTED) {
            SentinelService.startSentinel(this)
        }

        setContent {
            var isDarkMode by remember { mutableStateOf(false) } // Default to Day Mode / Pastel Blue & White
            val activeRecord = liveRecordState.value
            PhishGuardTheme(darkTheme = isDarkMode) {
                MainAppScaffold(
                    initialRecord = activeRecord,
                    isDarkMode = isDarkMode,
                    onToggleTheme = { isDarkMode = !isDarkMode }
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        val incomingSender = intent.getStringExtra("EXTRA_INCOMING_SENDER")
        val incomingMessage = intent.getStringExtra("EXTRA_INCOMING_MESSAGE")
        if (!incomingSender.isNullOrEmpty() && !incomingMessage.isNullOrEmpty()) {
            liveRecordState.value = SmishingAnalyzer.analyzeSmishingMessage(incomingSender, incomingMessage)
        }
    }

    private fun requestRequiredPermissions() {
        val permissions = mutableListOf<String>()
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECEIVE_SMS) != PackageManager.PERMISSION_GRANTED) {
            permissions.add(Manifest.permission.RECEIVE_SMS)
        }
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_SMS) != PackageManager.PERMISSION_GRANTED) {
            permissions.add(Manifest.permission.READ_SMS)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            permissions.add(Manifest.permission.POST_NOTIFICATIONS)
        }
        if (permissions.isNotEmpty()) {
            permissionLauncher.launch(permissions.toTypedArray())
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainAppScaffold(
    initialRecord: SmishingRecord? = null,
    isDarkMode: Boolean = false,
    onToggleTheme: () -> Unit = {}
) {
    var activeVector by remember { mutableStateOf(ThreatVector.SMS) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(36.dp)
                                .background(if (isDarkMode) Color(0x334D65FF) else Color(0x224D65FF), RoundedCornerShape(8.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                Icons.Default.Security,
                                contentDescription = "Shield Logo",
                                tint = if (isDarkMode) PrimaryCobaltLight else PrimaryCobalt,
                                modifier = Modifier.size(20.dp)
                            )
                        }
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    text = "PhishGuard",
                                    color = TextPrimary,
                                    fontSize = 17.sp,
                                    fontWeight = FontWeight.ExtraBold
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Box(
                                    modifier = Modifier
                                        .background(if (isDarkMode) Color(0x3338BDF8) else Color(0x2238BDF8), RoundedCornerShape(4.dp))
                                        .padding(horizontal = 5.dp, vertical = 2.dp)
                                ) {
                                    Text(
                                        text = "MOBILE SOC",
                                        color = if (isDarkMode) AccentCyan else PrimaryCobalt,
                                        fontSize = 8.sp,
                                        fontWeight = FontWeight.Bold
                                    )
                                }
                            }
                            Text(
                                text = "Autonomous Threat Sentinel",
                                color = TextSecondary,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Normal
                            )
                        }
                    }
                },
                actions = {
                    // 1-Tap Day / Night Mode Toggle (Sun / Moon)
                    IconButton(
                        onClick = onToggleTheme,
                        modifier = Modifier.size(36.dp)
                    ) {
                        Icon(
                            imageVector = if (isDarkMode) Icons.Default.LightMode else Icons.Default.DarkMode,
                            contentDescription = if (isDarkMode) "Switch to Day Mode" else "Switch to Night Mode",
                            tint = if (isDarkMode) Color(0xFFFDE047) else Color(0xFF334155),
                            modifier = Modifier.size(20.dp)
                        )
                    }
                    Spacer(modifier = Modifier.width(4.dp))
                    Box(
                        modifier = Modifier
                            .padding(end = 12.dp)
                            .background(if (isDarkMode) Color(0x2610B981) else Color(0x2210B981), RoundedCornerShape(12.dp))
                            .padding(horizontal = 8.dp, vertical = 4.dp)
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(6.dp)
                                    .background(RiskClean, RoundedCornerShape(3.dp))
                            )
                            Spacer(modifier = Modifier.width(5.dp))
                            Text(
                                text = "ENGINE ONLINE",
                                color = if (isDarkMode) RiskCleanLight else Color(0xFF047857),
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = BgDark,
                    titleContentColor = TextPrimary
                )
            )
        },
        containerColor = BgDark
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            // Multi-Vector Switcher Buttons (GeekPay Theme)
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 6.dp),
                horizontalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Button(
                    onClick = { activeVector = ThreatVector.SMS },
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(horizontal = 2.dp, vertical = 6.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (activeVector == ThreatVector.SMS) PrimaryCobalt else CardDark,
                        contentColor = if (activeVector == ThreatVector.SMS) Color.White else TextSecondary
                    ),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Text(
                        text = "📱 SMS" + if (activeVector == ThreatVector.SMS) " ✓" else "",
                        fontSize = 10.sp,
                        maxLines = 1,
                        fontWeight = if (activeVector == ThreatVector.SMS) FontWeight.Bold else FontWeight.Medium
                    )
                }

                Button(
                    onClick = { activeVector = ThreatVector.EMAIL },
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(horizontal = 2.dp, vertical = 6.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (activeVector == ThreatVector.EMAIL) PrimaryCobalt else CardDark,
                        contentColor = if (activeVector == ThreatVector.EMAIL) Color.White else TextSecondary
                    ),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Text(
                        text = "📧 Mail" + if (activeVector == ThreatVector.EMAIL) " ✓" else "",
                        fontSize = 10.sp,
                        maxLines = 1,
                        fontWeight = if (activeVector == ThreatVector.EMAIL) FontWeight.Bold else FontWeight.Medium
                    )
                }

                Button(
                    onClick = { activeVector = ThreatVector.QUISHING },
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(horizontal = 2.dp, vertical = 6.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (activeVector == ThreatVector.QUISHING) PrimaryCobalt else CardDark,
                        contentColor = if (activeVector == ThreatVector.QUISHING) Color.White else TextSecondary
                    ),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Text(
                        text = "🎯 QR" + if (activeVector == ThreatVector.QUISHING) " ✓" else "",
                        fontSize = 10.sp,
                        maxLines = 1,
                        fontWeight = if (activeVector == ThreatVector.QUISHING) FontWeight.Bold else FontWeight.Medium
                    )
                }

                Button(
                    onClick = { activeVector = ThreatVector.CHILD_SAFETY },
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(horizontal = 2.dp, vertical = 6.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (activeVector == ThreatVector.CHILD_SAFETY) PrimaryCobalt else CardDark,
                        contentColor = if (activeVector == ThreatVector.CHILD_SAFETY) Color.White else TextSecondary
                    ),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Text(
                        text = "👨‍👩‍👧 Kids" + if (activeVector == ThreatVector.CHILD_SAFETY) " ✓" else "",
                        fontSize = 10.sp,
                        maxLines = 1,
                        fontWeight = if (activeVector == ThreatVector.CHILD_SAFETY) FontWeight.Bold else FontWeight.Medium
                    )
                }
            }

            when (activeVector) {
                ThreatVector.SMS -> SmishingScreen(initialRecord = initialRecord)
                ThreatVector.EMAIL -> EmailScreen()
                ThreatVector.QUISHING -> QuishingScreen()
                ThreatVector.CHILD_SAFETY -> ChildSafetyScreen()
            }
        }
    }
}
