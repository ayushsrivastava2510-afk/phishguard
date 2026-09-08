package com.binarybattalion.phishguard

import android.Manifest
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
import com.binarybattalion.phishguard.core.SmishingAnalyzer
import com.binarybattalion.phishguard.core.SmishingRecord
import com.binarybattalion.phishguard.ui.screens.EmailScreen
import com.binarybattalion.phishguard.ui.screens.SmishingScreen
import com.binarybattalion.phishguard.ui.theme.*

enum class ThreatVector {
    SMS, EMAIL
}

class MainActivity : ComponentActivity() {

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { _ ->
        // Permissions granted/denied handled gracefully; on-device scanning continues
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestRequiredPermissions()

        val incomingSender = intent.getStringExtra("EXTRA_INCOMING_SENDER")
        val incomingMessage = intent.getStringExtra("EXTRA_INCOMING_MESSAGE")
        val initialRecord: SmishingRecord? = if (!incomingSender.isNullOrEmpty() && !incomingMessage.isNullOrEmpty()) {
            SmishingAnalyzer.analyzeSmishingMessage(incomingSender, incomingMessage)
        } else null

        setContent {
            PhishGuardTheme {
                MainAppScaffold(initialRecord = initialRecord)
            }
        }
    }

    private fun requestRequiredPermissions() {
        val permissions = mutableListOf<String>()
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECEIVE_SMS) != PackageManager.PERMISSION_GRANTED) {
            permissions.add(Manifest.permission.RECEIVE_SMS)
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
fun MainAppScaffold(initialRecord: SmishingRecord? = null) {
    var activeVector by remember { mutableStateOf(ThreatVector.SMS) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(36.dp)
                                .background(Color(0x334D65FF), RoundedCornerShape(8.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                Icons.Default.Security,
                                contentDescription = "Shield Logo",
                                tint = PrimaryCobaltLight,
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
                                        .background(Color(0x3338BDF8), RoundedCornerShape(4.dp))
                                        .padding(horizontal = 5.dp, vertical = 2.dp)
                                ) {
                                    Text(
                                        text = "MOBILE SOC",
                                        color = AccentCyan,
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
                    Box(
                        modifier = Modifier
                            .padding(end = 12.dp)
                            .background(Color(0x2610B981), RoundedCornerShape(12.dp))
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
                                color = RiskCleanLight,
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
            // Dual-Vector Switcher Buttons (GeekPay Theme)
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 6.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Button(
                    onClick = { activeVector = ThreatVector.SMS },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (activeVector == ThreatVector.SMS) PrimaryCobalt else CardDark,
                        contentColor = if (activeVector == ThreatVector.SMS) TextPrimary else TextSecondary
                    ),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Text(
                        text = "📱 SMS Sentinel" + if (activeVector == ThreatVector.SMS) " ✓" else "",
                        fontSize = 12.sp,
                        fontWeight = if (activeVector == ThreatVector.SMS) FontWeight.Bold else FontWeight.Medium
                    )
                }

                Button(
                    onClick = { activeVector = ThreatVector.EMAIL },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (activeVector == ThreatVector.EMAIL) PrimaryCobalt else CardDark,
                        contentColor = if (activeVector == ThreatVector.EMAIL) TextPrimary else TextSecondary
                    ),
                    shape = RoundedCornerShape(10.dp)
                ) {
                    Text(
                        text = "📧 Email Threat" + if (activeVector == ThreatVector.EMAIL) " ✓" else "",
                        fontSize = 12.sp,
                        fontWeight = if (activeVector == ThreatVector.EMAIL) FontWeight.Bold else FontWeight.Medium
                    )
                }
            }

            when (activeVector) {
                ThreatVector.SMS -> SmishingScreen(initialRecord = initialRecord)
                ThreatVector.EMAIL -> EmailScreen()
            }
        }
    }
}
