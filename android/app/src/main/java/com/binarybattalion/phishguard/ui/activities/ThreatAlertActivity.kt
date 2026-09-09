package com.binarybattalion.phishguard.ui.activities

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.binarybattalion.phishguard.MainActivity
import com.binarybattalion.phishguard.core.SmishingAnalyzer
import com.binarybattalion.phishguard.core.SmishingRecord
import com.binarybattalion.phishguard.core.ThreatSirenPlayer
import com.binarybattalion.phishguard.ui.theme.*

class ThreatAlertActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Ensure alert pops up even when device is locked
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
            setShowWhenLocked(true)
            setTurnScreenOn(true)
        } else {
            @Suppress("DEPRECATION")
            window.addFlags(
                WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
                WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON or
                WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON
            )
        }

        val sender = intent.getStringExtra(EXTRA_SENDER) ?: "Unknown"
        val message = intent.getStringExtra(EXTRA_MESSAGE) ?: ""
        
        // Analyze or reconstruct record
        val record = SmishingAnalyzer.analyzeSmishingMessage(sender, message)

        // 🔊 If threat score > 90, play custom 3-second emergency siren audio alert
        if (record.riskScore > 90) {
            ThreatSirenPlayer.playSiren(this, 3000L)
        }

        setContent {
            PhishGuardTheme(darkTheme = true) {
                ThreatAlertPopup(
                    record = record,
                    onOpenSoc = {
                        ThreatSirenPlayer.stop()
                        val mainIntent = Intent(this, MainActivity::class.java).apply {
                            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
                            putExtra("EXTRA_INCOMING_CASE_ID", record.caseId)
                            putExtra("EXTRA_INCOMING_SENDER", record.senderId)
                            putExtra("EXTRA_INCOMING_MESSAGE", record.rawMessage)
                        }
                        startActivity(mainIntent)
                        finish()
                    },
                    onDismiss = {
                        ThreatSirenPlayer.stop()
                        finish()
                    }
                )
            }
        }
    }

    override fun onPause() {
        super.onPause()
        ThreatSirenPlayer.stop()
    }

    override fun onDestroy() {
        super.onDestroy()
        ThreatSirenPlayer.stop()
    }

    companion object {
        const val EXTRA_SENDER = "EXTRA_SENDER"
        const val EXTRA_MESSAGE = "EXTRA_MESSAGE"

        fun launch(context: Context, sender: String, message: String) {
            val intent = Intent(context, ThreatAlertActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
                putExtra(EXTRA_SENDER, sender)
                putExtra(EXTRA_MESSAGE, message)
            }
            context.startActivity(intent)
        }
    }
}

@Composable
fun ThreatAlertPopup(
    record: SmishingRecord,
    onOpenSoc: () -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val isCritical = record.riskScore >= 70
    val isSuspicious = record.riskScore in 35..69
    val alertAccent = when {
        isCritical -> RiskCriticalLight
        isSuspicious -> Color(0xFFFBBF24)
        else -> RiskCleanLight
    }
    val alertBorder = when {
        isCritical -> RiskCritical
        isSuspicious -> RiskWarning
        else -> RiskClean
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        contentAlignment = Alignment.Center
    ) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .widthIn(max = 480.dp),
            colors = CardDefaults.cardColors(containerColor = CardDark),
            border = BorderStroke(1.5.dp, alertBorder),
            shape = RoundedCornerShape(16.dp)
        ) {
            Column(
                modifier = Modifier
                    .padding(18.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                // 1. Header Banner
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(34.dp)
                                .background(alertBorder.copy(alpha = 0.2f), CircleShape),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = if (isCritical) Icons.Default.Warning else Icons.Default.Shield,
                                contentDescription = null,
                                tint = alertAccent,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(
                                text = "REAL-TIME THREAT SENTINEL",
                                color = alertAccent,
                                fontWeight = FontWeight.ExtraBold,
                                fontSize = 12.sp,
                                letterSpacing = 0.8.sp
                            )
                            Text(
                                text = "Interception Case: ${record.caseId}",
                                color = TextSecondary,
                                fontSize = 10.sp,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                    }

                    IconButton(
                        onClick = onDismiss,
                        modifier = Modifier.size(28.dp)
                    ) {
                        Icon(Icons.Default.Close, contentDescription = "Close", tint = TextSecondary, modifier = Modifier.size(16.dp))
                    }
                }

                Spacer(modifier = Modifier.height(14.dp))

                // 2. Risk Meter Highlight
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(alertBorder.copy(alpha = 0.15f), RoundedCornerShape(10.dp))
                        .border(1.dp, alertBorder.copy(alpha = 0.35f), RoundedCornerShape(10.dp))
                        .padding(10.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column {
                            Text("ASSESSED RISK SCORE", color = TextTertiary, fontSize = 9.sp, fontWeight = FontWeight.Bold)
                            Text(
                                text = "${record.riskScore}/100 • ${record.verdict}",
                                color = alertAccent,
                                fontSize = 14.sp,
                                fontWeight = FontWeight.ExtraBold
                            )
                        }
                        Box(
                            modifier = Modifier
                                .background(CardDarkElevated, RoundedCornerShape(6.dp))
                                .padding(horizontal = 8.dp, vertical = 4.dp)
                        ) {
                            Text(
                                text = if (record.senderInfo.isDltCompliant) "DLT VERIFIED" else "DLT VIOLATION",
                                color = if (record.senderInfo.isDltCompliant) RiskCleanLight else RiskCriticalLight,
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }

                if (record.riskScore > 90) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(RiskCritical.copy(alpha = 0.2f), RoundedCornerShape(8.dp))
                            .border(1.dp, RiskCriticalLight.copy(alpha = 0.6f), RoundedCornerShape(8.dp))
                            .padding(horizontal = 10.dp, vertical = 6.dp)
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Icon(
                                Icons.Default.VolumeUp,
                                contentDescription = null,
                                tint = RiskCriticalLight,
                                modifier = Modifier.size(18.dp)
                            )
                            Column {
                                Text(
                                    text = "🚨 3-SECOND SIREN ALARM TRIGGERED",
                                    color = RiskCriticalLight,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.ExtraBold
                                )
                                Text(
                                    text = "Threat factor (${record.riskScore}/100) exceeds safety threshold (>90). Custom audio alarm played for 3 seconds.",
                                    color = TextSecondary,
                                    fontSize = 9.5.sp
                                )
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                // 3. Side-By-Side Comparison Grid
                Text(
                    text = "SIDE-BY-SIDE THREAT AUDIT",
                    color = TextTertiary,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 0.6.sp
                )

                Spacer(modifier = Modifier.height(6.dp))

                // Side 1: Incoming Carrier SMS (Raw Evidence)
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = CardDarkElevated),
                    border = BorderStroke(1.dp, BorderDark),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text("📨 INCOMING CARRIER SMS", color = AccentCyan, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                            Text("Sender: ${record.senderId}", color = TextSecondary, fontSize = 10.sp, fontWeight = FontWeight.SemiBold)
                        }
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "\"${record.rawMessage}\"",
                            color = TextPrimary,
                            fontSize = 11.sp,
                            lineHeight = 15.sp,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))

                // Side 2: PhishGuard Forensic AI Verdict
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = CardDarkElevated),
                    border = BorderStroke(1.dp, alertBorder.copy(alpha = 0.4f)),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text("🛡️ PHISHGUARD VERDICT", color = alertAccent, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                            Text(record.threatCategory, color = TextPrimary, fontSize = 10.sp, fontWeight = FontWeight.SemiBold)
                        }

                        if (record.vernacularInfo.isVernacular) {
                            Spacer(modifier = Modifier.height(4.dp))
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Box(
                                    modifier = Modifier
                                        .background(Color(0x26F59E0B), RoundedCornerShape(4.dp))
                                        .padding(horizontal = 4.dp, vertical = 2.dp)
                                ) {
                                    Text(
                                        text = record.vernacularInfo.detectedLanguage,
                                        color = Color(0xFFFBBF24),
                                        fontSize = 9.sp,
                                        fontWeight = FontWeight.Bold
                                    )
                                }
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(
                                    text = "\"${record.vernacularInfo.englishMeaning}\"",
                                    color = TextSecondary,
                                    fontSize = 10.sp,
                                    fontStyle = FontStyle.Italic,
                                    maxLines = 2
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = record.actionMsg,
                            color = if (isCritical) RiskCriticalLight else TextPrimary,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Medium
                        )
                    }
                }

                Spacer(modifier = Modifier.height(14.dp))

                // 4. Action Buttons
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = {
                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            clipboard.setPrimaryClip(ClipData.newPlainText("Chakshu Dossier", record.chakshuDraft))
                            Toast.makeText(context, "Sanchar Saathi 1930 report copied!", Toast.LENGTH_SHORT).show()
                        },
                        modifier = Modifier.weight(1f),
                        border = BorderStroke(1.dp, PrimaryCobaltLight.copy(alpha = 0.6f)),
                        shape = RoundedCornerShape(8.dp),
                        contentPadding = PaddingValues(vertical = 8.dp, horizontal = 6.dp)
                    ) {
                        Icon(Icons.Default.ContentCopy, contentDescription = null, tint = AccentCyan, modifier = Modifier.size(14.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Copy 1930", color = AccentCyan, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                    }

                    Button(
                        onClick = onOpenSoc,
                        modifier = Modifier.weight(1.3f),
                        colors = ButtonDefaults.buttonColors(containerColor = PrimaryCobalt),
                        shape = RoundedCornerShape(8.dp),
                        contentPadding = PaddingValues(vertical = 8.dp, horizontal = 6.dp)
                    ) {
                        Icon(Icons.Default.Visibility, contentDescription = null, tint = TextPrimary, modifier = Modifier.size(14.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Open In SOC", color = TextPrimary, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
    }
}
