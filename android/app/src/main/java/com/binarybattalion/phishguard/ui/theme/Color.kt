package com.binarybattalion.phishguard.ui.theme

import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Base Dark Palette (Cyber SOC Night Mode)
val DarkBackground = Color(0xFF0B0F19)
val DarkCard = Color(0xFF1E293B)
val DarkCardElevated = Color(0xFF161F30)
val DarkBorder = Color(0xFF334155)
val DarkTextPrimary = Color(0xFFF8FAFC)
val DarkTextSecondary = Color(0xFF94A3B8)
val DarkTextTertiary = Color(0xFF64748B)

// Base Light Palette (Pastel Blue & White Day Mode)
val LightBackground = Color(0xFFF0F6FC) // Serene pastel blue tint
val LightCard = Color(0xFFFFFFFF)       // Crisp pure white card
val LightCardElevated = Color(0xFFE8F2FB) // Soft elevated pastel surface
val LightBorder = Color(0xFFDBEAFE)     // Subtle crisp sky-tinted border
val LightTextPrimary = Color(0xFF0F172A) // Deep navy slate text
val LightTextSecondary = Color(0xFF475569) // Muted slate text
val LightTextTertiary = Color(0xFF64748B)

// Brand Accents
val PrimaryCobalt = Color(0xFF4D65FF)
val PrimaryCobaltLight = Color(0xFF6B80FF)
val AccentCyan = Color(0xFF38BDF8)

// Risk Indicators
val RiskCritical = Color(0xFFEF4444)
val RiskCriticalLight = Color(0xFFFCA5A5)
val RiskWarning = Color(0xFFF59E0B)
val RiskWarningLight = Color(0xFFFDE68A)
val RiskClean = Color(0xFF10B981)
val RiskCleanLight = Color(0xFF86EFAC)

// Dynamic Composable Color Accessors (instantly toggle between Day & Night modes across all UI components)
val BgDark: Color
    @Composable
    get() = if (LocalIsDarkMode.current) DarkBackground else LightBackground

val CardDark: Color
    @Composable
    get() = if (LocalIsDarkMode.current) DarkCard else LightCard

val CardDarkElevated: Color
    @Composable
    get() = if (LocalIsDarkMode.current) DarkCardElevated else LightCardElevated

val BorderDark: Color
    @Composable
    get() = if (LocalIsDarkMode.current) DarkBorder else LightBorder

val TextPrimary: Color
    @Composable
    get() = if (LocalIsDarkMode.current) DarkTextPrimary else LightTextPrimary

val TextSecondary: Color
    @Composable
    get() = if (LocalIsDarkMode.current) DarkTextSecondary else LightTextSecondary

val TextTertiary: Color
    @Composable
    get() = if (LocalIsDarkMode.current) DarkTextTertiary else LightTextTertiary
