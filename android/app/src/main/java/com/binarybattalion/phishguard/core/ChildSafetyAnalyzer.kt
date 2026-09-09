package com.binarybattalion.phishguard.core

import java.net.URI
import java.util.Locale

data class ChildSafetyRecord(
    val url: String,
    val hostname: String,
    val safetyScore: Int,
    val ageRating: String,
    val verdict: String,
    val primaryCategory: String,
    val matchedCues: List<String>,
    val reason: String,
    val recommendedAction: String,
    val isBlocked: Boolean,
    val analysisTimeMs: Long = 12L
)

data class ChildSafetyBenchmark(
    val id: String,
    val title: String,
    val url: String,
    val context: String,
    val description: String
)

object ChildSafetyAnalyzer {

    private val SAFE_EDUCATIONAL_DOMAINS = setOf(
        "khanacademy.org",
        "ncert.nic.in",
        "cbse.gov.in",
        "cbse.nic.in",
        "diksha.gov.in",
        "swayam.gov.in",
        "scratch.mit.edu",
        "natgeokids.com",
        "duolingo.com",
        "code.org",
        "wikipedia.org",
        "britannica.com",
        "nasa.gov",
        "scholastic.com",
        "funbrain.com",
        "pbskids.org"
    )

    private val GAMING_PHISHING_KEYWORDS = listOf(
        "free-fire-diamond", "freefirediamond", "free-diamonds", "unlimited-diamonds",
        "free-robux", "freerobux", "robux-generator", "free-uc", "bgmi-uc",
        "free-vbucks", "vbucks-generator", "steam-wallet-free", "minecraft-free-account",
        "mod-apk-unlimited", "hack-diamond", "diamond-generator", "redeem-free-fire",
        "bgmi-skin-free", "pubg-uc-hack", "elite-pass-free", "free-skin-generator",
        "roblox-free", "freefire-reward", "garena-free-reward"
    )

    private val GAMBLING_KEYWORDS = listOf(
        "mahadev", "mahadev-book", "betway", "1xbet", "parimatch", "lotus365",
        "fairplay", "cricket-betting", "casino", "teen-patti-real-cash", "rummy-wealth",
        "color-prediction", "satta-matka", "aviator-signal", "aviator-hack",
        "real-cash-game", "win-zo-hack", "roulette", "stake-casino", "bet365"
    )

    private val ADULT_KEYWORDS = listOf(
        "porn", "xxx", "sex", "adult", "erotic", "nude", "strip", "escort",
        "webcam", "nsfw", "camgirl", "dating-hookup", "horny", "milf", "taboo"
    )

    private val STRANGER_CHAT_KEYWORDS = listOf(
        "omegle", "chatroulette", "stranger-chat", "coomeet", "chathub",
        "monkey-app", "talk-to-strangers", "video-chat-random", "adult-chat"
    )

    private val SUSPICIOUS_TLDS = setOf(".xyz", ".top", ".tk", ".ml", ".cf", ".gq", ".buzz", ".work", ".site", ".live")

    fun analyzeUrl(url: String, contextText: String = ""): ChildSafetyRecord {
        val startTime = System.nanoTime()
        var cleanUrl = url.trim()
        if (!cleanUrl.startsWith("http://") && !cleanUrl.startsWith("https://")) {
            cleanUrl = "https://$cleanUrl"
        }

        val hostname = try {
            val uri = URI(cleanUrl)
            uri.host?.lowercase(Locale.ROOT) ?: ""
        } catch (e: Exception) {
            cleanUrl.substringAfter("://").substringBefore("/").lowercase(Locale.ROOT)
        }

        val combinedTarget = "$cleanUrl ${contextText.lowercase(Locale.ROOT)}"
        val matchedCues = mutableListOf<String>()
        var safetyScore = 100
        var ageRating = "Safe for All Ages (3+)"
        var verdict = "ALLOWED (SAFE FOR KIDS)"
        var category = "General Web Content"
        var reason = "Domain is safe for children and general learning."
        var action = "No restrictions required. Safe for child browsing."

        // 1. Check Educational Whitelist
        for (safe in SAFE_EDUCATIONAL_DOMAINS) {
            if (hostname == safe || hostname.endsWith(".$safe")) {
                return ChildSafetyRecord(
                    url = url,
                    hostname = hostname,
                    safetyScore = 100,
                    ageRating = "Safe for All Ages (3+)",
                    verdict = "ALLOWED (SAFE FOR KIDS)",
                    primaryCategory = "Educational & Creative Learning",
                    matchedCues = listOf("Official educational domain ($safe)"),
                    reason = "Verified educational domain ($safe) compliant with child privacy guidelines.",
                    recommendedAction = "Safe for unmonitored child exploration and homework study.",
                    isBlocked = false,
                    analysisTimeMs = Math.max(1L, (System.nanoTime() - startTime) / 1_000_000L)
                )
            }
        }

        // 2. Check Gaming Phishing Traps
        val gamingHits = GAMING_PHISHING_KEYWORDS.filter { combinedTarget.contains(it) }
        if (gamingHits.isNotEmpty()) {
            matchedCues.addAll(gamingHits)
            safetyScore = minOf(safetyScore, 10)
            ageRating = "Restricted (Fraud Hazard)"
            verdict = "BLOCKED (PREDATORY GAMING SCAM)"
            category = "Gaming Currency & Account Phishing Trap"
            reason = "Deceptive gaming rewards trap designed to steal parent credentials or payment accounts with fake currency promises."
            action = "BLOCK IMMEDIATELY: Legitimate games never distribute free Diamonds or Robux via 3rd-party websites."
        }

        // 3. Check Illegal Gambling & Betting
        val gamblingHits = GAMBLING_KEYWORDS.filter { combinedTarget.contains(it) }
        if (gamblingHits.isNotEmpty()) {
            matchedCues.addAll(gamblingHits)
            safetyScore = minOf(safetyScore, 5)
            ageRating = "Restricted (18+ Gambling)"
            verdict = "BLOCKED (ILLEGAL YOUTH BETTING HAZARD)"
            category = "Illegal Underage Gambling & Betting Portal"
            reason = "Gambling, color prediction, or unlicensed casino portal prohibited for minors under online gaming regulations."
            action = "STRICT BLOCK: High financial addiction and fraud risk for children."
        }

        // 4. Check Adult Content
        val adultHits = ADULT_KEYWORDS.filter { combinedTarget.contains(it) }
        if (adultHits.isNotEmpty()) {
            matchedCues.addAll(adultHits)
            safetyScore = minOf(safetyScore, 0)
            ageRating = "Restricted (18+ Adult)"
            verdict = "BLOCKED (EXPLICIT / AGE-INAPPROPRIATE)"
            category = "Adult & Age-Restricted Content"
            reason = "Contains explicit adult content or forced redirection to age-restricted portals."
            action = "STRICT BLOCK: Inappropriate for minors under POCSO and child safety guidelines."
        }

        // 5. Check Stranger Chat
        val chatHits = STRANGER_CHAT_KEYWORDS.filter { combinedTarget.contains(it) }
        if (chatHits.isNotEmpty()) {
            matchedCues.addAll(chatHits)
            safetyScore = minOf(safetyScore, 15)
            ageRating = "Restricted (Predatory Grooming Risk)"
            verdict = "BLOCKED (STRANGER CHAT HAZARD)"
            category = "Unmonitored Stranger Video/Text Chat"
            reason = "Unmoderated video/text chat platform with severe exposure to online grooming and harassment."
            action = "BLOCK: Minors must not access unmonitored random stranger video services."
        }

        // 6. Check Disposable / Suspicious TLDs
        for (tld in SUSPICIOUS_TLDS) {
            if (hostname.endsWith(tld)) {
                matchedCues.add("Suspicious disposable TLD ($tld)")
                safetyScore = maxOf(0, safetyScore - 25)
                if (safetyScore < 50 && verdict.startsWith("ALLOWED")) {
                    verdict = "CAUTION (SUSPICIOUS UNVERIFIED DOMAIN)"
                    ageRating = "Teen (13+) with Parental Oversight"
                    reason = "Domain uses a disposable TLD commonly abused in mobile malware and phishing droppers."
                }
                break
            }
        }

        val isBlocked = safetyScore < 40

        return ChildSafetyRecord(
            url = url,
            hostname = hostname,
            safetyScore = maxOf(0, minOf(100, safetyScore)),
            ageRating = ageRating,
            verdict = verdict,
            primaryCategory = category,
            matchedCues = matchedCues,
            reason = reason,
            recommendedAction = action,
            isBlocked = isBlocked,
            analysisTimeMs = Math.max(1L, (System.nanoTime() - startTime) / 1_000_000L)
        )
    }

    val BENCHMARKS = listOf(
        ChildSafetyBenchmark(
            id = "freefire_diamond_scam",
            title = "🎮 Scenario 1: Free Fire 10,000 Diamonds Scam",
            url = "https://garena-freefire-unlimited-diamonds.xyz/claim?gift=10000",
            context = "Free Fire Season 48 Mega Giveaway! Claim 10,000 Free Diamonds immediately!",
            description = "Predatory gaming phishing kit targeting kids with fake game currency to steal parent payment credentials."
        ),
        ChildSafetyBenchmark(
            id = "mahadev_betting_scam",
            title = "🎰 Scenario 2: Mahadev Youth Betting App",
            url = "http://mahadev-book-teen-patti-cash.site/download_betting.apk",
            context = "Win ₹5,000 daily playing simple color prediction! Download Mahadev official betting app now.",
            description = "Illegal underage gambling and color prediction app heavily marketed to teenagers."
        ),
        ChildSafetyBenchmark(
            id = "stranger_chat_scam",
            title = "💬 Scenario 3: Unmoderated Stranger Video Chat",
            url = "https://omegle-free-video-chat.live/join?room=random",
            context = "Talk to random strangers with one click! No age verification required.",
            description = "Unmoderated stranger video chat presenting extreme cyberbullying and predatory grooming hazards."
        ),
        ChildSafetyBenchmark(
            id = "khan_academy_safe",
            title = "📚 Scenario 4: Khan Academy India (Safe)",
            url = "https://www.khanacademy.org/math/class-10-math-india",
            context = "NCERT Class 10 Mathematics Interactive Video Lessons and Practice Quizzes.",
            description = "Certified kid-safe educational platform compliant with student privacy regulations."
        )
    )
}
