"""
PhishGuard Child Safe Browsing & Parental Control Sentinel
==========================================================
Autonomous on-device & server-side content filter analyzing URLs and domains
for child-targeted cyber exploitation, predatory gaming phishing traps,
underage betting/gambling, and age-inappropriate adult content.
"""

import re
from urllib.parse import urlparse
from typing import Dict, Any, List

# Known Educational / Whitelisted Child-Safe Domains
SAFE_EDUCATIONAL_DOMAINS = {
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
    "pbskids.org",
}

# Gaming Currency & Account Phishing Keywords (Targeting Kids & Teens)
GAMING_PHISHING_KEYWORDS = [
    "free-fire-diamond", "freefirediamond", "free-diamonds", "unlimited-diamonds",
    "free-robux", "freerobux", "robux-generator", "free-uc", "bgmi-uc",
    "free-vbucks", "vbucks-generator", "steam-wallet-free", "minecraft-free-account",
    "mod-apk-unlimited", "hack-diamond", "diamond-generator", "redeem-free-fire",
    "bgmi-skin-free", "pubg-uc-hack", "elite-pass-free", "free-skin-generator",
    "roblox-free", "freefire-reward", "garena-free-reward"
]

# Illegal Gambling / Betting Keywords (Promoted heavily to youth in India)
GAMBLING_KEYWORDS = [
    "mahadev", "mahadev-book", "betway", "1xbet", "parimatch", "lotus365",
    "fairplay", "cricket-betting", "casino", "teen-patti-real-cash", "rummy-wealth",
    "color-prediction", "satta-matka", "aviator-signal", "aviator-hack",
    "real-cash-game", "win-zo-hack", "roulette", "stake-casino", "bet365"
]

# Adult & Age-Inappropriate Keywords
ADULT_KEYWORDS = [
    "porn", "xxx", "sex", "adult", "erotic", "nude", "strip", "escort",
    "webcam", "nsfw", "camgirl", "dating-hookup", "horny", "milf", "taboo"
]

# Unverified Stranger Chat & Predator Platforms
STRANGER_CHAT_KEYWORDS = [
    "omegle", "chatroulette", "stranger-chat", "coomeet", "chathub",
    "monkey-app", "talk-to-strangers", "video-chat-random", "adult-chat"
]

# Known Malicious / Disposable TLDs used in child-targeted scams
SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".ml", ".cf", ".gq", ".buzz", ".work", ".site", ".live"}


def analyze_child_safety_url(url: str, context_text: str = "") -> Dict[str, Any]:
    """
    Analyzes a URL and optional accompanying context for child safety threats.
    
    Returns:
        dict containing safety_score (0-100), age_rating, category, verdict,
        detected_cues, plain-language reason, and clean browsing guidance.
    """
    cleaned_url = url.strip()
    if not cleaned_url.startswith(("http://", "https://")):
        cleaned_url = "https://" + cleaned_url

    parsed = urlparse(cleaned_url)
    hostname = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()
    combined_target = f"{hostname}{path}?{query}".lower()
    full_context = f"{combined_target} {context_text.lower()}"

    detected_categories = []
    matched_cues = []
    safety_score = 100
    age_rating = "Safe for All Ages (3+)"
    verdict = "ALLOWED (SAFE FOR KIDS)"
    reason = "Domain is verified safe for children and general learning."
    recommended_action = "No restrictions required. Safe for child browsing."

    # 1. Check Whitelisted Safe Educational Domains
    is_whitelisted = False
    for safe_domain in SAFE_EDUCATIONAL_DOMAINS:
        if hostname == safe_domain or hostname.endswith("." + safe_domain):
            is_whitelisted = True
            detected_categories.append("Verified Educational & Kid-Safe Portal")
            matched_cues.append(f"Official educational domain ({safe_domain})")
            safety_score = 100
            age_rating = "Safe for All Ages (3+)"
            verdict = "ALLOWED (SAFE FOR KIDS)"
            reason = f"Verified educational domain ({safe_domain}) compliant with child privacy and education guidelines."
            break

    if is_whitelisted:
        return {
            "url": url,
            "hostname": hostname,
            "safety_score": safety_score,
            "age_rating": age_rating,
            "verdict": verdict,
            "primary_category": "Educational & Creative Learning",
            "all_categories": detected_categories,
            "matched_cues": matched_cues,
            "reason": reason,
            "recommended_action": recommended_action,
            "clean_dns_recommendation": "Cloudflare 1.1.1.3 / CleanBrowsing Family Filter Active",
            "is_blocked": False
        }

    # 2. Check Gaming Phishing Traps (Free Diamonds, Robux, BGMI UC)
    gaming_matches = [kw for kw in GAMING_PHISHING_KEYWORDS if kw in full_context]
    if gaming_matches:
        detected_categories.append("Gaming Currency & Account Phishing Trap")
        matched_cues.extend(gaming_matches)
        safety_score = min(safety_score, 10)
        age_rating = "Restricted (Fraud Hazard)"
        verdict = "BLOCKED (PREDATORY GAMING SCAM)"
        reason = (
            "Deceptive gaming rewards trap designed to steal parent credentials, "
            "Google Play billing access, or phone numbers under the guise of free game currency."
        )
        recommended_action = (
            "BLOCK IMMEDIATELY: Never enter phone numbers, OTPs, or parent payment details "
            "for free game currencies. Legitimate games never distribute currency via 3rd-party websites."
        )

    # 3. Check Illegal Underage Gambling & Betting Apps
    gambling_matches = [kw for kw in GAMBLING_KEYWORDS if kw in full_context]
    if gambling_matches:
        detected_categories.append("Illegal Underage Gambling & Betting Portal")
        matched_cues.extend(gambling_matches)
        safety_score = min(safety_score, 5)
        age_rating = "Restricted (18+ Only - Gambling)"
        verdict = "BLOCKED (ILLEGAL YOUTH BETTING HAZARD)"
        reason = (
            "Gambling, color prediction, or unlicensed online casino portal prohibited for minors "
            "under Indian Public Gambling Act and state online gaming regulations."
        )
        recommended_action = (
            "STRICT BLOCK: High financial addiction and fraud risk. Report link to Cyber Cell (1930)."
        )

    # 4. Check Adult & Age-Inappropriate Content
    adult_matches = [kw for kw in ADULT_KEYWORDS if kw in full_context]
    if adult_matches:
        detected_categories.append("Adult & Age-Restricted Content")
        matched_cues.extend(adult_matches)
        safety_score = min(safety_score, 0)
        age_rating = "Restricted (18+ Adult)"
        verdict = "BLOCKED (EXPLICIT / AGE-INAPPROPRIATE)"
        reason = "Contains explicit adult content or forced redirection to age-restricted entertainment."
        recommended_action = "STRICT BLOCK: Inappropriate for minors under POCSO / child safety guidelines."

    # 5. Check Unverified Stranger Chat & Predator Platforms
    chat_matches = [kw for kw in STRANGER_CHAT_KEYWORDS if kw in full_context]
    if chat_matches:
        detected_categories.append("Unmonitored Stranger Video/Text Chat")
        matched_cues.extend(chat_matches)
        safety_score = min(safety_score, 15)
        age_rating = "Restricted (Predatory Grooming Risk)"
        verdict = "BLOCKED (STRANGER CHAT HAZARD)"
        reason = (
            "Unmoderated video/text chat platform with high exposure to online grooming, "
            "cyberbullying, and explicit adult harassment."
        )
        recommended_action = "BLOCK: Minors must not access unmoderated stranger chat services."

    # 6. Check Disposable / Suspicious TLDs
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            matched_cues.append(f"Suspicious disposable TLD ({tld})")
            safety_score = max(0, safety_score - 25)
            if safety_score < 50 and verdict == "ALLOWED (SAFE FOR KIDS)":
                verdict = "CAUTION (SUSPICIOUS UNVERIFIED DOMAIN)"
                age_rating = "Teen (13+) with Parental Oversight"
                reason = "Domain uses a disposable TLD commonly abused in mobile fraud and malware droppers."
            break

    # Determine Final Status
    is_blocked = safety_score < 40
    primary_category = detected_categories[0] if detected_categories else "General Web Content"

    if safety_score >= 80 and not detected_categories:
        verdict = "ALLOWED (SAFE FOR GENERAL BROWSING)"
        age_rating = "Safe for All Ages (3+)"
        reason = "No child-safety hazards or predatory social engineering markers detected."

    return {
        "url": url,
        "hostname": hostname,
        "safety_score": max(0, min(100, safety_score)),
        "age_rating": age_rating,
        "verdict": verdict,
        "primary_category": primary_category,
        "all_categories": detected_categories or ["General Web Browsing"],
        "matched_cues": matched_cues,
        "reason": reason,
        "recommended_action": recommended_action,
        "clean_dns_recommendation": "Cloudflare Family DNS (1.1.1.3) blocks adult and malware traffic at router level.",
        "is_blocked": is_blocked
    }


# Built-in Interactive Benchmarks for Hackathon Demonstrations
CHILD_SAFETY_BENCHMARKS = [
    {
        "id": "freefire_diamond_scam",
        "title": "🎮 Scenario 1: Free Fire 10,000 Free Diamonds & UC Trap",
        "url": "https://garena-freefire-unlimited-diamonds.xyz/claim?gift=10000",
        "context": "Free Fire Season 48 Mega Giveaway! Enter parent Google Play mobile number to claim 10,000 Free Diamonds immediately!",
        "description": "Predatory gaming phishing kit targeting kids with fake game currency to steal parent payment credentials."
    },
    {
        "id": "mahadev_betting_scam",
        "title": "🎰 Scenario 2: Mahadev Youth Betting & Casino App",
        "url": "http://mahadev-book-teen-patti-cash.site/download_betting.apk",
        "context": "Win ₹5,000 daily playing simple color prediction and Aviator game! Download Mahadev official betting app now.",
        "description": "Illegal underage gambling and color prediction app heavily marketed to teenagers via social media."
    },
    {
        "id": "stranger_chat_scam",
        "title": "💬 Scenario 3: Unmoderated Stranger Video Chat Platform",
        "url": "https://omegle-free-video-chat.live/join?room=random",
        "context": "Talk to random cute strangers with one click! No registration or age verification required.",
        "description": "Unmoderated stranger video chat presenting extreme cyberbullying, grooming, and explicit content hazards."
    },
    {
        "id": "khan_academy_safe",
        "title": "📚 Scenario 4: Khan Academy India (Verified Educational Safe)",
        "url": "https://www.khanacademy.org/math/class-10-math-india",
        "context": "NCERT Class 10 Mathematics Interactive Video Lessons and Practice Quizzes for CBSE Students.",
        "description": "Certified kid-safe, ad-free educational platform compliant with global student privacy regulations."
    }
]
