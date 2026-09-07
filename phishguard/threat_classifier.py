"""
threat_classifier.py
--------------------
Advanced Threat and Social Engineering Detection Engine for PhishGuard.
Analyzes email text, subject lines, and body content for:
  - Business Email Compromise (BEC) and Payment Diversion
  - Credential Harvesting and Account Takeover
  - Banking / KYC Verification Fraud (crucial for Indian enterprise/govt contexts)
  - Urgency, Coercion, and Psychological Manipulation Cues
  - Suspicious URLs and Link Obfuscation
"""

import re
from urllib.parse import urlparse

# Threat detection patterns
BEC_PAYMENT_PATTERNS = [
    r"\b(wire transfer|bank transfer|payment diversion|routing number|iban|swift code)\b",
    r"\b(update payment details|new bank account|invoice attached|unpaid invoice)\b",
    r"\b(remittance advice|overdue balance|vendor payment|direct deposit)\b",
    r"\b(payroll update|gift card|wire immediately|financial department)\b",
]

CREDENTIAL_HARVEST_PATTERNS = [
    r"\b(password expired|reset your password|login attempt|unauthorized access)\b",
    r"\b(verify your account|confirm your identity|security alert|account suspended)\b",
    r"\b(click here to login|sign in to review|reactivate account|mfa verification)\b",
    r"\b(microsoft 365|google workspace|outlook|onedrive|sharepoint login)\b",
]

BANKING_KYC_PATTERNS = [
    r"\b(kyc verification|pan card|aadhaar|debit card blocked|net banking)\b",
    r"\b(sbi|hdfc|icici|axis bank|rbi guidelines|mandatory kyc update)\b",
    r"\b(update kyc|bank account suspended|otp verification|credit limit)\b",
]

URGENCY_PATTERNS = [
    r"\b(urgent|immediate action required|within 24 hours|within 48 hours|act now)\b",
    r"\b(final notice|account will be deleted|legal action|strictly confidential)\b",
    r"\b(do not ignore|immediately|asap|time sensitive)\b",
]

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".click",
    ".loan", ".racing", ".live", ".fit", ".rest", ".bar",
}

URL_REGEX = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)


def extract_urls(text):
    """Extracts all HTTP/HTTPS and www URLs from body text."""
    if not text:
        return []
    return URL_REGEX.findall(text)


def analyze_urls(urls):
    """
    Examines extracted URLs for phishing indicators:
    - IP address used as hostname (e.g. http://192.168.1.1/login)
    - High-risk / disposable TLDs (.xyz, .top, etc.)
    - Suspicious keywords in path (login, verify, update, secure)
    - URL shortening services
    """
    flags = []
    shorteners = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "ow.ly"}

    for url in urls:
        parsed = urlparse(url if url.startswith("http") else f"http://{url}")
        host = parsed.netloc.lower().split(":")[0]

        # IP address check
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
            flags.append(f"Suspicious link using direct IP address instead of domain: {url[:50]}...")

        # URL Shortener check
        if host in shorteners:
            flags.append(f"Obfuscated link using URL shortener ({host}) to hide destination")

        # Suspicious TLD check
        for tld in SUSPICIOUS_TLDS:
            if host.endswith(tld):
                flags.append(f"Link points to high-risk disposable TLD ('{tld}'): {host}")

        # Sensitive keywords in path
        path_lower = parsed.path.lower()
        for kw in ["login", "signin", "verify", "secure", "update-account", "wallet", "banking"]:
            if kw in path_lower and host not in ["microsoft.com", "google.com", "apple.com", "paypal.com"]:
                flags.append(f"Link path contains sensitive action keyword ('{kw}') on third-party domain: {host}")
                break

    return flags


def classify_threat_intent(text, subject=""):
    """
    Evaluates text semantics to identify threat categories, urgency level,
    and business email compromise (BEC) signals.
    """
    combined_text = f"{subject}\n{text}".lower()
    categories = []
    cues_detected = []
    score_increment = 0

    # 1. BEC & Payment Diversion
    bec_hits = []
    for pattern in BEC_PAYMENT_PATTERNS:
        matches = re.findall(pattern, combined_text)
        if matches:
            bec_hits.extend(matches)
    if bec_hits:
        categories.append("Business Email Compromise (BEC) / Payment Diversion")
        cues_detected.append(f"Payment manipulation terms detected: {', '.join(set(bec_hits[:3]))}")
        score_increment += 30

    # 2. Credential Harvesting
    cred_hits = []
    for pattern in CREDENTIAL_HARVEST_PATTERNS:
        matches = re.findall(pattern, combined_text)
        if matches:
            cred_hits.extend(matches)
    if cred_hits:
        categories.append("Credential Harvesting / Account Takeover")
        cues_detected.append(f"Credential theft indicators found: {', '.join(set(cred_hits[:3]))}")
        score_increment += 25

    # 3. Banking & KYC Fraud
    kyc_hits = []
    for pattern in BANKING_KYC_PATTERNS:
        matches = re.findall(pattern, combined_text)
        if matches:
            kyc_hits.extend(matches)
    if kyc_hits:
        categories.append("Financial / Banking KYC Fraud")
        cues_detected.append(f"Indian banking or KYC impersonation terms: {', '.join(set(kyc_hits[:3]))}")
        score_increment += 30

    # 4. Urgency and Coercion
    urgency_hits = []
    for pattern in URGENCY_PATTERNS:
        matches = re.findall(pattern, combined_text)
        if matches:
            urgency_hits.extend(matches)
    urgency_level = "Normal"
    if urgency_hits:
        urgency_level = "High / Coercive"
        cues_detected.append(f"Artificial urgency/deadline cues: {', '.join(set(urgency_hits[:3]))}")
        score_increment += 15

    # 5. URL analysis
    urls = extract_urls(text)
    url_flags = analyze_urls(urls)

    if not categories:
        primary_threat = "General Suspicion" if score_increment > 0 else "Benign Communication"
    else:
        primary_threat = " & ".join(categories)

    return {
        "primary_threat": primary_threat,
        "categories": categories,
        "urgency_level": urgency_level,
        "cues_detected": cues_detected,
        "urls_found": urls,
        "url_flags": url_flags,
        "threat_score_boost": min(40, score_increment),
    }


if __name__ == "__main__":
    sample = (
        "Dear Vendor, please note our updated bank account details for pending invoice #8892. "
        "Execute wire transfer of $45,000 immediately within 24 hours to avoid delivery disruption."
    )
    res = classify_threat_intent(sample, "URGENT: Revised Wire Details for Invoice #8892")
    print(res)
