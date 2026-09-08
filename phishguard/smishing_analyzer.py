"""
smishing_analyzer.py
--------------------
Mobile SMS Phishing (Smishing) Threat Defense & Telemetry Engine.
Engineered for PhishGuard SOC to detect mobile-targeted cyber fraud:
  - TRAI DLT (Distributed Ledger Technology) Alphanumeric Sender ID Verification
  - Malicious URL Shortener & Android APK Trojan Dropper Detection
  - Psychological Panic Cues (KYC Freeze, Electricity Cut-Off, E-Challan)
  - Sanchar Saathi (Chakshu) & National Cyber Crime (1930) Complaint Generator
"""

import re
import time
import hashlib
from datetime import datetime

# Regex pattern for TRAI DLT Compliant Alphanumeric Headers:
# Format: 2-letter operator prefix + hyphen + 6-character entity code (e.g. AX-SBINB, VK-HDFCBK)
TRAI_DLT_REGEX = re.compile(r"^[A-Za-z]{2}-[A-Za-z0-9]{6}$")

# Common legitimate DLT entity codes in India
VERIFIED_DLT_ENTITIES = {
    "SBINB": "State Bank of India (Net Banking)",
    "SBIINB": "State Bank of India (Core Ingress)",
    "HDFCBK": "HDFC Bank Ltd",
    "ICICIB": "ICICI Bank Ltd",
    "AXISBK": "Axis Bank Ltd",
    "PAYTMB": "Paytm Payments Bank",
    "GOVTIN": "Government of India Citizen Portal",
    "AIRTEL": "Bharti Airtel Ltd",
    "JIOINF": "Reliance Jio Infocomm",
    "AMAZON": "Amazon India Payments",
}

# Known URL Shortener Domains commonly abused in Smishing
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "is.gd", "t.co", "cutt.ly", "rb.gy", "goo.gl",
    "ow.ly", "shorturl.at", "bl.ink", "hyperurl.co", "surl.li"
}

# Suspicious domain keywords imitating institutions
IMPERSONATION_TARGETS = {
    "sbi": "State Bank of India",
    "yono": "SBI YONO Banking Portal",
    "hdfc": "HDFC Bank",
    "icici": "ICICI Bank",
    "parivahan": "MoRTH E-Challan / Parivahan",
    "echallan": "Traffic Police E-Challan System",
    "bijli": "State Electricity Board",
    "electricity": "State Electricity Distribution Corp",
    "urja": "National Power Distribution Grid",
    "pan": "Income Tax NSDL / UTIITSL Portal",
    "aadhaar": "UIDAI Aadhaar Verification",
}


def validate_sender_id(sender_id):
    """
    Validates mobile SMS sender identity against TRAI DLT regulations
    and carrier telecommunication rules.
    """
    sid = str(sender_id or "").strip()
    result = {
        "raw_sender": sid,
        "is_dlt_compliant": False,
        "sender_type": "Unknown",
        "operator_circle": "N/A",
        "entity_name": "Unregistered / Private Sender",
        "risk_boost": 0,
        "red_flags": [],
    }

    if not sid:
        result["red_flags"].append("Missing Sender Identifier in transmission headers.")
        result["risk_boost"] += 20
        return result

    # Check TRAI DLT Compliant Alphanumeric Header (e.g., AD-HDFCBK, AX-SBINB)
    if TRAI_DLT_REGEX.match(sid):
        prefix, entity_code = sid.split("-")
        result["is_dlt_compliant"] = True
        result["sender_type"] = "TRAI DLT Registered Commercial Header"
        result["operator_circle"] = prefix.upper()

        code_upper = entity_code.upper()
        if code_upper in VERIFIED_DLT_ENTITIES:
            result["entity_name"] = VERIFIED_DLT_ENTITIES[code_upper]
        else:
            result["entity_name"] = f"Registered Entity ({code_upper})"
        return result

    # Check 10-digit Indian Mobile Number (Personal SIM used for Commercial SMS)
    digits = re.sub(r"[^\d]", "", sid)
    if (len(digits) == 10 and digits[0] in "6789") or (len(digits) == 12 and digits.startswith("91")):
        result["is_dlt_compliant"] = False
        result["sender_type"] = "Personal 10-Digit Mobile SIM (Unauthenticated Carrier Channel)"
        result["entity_name"] = f"Private SIM (+91-{digits[-10:]})"
        result["risk_boost"] += 45
        result["red_flags"].append(
            "Regulatory Violation: Commercial/Banking SMS dispatched from a personal 10-digit mobile number instead of a registered TRAI DLT header."
        )
        return result

    # Check International Virtual Number (+1, +44, +62, etc.)
    if sid.startswith("+") and not sid.startswith("+91"):
        country = "International (Virtual/VOIP)"
        if sid.startswith("+62"):
            country = "Indonesia (+62)"
        elif sid.startswith("+1"):
            country = "USA / Canada (+1)"
        elif sid.startswith("+44"):
            country = "United Kingdom (+44)"
        elif sid.startswith("+84"):
            country = "Vietnam (+84)"
        elif sid.startswith("+880"):
            country = "Bangladesh (+880)"

        result["is_dlt_compliant"] = False
        result["sender_type"] = f"Cross-Border Virtual Number ({country})"
        result["entity_name"] = f"International Route ({sid})"
        result["risk_boost"] += 50
        result["red_flags"].append(
            f"Suspicious Origin: Dispatched from cross-border mobile route {country}, commonly rented for organized bulk smishing campaigns."
        )
        return result

    # Non-compliant alphanumeric header (spoofed without hyphen or improper length)
    result["is_dlt_compliant"] = False
    result["sender_type"] = "Unregistered Custom Sender Header"
    result["entity_name"] = f"Non-DLT Header ({sid})"
    result["risk_boost"] += 35
    result["red_flags"].append("Unverified Sender Header: Does not conform to TRAI DLT alphanumeric header standards.")
    return result


def extract_and_analyze_urls(text):
    """
    Extracts URLs from SMS text, detects URL shorteners, checks for
    malicious Android APK trojan droppers, and identifies lookalike domains.
    """
    urls_found = re.findall(r"(?:https?://|www\.)[^\s]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}/[^\s]*", text)
    analysis = {
        "urls": urls_found,
        "has_urls": len(urls_found) > 0,
        "shortened_urls": [],
        "apk_droppers": [],
        "impersonated_entities": [],
        "risk_boost": 0,
        "red_flags": [],
    }

    for raw_url in urls_found:
        url_clean = raw_url.lower().rstrip(".,;!?:")

        # 1. Detect URL Shorteners
        for shortener in URL_SHORTENERS:
            if shortener in url_clean:
                analysis["shortened_urls"].append(raw_url)
                analysis["risk_boost"] += 25
                analysis["red_flags"].append(
                    f"Obfuscated Shortened Link: <code>{shortener}</code> obscures the ultimate malicious destination."
                )
                break

        # 2. Detect Android APK Trojan Droppers
        if ".apk" in url_clean or url_clean.endswith(".zip"):
            analysis["apk_droppers"].append(raw_url)
            analysis["risk_boost"] += 50
            analysis["red_flags"].append(
                f"🚨 Malicious Android Dropper: Link directs to an unverified <code>.apk</code> payload (Banking Trojan installer)."
            )

        # 3. Detect Impersonated Brands in Link
        for keyword, target_name in IMPERSONATION_TARGETS.items():
            if keyword in url_clean:
                # Ensure it's not the authentic official root
                if not any(auth in url_clean for auth in ["onlinesbi.sbi", "hdfcbank.com", "icicibank.com", "parivahan.gov.in"]):
                    analysis["impersonated_entities"].append(target_name)
                    analysis["risk_boost"] += 30
                    analysis["red_flags"].append(
                        f"Lookalike Domain: URL contains <code>'{keyword}'</code> imitating <b>{target_name}</b> on an unverified domain."
                    )
                    break

    return analysis


def classify_sms_intent(text, sender_id):
    """
    Classifies the social engineering intent and psychological urgency
    mechanisms within the SMS text.
    """
    text_lower = text.lower()
    cues_detected = []
    category = "General Communication"
    urgency_level = "Normal"
    risk_boost = 0

    # 1. Banking / YONO KYC Suspension Panic
    if any(k in text_lower for k in ["kyc", "pan card", "aadhaar", "yono", "debit card block", "account suspend", "account close", "sbi"]):
        cues_detected.append("Banking KYC Account Suspension Coercion")
        category = "Financial / Banking KYC Fraud"
        urgency_level = "Critical"
        risk_boost += 35

    # 2. Electricity Bill Power Disconnection Threat
    elif any(k in text_lower for k in ["electricity", "power will be disconnect", "power office", "bill update", "line cut", "tonight 9:30"]):
        cues_detected.append("Essential Utility (Electricity) Cut-off Intimidation")
        category = "Utility & Electricity Disconnection Scam"
        urgency_level = "Critical"
        risk_boost += 40

    # 3. Traffic E-Challan / Court Summons
    elif any(k in text_lower for k in ["challan", "parivahan", "traffic police", "vehicle fine", "court summon"]):
        cues_detected.append("Government Penalty & Legal Intimidation")
        category = "Traffic E-Challan Malware Dropper"
        urgency_level = "High"
        risk_boost += 35

    # 4. Part-time Job / VIP Task Fraud
    elif any(k in text_lower for k in ["earn daily", "part-time job", "part time job", "work from home", "review hotel", "like youtube", "telegram vip", "daily income"]):
        cues_detected.append("Work-From-Home Task Investment Fraud")
        category = "Part-Time Job / Task Investment Scam"
        urgency_level = "Medium"
        risk_boost += 30

    # 5. Legitimate Transactional OTP or Debit Alert
    elif any(k in text_lower for k in ["is your otp", "one time password", "debited by", "credited with", "txn of inr", "card ending"]):
        cues_detected.append("Authentic Transactional / OTP Pattern")
        category = "Transactional Banking Alert"
        urgency_level = "Normal"
        risk_boost = 0

    # Urgency cues check
    if any(u in text_lower for u in ["urgent", "immediately", "today", "tonight", "within 24 hours", "last notice", "final warning"]):
        cues_detected.append("Artificial Time-Pressure Constraint")
        risk_boost += 15

    return {
        "primary_category": category,
        "urgency_level": urgency_level,
        "cues_detected": cues_detected,
        "intent_risk_boost": risk_boost,
    }


def generate_chakshu_complaint_draft(smishing_record):
    """
    Generates a structured complaint template formatted for immediate submission
    to the Department of Telecommunications (DoT) Sanchar Saathi Chakshu Portal
    and the National Cyber Crime Reporting Portal (1930 / cybercrime.gov.in).
    """
    sid = smishing_record["sender_info"]["raw_sender"]
    cat = smishing_record["threat_category"]
    body = smishing_record["raw_message"]
    score = smishing_record["risk_score"]
    case_id = smishing_record["case_id"]
    timestamp = smishing_record["timestamp"]

    draft = (
        f"INCIDENT REPORT FOR Sanchar Saathi (Chakshu) & National Cyber Crime Helpline (1930)\n"
        f"Generated by PhishGuard Autonomous SOC Sentinel\n"
        f"--------------------------------------------------------------------------------\n"
        f"Reference Case Tracking ID : {case_id}\n"
        f"Detection Timestamp        : {timestamp}\n"
        f"Assessed Risk Score        : {score} / 100 (HIGH SEVERITY SMISHING)\n"
        f"Offending Sender ID / SIM  : {sid}\n"
        f"Incident Category          : {cat}\n"
        f"TRAI DLT Compliance Status : {'VIOLATION (Unauthenticated Route)' if not smishing_record['sender_info']['is_dlt_compliant'] else 'Registered Header Abuse'}\n\n"
        f"Extracted Malicious URLs / Indicators:\n"
    )
    for u in smishing_record["url_info"].get("urls", []):
        draft += f"  - Malicious Link: {u}\n"

    draft += (
        f"\nRaw Message Body Evidence:\n"
        f'"{body}"\n\n'
        f"Forensic Findings:\n"
    )
    for rf in smishing_record["all_red_flags"]:
        clean_rf = re.sub(r"<[^>]+>", "", rf)
        draft += f"  * {clean_rf}\n"

    draft += (
        f"\nRequested Law Enforcement Actions:\n"
        f"  1. Immediate IMEI/SIM suspension of {sid} via DoT Chakshu telecom registry.\n"
        f"  2. Takedown of associated phishing domains and redirection shorteners.\n"
        f"  3. Blocking of inbound SMS delivery across telecom operator SMSCs.\n"
    )
    return draft


def analyze_smishing_message(sender_id, message_text):
    """
    Executes the multi-layer Smishing inspection pipeline and returns
    comprehensive telemetry, risk score, and containment actions.
    """
    sender_res = validate_sender_id(sender_id)
    url_res = extract_and_analyze_urls(message_text)
    intent_res = classify_sms_intent(message_text, sender_id)

    # Calculate Composite Smishing Risk Score
    composite_score = sender_res["risk_boost"] + url_res["risk_boost"] + intent_res["intent_risk_boost"]

    # If sender is authentic DLT and intent is purely transactional OTP, clamp to low safe risk
    if sender_res["is_dlt_compliant"] and "Transactional" in intent_res["primary_category"] and not url_res["shortened_urls"] and not url_res["apk_droppers"]:
        composite_score = min(composite_score, 12)
    elif sender_res["risk_boost"] >= 45 and (url_res["shortened_urls"] or url_res["apk_droppers"]):
        # Personal SIM + shortened link or APK dropper is almost definitively malicious
        composite_score = max(composite_score, 88)

    final_score = max(5, min(100, composite_score))

    # Determine Verdict
    if final_score >= 70:
        verdict = "CRITICAL SMISHING THREAT"
        badge_cls = "badge-critical"
        action_msg = "⛔ DANGER: DO NOT CLICK LINKS, DO NOT CALL NUMBERS, AND NEVER INSTALL SUGGESTED APKS."
    elif final_score >= 35:
        verdict = "SUSPICIOUS / ELEVATED RISK"
        badge_cls = "badge-suspicious"
        action_msg = "⚠️ PROCEED WITH CAUTION: Unverified communication route; verify via official bank app."
    else:
        verdict = "VERIFIED SAFE SMS"
        badge_cls = "badge-clean"
        action_msg = "✅ VERIFIED SAFE: Dispatched via registered TRAI DLT commercial entity; standard alert."

    all_flags = sender_res["red_flags"] + url_res["red_flags"]
    for cue in intent_res["cues_detected"]:
        if "Authentic" not in cue:
            all_flags.append(f"Social Engineering: {cue}")

    case_id = f"SMS-2026-{int(time.time()) % 100000:05d}"
    sha256_hash = hashlib.sha256(f"{sender_id}:{message_text}".encode("utf-8")).hexdigest()

    record = {
        "case_id": case_id,
        "channel": "Mobile SMS (GSM/LTE Telemetry)",
        "sender_id": sender_res["raw_sender"],
        "sender_info": sender_res,
        "raw_message": message_text,
        "risk_score": final_score,
        "verdict": verdict,
        "badge_cls": badge_cls,
        "action_msg": action_msg,
        "threat_category": intent_res["primary_category"],
        "urgency_level": intent_res["urgency_level"],
        "url_info": url_res,
        "all_red_flags": all_flags,
        "evidence_hash": sha256_hash,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S IST"),
    }
    record["chakshu_draft"] = generate_chakshu_complaint_draft(record)
    return record


# --------------------------------------------------------------------
# 5 Built-in Real-World Smishing Demonstration Benchmark Scenarios
# --------------------------------------------------------------------
SMISHING_BENCHMARKS = [
    {
        "id": "sbi_kyc_sms",
        "title": "🚨 Scenario 1: SBI YONO Account Suspension",
        "sender_id": "+91 98234 11223",
        "text": "Dear SBI Customer, your YONO account is blocked today due to pending KYC. Please update your PAN Card immediately to avoid account closure: bit.ly/sbi-yono-kyc-update",
        "description": "Personal 10-digit SIM imitating SBI with an obfuscated bit.ly link harvesting banking credentials.",
    },
    {
        "id": "electricity_sms",
        "title": "🚨 Scenario 2: Electricity Bill Disconnection Panic",
        "sender_id": "+91 91234 56789",
        "text": "Dear Consumer, your electricity power will be disconnected tonight at 9:30 PM from the power office because your previous month bill was not updated. Please immediately call power officer at 9123456789.",
        "description": "High-pressure psychological coercion threat claiming urgent power cut-off with a fraudulent helpline number.",
    },
    {
        "id": "echallan_apk_sms",
        "title": "🚨 Scenario 3: Traffic E-Challan APK Trojan Dropper",
        "sender_id": "+91 87654 32109",
        "text": "Traffic Police Notice: An unpaid challan of INR 1,500 is pending against vehicle DL14CX1234. Pay immediately to avoid court summons. Download mParivahan app: http://echallan-parivahan.in/Parivahan_Update.apk",
        "description": "Government vehicle penalty scam delivering a direct Android .apk banking trojan dropper payload.",
    },
    {
        "id": "job_scam_sms",
        "title": "⚠️ Scenario 4: Part-Time Telegram Task Fraud",
        "sender_id": "+62 812 3456 7890",
        "text": "Part-Time Job Offer: Earn INR 2,500 to INR 5,000 daily working 30 mins from home by reviewing hotels and YouTube videos. Contact VIP HR Manager on Telegram: t.me/VipHotelTasks77",
        "description": "Cross-border virtual number from Indonesia (+62) pushing task-based crypto and advance-fee investment fraud.",
    },
    {
        "id": "legit_otp_sms",
        "title": "🟢 Scenario 5: Verified Bank Transaction OTP (Safe)",
        "sender_id": "AD-HDFCBK",
        "text": "847291 is your OTP for purchase of INR 2,499.00 at FLIPKART using HDFC Bank Credit Card ending 7041. Valid for 10 mins. Do not share OTP with anyone. Bank never calls for OTP.",
        "description": "Authentic transactional SMS compliant with TRAI DLT alphanumeric regulations (AD-HDFCBK) containing no external URLs.",
    },
]
