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


# =========================================================================
# VERNACULAR & HINGLISH TELEMETRY PATTERNS (INDIA-SPECIFIC CYBER FRAUD)
# =========================================================================
DEVANAGARI_REGEX = re.compile(r"[\u0900-\u097F]")
TAMIL_REGEX = re.compile(r"[\u0B80-\u0BFF]")
TELUGU_REGEX = re.compile(r"[\u0C00-\u0C7F]")
BENGALI_REGEX = re.compile(r"[\u0980-\u09FF]")

# Common Hinglish (Romanized Hindi) threat tokens
HINGLISH_THREAT_KEYWORDS = {
    "bijli", "bijlee", "line cut", "kaat diya", "kat diya", "kat jayega", "kaat di jayegi",
    "power office", "bill update nahi", "aaj raat", "khata", "khaata", "band ho jayega",
    "block ho gaya", "pan card link", "pan update", "yono block", "turant link open",
    "turant", "tatkal", "tatkaal", "sampark karein", "sampark kare", "call karein",
    "adhikari", "afsar", "badhai ho", "badhai", "inaam", "inam", "lottery lag gayi",
    "raashi", "subsidy manzoor", "pm kisan", "pm awas", "claim karein", "yojana labh",
    "gaadi ka challan", "challan pending", "court summon", "police karwayi", "jurmana"
}


def detect_script_and_language(text):
    """
    Identifies the script and linguistic style of the SMS text:
      - Hindi (Devanagari)
      - Hinglish (Code-mixed Romanized Hindi)
      - Tamil / Telugu / Bengali (Indic Regional)
      - English (Standard Latin)
    """
    raw = str(text or "").strip()
    if not raw:
        return {
            "detected_language": "English",
            "language_code": "en",
            "script_type": "Latin (Standard)",
            "is_vernacular": False,
            "regional_family": "Indo-European / English"
        }

    # 1. Devanagari Script (Hindi / Marathi)
    devanagari_chars = len(DEVANAGARI_REGEX.findall(raw))
    if devanagari_chars >= 3 or (devanagari_chars > 0 and len(raw) < 20):
        is_marathi = any(mw in raw for mw in ["आहे", "झाले", "करा", "नाही", "माहिती"])
        lang_title = "Marathi (Devanagari Script)" if is_marathi else "Hindi (Devanagari Script)"
        lang_code = "mr" if is_marathi else "hi"
        return {
            "detected_language": lang_title,
            "language_code": lang_code,
            "script_type": "Devanagari Script (Unicode U+0900-U+097F)",
            "is_vernacular": True,
            "regional_family": "Indo-Aryan (Official Scheduled Language)"
        }

    # 2. Other Indic Regional Scripts
    if TAMIL_REGEX.search(raw):
        return {
            "detected_language": "Tamil (தமிழ் Script)",
            "language_code": "ta",
            "script_type": "Tamil Script (Unicode U+0B80-U+0BFF)",
            "is_vernacular": True,
            "regional_family": "Dravidian (Classical Indian Language)"
        }
    if TELUGU_REGEX.search(raw):
        return {
            "detected_language": "Telugu (తెలుగు Script)",
            "language_code": "te",
            "script_type": "Telugu Script (Unicode U+0C00-U+0C7F)",
            "is_vernacular": True,
            "regional_family": "Dravidian (Classical Indian Language)"
        }
    if BENGALI_REGEX.search(raw):
        return {
            "detected_language": "Bengali (বাংলা Script)",
            "language_code": "bn",
            "script_type": "Bengali Script (Unicode U+0980-U+09FF)",
            "is_vernacular": True,
            "regional_family": "Indo-Aryan (Official Scheduled Language)"
        }

    # 3. Hinglish (Latin Script transliteration of Hindi / Regional dialects)
    text_lower = raw.lower()
    matched_hinglish = [kw for kw in HINGLISH_THREAT_KEYWORDS if kw in text_lower]
    if len(matched_hinglish) >= 1:
        return {
            "detected_language": "Hinglish (Romanized Hindi)",
            "language_code": "hinglish",
            "script_type": "Latin Script (Transliterated Vernacular)",
            "is_vernacular": True,
            "regional_family": "Code-Mixed Indo-Aryan / English"
        }

    return {
        "detected_language": "English",
        "language_code": "en",
        "script_type": "Latin (Standard)",
        "is_vernacular": False,
        "regional_family": "Standard English"
    }


def classify_sms_intent(text, sender_id):
    """
    Classifies the social engineering intent, psychological urgency
    mechanisms, and vernacular/Hinglish semantics within the SMS text.
    """
    text_lower = text.lower()
    raw_text = text
    lang_info = detect_script_and_language(text)

    cues_detected = []
    matched_vernacular_tokens = []
    category = "General Communication"
    urgency_level = "Normal"
    risk_boost = 0
    english_forensic_meaning = "Routine conversational or informational SMS message."

    # Define multilingual token lexicons
    bank_en = ["kyc", "pan card", "aadhaar", "yono", "debit card block", "account suspend", "account close", "sbi"]
    bank_hi = ["खाता ब्लॉक", "खाता बंद", "पैन कार्ड अपडेट", "केवाईसी लंबित", "योनो ब्लॉक", "तुरंत अपडेट करें", "खाता चालू", "डेबिट कार्ड ब्लॉक", "खाता निष्क्रय"]
    bank_hing = ["khata block", "khata band", "pan card link", "pan link", "kyc update", "yono block", "debit card block", "khata chalu", "turant link open", "account block ho"]

    elec_en = ["electricity", "power will be disconnect", "power office", "bill update", "line cut", "tonight 9:30"]
    elec_hi = ["बिजली बिल", "बिजली काट", "पावर कट", "लाइन कट", "बिल अपडेट", "आज रात 9:30", "बिजली अधिकारी", "पावर ऑफिस", "विद्युत", "ऊर्जा"]
    elec_hing = ["bijli", "bijlee", "line cut", "kat jayega", "kaat diya", "power office", "bill update nahi", "aaj raat 9:30", "aaj raat 9 baje", "officer ko call"]

    gov_en = ["pm kisan", "pm awas", "subsidy approved", "congratulations lottery", "prize claim", "government benefit"]
    gov_hi = ["पीएम किसान", "पीएम आवास", "सब्सिडी स्वीकृत", "बधाई हो", "लॉटरी", "इनाम", "राशि प्राप्त करें", "योजना लाभ", "सरकारी अनुदान"]
    gov_hing = ["pm kisan", "pm awas", "subsidy manzoor", "badhai ho", "lottery lag gayi", "inaam", "inam", "raashi prapt", "claim karein", "yojana labh"]

    chal_en = ["challan", "parivahan", "traffic police", "vehicle fine", "court summon"]
    chal_hi = ["ट्रैफिक पुलिस", "ई-चालान", "कोर्ट समन", "वाहन जुर्माना", "गिरफ्तारी वारंट", "तुरंत भरें", "चालान लंबित"]
    chal_hing = ["traffic police", "e-challan", "court summon", "gaadi ka challan", "gaadi challan", "jurmana", "police karwayi", "challan pending"]

    job_en = ["earn daily", "part-time job", "part time job", "work from home", "review hotel", "like youtube", "telegram vip", "daily income"]
    job_hi = ["पार्ट टाइम जॉब", "घर बैठे कमाएं", "दैनिक आय", "टेलीग्राम कार्य", "होटल रिव्यू"]
    job_hing = ["part-time job", "ghar baithe kamaye", "daily kamaye", "telegram task"]

    otp_en = ["is your otp", "one time password", "debited by", "credited with", "txn of inr", "card ending"]
    otp_hi = ["आपका ओटीपी है", "ओटीपी किसी से साझा न करें", "बैंक कभी ओटीपी नहीं मांगता", "खाते से निकाले गए"]
    otp_hing = ["aapka otp hai", "kisi ko na batayein", "otp share na karein", "bank kabhi otp nahi mangta"]

    urgency_en = ["urgent", "immediately", "act today", "pay today", "blocked today", "suspended today", "expire today", "due today", "tonight 9:30", "disconnect tonight", "within 24 hours", "within 2 hours", "last notice", "final warning"]
    urgency_hi = ["तुरंत", "तत्काल", "आज ही", "24 घंटे", "आज रात", "अंतिम चेतावनी", "समय सीमा"]
    urgency_hing = ["turant", "tatkal", "tatkaal", "aaj hi", "24 ghante", "aaj raat", "last warning", "aaj sham"]

    # 1. Banking / YONO KYC Suspension Panic
    if any(k in text_lower for k in bank_en) or any(k in raw_text for k in bank_hi) or any(k in text_lower for k in bank_hing):
        cues_detected.append("Banking KYC Account Suspension Coercion")
        category = "Financial / Banking KYC Fraud (बैंक खाता एवं केवाईसी धोखाधड़ी)"
        urgency_level = "Critical"
        risk_boost += 35
        english_forensic_meaning = "Coercive banking freeze threat: victim is told their account is suspended or blocked due to pending KYC/PAN verification."
        for tk in bank_hi:
            if tk in raw_text: matched_vernacular_tokens.append(tk)
        for tk in bank_hing:
            if tk in text_lower: matched_vernacular_tokens.append(tk)

    # 2. Electricity Bill Power Disconnection Threat
    elif any(k in text_lower for k in elec_en) or any(k in raw_text for k in elec_hi) or any(k in text_lower for k in elec_hing):
        cues_detected.append("Essential Utility (Electricity) Cut-off Intimidation")
        category = "Utility & Electricity Disconnection Scam (बिजली बिल धोखाधड़ी)"
        urgency_level = "Critical"
        risk_boost += 40
        english_forensic_meaning = "Urgent utility power cut-off scare: victim is intimidated with imminent electricity disconnection tonight unless they call or pay immediately."
        for tk in elec_hi:
            if tk in raw_text: matched_vernacular_tokens.append(tk)
        for tk in elec_hing:
            if tk in text_lower: matched_vernacular_tokens.append(tk)

    # 3. Government Scheme & Subsidy Lottery Lure
    elif any(k in text_lower for k in gov_en) or any(k in raw_text for k in gov_hi) or any(k in text_lower for k in gov_hing):
        cues_detected.append("Fake Government Scheme / Subsidy Lottery Lure")
        category = "Govt Scheme / Subsidy Impersonation (सरकारी योजना व लॉटरी प्रलोभन)"
        urgency_level = "High"
        risk_boost += 35
        english_forensic_meaning = "Advance-fee / fake government scheme subsidy approval lure harvesting personal or banking information."
        for tk in gov_hi:
            if tk in raw_text: matched_vernacular_tokens.append(tk)
        for tk in gov_hing:
            if tk in text_lower: matched_vernacular_tokens.append(tk)

    # 4. Traffic E-Challan / Police Intimidation
    elif any(k in text_lower for k in chal_en) or any(k in raw_text for k in chal_hi) or any(k in text_lower for k in chal_hing):
        cues_detected.append("Government Penalty & Legal Intimidation")
        category = "Traffic E-Challan Legal Coercion (ट्रैफिक चालान व पुलिस नोटिस)"
        urgency_level = "High"
        risk_boost += 35
        english_forensic_meaning = "Government penalty intimidation: victim is threatened with court summons or vehicle impounding over unpaid traffic challan."
        for tk in chal_hi:
            if tk in raw_text: matched_vernacular_tokens.append(tk)
        for tk in chal_hing:
            if tk in text_lower: matched_vernacular_tokens.append(tk)

    # 5. Part-Time Job / Task Investment Fraud
    elif any(k in text_lower for k in job_en) or any(k in raw_text for k in job_hi) or any(k in text_lower for k in job_hing):
        cues_detected.append("Work-From-Home Task Investment Fraud")
        category = "Part-Time Job / Task Investment Scam"
        urgency_level = "Medium"
        risk_boost += 30
        english_forensic_meaning = "Advance-fee task fraud promising daily earnings for liking videos or rating hotels via Telegram."
        for tk in job_hi:
            if tk in raw_text: matched_vernacular_tokens.append(tk)
        for tk in job_hing:
            if tk in text_lower: matched_vernacular_tokens.append(tk)

    # 6. Legitimate Transactional OTP or Debit Alert
    elif any(k in text_lower for k in otp_en) or any(k in raw_text for k in otp_hi) or any(k in text_lower for k in otp_hing):
        cues_detected.append("Authentic Transactional / OTP Pattern")
        category = "Transactional Banking Alert (प्रमाणित बैंक ओटीपी)"
        urgency_level = "Normal"
        risk_boost = 0
        english_forensic_meaning = "Standard transactional alert containing one-time authorization code with security confidentiality warnings."
        for tk in otp_hi:
            if tk in raw_text: matched_vernacular_tokens.append(tk)
        for tk in otp_hing:
            if tk in text_lower: matched_vernacular_tokens.append(tk)

    # Coercive Urgency Cues Check
    if any(u in text_lower for u in urgency_en) or any(u in raw_text for u in urgency_hi) or any(u in text_lower for u in urgency_hing):
        cues_detected.append("Artificial Time-Pressure Constraint")
        risk_boost += 15
        for tk in urgency_hi:
            if tk in raw_text: matched_vernacular_tokens.append(tk)
        for tk in urgency_hing:
            if tk in text_lower: matched_vernacular_tokens.append(tk)

    vernacular_info = {
        "detected_language": lang_info["detected_language"],
        "language_code": lang_info["language_code"],
        "script_type": lang_info["script_type"],
        "is_vernacular": lang_info["is_vernacular"],
        "regional_family": lang_info["regional_family"],
        "matched_keywords": list(dict.fromkeys(matched_vernacular_tokens)),
        "english_meaning": english_forensic_meaning,
    }

    return {
        "primary_category": category,
        "urgency_level": urgency_level,
        "cues_detected": cues_detected,
        "intent_risk_boost": risk_boost,
        "vernacular_info": vernacular_info,
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
    v_info = smishing_record.get("vernacular_info", {})
    lang_str = v_info.get("detected_language", "English")
    script_str = v_info.get("script_type", "Latin (Standard)")
    meaning_str = v_info.get("english_meaning", "N/A")
    vernacular_tokens = ", ".join(v_info.get("matched_keywords", [])) or "None (English syntax)"

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
        f"Linguistic & Vernacular Telemetry:\n"
        f"  - Detected Language / Script : {lang_str} ({script_str})\n"
        f"  - Vernacular Alarm Keywords  : {vernacular_tokens}\n"
        f"  - Plain-English Translation  : {meaning_str}\n\n"
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
    t_start = time.perf_counter()
    sender_res = validate_sender_id(sender_id)
    url_res = extract_and_analyze_urls(message_text)
    intent_res = classify_sms_intent(message_text, sender_id)
    v_info = intent_res.get("vernacular_info", {})

    # Check if this is a personal 10-digit number AND casual P2P conversation
    is_personal_p2p = (
        not sender_res["is_dlt_compliant"]
        and "Personal 10-Digit" in sender_res["sender_type"]
        and intent_res["primary_category"] == "General Communication"
        and not url_res["urls"]
        and not any(c for c in intent_res["cues_detected"] if "Coercion" in c or "Intimidation" in c or "Fraud" in c)
    )

    if is_personal_p2p:
        sender_res["sender_type"] = "Personal Contact (Private P2P SMS)"
        sender_res["risk_boost"] = 0
        sender_res["red_flags"] = []
        composite_score = 5
    else:
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
        action_msg = "✅ VERIFIED SAFE: Person-to-Person (P2P) message. Exempt from commercial DLT regulations." if is_personal_p2p else "✅ VERIFIED SAFE: Dispatched via registered TRAI DLT commercial entity; standard alert."

    all_flags = sender_res["red_flags"] + url_res["red_flags"]
    if v_info.get("is_vernacular"):
        all_flags.append(f"Vernacular Telemetry: Intercepted in <b>{v_info.get('detected_language')}</b> ({v_info.get('script_type')}).")
        all_flags.append(f"Forensic Translation: <i>\"{v_info.get('english_meaning')}\"</i>")

    for cue in intent_res["cues_detected"]:
        if "Authentic" not in cue:
            all_flags.append(f"Social Engineering: {cue}")

    # DistilBERT Transformer NLP Semantic Inference & Token Attribution
    try:
        from transformer_classifier import predict_phishing
        nlp_res = predict_phishing(message_text)
    except Exception as e:
        nlp_res = {
            "label": "unknown",
            "confidence": 0.5,
            "model_name": "DistilBERT-Base-Uncased",
            "latency_ms": 0,
            "attributions": [],
        }

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
        "vernacular_info": v_info,
        "transformer_label": nlp_res["label"],
        "transformer_confidence": nlp_res["confidence"],
        "model_name": nlp_res["model_name"],
        "nlp_latency_ms": nlp_res["latency_ms"],
        "token_attributions": nlp_res["attributions"],
        "analysis_time_s": round(time.perf_counter() - t_start, 3),
        "analysis_time_ms": round((time.perf_counter() - t_start) * 1000, 1),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S IST"),
    }
    record["chakshu_draft"] = generate_chakshu_complaint_draft(record)
    return record


# --------------------------------------------------------------------
# 7 Built-in Real-World Smishing Demonstration Benchmark Scenarios
# (Includes English, Hindi Devanagari, and Hinglish vectors)
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
        "id": "hindi_electricity_sms",
        "title": "🚨 Scenario 5: 🇮🇳 Hindi Electricity Disconnection Panic",
        "sender_id": "+91 98712 34567",
        "text": "प्रिय उपभोक्ता, आपका बिजली बिल अपडेट नहीं हुआ है। आज रात 9:30 बजे बिजली काट दी जाएगी। तुरंत बिजली अधिकारी 9871234567 पर संपर्क करें या बिल अपडेट करें: bit.ly/bijli-bill-update",
        "description": "Devanagari script electricity cut-off intimidation deployed across rural/semi-urban belts in northern & central India.",
    },
    {
        "id": "hinglish_sbi_sms",
        "title": "🚨 Scenario 6: 🗣️ Hinglish SBI KYC Account Suspension",
        "sender_id": "+91 91234 88990",
        "text": "Dear customer aapka SBI khata aaj raat 12 baje block kar diya jayega kyonki PAN card link nahi hai. Turant apna khata chalu rakhne ke liye yahan update karein: bit.ly/sbi-pan-khata",
        "description": "Code-mixed Hinglish SMS exploiting KYC panic to steal banking credentials from mobile users.",
    },
    {
        "id": "legit_otp_sms",
        "title": "🟢 Scenario 7: Verified Bank Transaction OTP (Safe)",
        "sender_id": "AD-HDFCBK",
        "text": "847291 is your OTP for purchase of INR 2,499.00 at FLIPKART using HDFC Bank Credit Card ending 7041. Valid for 10 mins. Do not share OTP with anyone. Bank never calls for OTP.",
        "description": "Authentic transactional SMS compliant with TRAI DLT alphanumeric regulations (AD-HDFCBK) containing no external URLs.",
    },
]
