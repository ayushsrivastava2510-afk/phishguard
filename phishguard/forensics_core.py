"""
forensics_core.py
-----------------
Core forensic utilities for PhishGuard:
  - Cryptographic Evidence Integrity (SHA-256, MD5 hashing)
  - Detailed Hop-by-Hop SMTP Relay Path Reconstruction
  - Privacy Safeguards & PII (Personally Identifiable Information) Redaction
  - Source Threat Actor Infrastructure Attribution Classifier
"""

import re
import hashlib
from datetime import datetime

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def compute_evidence_hashes(raw_bytes):
    """
    Computes SHA-256 and MD5 cryptographic hashes of raw email bytes
    for chain-of-custody evidence preservation and legal integrity.
    """
    if not raw_bytes:
        return {"sha256": "N/A", "md5": "N/A", "timestamp_utc": datetime.utcnow().isoformat() + "Z"}

    sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
    md5_hash = hashlib.md5(raw_bytes).hexdigest()

    return {
        "sha256": sha256_hash,
        "md5": md5_hash,
        "size_bytes": len(raw_bytes),
        "timestamp_utc": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }


def parse_relay_hops(msg):
    """
    Extracts structured hop-by-hop relay timeline from 'Received' headers.
    Headers are ordered chronologically from earliest (origin) to latest (destination).
    """
    received_headers = msg.get_all("Received", [])
    if not received_headers:
        return []

    hops = []
    # Received headers in email files are stacked in reverse: top = newest, bottom = oldest
    # We reverse them so Hop 1 is the earliest originating server.
    chronological_headers = list(reversed(received_headers))

    for idx, header in enumerate(chronological_headers, start=1):
        # Clean up whitespace
        clean_header = " ".join(header.split())

        # Extract 'from' host
        from_match = re.search(r"from\s+([^\s;]+)", clean_header, re.IGNORECASE)
        from_host = from_match.group(1) if from_match else "Unknown Host"

        # Extract 'by' host
        by_match = re.search(r"by\s+([^\s;]+)", clean_header, re.IGNORECASE)
        by_host = by_match.group(1) if by_match else "Unknown Receiver"

        # Extract legitimate IPs (ignore version strings like 09.04.22.03)
        bracket_ips = re.findall(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", clean_header)
        paren_ips = re.findall(r"\((\d{1,3}(?:\.\d{1,3}){3})\)", clean_header)
        general_ips = IP_REGEX.findall(clean_header)
        ip_addr = None
        for cand in bracket_ips + paren_ips + general_ips:
            # Inline octet validation for IPv4
            parts = cand.split('.')
            if len(parts) == 4 and all(p.isdigit() and (len(p) == 1 or not p.startswith('0')) and 0 <= int(p) <= 255 for p in parts):
                ip_addr = cand
                break

        # Extract timestamp if present at the end of the header (after ;)
        timestamp_str = "N/A"
        if ";" in clean_header:
            raw_time = clean_header.split(";")[-1].strip()
            timestamp_str = raw_time[:35]

        # Protocol / mechanism
        proto_match = re.search(r"with\s+([^\s;]+)", clean_header, re.IGNORECASE)
        protocol = proto_match.group(1) if proto_match else "SMTP"

        hops.append({
            "hop_number": idx,
            "role": "Earliest Originating Node" if idx == 1 else ("Final Receiving MX" if idx == len(chronological_headers) else "Intermediate Relay"),
            "from_host": from_host,
            "by_host": by_host,
            "ip": ip_addr,
            "protocol": protocol,
            "timestamp": timestamp_str,
        })

    return hops


def redact_pii(text):
    """
    Masks sensitive Personally Identifiable Information (PII)
    such as personal email addresses, phone numbers, and account numbers
    for privacy and evidentiary compliance.
    """
    if not text:
        return ""

    # Mask email addresses (keep first and last char of username, and domain)
    def mask_email(match):
        full = match.group(0)
        user, domain = full.split("@", 1)
        if len(user) <= 2:
            masked_user = user[0] + "*"
        else:
            masked_user = user[0] + ("*" * (len(user) - 2)) + user[-1]
        return f"{masked_user}@{domain}"

    redacted = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", mask_email, text)

    # Mask Indian / International phone numbers (10+ digits)
    redacted = re.sub(
        r"(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
        r"[REDACTED PHONE]",
        redacted
    )

    # Mask 12-16 digit bank / card numbers
    redacted = re.sub(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{2,4}\b", r"[REDACTED ACCOUNT/CARD]", redacted)

    return redacted


def classify_attribution_source(auth_results, geo_info, dns_info, threat_categories):
    """
    Evaluates indicators to classify the probable infrastructure origin:
      1. Anonymized Proxy / Bulletproof Infrastructure
      2. Spoofed Domain via Unauthorized Relay
      3. Compromised Legitimate Mailbox (BEC)
      4. Direct Malicious Actor Infrastructure
    """
    spf = auth_results.get("spf", "").lower()
    dkim = auth_results.get("dkim", "").lower()
    dmarc = auth_results.get("dmarc", "").lower()
    is_vpn_proxy = geo_info.get("is_likely_proxy_or_vpn", False)
    is_hosting = geo_info.get("is_hosting_provider", False)

    # Check for fully authenticated legitimate traffic first
    if spf == "pass" and dkim == "pass" and dmarc != "fail" and not threat_categories:
        return {
            "source_type": "Authorized & Verified Infrastructure (Legitimate Sender)",
            "confidence": "High (96%)",
            "explanation": "Message passed SPF, DKIM, and DMARC checks from verified sender infrastructure with no social engineering indicators.",
            "recommendation": "Normal processing. No containment or mitigation needed.",
        }

    if is_vpn_proxy and (spf == "fail" or dmarc == "fail" or threat_categories):
        return {
            "source_type": "Anonymized / Proxy Attack Infrastructure",
            "confidence": "High (88%)",
            "explanation": "Sending server is routed through a known commercial proxy, VPN, or Tor exit node designed to conceal geographic origin.",
            "recommendation": "Correlate with egress IP threat feeds and request ISP subscriber metadata via legal process.",
        }

    if (spf == "fail" or dmarc == "fail") and is_hosting:
        return {
            "source_type": "Direct Malicious Actor Infrastructure (Spoofed)",
            "confidence": "High (90%)",
            "explanation": "Email was dispatched from an unauthorized cloud/datacenter server failing SPF/DMARC authentication.",
            "recommendation": "Blacklist originating IP, report abuse to hosting provider, and enforce DMARC 'reject' policy.",
        }

    if spf == "pass" and dkim == "pass" and ("Business Email Compromise (BEC) / Payment Diversion" in threat_categories):
        return {
            "source_type": "Compromised Legitimate Account (Internal/Vendor BEC)",
            "confidence": "Moderate-High (78%)",
            "explanation": "SPF and DKIM cryptographic signatures passed validly, yet the message contains high-confidence payment manipulation patterns.",
            "recommendation": "Immediately trigger credential reset, terminate active sessions, and audit mailbox forwarding rules.",
        }

    if spf == "fail" or dkim == "fail":
        return {
            "source_type": "Spoofed Domain via Unauthorized External Relay",
            "confidence": "Moderate (70%)",
            "explanation": "Sender domain authentication failed; sender address was forged at the transport layer.",
            "recommendation": "Add domain to internal quarantine list and verify incoming mail filter SPF enforcement.",
        }

    return {
        "source_type": "Standard / Direct Transmission",
        "confidence": "Normal (60%)",
        "explanation": "No overt anonymizer or authentication anomaly detected in transmission headers.",
        "recommendation": "Standard baseline monitoring.",
    }


if __name__ == "__main__":
    test_text = "Contact CEO at alice.smith@defence-corp.gov.in or call +91-9876543210. Account number 4321-5678-9012-3456."
    print("Redaction test:")
    print(redact_pii(test_text))
