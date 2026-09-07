"""
header_analysis.py
-------------------
The "Email Header and Protocol Analysis Module" from the problem
statement. Parses raw .eml files (or raw header text) and extracts
forensic signals:

  - SPF / DKIM / DMARC authentication results
  - From / Return-Path / Reply-To mismatches (classic spoofing sign)
  - Lookalike domains (e.g. "paypa1.com" instead of "paypal.com")
  - The chain of Received headers (the email's relay path)
  - The earliest (originating) IP address in that chain

Uses only Python's standard library `email` module for parsing --
no paid service needed.
"""

import re
import email
import difflib
from email import policy
from email.parser import BytesParser
import tldextract

# Force tldextract to use its bundled offline domain-suffix snapshot
# instead of trying to download an updated list from the internet.
# This makes the app 100% reliable even with no/unstable wifi during
# your demo.
_tld_extractor = tldextract.TLDExtract(suffix_list_urls=())

# A small list of frequently-impersonated brands, used to catch
# lookalike/typosquatted domains. Expand this list for a real deployment.
COMMONLY_SPOOFED_BRANDS = [
    "paypal", "microsoft", "google", "amazon", "apple", "netflix",
    "facebook", "bankofamerica", "hdfcbank", "icicibank", "sbi",
]

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def parse_eml_file(filepath):
    """Load a .eml file and return a parsed email.message.Message object."""
    with open(filepath, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg


def parse_eml_bytes(raw_bytes):
    """Parse raw email bytes (e.g. from a file upload) into a message object."""
    return BytesParser(policy=policy.default).parsebytes(raw_bytes)


def get_domain(email_address):
    """Extract the domain from an email address like 'a@b.com' -> 'b.com'."""
    if not email_address or "@" not in email_address:
        return None
    return email_address.split("@")[-1].strip().rstrip(">").lower()


def extract_auth_results(msg):
    """
    Reads the 'Authentication-Results' header (added by the receiving
    mail server) to find SPF / DKIM / DMARC pass/fail results.
    """
    auth_header = msg.get("Authentication-Results", "")
    results = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}

    for mechanism in ["spf", "dkim", "dmarc"]:
        match = re.search(rf"{mechanism}=(\w+)", auth_header, re.IGNORECASE)
        if match:
            results[mechanism] = match.group(1).lower()
    return results


import ipaddress
import socket

def is_valid_ipv4(ip_str):
    """
    Validates that a string is a legitimate IPv4 address.
    Rejects software versions (e.g. 09.04.22.03), octets > 255, and octets with leading zeros.
    """
    if not ip_str or not isinstance(ip_str, str):
        return False
    parts = ip_str.split('.')
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        if len(p) > 1 and p.startswith('0'):
            return False
        val = int(p)
        if val < 0 or val > 255:
            return False
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.version == 4
    except (ValueError, AttributeError):
        return False


def is_public_ipv4(ip_str):
    """Returns True only if ip_str is a valid, globally-routable public IPv4 address."""
    if not is_valid_ipv4(ip_str):
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return not (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_reserved or
            ip_obj.is_multicast or
            ip_obj.is_link_local or
            ip_obj.is_unspecified
        )
    except Exception:
        return False


def is_private_ip(ip):
    """Legacy helper for backward compatibility."""
    return not is_public_ipv4(ip)


def extract_ips_from_received(msg):
    """
    Walks all 'Received' headers (each mail server that touched the
    message adds one, oldest at the bottom) and pulls out every legitimate IP
    address mentioned, rejecting version strings and timestamps.
    """
    received_headers = msg.get_all("Received", [])
    ip_chain = []

    for header in received_headers:
        # Prioritize IPs inside brackets [x.x.x.x] or parentheses (x.x.x.x)
        bracket_ips = re.findall(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", header)
        paren_ips = re.findall(r"\((\d{1,3}(?:\.\d{1,3}){3})\)", header)
        general_ips = IP_REGEX.findall(header)

        for candidate in bracket_ips + paren_ips + general_ips:
            if is_valid_ipv4(candidate) and candidate not in ip_chain:
                ip_chain.append(candidate)

    return ip_chain


def check_display_name_spoofing(from_header, from_domain):
    """
    Detects display-name spoofing where the display name claims to be
    a recognized entity (e.g., 'SBI Alerts', 'PayPal Security') but the
    underlying domain does not match.
    """
    if not from_header or not from_domain:
        return None

    display_name = email.utils.parseaddr(from_header)[0].lower()
    if not display_name:
        return None

    for brand in COMMONLY_SPOOFED_BRANDS:
        if brand in display_name and brand not in from_domain:
            return (
                f"Display-name spoofing detected: Sender name '{display_name}' claims to represent "
                f"'{brand}', but actual domain is '{from_domain}'"
            )
    return None


def check_domain_mismatch(msg):
    """
    Compares the domain in From: vs Return-Path: vs Reply-To:.
    Legitimate mail usually has these aligned. A mismatch is a
    classic spoofing/BEC red flag.
    """
    from_addr = msg.get("From", "")
    return_path = msg.get("Return-Path", "")
    reply_to = msg.get("Reply-To", "")

    from_domain = get_domain(email.utils.parseaddr(from_addr)[1])
    return_path_domain = get_domain(email.utils.parseaddr(return_path)[1])
    reply_to_domain = get_domain(email.utils.parseaddr(reply_to)[1]) if reply_to else None

    mismatches = []
    if from_domain and return_path_domain and from_domain != return_path_domain:
        mismatches.append(
            f"From domain ('{from_domain}') does not match Return-Path domain ('{return_path_domain}')"
        )
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        mismatches.append(
            f"Reply-To domain ('{reply_to_domain}') differs from From domain ('{from_domain}') "
            f"— replies would go somewhere other than the sender"
        )
    return mismatches, from_domain


def _normalize_lookalike_chars(text):
    """
    Attackers swap visually-similar characters to fool the eye:
    '1' for 'l', '0' for 'o', 'rn' for 'm', etc. Normalizing these
    before comparison catches tricks a plain substring check would miss
    (e.g. 'paypa1' vs 'paypal').
    """
    substitutions = {"1": "l", "0": "o", "5": "s", "3": "e", "@": "a", "rn": "m"}
    normalized = text
    for fake, real in substitutions.items():
        normalized = normalized.replace(fake, real)
    return normalized


def check_lookalike_domain(domain):
    """
    Flags domains that look like a well-known brand but aren't exactly
    that brand's real domain. Catches both:
      - substring impersonation, e.g. 'paypal-support.com'
      - character-swap typosquatting, e.g. 'paypa1-support.com'
    """
    if not domain:
        return None

    extracted = _tld_extractor(domain)
    root = extracted.domain.lower()
    normalized_root = _normalize_lookalike_chars(root)

    for brand in COMMONLY_SPOOFED_BRANDS:
        if root == brand:
            continue  # it IS the real brand domain, not a lookalike
        if brand in root or brand in normalized_root:
            return f"Domain '{domain}' resembles the brand '{brand}' but is not its real domain — likely impersonation"
        # Fuzzy check catches subtler typosquats (e.g. one-character swaps)
        similarity = difflib.SequenceMatcher(None, normalized_root, brand).ratio()
        if similarity > 0.8:
            return (f"Domain '{domain}' is a close visual match to '{brand}' "
                    f"({similarity:.0%} similar) — likely typosquatting")
    return None


def analyze_headers(msg):
    """
    Runs all checks and returns a single structured forensic result.
    """
    auth = extract_auth_results(msg)
    mismatches, from_domain = check_domain_mismatch(msg)
    lookalike_flag = check_lookalike_domain(from_domain)
    display_spoof_flag = check_display_name_spoofing(msg.get("From", ""), from_domain)
    ip_chain = extract_ips_from_received(msg)

    # Multi-layer public IP extraction:
    # 1. Direct originating headers (X-Originating-IP, X-Sender-IP)
    explicit_origin = None
    for h_name in ["X-Originating-IP", "X-Sender-IP", "X-Client-IP"]:
        raw_val = msg.get(h_name, "")
        if raw_val:
            found = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw_val)
            for f in found:
                if is_public_ipv4(f):
                    explicit_origin = f
                    break
        if explicit_origin:
            break

    # 2. Check SPF / Authentication-Results client-ip stamps
    spf_client_ip = None
    spf_headers = msg.get_all("Received-SPF", []) + [msg.get("Authentication-Results", "")]
    for sh in spf_headers:
        if not sh:
            continue
        c_match = re.search(r"client-ip=([0-9.]+)", sh, re.IGNORECASE) or re.search(r"designates\s+([0-9.]+)", sh, re.IGNORECASE)
        if c_match and is_public_ipv4(c_match.group(1)):
            spf_client_ip = c_match.group(1)
            break

    # 3. Earliest validated public IP from Received relay chain
    public_ips = [ip for ip in ip_chain if is_public_ipv4(ip)]

    # Select best candidate
    originating_ip = explicit_origin or (public_ips[-1] if public_ips else (spf_client_ip or None))

    # 4. Fallback if mail relay path was stripped/internal: Resolve sender domain IP
    if not originating_ip and from_domain:
        try:
            resolved_ip = socket.gethostbyname(from_domain)
            if is_public_ipv4(resolved_ip):
                originating_ip = resolved_ip
        except Exception:
            pass

    red_flags = []
    if auth["spf"] == "fail":
        red_flags.append("SPF check FAILED — sending server is not authorized for this domain")
    if auth["dkim"] == "fail":
        red_flags.append("DKIM check FAILED — message signature could not be verified (content may be altered or spoofed)")
    if auth["dmarc"] == "fail":
        red_flags.append("DMARC check FAILED — this message fails the domain's own anti-spoofing policy")
    red_flags.extend(mismatches)
    if lookalike_flag:
        red_flags.append(lookalike_flag)
    if display_spoof_flag:
        red_flags.append(display_spoof_flag)
    if not ip_chain:
        red_flags.append("No traceable IP found in headers — relay path may be stripped or malformed")

    # Simple 0-100 risk score based on how many red flags fired
    risk_score = min(100, len(red_flags) * 22)

    return {
        "from": msg.get("From", ""),
        "subject": msg.get("Subject", ""),
        "return_path": msg.get("Return-Path", ""),
        "reply_to": msg.get("Reply-To", ""),
        "from_domain": from_domain,
        "auth_results": auth,
        "ip_chain": ip_chain,
        "originating_ip": originating_ip,
        "red_flags": red_flags,
        "header_risk_score": risk_score,
    }


def get_body_text(msg):
    """Extracts the plain-text body from a parsed email message."""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                return part.get_content()
        return ""
    return msg.get_content()


if __name__ == "__main__":
    # Quick self-test against our two sample emails
    for label, path in [
        ("PHISHING SAMPLE", "sample_emails/phishing_sample.eml"),
        ("LEGITIMATE SAMPLE", "sample_emails/legit_sample.eml"),
    ]:
        print(f"\n{'=' * 60}\n{label}\n{'=' * 60}")
        msg = parse_eml_file(path)
        result = analyze_headers(msg)
        for key, value in result.items():
            print(f"{key}: {value}")
