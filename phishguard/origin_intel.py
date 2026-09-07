"""
origin_intel.py
----------------
The "Origin Traceability and Location Analysis" + basic "Domain
Intelligence" components from the problem statement.

Uses only FREE services, no API key required:
  - ip-api.com          -> free IP geolocation (45 requests/min limit,
                            no signup, non-commercial use)
  - Python's dns module -> free MX/SPF/DMARC DNS record lookups
  - python-whois        -> free WHOIS domain registration lookups

IMPORTANT: these functions need internet access to work (they query
live public services). They will work fine on your laptop / at the
hackathon venue. Every function fails gracefully (returns "unknown"
values) if there's no internet, so the app never crashes if wifi
drops during your demo -- it just shows less detail.
"""

import requests
import dns.resolver
import whois


def is_valid_ipv4_address(ip):
    if not ip or not isinstance(ip, str):
        return False
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or (len(p) > 1 and p.startswith('0')) or not (0 <= int(p) <= 255):
            return False
    return True


def geolocate_ip(ip_address, timeout=3):
    """
    Free IP geolocation lookup via ip-api.com (no key needed).
    Returns country, region, city, ISP, and whether it looks like a
    hosting/proxy/VPN provider (a common sign of malicious infra).
    """
    if not ip_address:
        return {"status": "no_ip", "note": "No IP address provided"}

    if not is_valid_ipv4_address(ip_address):
        return {"status": "invalid_ip", "note": f"'{ip_address}' is not a valid IPv4 address"}

    # Don't bother looking up private/internal IPs (e.g. 10.x, 192.168.x)
    if ip_address.startswith(("10.", "192.168.", "172.16.", "127.", "0.")):
        return {"status": "private_ip", "note": "Internal/private network address, not publicly traceable"}

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip_address}",
            params={"fields": "status,message,country,regionName,city,isp,org,as,proxy,hosting,lat,lon"},
            timeout=timeout,
        )
        try:
            data = resp.json()
        except ValueError:
            return {"status": "error", "note": "Geolocation service returned an unexpected response (check internet connection)"}

        if data.get("status") != "success":
            return {"status": "lookup_failed", "note": data.get("message", "unknown error")}

        return {
            "status": "success",
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": data.get("as"),
            "is_likely_proxy_or_vpn": data.get("proxy", False),
            "is_hosting_provider": data.get("hosting", False),
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
        }
    except requests.exceptions.RequestException as e:
        return {"status": "error", "note": f"Could not reach geolocation service: {e}"}


def check_domain_dns_records(domain, timeout=3):
    """
    Checks whether a domain has valid SPF and DMARC DNS records set up
    at all. A domain with NO SPF/DMARC record configured is easier to
    spoof -- this is domain-level infrastructure intelligence,
    independent of any single email's headers.
    """
    result = {"has_spf_record": False, "has_dmarc_record": False, "mx_records": []}
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        try:
            txt_records = resolver.resolve(domain, "TXT")
            for record in txt_records:
                if "v=spf1" in str(record):
                    result["has_spf_record"] = True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass

        try:
            dmarc_records = resolver.resolve(f"_dmarc.{domain}", "TXT")
            for record in dmarc_records:
                if "v=DMARC1" in str(record):
                    result["has_dmarc_record"] = True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass

        try:
            mx_records = resolver.resolve(domain, "MX")
            result["mx_records"] = [str(r.exchange) for r in mx_records]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass

    except Exception as e:
        result["error"] = str(e)

    return result


def check_domain_age(domain, timeout=5):
    """
    WHOIS lookup for domain registration date. Freshly-registered
    domains (days or weeks old) are a strong phishing indicator --
    attackers often spin up new lookalike domains for each campaign.
    """
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return {"status": "unknown", "note": "No creation date found in WHOIS record"}

        from datetime import datetime
        if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo is not None:
            creation_date = creation_date.replace(tzinfo=None)
        age_days = (datetime.now() - creation_date).days

        return {
            "status": "success",
            "creation_date": str(creation_date),
            "age_days": age_days,
            "is_recently_registered": age_days < 90,  # under 3 months = suspicious
            "registrar": w.registrar,
        }
    except Exception as e:
        return {"status": "error", "note": f"WHOIS lookup failed: {e}"}


def resolve_domain_ip(domain, timeout=3):
    """
    Fallback resolver: if no transmission Received: IP was extracted
    (e.g., email audited directly from webmail client UI without raw headers),
    resolves the sender domain's A-record or primary MX gateway IP.
    """
    if not domain or not isinstance(domain, str):
        return None, None

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    # 1. Try sender domain's web/host server (DNS A-record)
    try:
        answers = resolver.resolve(domain, "A")
        for r in answers:
            addr = str(r.address)
            if is_valid_ipv4_address(addr) and not addr.startswith(("10.", "192.168.", "172.16.", "127.", "0.")):
                return addr, "Domain Host Server (DNS A-Record)"
    except Exception:
        pass

    # 2. Try primary MX mail exchange server
    try:
        answers = resolver.resolve(domain, "MX")
        if answers:
            sorted_mx = sorted(answers, key=lambda r: r.preference)
            for r in sorted_mx:
                mx_host = str(r.exchange).rstrip(".")
                try:
                    mx_answers = resolver.resolve(mx_host, "A")
                    for ma in mx_answers:
                        m_addr = str(ma.address)
                        if is_valid_ipv4_address(m_addr) and not m_addr.startswith(("10.", "192.168.", "172.16.", "127.", "0.")):
                            return m_addr, f"Primary Mail Gateway ({mx_host})"
                except Exception:
                    continue
    except Exception:
        pass

    return None, None


def analyze_origin(ip_address, domain):
    """
    Combines IP geolocation + domain DNS intelligence + WHOIS age
    into one forensic summary, with additional red flags.
    If ip_address is not found in transmission headers (e.g., direct webmail audit),
    resolves the sender domain's physical gateway IP via DNS.
    """
    resolution_source = "Extracted from Transmission Header (Received: hop)"
    resolved_ip = ip_address

    if not resolved_ip and domain:
        fallback_ip, src = resolve_domain_ip(domain)
        if fallback_ip:
            resolved_ip = fallback_ip
            resolution_source = src

    geo = geolocate_ip(resolved_ip) if resolved_ip else {"status": "no_ip"}
    if geo.get("status") == "success":
        geo["resolution_source"] = resolution_source
        geo["resolved_ip"] = resolved_ip

    dns_info = check_domain_dns_records(domain) if domain else {}
    whois_info = check_domain_age(domain) if domain else {}

    red_flags = []
    if geo.get("is_likely_proxy_or_vpn"):
        red_flags.append("Sending IP is associated with a known proxy/VPN service — origin may be masked")
    if geo.get("is_hosting_provider"):
        red_flags.append("Sending IP belongs to a cloud/hosting provider, not a typical mail server — common for attacker infrastructure")
    if dns_info and not dns_info.get("has_spf_record"):
        red_flags.append("Sender domain has NO SPF record configured — easy to spoof")
    if dns_info and not dns_info.get("has_dmarc_record"):
        red_flags.append("Sender domain has NO DMARC policy configured — no protection against impersonation")
    if whois_info.get("is_recently_registered"):
        red_flags.append(f"Sender domain was registered only {whois_info.get('age_days')} days ago — common with disposable phishing domains")

    return {
        "origin_ip": resolved_ip,
        "geolocation": geo,
        "dns_intelligence": dns_info,
        "domain_age": whois_info,
        "origin_red_flags": red_flags,
    }


if __name__ == "__main__":
    # Quick manual test (needs internet access to actually resolve)
    print("Testing geolocation for 8.8.8.8 (Google DNS, known-good IP)...")
    print(geolocate_ip("8.8.8.8"))

    print("\nTesting DNS intelligence for google.com...")
    print(check_domain_dns_records("google.com"))
