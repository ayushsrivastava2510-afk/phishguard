"""
report_generator.py
-------------------
Generates court-ready, standardized Forensic Intelligence Reports in:
  1. Formal PDF format (using reportlab)
  2. Machine-readable JSON format (for SIEM/SOAR/SOC integration)

Includes Chain-of-Custody SHA-256 evidence hashing, hop-by-hop relay timeline,
threat classification, protocol authentication audit, and legal preservation notices.
"""

import io
import json
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


def generate_pdf_report(analysis_data):
    """
    Builds a professional multi-page PDF forensic report.
    Returns a BytesIO buffer containing the PDF file.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#1A202C"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#4A5568"),
        spaceAfter=12,
    )
    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#2B6CB0"),
        spaceBefore=10,
        spaceAfter=6,
        keepWithNext=True,
    )
    body_text = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#2D3748"),
    )
    bold_label = ParagraphStyle(
        "BoldLabel",
        parent=body_text,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#1A202C"),
    )
    badge_high = ParagraphStyle(
        "BadgeHigh",
        parent=styles["Normal"],
        fontSize=11,
        leading=13,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#9B2C2C"),
    )
    badge_low = ParagraphStyle(
        "BadgeLow",
        parent=styles["Normal"],
        fontSize=11,
        leading=13,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#22543D"),
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph("🛡️ PHISHGUARD CYBER FORENSICS INTELLIGENCE PLATFORM", title_style))
    story.append(Paragraph("OFFICIAL EMAIL THREAT, GEOLOCATION & INVESTIGATIVE FORENSIC REPORT", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2B6CB0"), spaceAfter=10))

    # 2. Chain of Custody & Evidence Metadata Table
    hashes = analysis_data.get("evidence_hashes", {})
    metadata_data = [
        [Paragraph("<b>Case / Evidence ID:</b>", body_text), Paragraph(analysis_data.get("case_id", "PG-2026-INC-001"), body_text)],
        [Paragraph("<b>Timestamp (UTC):</b>", body_text), Paragraph(hashes.get("timestamp_utc", "N/A"), body_text)],
        [Paragraph("<b>Evidence SHA-256:</b>", body_text), Paragraph(f"<font size='7'>{hashes.get('sha256', 'N/A')}</font>", body_text)],
        [Paragraph("<b>Evidence MD5:</b>", body_text), Paragraph(f"<font size='7'>{hashes.get('md5', 'N/A')}</font>", body_text)],
        [Paragraph("<b>File Size:</b>", body_text), Paragraph(f"{hashes.get('size_bytes', 0)} bytes", body_text)],
        [Paragraph("<b>Subject:</b>", body_text), Paragraph(str(analysis_data.get("subject", "N/A")), body_text)],
        [Paragraph("<b>Sender (From):</b>", body_text), Paragraph(str(analysis_data.get("from", "N/A")), body_text)],
    ]
    t_meta = Table(metadata_data, colWidths=[130, 400])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F7FAFC")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 10))

    # 3. Threat Assessment & Risk Score Banner
    risk_score = analysis_data.get("risk_score", 0)
    verdict = "🔴 CRITICAL / HIGH RISK" if risk_score >= 70 else ("🟠 SUSPICIOUS / ELEVATED" if risk_score >= 35 else "🟢 LIKELY LEGITIMATE")
    badge_style = badge_high if risk_score >= 70 else badge_low

    threat_summary_data = [
        [
            Paragraph("<b>Overall Fraud Risk Score:</b>", body_text),
            Paragraph(f"<b>{risk_score} / 100</b>", badge_style),
            Paragraph("<b>Threat Classification:</b>", body_text),
            Paragraph(str(analysis_data.get("threat_category", "General Phishing")), body_text),
        ],
        [
            Paragraph("<b>Attribution Profile:</b>", body_text),
            Paragraph(str(analysis_data.get("attribution_source", "Unverified Source")), body_text),
            Paragraph("<b>Urgency / Coercion:</b>", body_text),
            Paragraph(str(analysis_data.get("urgency_level", "Normal")), body_text),
        ]
    ]
    t_summary = Table(threat_summary_data, colWidths=[120, 145, 120, 145])
    t_summary.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#EDF2F7")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_summary)
    story.append(Spacer(1, 10))

    # 4. Technical Protocol Authentication Audit (SPF, DKIM, DMARC)
    story.append(Paragraph("1. Technical Protocol & Header Authentication Audit", section_heading))
    auth = analysis_data.get("auth_results", {})
    auth_data = [
        [
            Paragraph("<b>Mechanism</b>", bold_label),
            Paragraph("<b>Status</b>", bold_label),
            Paragraph("<b>Diagnostic Finding</b>", bold_label),
        ],
        [
            Paragraph("SPF (Sender Policy Framework)", body_text),
            Paragraph(f"<b>{auth.get('spf', 'unknown').upper()}</b>", body_text),
            Paragraph("Sending IP authorization against sender domain DNS policy", body_text),
        ],
        [
            Paragraph("DKIM (DomainKeys Identified Mail)", body_text),
            Paragraph(f"<b>{auth.get('dkim', 'unknown').upper()}</b>", body_text),
            Paragraph("Cryptographic signature validation of message contents", body_text),
        ],
        [
            Paragraph("DMARC Alignment", body_text),
            Paragraph(f"<b>{auth.get('dmarc', 'unknown').upper()}</b>", body_text),
            Paragraph("Domain enforcement policy alignment for From header", body_text),
        ],
    ]
    t_auth = Table(auth_data, colWidths=[160, 90, 280])
    t_auth.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(t_auth)
    story.append(Spacer(1, 10))

    # 5. Origin Traceability & Geolocation Intelligence
    story.append(Paragraph("2. Origin Traceability & Geolocation Intelligence", section_heading))
    geo = analysis_data.get("geolocation", {})
    dns_intel = analysis_data.get("dns_intelligence", {})
    whois_info = analysis_data.get("domain_age", {})

    origin_data = [
        [
            Paragraph("<b>Originating IP:</b>", body_text),
            Paragraph(str(analysis_data.get("originating_ip", "N/A")), body_text),
            Paragraph("<b>Estimated Location:</b>", body_text),
            Paragraph(f"{geo.get('city', 'Unknown')}, {geo.get('region', '')}, {geo.get('country', 'Unknown')}", body_text),
        ],
        [
            Paragraph("<b>ISP / Autonomous System:</b>", body_text),
            Paragraph(f"{geo.get('isp', 'N/A')} ({geo.get('asn', 'N/A')})", body_text),
            Paragraph("<b>Infrastructure Type:</b>", body_text),
            Paragraph("Hosting/Cloud Node" if geo.get("is_hosting_provider") else ("Proxy/VPN Service" if geo.get("is_likely_proxy_or_vpn") else "Standard Mail Node"), body_text),
        ],
        [
            Paragraph("<b>Domain Age (WHOIS):</b>", body_text),
            Paragraph(f"{whois_info.get('age_days', 'N/A')} days old ({whois_info.get('creation_date', 'Unknown')[:10]})", body_text),
            Paragraph("<b>Registrar:</b>", body_text),
            Paragraph(str(whois_info.get("registrar", "N/A")), body_text),
        ],
    ]
    t_origin = Table(origin_data, colWidths=[125, 140, 125, 140])
    t_origin.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F7FAFC")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(t_origin)
    story.append(Spacer(1, 10))

    # 6. SMTP Relay Hop Reconstruction
    hops = analysis_data.get("relay_hops", [])
    if hops:
        story.append(Paragraph("3. SMTP Relay Transmission Path (Hop-by-Hop Reconstruction)", section_heading))
        hop_rows = [
            [
                Paragraph("<b>Hop #</b>", bold_label),
                Paragraph("<b>Transmission Node Role</b>", bold_label),
                Paragraph("<b>Relay Host / IP</b>", bold_label),
                Paragraph("<b>Timestamp (Extracted)</b>", bold_label),
            ]
        ]
        for h in hops:
            hop_rows.append([
                Paragraph(str(h.get("hop_number", "")), body_text),
                Paragraph(str(h.get("role", "")), body_text),
                Paragraph(f"{h.get('from_host', 'N/A')} ({h.get('ip', 'N/A')})", body_text),
                Paragraph(str(h.get("timestamp", "N/A"))[:28], body_text),
            ])
        t_hops = Table(hop_rows, colWidths=[40, 140, 200, 150])
        t_hops.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 2),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ]))
        story.append(t_hops)
        story.append(Spacer(1, 10))

    # 7. Red Flags & Forensic Indicators of Compromise (IOCs)
    all_flags = analysis_data.get("red_flags", [])
    if all_flags:
        story.append(Paragraph("4. Forensic Findings & Indicators of Compromise (IOCs)", section_heading))
        for flag in all_flags:
            story.append(Paragraph(f"• {flag}", body_text))
            story.append(Spacer(1, 2))
        story.append(Spacer(1, 8))

    # 8. Legal Disclaimer and Evidentiary Declaration
    story.append(Spacer(1, 8))
    legal_text = (
        "<b>LEGAL & FORENSIC PRESERVATION NOTICE:</b> This document constitutes a preliminary technical forensic "
        "intelligence summary produced by PhishGuard for cyber incident response, institutional security auditing, "
        "and investigative coordination with Law Enforcement Agencies (LEAs / CERT-In). Cryptographic hashes recorded above "
        "verify evidence authenticity at time of ingestion in accordance with digital chain-of-custody standards."
    )
    story.append(Paragraph(legal_text, ParagraphStyle("Legal", parent=body_text, fontSize=7, leading=9, textColor=colors.HexColor("#718096"))))

    doc.build(story)
    buffer.seek(0)
    return buffer


def generate_json_report(analysis_data):
    """Generates an indented JSON string formatted for SIEM/SOAR ingestion."""
    clean_data = {}
    for k, v in analysis_data.items():
        if isinstance(v, (str, int, float, bool, list, dict, type(None))):
            clean_data[k] = v
        else:
            clean_data[k] = str(v)
    return json.dumps(clean_data, indent=2)


if __name__ == "__main__":
    sample_data = {
        "case_id": "PG-2026-DEMO-001",
        "subject": "URGENT: Verify Payment Details",
        "from": "accounting@paypa1-support.com",
        "risk_score": 88,
        "threat_category": "Business Email Compromise (BEC)",
        "attribution_source": "Anonymized / Proxy Attack Infrastructure",
        "urgency_level": "High / Coercive",
        "originating_ip": "45.155.204.12",
        "auth_results": {"spf": "fail", "dkim": "fail", "dmarc": "fail"},
        "geolocation": {"city": "Frankfurt", "region": "Hesse", "country": "Germany", "isp": "Cloud Hosting LLC", "is_hosting_provider": True},
        "domain_age": {"age_days": 12, "creation_date": "2026-08-20", "registrar": "NameCheap Inc"},
        "evidence_hashes": {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size_bytes": 1024, "timestamp_utc": "2026-09-04 12:00:00 UTC"},
        "relay_hops": [{"hop_number": 1, "role": "Earliest Originating Node", "from_host": "mail.attacker.com", "ip": "45.155.204.12", "timestamp": "Fri, 4 Sep 2026 11:59:00 +0000"}],
        "red_flags": ["SPF check FAILED", "Domain resembles 'paypal' (lookalike)", "IP belongs to cloud hosting provider"],
    }

    pdf_buf = generate_pdf_report(sample_data)
    with open("test_report.pdf", "wb") as f:
        f.write(pdf_buf.read())
    print("Test PDF successfully created: test_report.pdf")
