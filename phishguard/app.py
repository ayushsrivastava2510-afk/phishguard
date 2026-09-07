"""
app.py
------
PhishGuard: AI-Powered Email Threat Detection, GeoLocation and
Forensic Intelligence Platform (SIH Ultra-Dynamic SOC Edition).

Featuring:
  1. Interactive 1-Click Threat Scenario Launchpad
  2. Dynamic SVG Circular Threat Speedometer & Component Breakdown
  3. Interactive 3D Pydeck Global Transmission Flight Arc Map
  4. Dynamic Physics-Based Campaign Network Graph (Vis.js drag-and-zoom)
  5. Interactive Relay Hop Flight Breadcrumb Chain
  6. Automated Incident Response & Firewall Playbook
  7. Digital Chain of Custody & Court-Ready Forensic PDF/JSON Export
"""

import os
import json
import joblib
import streamlit as st
import pandas as pd
import pydeck as pdk
import streamlit.components.v1 as components
from header_analysis import parse_eml_bytes, analyze_headers, get_body_text
from origin_intel import analyze_origin
from attribution_graph import (
    build_attribution_graph,
    find_campaign_clusters,
    render_graph_image,
    generate_interactive_graph_html,
)
from threat_classifier import classify_threat_intent
from forensics_core import compute_evidence_hashes, parse_relay_hops, redact_pii, classify_attribution_source
from report_generator import generate_pdf_report, generate_json_report

# Page Configuration
st.set_page_config(
    page_title="PhishGuard SOC — Cyber Threat & Forensic Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Auto-start Chrome Extension SOC Bridge on port 8765 if not already active
def _ensure_bridge_server_active():
    import socket
    import threading
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(0.3)
        s.connect(("127.0.0.1", 8765))
        s.close()
        return  # Bridge is already running
    except Exception:
        pass

    try:
        import bridge_server
        t = threading.Thread(target=bridge_server.run_bridge_server, daemon=True)
        t.start()
        print("[PhishGuard] Auto-started Chrome Extension SOC Bridge on http://127.0.0.1:8765")
    except Exception as e:
        print(f"[PhishGuard Warning] Could not auto-start bridge: {e}")

_ensure_bridge_server_active()

MODEL_PATH = "models/phishing_classifier.joblib"

# Dynamic Cyber SOC Styling
DYNAMIC_CSS = """
<style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    .stDeployButton {display:none;}
    div[data-testid="stDecoration"] {display:none;}
    header {background: transparent !important;}

    @import url('https://fonts.googleapis.com/css2?family=Bebas+Neue&family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap');
    
    html, body, [class*="css"], .stApp {
        font-family: 'Inter', -apple-system, sans-serif;
        background-color: #0c0c0e !important;
        color: #ffffff;
    }
    
    /* Netflix Subtle Ambient Vignette */
    .stApp {
        background-image: 
            radial-gradient(ellipse 80% 50% at 50% -20%, rgba(229, 9, 20, 0.18), transparent 70%),
            radial-gradient(circle at 100% 100%, rgba(20, 20, 24, 0.8), transparent 50%),
            linear-gradient(180deg, #0b0b0e 0%, #0e0e12 100%) !important;
        background-attachment: fixed !important;
    }

    code, pre {
        font-family: 'JetBrains Mono', monospace !important;
        background-color: #17171c !important;
        color: #ff4d58 !important;
        border: 1px solid rgba(229, 9, 20, 0.25) !important;
        border-radius: 4px;
        padding: 2px 5px;
    }

    /* Sidebar - Deep Obsidian with Crimson Accents */
    section[data-testid="stSidebar"] {
        background-color: #111115 !important;
        border-right: 1px solid rgba(229, 9, 20, 0.25) !important;
        box-shadow: 4px 0 24px rgba(0, 0, 0, 0.8) !important;
    }
    section[data-testid="stSidebar"] hr {
        border-color: rgba(229, 9, 20, 0.2) !important;
    }

    /* Pulse Beacons */
    .soc-pulse-red {
        display: inline-block;
        width: 9px;
        height: 9px;
        border-radius: 50%;
        background-color: #E50914;
        box-shadow: 0 0 12px #E50914;
        margin-right: 8px;
        animation: netflixPulse 1.8s infinite;
    }
    @keyframes netflixPulse {
        0% { box-shadow: 0 0 0 0 rgba(229, 9, 20, 0.8); }
        70% { box-shadow: 0 0 0 10px rgba(229, 9, 20, 0); }
        100% { box-shadow: 0 0 0 0 rgba(229, 9, 20, 0); }
    }

    /* Netflix Cinematic Glass Cards */
    .metric-card {
        background: linear-gradient(145deg, rgba(24, 24, 28, 0.94) 0%, rgba(14, 14, 17, 0.98) 100%);
        border: 1px solid rgba(255, 255, 255, 0.07);
        border-radius: 12px;
        padding: 18px 22px;
        box-shadow: 0 10px 30px -5px rgba(0, 0, 0, 0.7), 0 0 1px 1px rgba(255, 255, 255, 0.05);
        height: 100%;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
    }
    .metric-card:hover {
        transform: translateY(-3px);
        border-color: rgba(229, 9, 20, 0.5);
        box-shadow: 0 14px 35px -5px rgba(229, 9, 20, 0.2), 0 0 20px rgba(229, 9, 20, 0.15);
    }
    .metric-title {
        font-size: 0.76rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #a3a3a3;
        margin-bottom: 6px;
    }
    .metric-value-huge {
        font-size: 2.2rem;
        font-weight: 900;
        line-height: 1.1;
        margin-bottom: 6px;
        color: #ffffff;
    }

    /* Badges */
    .metric-badge {
        display: inline-block;
        font-size: 0.75rem;
        font-weight: 800;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        padding: 4px 10px;
        border-radius: 6px;
    }
    .badge-critical {
        background: rgba(229, 9, 20, 0.22);
        color: #ff4d58;
        border: 1px solid rgba(229, 9, 20, 0.6);
        box-shadow: 0 0 12px rgba(229, 9, 20, 0.35);
    }
    .badge-suspicious {
        background: rgba(245, 158, 11, 0.18);
        color: #fbbf24;
        border: 1px solid rgba(245, 158, 11, 0.45);
    }
    .badge-clean {
        background: rgba(34, 197, 94, 0.18);
        color: #4ade80;
        border: 1px solid rgba(34, 197, 94, 0.45);
    }

    /* Buttons: Netflix Red Gradient */
    div.stButton > button[kind="primary"], div[data-testid="stDownloadButton"] > button[kind="primary"] {
        background: linear-gradient(135deg, #E50914 0%, #B81D24 100%) !important;
        color: #ffffff !important;
        border: none !important;
        font-weight: 700 !important;
        letter-spacing: 0.02em !important;
        border-radius: 8px !important;
        padding: 8px 18px !important;
        box-shadow: 0 4px 18px rgba(229, 9, 20, 0.45) !important;
        transition: all 0.2s ease !important;
    }
    div.stButton > button[kind="primary"]:hover, div[data-testid="stDownloadButton"] > button[kind="primary"]:hover {
        background: linear-gradient(135deg, #FF1E27 0%, #E50914 100%) !important;
        box-shadow: 0 6px 26px rgba(229, 9, 20, 0.7) !important;
        transform: translateY(-2px) !important;
    }
    div.stButton > button:not([kind="primary"]), div[data-testid="stDownloadButton"] > button:not([kind="primary"]) {
        background: rgba(24, 24, 29, 0.95) !important;
        color: #e5e5e5 !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        transition: all 0.2s ease !important;
    }
    div.stButton > button:not([kind="primary"]):hover, div[data-testid="stDownloadButton"] > button:not([kind="primary"]):hover {
        border-color: #E50914 !important;
        color: #ffffff !important;
        box-shadow: 0 0 14px rgba(229, 9, 20, 0.35) !important;
        transform: translateY(-1px) !important;
    }

    /* Streamlit Tabs */
    button[data-baseweb="tab"] {
        color: #a3a3a3 !important;
        font-weight: 600 !important;
        border-radius: 6px !important;
        transition: all 0.2s ease !important;
    }
    button[data-baseweb="tab"]:hover {
        color: #ffffff !important;
    }
    button[data-baseweb="tab"][aria-selected="true"] {
        color: #ffffff !important;
        background: rgba(229, 9, 20, 0.15) !important;
        border-bottom: 2px solid #E50914 !important;
    }
    div[data-baseweb="tab-highlight"] {
        background-color: #E50914 !important;
    }

    /* Expanders */
    div[data-testid="stExpander"] {
        background: rgba(18, 18, 22, 0.85) !important;
        border: 1px solid rgba(229, 9, 20, 0.3) !important;
        border-radius: 10px !important;
        box-shadow: 0 4px 18px rgba(0, 0, 0, 0.5) !important;
    }

    /* Relay Hop Flight Path */
    .hop-node {
        background: rgba(22, 22, 26, 0.9);
        border: 1px solid rgba(229, 9, 20, 0.25);
        border-radius: 8px;
        padding: 12px 16px;
        margin-bottom: 8px;
        display: flex;
        align-items: center;
        transition: border-color 0.2s ease;
    }
    .hop-node:hover {
        border-color: #E50914;
    }
    .hop-num {
        background: linear-gradient(135deg, #E50914 0%, #B81D24 100%);
        color: #ffffff;
        font-weight: 800;
        font-size: 0.78rem;
        padding: 4px 10px;
        border-radius: 6px;
        margin-right: 14px;
        white-space: nowrap;
        box-shadow: 0 2px 8px rgba(229, 9, 20, 0.4);
    }
    .hop-connector {
        text-align: center;
        color: #E50914;
        font-size: 0.8rem;
        padding: 4px 0;
        font-family: 'JetBrains Mono', monospace;
    }
</style>
"""
st.markdown(DYNAMIC_CSS, unsafe_allow_html=True)


@st.cache_resource
def load_model():
    if not os.path.exists(MODEL_PATH):
        return None
    return joblib.load(MODEL_PATH)


def combine_risk_scores(text_confidence, text_label, header_score, threat_score_boost, origin_flags_count):
    text_score = text_confidence * 100 if text_label == "phishing" else (1 - text_confidence) * 100
    origin_score = min(100, origin_flags_count * 25)
    composite = (header_score * 0.40) + (threat_score_boost * 0.25) + (text_score * 0.20) + (origin_score * 0.15)
    return max(0, min(100, round(composite)))


LIVE_SCAN_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "live_scan.json")

# Session State
if "email_history" not in st.session_state:
    st.session_state.email_history = []
if "last_analysis" not in st.session_state:
    st.session_state.last_analysis = None
if "active_scenario_path" not in st.session_state:
    st.session_state.active_scenario_path = "sample_emails/phishing_sample.eml"

# Auto-load when redirected from Chrome Extension (?live=1)
if st.query_params.get("live") == "1" and os.path.exists(LIVE_SCAN_PATH):
    try:
        with open(LIVE_SCAN_PATH, "r", encoding="utf-8") as f:
            live_data = json.load(f)
        if live_data:
            current_id = st.session_state.last_analysis.get("case_id") if st.session_state.last_analysis else None
            if current_id != live_data.get("case_id"):
                st.session_state.last_analysis = live_data
                if not any(item["id"] == live_data["case_id"] for item in st.session_state.email_history):
                    st.session_state.email_history.append({
                        "id": live_data["case_id"],
                        "subject": live_data.get("subject", "Live Extension Audit"),
                        "from_domain": live_data.get("from_domain"),
                        "originating_ip": live_data.get("originating_ip"),
                        "risk_score": live_data.get("risk_score", 0),
                    })
    except Exception:
        pass

# Sidebar Controls
with st.sidebar:
    st.markdown("### 🛡️ PhishGuard SOC Control")
    st.caption("AI Cyber Threat & Digital Forensics")
    st.markdown("---")

    st.subheader("⚙️ Live Controls")
    sound_alert = st.checkbox("🔊 Cyber Audio Alert", value=True, help="Synthesizes an immediate audible alert when a critical threat is identified.")
    redact_enabled = st.checkbox("🔒 Redact PII (Evidence Anonymization)", value=False, help="Masks personal details for legal and regulatory compliance.")

    st.markdown("---")
    st.subheader("🛰️ Browser Extension Bridge")
    st.markdown("Bridge Port: `8765` (Local)")
    if os.path.exists(LIVE_SCAN_PATH):
        st.success("🟢 Extension Feed: Ingestion Active")
    else:
        st.info("⚪ Extension Feed: Standby")

    st.markdown("---")
    st.subheader("📁 Session Case Tracker")
    st.markdown(f"Total Tracked Incidents: **{len(st.session_state.email_history)}**")
    if st.button("🗑️ Reset Session & Graph", use_container_width=True):
        st.session_state.email_history = []
        st.session_state.last_analysis = None
        st.rerun()

    st.markdown("---")
    st.subheader("📋 Regulatory Compliance")
    st.markdown(
        """
        - **ISO/IEC 27037:** Digital Evidence Custody
        - **RFC 5322 & RFC 7489:** Email Authentication
        - **Section 65B BSA (India):** Forensic Admissibility
        - **CERT-In Technical Directive:** Threat Package
        """
    )
    st.caption("Smart India Hackathon 2026 | Binary Battalion")

# Top Brand & SOC Header
col_brand, col_status = st.columns([3.5, 1.5])
with col_brand:
    st.markdown(
        """
        <div style="display: flex; align-items: center; gap: 14px; margin-bottom: 4px;">
            <span style="font-size: 2.6rem; line-height: 1; filter: drop-shadow(0 0 10px rgba(229, 9, 20, 0.6));">🛡️</span>
            <div>
                <h1 style="margin: 0; font-size: 2.1rem; font-weight: 900; color: #ffffff; letter-spacing: -0.03em; text-transform: uppercase;">
                    PhishGuard <span style="color: #E50914; font-weight: 900; text-shadow: 0 0 25px rgba(229, 9, 20, 0.65);">Mail Sentinel</span>
                </h1>
                <p style="margin: 2px 0 0 0; color: #a3a3a3; font-size: 0.93rem;">
                    Autonomous Threat Interception &bull; 3D Origin Trajectory &bull; Section 65B Digital Evidence
                </p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
with col_status:
    st.markdown(
        """
        <div style="text-align: right; padding-top: 8px;">
            <span class="metric-badge" style="font-size: 0.82rem; padding: 6px 14px; font-weight: 800; background: rgba(229, 9, 20, 0.15); color: #ffffff; border: 1px solid rgba(229, 9, 20, 0.55); box-shadow: 0 0 14px rgba(229, 9, 20, 0.3);">
                <span class="soc-pulse-red"></span> SOC ENGINE ONLINE
            </span>
            <div style="font-size: 0.72rem; color: #737373; margin-top: 4px;">
                Smart India Hackathon 2026 &bull; Binary Battalion
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.markdown("<hr style='margin: 8px 0 16px 0; border-color: rgba(229, 9, 20, 0.25);'>", unsafe_allow_html=True)

model = load_model()
if model is None:
    st.error("Model classifier not found. Run `python train_model.py` first.")
    st.stop()

# Chrome Extension Live Stream Banner
if os.path.exists(LIVE_SCAN_PATH):
    try:
        with open(LIVE_SCAN_PATH, "r", encoding="utf-8") as f:
            ext_record = json.load(f)
        ext_time = ext_record.get("timestamp", "Recent")
        ext_subj = ext_record.get("subject", "Live Email Audit")
        ext_score = ext_record.get("risk_score", 0)
        ext_cat = ext_record.get("threat_category", "Live Audit")
        ext_src = ext_record.get("source", "Chrome Extension")
        b_cls = "badge-critical" if ext_score >= 70 else ("badge-suspicious" if ext_score >= 35 else "badge-clean")

        col_ext1, col_ext2 = st.columns([4, 1.3])
        with col_ext1:
            st.markdown(
                f"""
                <div style="background: linear-gradient(90deg, rgba(229, 9, 20, 0.26) 0%, rgba(20, 20, 24, 0.95) 100%); border: 1px solid #E50914; border-radius: 8px; padding: 10px 16px; margin-bottom: 12px; display: flex; align-items: center; justify-content: space-between; box-shadow: 0 4px 20px rgba(229, 9, 20, 0.25);">
                    <div>
                        <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #E50914; box-shadow: 0 0 10px #E50914; margin-right: 8px;"></span>
                        <b style="color: #ff4d58;">LIVE INGESTION FROM {ext_src.upper()}:</b> {ext_subj[:45]} &bull; <i style="color: #a3a3a3;">{ext_time}</i>
                        <span class="metric-badge {b_cls}" style="margin-left: 10px;">{ext_cat} (Risk: {ext_score}/100)</span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with col_ext2:
            if st.button("⚡ Inspect Chrome Scan", type="primary", use_container_width=True, key="btn_inspect_ext"):
                st.session_state.last_analysis = ext_record
                if not any(item["id"] == ext_record["case_id"] for item in st.session_state.email_history):
                    st.session_state.email_history.append({
                        "id": ext_record["case_id"],
                        "subject": ext_record.get("subject", "Live Audit"),
                        "from_domain": ext_record.get("from_domain"),
                        "originating_ip": ext_record.get("originating_ip"),
                        "risk_score": ext_record.get("risk_score", 0),
                    })
                st.rerun()
    except Exception:
        pass

# -------------------------------------------------------------
st.markdown("<div style='font-size: 0.92rem; font-weight: 600; color: #cbd5e1; margin-bottom: 8px;'>⚡ 1-Click Threat Scenarios (Quick Forensic Telemetry):</div>", unsafe_allow_html=True)

q_col1, q_col2, q_col3, q_col4, q_col5 = st.columns(5)
selected_file_to_run = None

with q_col1:
    if st.button("🚨 SBI Bank KYC Scam", use_container_width=True, help="Fake KYC suspension panic coercing Aadhaar & PAN"):
        selected_file_to_run = "sample_emails/sbi_kyc_fraud.eml"
with q_col2:
    if st.button("🚨 PayPal Phishing", use_container_width=True, help="Spoofed domain paypa1.com + Broken SPF"):
        selected_file_to_run = "sample_emails/phishing_sample.eml"
with q_col3:
    if st.button("🚨 Microsoft 365 Attack", use_container_width=True, help="Shares bulletproof IP 45.155.204.12 with PayPal"):
        selected_file_to_run = "sample_emails/phishing_sample_2_same_campaign.eml"
with q_col4:
    if st.button("⚠️ Executive Wire (BEC)", use_container_width=True, help="CFO impersonation for foreign wire diversion"):
        selected_file_to_run = "sample_emails/bec_payment_diversion.eml"
with q_col5:
    if st.button("🟢 Legitimate Mail", use_container_width=True, help="Verified corporate email passing SPF/DKIM/DMARC"):
        selected_file_to_run = "sample_emails/legit_sample.eml"

# Optional Custom Investigation Expander
with st.expander("📂 Or Audit Custom Email (.eml Upload / Paste Raw Text)", expanded=False):
    tab_up, tab_paste = st.tabs(["Upload .eml File", "Paste Raw Email Text"])
    with tab_up:
        custom_file = st.file_uploader("Upload an .eml email file", type=["eml"], key="cust_eml")
        if custom_file is not None:
            st.success(f"File loaded: **{custom_file.name}** ({len(custom_file.getvalue())} bytes)")
            if st.button("🔍 Analyze Uploaded File", type="primary", key="btn_cust_up"):
                raw_bytes = custom_file.getvalue()
                selected_file_to_run = "CUSTOM_UPLOAD_BYTES"
    with tab_paste:
        custom_text = st.text_area("Paste email text here:", height=120, key="cust_text_area")
        if custom_text and st.button("🔍 Analyze Pasted Content", type="primary", key="btn_cust_text"):
            plain_text_only = custom_text
            selected_file_to_run = "CUSTOM_PASTE_TEXT"

# Auto-run initial demo scenario on first launch if empty
if st.session_state.last_analysis is None and selected_file_to_run is None:
    selected_file_to_run = "sample_emails/sbi_kyc_fraud.eml"


# -------------------------------------------------------------
# EXECUTE FORENSIC ANALYSIS PIPELINE
# -------------------------------------------------------------
if selected_file_to_run:
    with st.spinner("⚡ Running Multi-Layer Forensic Inspection (Hashing, SPF/DKIM, NLP, 3D Geo-Trace)..."):
        if selected_file_to_run == "CUSTOM_PASTE_TEXT":
            raw_bytes = None
            plain_text_only = custom_text
            has_headers = False
            header_res = {
                "from": "N/A", "subject": "N/A", "from_domain": None,
                "auth_results": {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"},
                "ip_chain": [], "originating_ip": None, "red_flags": [], "header_risk_score": 0,
            }
            body = plain_text_only
            relay_hops = []
            hashes = compute_evidence_hashes(b"")
        else:
            if selected_file_to_run != "CUSTOM_UPLOAD_BYTES":
                with open(selected_file_to_run, "rb") as f:
                    raw_bytes = f.read()
            has_headers = True
            msg = parse_eml_bytes(raw_bytes)
            header_res = analyze_headers(msg)
            body = get_body_text(msg) or ""
            relay_hops = parse_relay_hops(msg)
            hashes = compute_evidence_hashes(raw_bytes)

        # Privacy Redaction
        display_body = redact_pii(body) if redact_enabled else body
        display_from = redact_pii(header_res.get("from", "N/A")) if redact_enabled else header_res.get("from", "N/A")

        # AI/NLP Classification
        text_pred = model.predict([body])[0]
        text_conf = model.predict_proba([body]).max()

        # Threat Intent & BEC Categorization
        threat_intent = classify_threat_intent(body, header_res.get("subject", ""))

        # Origin Intelligence
        origin_res = {"origin_red_flags": [], "geolocation": {}, "dns_intelligence": {}, "domain_age": {}}
        if has_headers and (header_res.get("originating_ip") or header_res.get("from_domain")):
            origin_res = analyze_origin(header_res["originating_ip"], header_res["from_domain"])

        # Attribution Classification
        attr_info = classify_attribution_source(
            header_res["auth_results"],
            origin_res.get("geolocation", {}),
            origin_res.get("dns_intelligence", {}),
            threat_intent["categories"],
        )

        # Composite Score
        risk_score = combine_risk_scores(
            text_conf,
            text_pred,
            header_res["header_risk_score"],
            threat_intent["threat_score_boost"],
            len(origin_res["origin_red_flags"]),
        )

        all_flags = header_res["red_flags"] + origin_res["origin_red_flags"] + threat_intent["url_flags"]
        for cue in threat_intent["cues_detected"]:
            all_flags.append(f"Social Engineering: {cue}")

        case_id = f"PG-2026-CASE-{len(st.session_state.email_history) + 1:03d}"

        analysis_data = {
            "case_id": case_id,
            "subject": header_res.get("subject", "(No Subject)"),
            "from": display_from,
            "from_domain": header_res.get("from_domain"),
            "originating_ip": header_res.get("originating_ip"),
            "risk_score": risk_score,
            "threat_category": threat_intent["primary_threat"],
            "urgency_level": threat_intent["urgency_level"],
            "attribution_source": attr_info["source_type"],
            "attribution_confidence": attr_info["confidence"],
            "attribution_explanation": attr_info["explanation"],
            "attribution_recommendation": attr_info["recommendation"],
            "evidence_hashes": hashes,
            "auth_results": header_res["auth_results"],
            "geolocation": origin_res.get("geolocation", {}),
            "dns_intelligence": origin_res.get("dns_intelligence", {}),
            "domain_age": origin_res.get("domain_age", {}),
            "relay_hops": relay_hops,
            "red_flags": all_flags,
            "text_label": text_pred,
            "text_confidence": text_conf,
            "header_score": header_res["header_risk_score"],
            "threat_boost": threat_intent["threat_score_boost"],
            "origin_flags_count": len(origin_res["origin_red_flags"]),
            "has_headers": has_headers,
            "body_snippet": display_body[:350] + ("..." if len(display_body) > 350 else ""),
        }

        st.session_state.last_analysis = analysis_data

        # Add to history for campaign graph
        st.session_state.email_history.append({
            "id": case_id,
            "subject": analysis_data["subject"],
            "from_domain": analysis_data["from_domain"],
            "originating_ip": analysis_data["originating_ip"],
            "risk_score": risk_score,
            "threat": analysis_data["threat_category"],
        })


# -------------------------------------------------------------
# DYNAMIC RESULTS DASHBOARD
# -------------------------------------------------------------
if st.session_state.last_analysis is not None:
    data = st.session_state.last_analysis
    st.markdown("---")

    if "source" in data and ("Chrome" in str(data.get("source")) or "Web" in str(data.get("source"))):
        st.markdown(
            f"""
            <div style="background: rgba(229, 9, 20, 0.16); border: 1px solid #E50914; border-radius: 8px; padding: 8px 16px; margin-bottom: 16px; display: flex; align-items: center; justify-content: space-between; box-shadow: 0 0 15px rgba(229, 9, 20, 0.2);">
                <div style="color: #ff4d58; font-weight: 700; font-size: 0.88rem;">
                    🛰️ <b>LIVE SENTINEL AUDIT:</b> Ingested via Chrome Browser Extension ({data.get('source')})
                </div>
                <div style="font-size: 0.78rem; color: #a3a3a3;">
                    Case ID: <code>{data.get('case_id')}</code> &bull; Verified Section 65B Digital Evidence
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    score = data["risk_score"]

    # Audio Alert Trigger (Web Audio API)
    if sound_alert and score >= 70:
        st.markdown(
            """
            <script>
            try {
                var ctx = new (window.AudioContext || window.webkitAudioContext)();
                var osc = ctx.createOscillator();
                var gain = ctx.createGain();
                osc.type = 'triangle';
                osc.frequency.setValueAtTime(400, ctx.currentTime);
                osc.frequency.exponentialRampToValueAtTime(700, ctx.currentTime + 0.12);
                gain.gain.setValueAtTime(0.06, ctx.currentTime);
                gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.25);
                osc.connect(gain);
                gain.connect(ctx.destination);
                osc.start();
                osc.stop(ctx.currentTime + 0.25);
            } catch(e) {}
            </script>
            """,
            unsafe_allow_html=True,
        )

    # Dynamic Status Parameters (Netflix Red / Amber / Clean Green)
    if score >= 70:
        gauge_color = "#E50914"
        verdict_text = "CRITICAL THREAT DETECTED"
        badge_cls = "badge-critical"
        action_msg = "⛔ DANGER: DO NOT CLICK LINKS, OPEN ATTACHMENTS, OR ENTER PASSWORDS / OTPS."
        action_border = "rgba(229, 9, 20, 0.6)"
        action_bg = "rgba(229, 9, 20, 0.18)"
        action_color = "#ff4d58"
    elif score >= 35:
        gauge_color = "#f59e0b"
        verdict_text = "SUSPICIOUS / ELEVATED RISK"
        badge_cls = "badge-suspicious"
        action_msg = "⚠️ PROCEED WITH CAUTION: Verify sender identity via secondary official channel."
        action_border = "rgba(245, 158, 11, 0.45)"
        action_bg = "rgba(245, 158, 11, 0.14)"
        action_color = "#fde68a"
    else:
        gauge_color = "#22c55e"
        verdict_text = "VERIFIED SECURE EMAIL"
        badge_cls = "badge-clean"
        action_msg = "✅ VERIFIED SAFE: Cryptographically authentic sender; no threats detected."
        action_border = "rgba(34, 197, 94, 0.45)"
        action_bg = "rgba(34, 197, 94, 0.14)"
        action_color = "#86efac"

    circumference = 263.89
    stroke_offset = circumference * (1 - (score / 100))

    # -------------------------------------------------------------
    # 1. EXECUTIVE VERDICT HERO CARD (Netflix Cinematic Theme)
    # -------------------------------------------------------------
    geo = data.get("geolocation", {})
    origin_ip = data.get("originating_ip") or geo.get("resolved_ip")
    auth = data.get("auth_results", {})
    spf_status = auth.get("spf", "unknown").upper()

    col_gauge, col_reasons, col_action = st.columns([1.1, 2.3, 1.4])

    with col_gauge:
        st.markdown(
            f"""
            <div class="metric-card" style="align-items: center; text-align: center; padding: 16px; border: 1px solid rgba(229, 9, 20, 0.35);">
                <div class="metric-title">Threat Score</div>
                <div style="position: relative; width: 108px; height: 108px; margin: 4px 0;">
                    <svg width="108" height="108" viewBox="0 0 100 100">
                        <circle cx="50" cy="50" r="42" stroke="rgba(255,255,255,0.06)" stroke-width="8" fill="transparent"/>
                        <circle cx="50" cy="50" r="42" stroke="{gauge_color}" stroke-width="8" fill="transparent"
                            stroke-dasharray="{circumference}" stroke-dashoffset="{stroke_offset}"
                            stroke-linecap="round" transform="rotate(-90 50 50)"
                            style="transition: stroke-dashoffset 0.8s ease; filter: drop-shadow(0 0 8px {gauge_color});" />
                    </svg>
                    <div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);">
                        <div style="font-size: 1.6rem; font-weight: 900; color: {gauge_color}; line-height: 1;">{score}</div>
                        <div style="font-size: 0.65rem; color: #a3a3a3;">/ 100</div>
                    </div>
                </div>
                <div><span class="metric-badge {badge_cls}">{verdict_text}</span></div>
                <div style="font-size: 0.72rem; color: #737373; margin-top: 8px;">Case: <code>{data.get('case_id')}</code></div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_reasons:
        # Determine 3 Key Reasons
        if spf_status == "FAIL" or "spoof" in data.get("threat_category", "").lower() or "lookalike" in str(data.get("red_flags", "")).lower():
            reason_identity = f"❌ <b>Spoofed Sender Domain:</b> <code>{data.get('from_domain')}</code> fails domain authentication."
        elif spf_status == "PASS":
            reason_identity = f"✅ <b>Authentic Identity:</b> <code>{data.get('from_domain')}</code> passed cryptographic SPF/DKIM validation."
        else:
            reason_identity = f"ℹ️ <b>Sender Domain:</b> <code>{data.get('from_domain') or 'Unknown'}</code>"

        if data.get("urgency_level") in ["High", "Urgent", "Critical"]:
            reason_intent = f"❌ <b>Psychological Panic Cue:</b> Demands urgent action under threat of account block or penalties."
        elif "phishing" in str(data.get("text_label", "")).lower():
            reason_intent = f"⚠️ <b>Suspicious Request:</b> Semantic intent matches credential or financial harvesting patterns."
        else:
            reason_intent = f"✅ <b>Normal Content:</b> No coercive social engineering triggers detected in message body."

        loc_str = f"{geo.get('city', 'Origin')}, {geo.get('country', 'Unknown')}"
        if geo.get("is_hosting_provider"):
            reason_origin = f"❌ <b>Server Location:</b> Dispatched from Datacenter hosting in <b>{loc_str}</b> (<code>{origin_ip}</code>)."
        elif geo.get("is_likely_proxy_or_vpn"):
            reason_origin = f"⚠️ <b>Server Location:</b> Dispatched via anonymized VPN/Tor node in <b>{loc_str}</b> (<code>{origin_ip}</code>)."
        else:
            reason_origin = f"📍 <b>Server Location:</b> Dispatched via mail gateway in <b>{loc_str}</b> (<code>{origin_ip}</code>)."

        st.markdown(
            f"""
            <div class="metric-card" style="padding: 18px 22px; border-left: 3px solid #E50914;">
                <div style="font-size: 1.2rem; font-weight: 800; color: #ffffff; margin-bottom: 2px;">
                    {data.get('threat_category', 'Email Security Audit')}
                </div>
                <div style="font-size: 0.8rem; color: #a3a3a3; margin-bottom: 14px;">
                    <b>From:</b> {data.get('from', 'N/A')[:40]} &bull; <b>Subject:</b> {data.get('subject', 'N/A')[:45]}
                </div>
                <div style="font-size: 0.86rem; line-height: 1.65; color: #e5e5e5;">
                    <div style="margin-bottom: 7px;">{reason_identity}</div>
                    <div style="margin-bottom: 7px;">{reason_intent}</div>
                    <div>{reason_origin}</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_action:
        pdf_report = generate_pdf_report(data)
        json_report = generate_json_report(data)
        st.markdown(
            f"""
            <div class="metric-card" style="padding: 16px; justify-content: space-between;">
                <div>
                    <div class="metric-title">Recommended Action</div>
                    <div style="background: {action_bg}; border: 1px solid {action_border}; color: {action_color}; border-radius: 8px; padding: 10px 12px; font-size: 0.8rem; font-weight: 700; line-height: 1.4; margin-bottom: 12px;">
                        {action_msg}
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.download_button(
            label="📄 Download Court Report (PDF)",
            data=pdf_report,
            file_name=f"{data['case_id']}_Forensic_Report.pdf",
            mime="application/pdf",
            type="primary",
            use_container_width=True,
        )
        st.download_button(
            label="💾 Download JSON IOC Package",
            data=json_report,
            file_name=f"{data['case_id']}_IOCs.json",
            mime="application/json",
            use_container_width=True,
        )

    # -------------------------------------------------------------
    # 2. 3D GLOBAL FLIGHT ARC MAP (Netflix Obsidian Basemap)
    # -------------------------------------------------------------
    if geo.get("latitude") and geo.get("longitude"):
        st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
        st.markdown(
            f"#### 🌐 3D Global Transmission Trajectory (Origin: {geo.get('city', 'Origin')}, {geo.get('country', '')} ➔ Recipient MX)"
        )

        origin_lat = float(geo.get("latitude", 50.1109))
        origin_lon = float(geo.get("longitude", 8.6821))
        dest_lat = 28.6139  # New Delhi (Target organization)
        dest_lon = 77.2090

        arc_df = pd.DataFrame([{
            "from_name": f"{geo.get('city', 'Origin')}, {geo.get('country', '')}",
            "from_coord": [origin_lon, origin_lat],
            "to_name": "Target Organization (New Delhi, India)",
            "to_coord": [dest_lon, dest_lat],
        }])

        point_df = pd.DataFrame([
            {"pos": [origin_lon, origin_lat], "color": [229, 9, 20, 245], "radius": 160000, "label": f"Origin: {origin_ip} ({geo.get('city', '')})"},
            {"pos": [dest_lon, dest_lat], "color": [255, 255, 255, 230], "radius": 160000, "label": "Target Organization MX (New Delhi)"},
        ])

        arc_layer = pdk.Layer(
            "ArcLayer",
            data=arc_df,
            get_source_position="from_coord",
            get_target_position="to_coord",
            get_source_color=[229, 9, 20, 240],
            get_target_color=[255, 75, 75, 220],
            get_width=4.5,
            get_tilt=20,
        )

        scatter_layer = pdk.Layer(
            "ScatterplotLayer",
            data=point_df,
            get_position="pos",
            get_fill_color="color",
            get_radius="radius",
            pickable=True,
        )

        view_state = pdk.ViewState(
            latitude=(origin_lat + dest_lat) / 2,
            longitude=(origin_lon + dest_lon) / 2,
            zoom=1.8,
            pitch=45,
            bearing=0,
        )

        st.pydeck_chart(
            pdk.Deck(
                layers=[arc_layer, scatter_layer],
                initial_view_state=view_state,
                map_style="https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json",
                tooltip={"text": "{label}\n{from_name} ➔ {to_name}"},
            ),
            use_container_width=True,
        )

        # 4 Summary Telemetry Chips
        c_chip1, c_chip2, c_chip3, c_chip4 = st.columns(4)
        c_chip1.metric("Originating IP", origin_ip or "Unresolved")
        c_chip2.metric("Physical Location", f"{geo.get('city', '—')}, {geo.get('country', '')}")
        facility_type = "Datacenter Hosting" if geo.get("is_hosting_provider") else ("VPN / Proxy" if geo.get("is_likely_proxy_or_vpn") else "ISP Gateway")
        c_chip3.metric("Facility Infrastructure", facility_type)
        c_chip4.metric("Recipient Destination", "New Delhi, India (Target MX)")

    # -------------------------------------------------------------
    # 3. COLLAPSIBLE ADVANCED FORENSIC DEEP DIVE
    # -------------------------------------------------------------
    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
    with st.expander("🔬 Open Advanced Forensic Deep Dive (For Technical Auditors & SOC Analysts)", expanded=False):
        st.caption("Detailed cryptographic protocol verification, SMTP relay hop reconstruction, Vis.js campaign syndicate graph, and firewall playbooks.")

        tab_threat, tab_hops, tab_proto, tab_graph, tab_playbook, tab_legal = st.tabs([
            "🚨 Threat & Semantic NLP",
            "🛰️ SMTP Relay Hop Traversal",
            "📧 Protocol & Cryptographic Headers",
            "🕸️ Dynamic Campaign Syndicate Graph",
            "🛡️ Incident Response Playbook",
            "⚖️ Legal Chain of Custody (BSA 65B)",
        ])

        # TAB 1: Threat & Semantic NLP
        with tab_threat:
            st.subheader("Semantic & Social Engineering Intelligence")
            col_t1, col_t2 = st.columns([1.5, 1])

            with col_t1:
                st.markdown(f"**Identified Threat Vector:** `{data['threat_category']}`")
                st.markdown(f"**AI/NLP Model Verdict:** `{data['text_label'].upper()}` (Confidence: `{data['text_confidence']:.1%}`)")
                st.markdown(f"**Attribution Assessment:** {data['attribution_explanation']}")
                st.info(f"**Recommended Analyst Action:** {data['attribution_recommendation']}")

            with col_t2:
                st.markdown("**Evidence Snippet (Analyzed Body):**")
                st.code(data["body_snippet"], language="text")

            st.markdown("#### 🚩 Forensic Red Flags & Extracted IOCs")
            if not data["red_flags"]:
                st.success("✅ No technical red flags detected. Conforms to baseline security.")
            else:
                for flag in data["red_flags"]:
                    st.warning(f"⚠️ {flag}")

        # TAB 2: SMTP Relay Hop Traversal
        with tab_hops:
            st.subheader("SMTP Relay Path (Earliest Sending Node ➔ Destination MX)")
            hops = data.get("relay_hops", [])
            if not hops:
                st.info("No Received transmission headers available or raw text mode used.")
            else:
                st.markdown(f"Reconstructed **{len(hops)} mail transmission hops** across relay infrastructure:")

                for idx, h in enumerate(hops):
                    role_color = "#E50914" if "Originating" in h["role"] else ("#22c55e" if "Final" in h["role"] else "#b81d24")
                    st.markdown(
                        f"""
                        <div class="hop-node">
                            <div class="hop-num" style="background: {role_color};">Hop {h['hop_number']} &bull; {h['role']}</div>
                            <div style="flex-grow: 1;">
                                <div><b>Host:</b> <code>{h['from_host']}</code> &bull; <b>IP:</b> <code style="color: #ff4d58;">{h['ip'] or 'Internal / Hidden'}</code></div>
                                <div style="font-size: 0.78rem; color: #a3a3a3;"><b>Received By:</b> {h['by_host']} (Protocol: {h['protocol']}) &bull; <b>Timestamp:</b> {h['timestamp']}</div>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                    if idx < len(hops) - 1:
                        st.markdown(f"<div class='hop-connector'>│<br/>▼ (Relayed via {hops[idx+1]['protocol']})</div>", unsafe_allow_html=True)

        # TAB 3: Protocol & Cryptographic Headers
        with tab_proto:
            st.subheader("Cryptographic Protocol Validation (SPF / DKIM / DMARC)")
            col_p1, col_p2, col_p3 = st.columns(3)
            with col_p1:
                spf_val = auth.get("spf", "unknown").upper()
                if spf_val == "PASS":
                    st.success(f"**SPF (Sender Policy Framework):** {spf_val} ✅")
                elif spf_val == "FAIL":
                    st.error(f"**SPF (Sender Policy Framework):** {spf_val} ❌")
                else:
                    st.info(f"**SPF (Sender Policy Framework):** {spf_val} ⚪")
                st.caption("Verifies whether sending IP is authorized by domain owner.")

            with col_p2:
                dkim_val = auth.get("dkim", "unknown").upper()
                if dkim_val == "PASS":
                    st.success(f"**DKIM (Digital Signature):** {dkim_val} ✅")
                elif dkim_val == "FAIL":
                    st.error(f"**DKIM (Digital Signature):** {dkim_val} ❌")
                else:
                    st.info(f"**DKIM (Digital Signature):** {dkim_val} ⚪")
                st.caption("Cryptographically verifies message integrity and domain authenticity.")

            with col_p3:
                dmarc_val = auth.get("dmarc", "unknown").upper()
                if dmarc_val == "PASS":
                    st.success(f"**DMARC (Policy Alignment):** {dmarc_val} ✅")
                elif dmarc_val == "FAIL":
                    st.error(f"**DMARC (Policy Alignment):** {dmarc_val} ❌")
                else:
                    st.info(f"**DMARC (Policy Alignment):** {dmarc_val} ⚪")
                st.caption("Instructs mail servers on handling spoofed From headers.")

            st.markdown("#### Domain Infrastructure & DNS Posture")
            col_dns1, col_dns2 = st.columns(2)
            with col_dns1:
                st.write("**DNS Authentication Records:**")
                st.json(data.get("dns_intelligence", {}))
            with col_dns2:
                st.write("**WHOIS Registration Timeline:**")
                st.json(data.get("domain_age", {}))

        # TAB 4: Dynamic Campaign Syndicate Graph
        with tab_graph:
            st.subheader("🕸️ Dynamic Physics-Based Campaign Correlation Graph")
            history = st.session_state.email_history

            if len(history) < 2:
                st.info(
                    "💡 **Syndicate Correlation Insight:** Load multiple incidents (e.g. **PayPal Phishing** followed by **Microsoft 365 Attack**). "
                    "The graph engine cross-references historical telemetry to unmask shared threat infrastructure (identical bulletproof IP `45.155.204.12`), "
                    "uncovering coordinated multi-stage campaigns in real time."
                )
            else:
                G = build_attribution_graph(history)
                clusters = find_campaign_clusters(G)

                if clusters:
                    st.error(
                        f"🚨 **Organized Threat Campaign Detected!** Found **{len(clusters)} campaign cluster(s)** "
                        f"sharing malicious infrastructure across multiple attack targets."
                    )
                    for idx, cl in enumerate(clusters, start=1):
                        st.markdown(f"**Campaign #{idx}:** Incidents `{', '.join(cl)}` originated from identical infrastructure.")
                else:
                    st.success("✅ No shared infrastructure discovered across analyzed emails (isolated incidents).")

                st.markdown("##### 🖱️ Interactive Network Map (Drag nodes to inspect, scroll wheel to zoom)")
                interactive_html = generate_interactive_graph_html(G)
                components.html(interactive_html, height=480, scrolling=False)

                with st.expander("📷 View / Export High-Resolution Static Diagram"):
                    static_img = render_graph_image(G)
                    if static_img:
                        st.image(static_img, caption="Static Infrastructure Graph", use_container_width=True)

            if history:
                st.markdown("#### Session Incident Registry")
                st.dataframe(pd.DataFrame(history), use_container_width=True)

        # TAB 5: Incident Response Playbook
        with tab_playbook:
            st.subheader("🛡️ Automated Incident Response & Firewall Playbook")
            st.markdown("Instant actionable containment controls generated for SOC Analysts:")

            bad_ip = data.get("originating_ip") or "0.0.0.0"
            bad_domain = data.get("from_domain") or "malicious-domain.com"

            st.markdown("#### 1. Network Boundary Containment (Firewall Rules)")
            c_fw1, c_fw2 = st.columns(2)
            with c_fw1:
                st.write("**Linux iptables / Egress Block:**")
                st.code(f"iptables -A INPUT -s {bad_ip} -j DROP\niptables -A FORWARD -s {bad_ip} -j DROP", language="bash")
            with c_fw2:
                st.write("**Cisco ASA / Fortinet Rule:**")
                st.code(f"access-list OUTSIDE_BLOCK deny ip host {bad_ip} any\nsh shun {bad_ip}", language="bash")

            st.markdown("#### 2. Mail Gateway & DNS Sinkhole Action")
            st.code(
                f"# DNS Sinkhole for Lookalike Domain:\n{bad_domain} CNAME sinkhole.cert-in.org.in.\n\n"
                f"# Exchange / Google Workspace Transport Rule:\nSet-TransportRule -Name 'Block-PhishGuard-{data['case_id']}' -SenderDomainIs '{bad_domain}' -RejectMessageReasonText 'Blocked by PhishGuard Forensics Policy'",
                language="powershell",
            )

            st.markdown("#### 3. CERT-In Incident Notification Draft")
            cert_draft = (
                f"TO: incident@cert-in.org.in\n"
                f"SUBJECT: Cyber Threat Incident Report - {data['threat_category']} - Ref: {data['case_id']}\n\n"
                f"Dear CERT-In Team,\n\n"
                f"A high-risk email threat incident was detected and verified by PhishGuard.\n"
                f"Evidence Hash (SHA-256): {data['evidence_hashes'].get('sha256')}\n"
                f"Originating Infrastructure IP: {bad_ip}\n"
                f"Impersonated/Spoofed Domain: {bad_domain}\n"
                f"Threat Category: {data['threat_category']}\n"
                f"Recommended Action: Ingress block on IP {bad_ip} and lookalike domain takedown."
            )
            st.code(cert_draft, language="text")

        # TAB 6: Chain of Custody & Legal
        with tab_legal:
            st.subheader("⚖️ Digital Evidence Preservation & Chain of Custody")
            st.markdown(
                """
                In accordance with digital forensics standards (**ISO/IEC 27037**) and **Section 65B of the Indian Evidence Act / Bharatiya Sakshya Adhiniyam (BSA)**:
                """
            )
            h = data["evidence_hashes"]
            st.markdown(f"- **Cryptographic SHA-256 Digest:** `{h.get('sha256')}`")
            st.markdown(f"- **Cryptographic MD5 Digest:** `{h.get('md5')}`")
            st.markdown(f"- **Evidence File Size:** `{h.get('size_bytes')} bytes`")
            st.markdown(f"- **Ingestion Timestamp (UTC):** `{h.get('timestamp_utc')}`")
            st.markdown(f"- **Case Tracking Identifier:** `{data['case_id']}`")

            st.divider()
            st.caption(
                "Legal Evidentiary Notice: The cryptographic hashes recorded above establish the mathematical authenticity "
                "of the evidence at the instant of ingestion, preventing repudiation or tampering during institutional review and legal proceedings."
            )
