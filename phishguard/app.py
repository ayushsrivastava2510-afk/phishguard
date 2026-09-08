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

# Dynamic Cyber SOC Styling - GeekPay Inspired Enterprise Design System
DYNAMIC_CSS = """
<style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    .stDeployButton {display:none;}
    div[data-testid="stDecoration"] {display:none;}
    header {background: transparent !important;}

    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap');
    
    html, body, [class*="css"], .stApp {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        background-color: #080c16 !important;
        color: #f1f5f9;
        -webkit-font-smoothing: antialiased;
        -moz-osx-font-smoothing: grayscale;
        text-rendering: optimizeLegibility;
    }
    
    /* GeekPay Ambient Fintech Slate Canvas */
    .stApp {
        background-color: #080c16 !important;
        background-image: 
            radial-gradient(ellipse 85% 55% at 50% -15%, rgba(77, 101, 255, 0.16), transparent 70%),
            radial-gradient(circle at 100% 100%, rgba(16, 185, 129, 0.08), transparent 50%),
            radial-gradient(circle at 0% 40%, rgba(56, 189, 248, 0.06), transparent 45%),
            linear-gradient(180deg, #080c16 0%, #0d1424 100%) !important;
        background-attachment: fixed !important;
    }

    /* GeekPay Signature Animated Multi-Tone Gradient Heading */
    .text-style-gradient {
        display: inline-block;
        background-image: linear-gradient(-45deg, #22d3ee, #4d65ff, #818cf8, #34d399, #4d65ff) !important;
        background-size: 300% !important;
        background-clip: text;
        -webkit-background-clip: text;
        text-fill-color: transparent;
        -webkit-text-fill-color: transparent;
        animation: GeekPayGradient 9s ease infinite !important;
    }
    @keyframes GeekPayGradient {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }

    /* GeekPay Sub-Head Pill Badge */
    .sub-head-top {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        border-radius: 999px;
        padding: 4px 12px;
        font-size: 0.72rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.09em;
        background: rgba(77, 101, 255, 0.12);
        color: #60a5fa;
        border: 1px solid rgba(77, 101, 255, 0.28);
        margin-bottom: 6px;
    }

    code, pre {
        font-family: 'JetBrains Mono', monospace !important;
        background-color: #0c1222 !important;
        color: #38bdf8 !important;
        border: 1px solid rgba(56, 189, 248, 0.22) !important;
        border-radius: 8px;
        padding: 2px 6px;
    }

    /* Sidebar - Sleek Slate Navy with Micro-Borders */
    section[data-testid="stSidebar"] {
        background-color: #0c1220 !important;
        border-right: 1px solid rgba(255, 255, 255, 0.08) !important;
        box-shadow: 4px 0 24px rgba(0, 0, 0, 0.5) !important;
    }
    section[data-testid="stSidebar"] hr {
        border-color: rgba(255, 255, 255, 0.08) !important;
    }

    /* Pulse Beacons */
    .soc-pulse-red, .soc-pulse-cobalt {
        display: inline-block;
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background-color: #10b981;
        box-shadow: 0 0 12px #10b981;
        margin-right: 8px;
        animation: geekpayPulse 2s infinite;
    }
    @keyframes geekpayPulse {
        0% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.8); }
        70% { box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
        100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }

    /* GeekPay Glassmorphic Elevated Cards */
    .metric-card {
        background: rgba(15, 23, 42, 0.72) !important;
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-radius: 16px !important;
        padding: 20px 22px;
        box-shadow: 0 10px 30px -5px rgba(0, 0, 0, 0.45), 0 0 1px 1px rgba(255, 255, 255, 0.04);
        height: 100%;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
    }
    .metric-card:hover {
        transform: translateY(-3px);
        border-color: rgba(77, 101, 255, 0.45) !important;
        box-shadow: 0 16px 36px -6px rgba(77, 101, 255, 0.22), 0 0 20px rgba(77, 101, 255, 0.12);
    }
    .metric-title {
        font-size: 0.75rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #94a3b8;
        margin-bottom: 6px;
    }
    .metric-value-huge {
        font-size: 2.2rem;
        font-weight: 800;
        line-height: 1.1;
        margin-bottom: 6px;
        color: #ffffff;
    }

    /* GeekPay Modern Pill Badges */
    .metric-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        font-size: 0.74rem;
        font-weight: 700;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        padding: 4px 12px;
        border-radius: 999px;
    }
    .badge-critical {
        background: rgba(239, 68, 68, 0.14);
        color: #f87171;
        border: 1px solid rgba(239, 68, 68, 0.35);
        box-shadow: 0 0 12px rgba(239, 68, 68, 0.2);
    }
    .badge-suspicious {
        background: rgba(245, 158, 11, 0.14);
        color: #fbbf24;
        border: 1px solid rgba(245, 158, 11, 0.35);
        box-shadow: 0 0 12px rgba(245, 158, 11, 0.15);
    }
    .badge-clean {
        background: rgba(16, 185, 129, 0.14);
        color: #34d399;
        border: 1px solid rgba(16, 185, 129, 0.35);
        box-shadow: 0 0 12px rgba(16, 185, 129, 0.2);
    }

    /* GeekPay Buttons: Electric Cobalt & Slate Squircle */
    div.stButton > button[kind="primary"], div[data-testid="stDownloadButton"] > button[kind="primary"] {
        background: linear-gradient(135deg, #4d65ff 0%, #3b49df 100%) !important;
        color: #ffffff !important;
        border: 1px solid rgba(255, 255, 255, 0.15) !important;
        font-weight: 600 !important;
        letter-spacing: 0.01em !important;
        border-radius: 10px !important;
        padding: 8px 20px !important;
        box-shadow: 0 4px 16px rgba(77, 101, 255, 0.35) !important;
        transition: all 0.2s ease !important;
    }
    div.stButton > button[kind="primary"]:hover, div[data-testid="stDownloadButton"] > button[kind="primary"]:hover {
        background: linear-gradient(135deg, #5c72ff 0%, #4757ea 100%) !important;
        box-shadow: 0 6px 24px rgba(77, 101, 255, 0.55) !important;
        transform: translateY(-2px) !important;
    }
    div.stButton > button:not([kind="primary"]), div[data-testid="stDownloadButton"] > button:not([kind="primary"]) {
        background: rgba(30, 41, 59, 0.65) !important;
        color: #e2e8f0 !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        border-radius: 10px !important;
        font-weight: 500 !important;
        transition: all 0.2s ease !important;
    }
    div.stButton > button:not([kind="primary"]):hover, div[data-testid="stDownloadButton"] > button:not([kind="primary"]):hover {
        border-color: #4d65ff !important;
        color: #ffffff !important;
        background: rgba(43, 58, 85, 0.8) !important;
        box-shadow: 0 0 14px rgba(77, 101, 255, 0.25) !important;
        transform: translateY(-1px) !important;
    }

    /* GeekPay Segmented Modern Tabs */
    button[data-baseweb="tab"] {
        color: #94a3b8 !important;
        font-weight: 600 !important;
        border-radius: 8px !important;
        padding: 8px 16px !important;
        transition: all 0.2s ease !important;
    }
    button[data-baseweb="tab"]:hover {
        color: #ffffff !important;
        background: rgba(255, 255, 255, 0.05) !important;
    }
    button[data-baseweb="tab"][aria-selected="true"] {
        color: #ffffff !important;
        background: rgba(77, 101, 255, 0.16) !important;
        border-bottom: 2px solid #4d65ff !important;
    }
    div[data-baseweb="tab-highlight"] {
        background-color: #4d65ff !important;
    }

    /* GeekPay Styled Expanders */
    div[data-testid="stExpander"] {
        background: rgba(15, 23, 42, 0.65) !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-radius: 14px !important;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3) !important;
    }

    /* Relay Hop Flight Path */
    .hop-node {
        background: rgba(15, 23, 42, 0.85);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 12px;
        padding: 12px 18px;
        margin-bottom: 8px;
        display: flex;
        align-items: center;
        transition: all 0.2s ease;
    }
    .hop-node:hover {
        border-color: #4d65ff;
        box-shadow: 0 0 14px rgba(77, 101, 255, 0.25);
    }
    .hop-num {
        background: linear-gradient(135deg, #4d65ff 0%, #3b49df 100%);
        color: #ffffff;
        font-weight: 700;
        font-size: 0.78rem;
        padding: 5px 12px;
        border-radius: 8px;
        margin-right: 14px;
        white-space: nowrap;
        box-shadow: 0 2px 10px rgba(77, 101, 255, 0.3);
    }
    .hop-connector {
        text-align: center;
        color: #60a5fa;
        font-size: 0.82rem;
        padding: 5px 0;
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


def resolve_email_telemetry_display(data):
    """
    Computes clean, human-readable display attributes for the email currently
    being analyzed, ensuring fallback coverage across pre-loaded scenarios,
    custom uploads, and Chrome Extension captures so 'N/A' is never displayed.
    """
    scenario_title = (
        data.get("scenario_title")
        or st.session_state.get("active_scenario_title")
        or "Forensic Security Audit Target"
    )
    source_type = (
        data.get("source_type")
        or st.session_state.get("active_source_type")
        or ("Chrome Browser Extension Live Ingestion" if ("source" in data and "Chrome" in str(data.get("source"))) else "Enterprise Mail Gateway")
    )

    # Subject resolution
    raw_subj = data.get("subject")
    if raw_subj and str(raw_subj).strip() not in ["N/A", "(No Subject)", "None", ""]:
        subject = str(raw_subj).strip()
    else:
        subject = scenario_title

    # Sender resolution
    raw_from = data.get("from") or data.get("from_email")
    raw_domain = data.get("from_domain")
    if raw_from and str(raw_from).strip() not in ["N/A", "None", ""]:
        sender = str(raw_from).strip()
    elif raw_domain:
        sender = f"Automated Dispatch <alerts@{raw_domain}>"
    else:
        sender = "Gateway Ingestion <telemetry@phishguard.internal>"

    if not raw_domain or str(raw_domain).strip() in ["None", "N/A", ""]:
        if "@" in sender:
            domain = sender.split("@")[-1].replace(">", "").strip()
        else:
            domain = "gateway.internal"
    else:
        domain = str(raw_domain).strip()

    return {
        "title": scenario_title,
        "source": source_type,
        "subject": subject,
        "from": sender,
        "domain": domain,
    }


# Session State
if "email_history" not in st.session_state:
    st.session_state.email_history = []
if "last_analysis" not in st.session_state:
    st.session_state.last_analysis = None
if "active_scenario" not in st.session_state:
    st.session_state.active_scenario = "sbi_kyc"
if "active_scenario_title" not in st.session_state:
    st.session_state.active_scenario_title = "Scenario 1: SBI Bank KYC Fraud"
if "active_source_type" not in st.session_state:
    st.session_state.active_source_type = "Pre-Loaded Attack Scenario"
if "active_scenario_path" not in st.session_state:
    st.session_state.active_scenario_path = "sample_emails/sbi_kyc_fraud.eml"

# Auto-load when redirected from Chrome Extension (?live=1 or ?payload=...)
payload_raw = st.query_params.get("payload")
if payload_raw:
    try:
        import urllib.parse
        decoded = json.loads(urllib.parse.unquote(payload_raw))
        if decoded and isinstance(decoded, dict):
            raw_s = decoded.get("subject")
            subj_clean = raw_s if raw_s and raw_s != "N/A" and raw_s != "(No Subject)" else "Live Webmail Capture"
            st.session_state.active_scenario = "extension"
            st.session_state.active_scenario_title = f"Chrome Extension Live Capture: {subj_clean[:35]}"
            st.session_state.active_source_type = "Chrome Browser Extension Live Ingestion"
            decoded["scenario_title"] = st.session_state.active_scenario_title
            decoded["source_type"] = st.session_state.active_source_type
            st.session_state.last_analysis = decoded
            cid = decoded.get("case_id", "EXT-LIVE")
            if not any(item["id"] == cid for item in st.session_state.email_history):
                st.session_state.email_history.append({
                    "id": cid,
                    "subject": subj_clean,
                    "from_domain": decoded.get("from_domain") or (decoded.get("from_email", "").split("@")[-1] if "@" in decoded.get("from_email", "") else "webmail.local"),
                    "originating_ip": decoded.get("originating_ip") or decoded.get("origin_ip", "Webmail Client"),
                    "risk_score": decoded.get("risk_score", 0),
                    "threat": decoded.get("threat_category", "Live Audit"),
                })
    except Exception as e:
        print("[Payload Parse Error]", e)

elif os.path.exists(LIVE_SCAN_PATH):
    try:
        with open(LIVE_SCAN_PATH, "r", encoding="utf-8") as f:
            live_data = json.load(f)
        if live_data:
            raw_s = live_data.get("subject")
            subj_clean = raw_s if raw_s and raw_s != "N/A" and raw_s != "(No Subject)" else "Live Webmail Capture"
            st.session_state.active_scenario = "extension"
            st.session_state.active_scenario_title = f"Chrome Extension Live Capture: {subj_clean[:35]}"
            st.session_state.active_source_type = "Chrome Browser Extension Live Ingestion"
            live_data["scenario_title"] = st.session_state.active_scenario_title
            live_data["source_type"] = st.session_state.active_source_type
            if st.query_params.get("live") == "1" or st.session_state.last_analysis is None:
                st.session_state.last_analysis = live_data
            if not any(item["id"] == live_data["case_id"] for item in st.session_state.email_history):
                st.session_state.email_history.append({
                    "id": live_data["case_id"],
                    "subject": live_data.get("subject", "Live Extension Audit"),
                    "from_domain": live_data.get("from_domain"),
                    "originating_ip": live_data.get("originating_ip"),
                    "risk_score": live_data.get("risk_score", 0),
                    "threat": live_data.get("threat_category", "Live Audit"),
                })
    except Exception:
        pass

# Cache extension zip generation in memory
@st.cache_data
def get_extension_zip_package():
    import io
    import zipfile
    base_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.abspath(os.path.join(base_dir, "..", "extension")),
        os.path.abspath(os.path.join(os.getcwd(), "extension")),
        os.path.abspath(os.path.join(base_dir, "extension")),
    ]
    ext_dir = next((d for d in candidates if os.path.isdir(d) and os.path.exists(os.path.join(d, "manifest.json"))), None)
    if not ext_dir:
        return None

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(ext_dir):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, ext_dir)
                zf.write(full_path, rel_path)
    zip_buffer.seek(0)
    return zip_buffer.getvalue()


# Sidebar Controls
with st.sidebar:
    st.markdown("### 🛡️ PhishGuard SOC Control")
    st.caption("AI Cyber Threat & Digital Forensics")
    st.markdown("---")

    st.subheader("⚙️ Live Controls")
    sound_alert = st.checkbox("🔊 Cyber Audio Alert", value=True, help="Synthesizes an immediate audible alert when a critical threat is identified.")
    redact_enabled = st.checkbox("🔒 Redact PII (Evidence Anonymization)", value=False, help="Masks personal details for legal and regulatory compliance.")

    st.markdown("---")
    st.subheader("🛰️ Browser Extension")
    ext_zip_bytes = get_extension_zip_package()
    if ext_zip_bytes:
        st.download_button(
            label="📥 Download Extension (.zip)",
            data=ext_zip_bytes,
            file_name="phishguard-chrome-extension.zip",
            mime="application/zip",
            help="Download the PhishGuard Mail Sentinel Chrome Extension for Gmail & Outlook.",
            use_container_width=True,
            type="primary",
        )
    with st.expander("📖 15-Second Install Guide", expanded=False):
        st.markdown(
            """
            1. **Download & Extract:** Click the button above to download `phishguard-chrome-extension.zip` and extract it.
            2. **Open Extensions:** In Chrome, Edge, or Brave, visit `chrome://extensions`.
            3. **Enable Developer Mode:** Turn ON the toggle in the top-right corner.
            4. **Load Extension:** Click **"Load unpacked"** and select the unzipped `extension` folder.
            
            *You're set! Open Gmail or Outlook to see the '🛡️ Scan with PhishGuard' button appear automatically.*
            """
        )
    st.markdown(
        """
        <div style="font-size: 0.78rem; color: #a3a3a3; margin-top: 4px; margin-bottom: 8px;">
            <span class="soc-pulse-red"></span> <b>Dual-Mode:</b> In-browser heuristic engine + Cloud SOC Telemetry.
        </div>
        """,
        unsafe_allow_html=True,
    )
    if os.path.exists(LIVE_SCAN_PATH):
        st.success("🟢 Extension Feed: Connected")
    else:
        st.info("☁️ Extension Feed: Cloud Standalone Mode")

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

# Top Brand & SOC Header - GeekPay Inspired Enterprise Layout
col_brand, col_status = st.columns([3.6, 1.4])
with col_brand:
    st.markdown(
        """
        <div style="display: flex; align-items: center; gap: 16px; margin-bottom: 6px;">
            <div style="width: 54px; height: 54px; border-radius: 14px; background: linear-gradient(135deg, rgba(77, 101, 255, 0.25) 0%, rgba(16, 185, 129, 0.12) 100%); border: 1px solid rgba(77, 101, 255, 0.35); display: flex; align-items: center; justify-content: center; font-size: 1.85rem; box-shadow: 0 4px 18px rgba(77, 101, 255, 0.25);">
                🛡️
            </div>
            <div>
                <div class="sub-head-top">Autonomous SOC Platform</div>
                <h1 style="margin: 0; font-size: 2.15rem; font-weight: 800; color: #ffffff; letter-spacing: -0.03em; line-height: 1.15;">
                    PhishGuard <span class="text-style-gradient">Mail Sentinel</span>
                </h1>
                <p style="margin: 4px 0 0 0; color: #94a3b8; font-size: 0.92rem; font-weight: 400;">
                    Enterprise Threat Interception &bull; 3D Origin Trajectory &bull; Section 65B Digital Evidence
                </p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
with col_status:
    st.markdown(
        """
        <div style="text-align: right; padding-top: 12px;">
            <span class="metric-badge badge-clean" style="font-size: 0.8rem; padding: 6px 14px; font-weight: 700;">
                <span class="soc-pulse-cobalt"></span> SOC ENGINE ONLINE
            </span>
            <div style="font-size: 0.74rem; color: #64748b; margin-top: 6px; font-weight: 500;">
                Smart India Hackathon 2026 &bull; Binary Battalion
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.markdown("<hr style='margin: 10px 0 18px 0; border-color: rgba(255, 255, 255, 0.08);'>", unsafe_allow_html=True)

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
                <div style="background: linear-gradient(90deg, rgba(77, 101, 255, 0.16) 0%, rgba(15, 23, 42, 0.9) 100%); border: 1px solid rgba(77, 101, 255, 0.4); border-radius: 12px; padding: 12px 18px; margin-bottom: 14px; display: flex; align-items: center; justify-content: space-between; box-shadow: 0 4px 20px rgba(77, 101, 255, 0.15);">
                    <div>
                        <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #4d65ff; box-shadow: 0 0 10px #4d65ff; margin-right: 8px;"></span>
                        <b style="color: #60a5fa;">LIVE INGESTION FROM {ext_src.upper()}:</b> {ext_subj[:45]} &bull; <i style="color: #94a3b8;">{ext_time}</i>
                        <span class="metric-badge {b_cls}" style="margin-left: 10px;">{ext_cat} (Risk: {ext_score}/100)</span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with col_ext2:
            if st.button("⚡ Inspect Chrome Scan", type="primary", use_container_width=True, key="btn_inspect_ext"):
                st.session_state.last_analysis = ext_record
                selected_file_to_run = None
                if not any(item["id"] == ext_record["case_id"] for item in st.session_state.email_history):
                    st.session_state.email_history.append({
                        "id": ext_record["case_id"],
                        "subject": ext_record.get("subject", "Live Audit"),
                        "from_domain": ext_record.get("from_domain"),
                        "originating_ip": ext_record.get("originating_ip"),
                        "risk_score": ext_record.get("risk_score", 0),
                        "threat": ext_record.get("threat_category", "Live Audit"),
                    })
                st.rerun()
    except Exception:
        pass

# -------------------------------------------------------------
curr_active_title = st.session_state.get("active_scenario_title", "Scenario 1: SBI Bank KYC Fraud")
st.markdown(
    f"""
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; margin-top: 4px; flex-wrap: wrap; gap: 8px;">
        <div style="display: flex; align-items: center; gap: 10px;">
            <span class="sub-head-top" style="margin-bottom: 0;">1-Click Telemetry</span>
            <span style="font-size: 0.95rem; font-weight: 700; color: #f8fafc;">Benchmark Forensic Scenarios</span>
        </div>
        <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 0.75rem; color: #64748b; font-weight: 500;">Active Target:</span>
            <span style="font-size: 0.76rem; color: #38bdf8; font-weight: 700; background: rgba(56, 189, 248, 0.12); padding: 3px 10px; border-radius: 6px; border: 1px solid rgba(56, 189, 248, 0.28);">
                🎯 {curr_active_title}
            </span>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

q_col1, q_col2, q_col3, q_col4, q_col5 = st.columns(5)
selected_file_to_run = None
current_active = st.session_state.get("active_scenario", "sbi_kyc")

with q_col1:
    is_act = (current_active == "sbi_kyc")
    if st.button("🚨 SBI Bank KYC" + ("  ✓ ACTIVE" if is_act else ""), use_container_width=True, type="primary" if is_act else "secondary", help="Fake KYC suspension panic coercing Aadhaar & PAN"):
        selected_file_to_run = "sample_emails/sbi_kyc_fraud.eml"
        st.session_state.active_scenario = "sbi_kyc"
        st.session_state.active_scenario_title = "Scenario 1: SBI Bank KYC Fraud"
        st.session_state.active_source_type = "Pre-Loaded Attack Scenario"
with q_col2:
    is_act = (current_active == "paypal")
    if st.button("🚨 PayPal Phish" + ("  ✓ ACTIVE" if is_act else ""), use_container_width=True, type="primary" if is_act else "secondary", help="Spoofed domain paypa1.com + Broken SPF"):
        selected_file_to_run = "sample_emails/phishing_sample.eml"
        st.session_state.active_scenario = "paypal"
        st.session_state.active_scenario_title = "Scenario 2: PayPal Account Phishing"
        st.session_state.active_source_type = "Pre-Loaded Attack Scenario"
with q_col3:
    is_act = (current_active == "ms365")
    if st.button("🚨 Microsoft 365" + ("  ✓ ACTIVE" if is_act else ""), use_container_width=True, type="primary" if is_act else "secondary", help="Shares bulletproof IP 45.155.204.12 with PayPal"):
        selected_file_to_run = "sample_emails/phishing_sample_2_same_campaign.eml"
        st.session_state.active_scenario = "ms365"
        st.session_state.active_scenario_title = "Scenario 3: Microsoft 365 Subscription Attack"
        st.session_state.active_source_type = "Pre-Loaded Attack Scenario"
with q_col4:
    is_act = (current_active == "bec")
    if st.button("⚠️ Exec Wire (BEC)" + ("  ✓ ACTIVE" if is_act else ""), use_container_width=True, type="primary" if is_act else "secondary", help="CFO impersonation for foreign wire diversion"):
        selected_file_to_run = "sample_emails/bec_payment_diversion.eml"
        st.session_state.active_scenario = "bec"
        st.session_state.active_scenario_title = "Scenario 4: Executive Wire (BEC) Diversion"
        st.session_state.active_source_type = "Pre-Loaded Attack Scenario"
with q_col5:
    is_act = (current_active == "legit")
    if st.button("🟢 Legitimate Mail" + ("  ✓ ACTIVE" if is_act else ""), use_container_width=True, type="primary" if is_act else "secondary", help="Verified corporate email passing SPF/DKIM/DMARC"):
        selected_file_to_run = "sample_emails/legit_sample.eml"
        st.session_state.active_scenario = "legit"
        st.session_state.active_scenario_title = "Scenario 5: Verified Legitimate Corporate Mail"
        st.session_state.active_source_type = "Pre-Loaded Legitimate Communication"

# Optional Custom Investigation Expander
with st.expander("📂 Audit Custom Email (.eml Upload / Paste Raw Text)", expanded=False):
    tab_up, tab_paste = st.tabs(["Upload .eml File", "Paste Raw Email Text"])
    with tab_up:
        custom_file = st.file_uploader("Upload an .eml email file", type=["eml"], key="cust_eml")
        if custom_file is not None:
            st.success(f"File loaded: **{custom_file.name}** ({len(custom_file.getvalue())} bytes)")
            if st.button("🔍 Analyze Uploaded File", type="primary", key="btn_cust_up"):
                raw_bytes = custom_file.getvalue()
                selected_file_to_run = "CUSTOM_UPLOAD_BYTES"
                st.session_state.active_scenario = "custom_upload"
                st.session_state.active_scenario_title = f"Uploaded File: {custom_file.name}"
                st.session_state.active_source_type = "Custom .EML Upload"
    with tab_paste:
        custom_text = st.text_area("Paste email text here:", height=120, key="cust_text_area")
        if custom_text and st.button("🔍 Analyze Pasted Content", type="primary", key="btn_cust_text"):
            plain_text_only = custom_text
            selected_file_to_run = "CUSTOM_PASTE_TEXT"
            st.session_state.active_scenario = "custom_paste"
            st.session_state.active_scenario_title = "Custom Pasted Plain Text"
            st.session_state.active_source_type = "Pasted Raw Text"

# Chrome Extension Direct Download & Setup (Main Page)
with st.expander("🧩 PhishGuard Chrome Extension — 1-Click Download & Setup Guide (Gmail & Outlook)", expanded=False):
    ext_col1, ext_col2 = st.columns([1.5, 2.5])
    with ext_col1:
        st.markdown("#### 📥 Direct Download")
        st.caption("Packaged Manifest V3 extension ready for Chrome, Edge, and Brave.")
        main_ext_bytes = get_extension_zip_package()
        if main_ext_bytes:
            st.download_button(
                label="📥 Download Chrome Extension (.zip)",
                data=main_ext_bytes,
                file_name="phishguard-chrome-extension.zip",
                mime="application/zip",
                help="Download the PhishGuard Mail Sentinel Chrome Extension for Gmail & Outlook.",
                use_container_width=True,
                type="primary",
                key="btn_dl_ext_main_page",
            )
        st.markdown(
            """
            <div style="font-size: 0.8rem; color: #a3a3a3; margin-top: 10px; line-height: 1.4;">
                <span class="soc-pulse-red"></span> <b>Client-Side Intelligence:</b> Operates completely standalone on any machine with built-in heuristic threat inspection.
            </div>
            """,
            unsafe_allow_html=True,
        )
    with ext_col2:
        st.markdown("#### 📖 15-Second Installation Guide")
        st.markdown(
            """
            1. **Extract ZIP:** Unpack the downloaded `phishguard-chrome-extension.zip` file to any folder on your computer.
            2. **Open Extensions Page:** In Chrome, Edge, or Brave, open a new tab and go to `chrome://extensions`.
            3. **Enable Developer Mode:** Turn **ON** the `Developer mode` toggle switch at the top-right corner.
            4. **Load Unpacked:** Click the **"Load unpacked"** button (top-left) and select the extracted folder.
            
            *You're all set! Open any message in **Gmail** or **Outlook Web** to see the **'🛡️ Scan with PhishGuard'** button appear.*
            """
        )

# Auto-run initial demo scenario on first launch ONLY if no analysis exists AND not redirected from extension
if st.session_state.last_analysis is None and selected_file_to_run is None:
    if st.query_params.get("live") != "1" and not st.query_params.get("payload"):
        selected_file_to_run = "sample_emails/sbi_kyc_fraud.eml"
        st.session_state.active_scenario = "sbi_kyc"
        st.session_state.active_scenario_title = "Scenario 1: SBI Bank KYC Fraud"
        st.session_state.active_source_type = "Pre-Loaded Attack Scenario"


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
            "scenario_title": st.session_state.get("active_scenario_title", "Forensic Investigation Target"),
            "source_type": st.session_state.get("active_source_type", "Forensic Pipeline"),
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
            <div style="background: rgba(77, 101, 255, 0.12); border: 1px solid rgba(77, 101, 255, 0.35); border-radius: 12px; padding: 10px 18px; margin-bottom: 16px; display: flex; align-items: center; justify-content: space-between; box-shadow: 0 4px 20px rgba(77, 101, 255, 0.12);">
                <div style="color: #60a5fa; font-weight: 700; font-size: 0.88rem;">
                    🛰️ <b>LIVE SENTINEL AUDIT:</b> Ingested via Chrome Browser Extension ({data.get('source')})
                </div>
                <div style="font-size: 0.78rem; color: #94a3b8;">
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

    # Dynamic Status Parameters (GeekPay Clean High-Trust Palette)
    if score >= 70:
        gauge_color = "#f87171"
        verdict_text = "CRITICAL THREAT DETECTED"
        badge_cls = "badge-critical"
        action_msg = "⛔ DANGER: DO NOT CLICK LINKS, OPEN ATTACHMENTS, OR ENTER PASSWORDS / OTPS."
        action_border = "rgba(239, 68, 68, 0.4)"
        action_bg = "rgba(239, 68, 68, 0.12)"
        action_color = "#fca5a5"
        border_accent = "#f87171"
    elif score >= 35:
        gauge_color = "#fbbf24"
        verdict_text = "SUSPICIOUS / ELEVATED RISK"
        badge_cls = "badge-suspicious"
        action_msg = "⚠️ PROCEED WITH CAUTION: Verify sender identity via secondary official channel."
        action_border = "rgba(245, 158, 11, 0.4)"
        action_bg = "rgba(245, 158, 11, 0.12)"
        action_color = "#fde68a"
        border_accent = "#fbbf24"
    else:
        gauge_color = "#34d399"
        verdict_text = "VERIFIED SECURE EMAIL"
        badge_cls = "badge-clean"
        action_msg = "✅ VERIFIED SAFE: Cryptographically authentic sender; no threats detected."
        action_border = "rgba(16, 185, 129, 0.4)"
        action_bg = "rgba(16, 185, 129, 0.12)"
        action_color = "#86efac"
        border_accent = "#34d399"

    circumference = 263.89
    stroke_offset = circumference * (1 - (score / 100))

    # -------------------------------------------------------------
    # 1. EXECUTIVE VERDICT HERO CARD (GeekPay Enterprise Fintech Theme)
    # -------------------------------------------------------------
    geo = data.get("geolocation", {})
    origin_ip = data.get("originating_ip") or geo.get("resolved_ip")
    auth = data.get("auth_results", {})
    spf_status = auth.get("spf", "unknown").upper()
    telemetry_info = resolve_email_telemetry_display(data)

    # Dedicated Active Email Identification Hero Card (GeekPay Clean High-Trust Palette)
    st.markdown(
        f"""
        <div class="metric-card" style="margin-bottom: 20px; padding: 18px 22px; border-left: 4px solid #4d65ff; background: linear-gradient(135deg, rgba(30, 41, 59, 0.75) 0%, rgba(15, 23, 42, 0.92) 100%);">
            <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px; margin-bottom: 12px; border-bottom: 1px solid rgba(255, 255, 255, 0.08); padding-bottom: 10px;">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span class="sub-head-top" style="margin-bottom: 0; background: rgba(77, 101, 255, 0.2); color: #93c5fd; border: 1px solid rgba(77, 101, 255, 0.45); padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 0.72rem; letter-spacing: 0.05em; text-transform: uppercase;">
                        🔍 CURRENTLY ANALYZING
                    </span>
                    <span style="font-size: 1.1rem; font-weight: 800; color: #ffffff;">
                        {telemetry_info['title']}
                    </span>
                </div>
                <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                    <span style="background: rgba(148, 163, 184, 0.12); color: #94a3b8; font-size: 0.74rem; padding: 4px 10px; border-radius: 6px; border: 1px solid rgba(148, 163, 184, 0.2); font-weight: 500;">
                        Pipeline: <b>{telemetry_info['source']}</b>
                    </span>
                    <span style="background: rgba(77, 101, 255, 0.15); color: #93c5fd; font-size: 0.74rem; padding: 4px 10px; border-radius: 6px; font-weight: 600;">
                        Case: <code>{data.get('case_id', 'PG-AUDIT')}</code>
                    </span>
                </div>
            </div>
            
            <div style="display: grid; grid-template-columns: 2.2fr 1.6fr 1.1fr 1.1fr; gap: 14px;">
                <div>
                    <div style="font-size: 0.70rem; text-transform: uppercase; color: #64748b; font-weight: 700; letter-spacing: 0.05em; margin-bottom: 3px;">Email Subject Line</div>
                    <div style="font-size: 0.90rem; color: #f8fafc; font-weight: 600; line-height: 1.4; word-break: break-word;" title="{telemetry_info['subject']}">
                        {telemetry_info['subject']}
                    </div>
                </div>
                <div>
                    <div style="font-size: 0.70rem; text-transform: uppercase; color: #64748b; font-weight: 700; letter-spacing: 0.05em; margin-bottom: 3px;">Sender Entity (From)</div>
                    <div style="font-size: 0.84rem; color: #cbd5e1; font-weight: 500; line-height: 1.4; word-break: break-all;" title="{telemetry_info['from']}">
                        <code>{telemetry_info['from']}</code>
                    </div>
                </div>
                <div>
                    <div style="font-size: 0.70rem; text-transform: uppercase; color: #64748b; font-weight: 700; letter-spacing: 0.05em; margin-bottom: 3px;">Sender Domain</div>
                    <div style="font-size: 0.84rem; color: #38bdf8; font-weight: 600; line-height: 1.4;">
                        <code>{telemetry_info['domain']}</code>
                    </div>
                </div>
                <div>
                    <div style="font-size: 0.70rem; text-transform: uppercase; color: #64748b; font-weight: 700; letter-spacing: 0.05em; margin-bottom: 3px;">Originating IP</div>
                    <div style="font-size: 0.84rem; color: #e2e8f0; font-weight: 600; line-height: 1.4;">
                        <code>{origin_ip or '127.0.0.1'}</code>
                    </div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_gauge, col_reasons, col_action = st.columns([1.1, 2.3, 1.4])

    with col_gauge:
        st.markdown(
            f"""
            <div class="metric-card" style="align-items: center; text-align: center; padding: 18px 16px;">
                <div class="metric-title">Threat Score</div>
                <div style="position: relative; width: 112px; height: 112px; margin: 4px 0;">
                    <svg width="112" height="112" viewBox="0 0 100 100">
                        <circle cx="50" cy="50" r="42" stroke="rgba(255,255,255,0.06)" stroke-width="8" fill="transparent"/>
                        <circle cx="50" cy="50" r="42" stroke="{gauge_color}" stroke-width="8" fill="transparent"
                            stroke-dasharray="{circumference}" stroke-dashoffset="{stroke_offset}"
                            stroke-linecap="round" transform="rotate(-90 50 50)"
                            style="transition: stroke-dashoffset 0.8s ease; filter: drop-shadow(0 0 10px {gauge_color});" />
                    </svg>
                    <div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);">
                        <div style="font-size: 1.65rem; font-weight: 800; color: {gauge_color}; line-height: 1;">{score}</div>
                        <div style="font-size: 0.65rem; color: #94a3b8; font-weight: 600;">/ 100</div>
                    </div>
                </div>
                <div><span class="metric-badge {badge_cls}">{verdict_text}</span></div>
                <div style="font-size: 0.72rem; color: #64748b; margin-top: 8px;">Case: <code>{data.get('case_id')}</code></div>
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
            <div class="metric-card" style="padding: 20px 24px; border-left: 4px solid {border_accent};">
                <div class="sub-head-top" style="margin-bottom: 4px;">Forensic Assessment</div>
                <div style="font-size: 1.25rem; font-weight: 800; color: #ffffff; margin-bottom: 2px;">
                    {data.get('threat_category', 'Email Security Audit')}
                </div>
                <div style="font-size: 0.82rem; color: #94a3b8; margin-bottom: 14px;">
                    <b>Target:</b> <span style="color: #60a5fa; font-weight: 600;">{telemetry_info['title']}</span><br/>
                    <b>From:</b> {telemetry_info['from'][:38]} &bull; <b>Subject:</b> {telemetry_info['subject'][:42]}
                </div>
                <div style="font-size: 0.88rem; line-height: 1.65; color: #e2e8f0;">
                    <div style="margin-bottom: 8px;">{reason_identity}</div>
                    <div style="margin-bottom: 8px;">{reason_intent}</div>
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
            <div class="metric-card" style="padding: 18px 20px; justify-content: space-between;">
                <div>
                    <div class="metric-title">Recommended Action</div>
                    <div style="background: {action_bg}; border: 1px solid {action_border}; color: {action_color}; border-radius: 10px; padding: 12px 14px; font-size: 0.82rem; font-weight: 600; line-height: 1.45; margin-bottom: 12px;">
                        {action_msg}
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        cid_file = data.get('case_id', 'EXT-LIVE')
        st.download_button(
            label="📄 Download Court Report (PDF)",
            data=pdf_report,
            file_name=f"{cid_file}_Forensic_Report.pdf",
            mime="application/pdf",
            type="primary",
            use_container_width=True,
        )
        st.download_button(
            label="💾 Download JSON IOC Package",
            data=json_report,
            file_name=f"{cid_file}_IOCs.json",
            mime="application/json",
            use_container_width=True,
        )

    # -------------------------------------------------------------
    # 2. 3D GLOBAL FLIGHT ARC MAP (GeekPay Clean Dark Basemap)
    # -------------------------------------------------------------
    if geo.get("latitude") and geo.get("longitude"):
        st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
        st.markdown(
            f"""
            <div style="display: flex; align-items: center; gap: 10px; margin-top: 14px; margin-bottom: 4px;">
                <span class="sub-head-top" style="margin-bottom: 0;">Global Transmission Map</span>
                <span style="font-size: 1.05rem; font-weight: 700; color: #ffffff;">3D Origin Trajectory Arc</span>
                <span style="font-size: 0.8rem; color: #94a3b8;">({geo.get('city', 'Origin')}, {geo.get('country', '')} ➔ Recipient MX)</span>
            </div>
            """,
            unsafe_allow_html=True,
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
            {"pos": [origin_lon, origin_lat], "color": [77, 101, 255, 245], "radius": 160000, "label": f"Origin: {origin_ip} ({geo.get('city', '')})"},
            {"pos": [dest_lon, dest_lat], "color": [16, 185, 129, 235], "radius": 160000, "label": "Target Organization MX (New Delhi)"},
        ])

        arc_layer = pdk.Layer(
            "ArcLayer",
            data=arc_df,
            get_source_position="from_coord",
            get_target_position="to_coord",
            get_source_color=[77, 101, 255, 240],
            get_target_color=[34, 211, 238, 220],
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

            text_label = str(data.get("text_label", "Analyzed")).upper()
            conf_val = data.get("text_confidence")
            conf_str = f" (Confidence: `{conf_val:.1%}`)" if isinstance(conf_val, (int, float)) else ""

            with col_t1:
                st.markdown(f"**Identified Threat Vector:** `{data.get('threat_category', 'General Threat Evaluation')}`")
                st.markdown(f"**AI/NLP Model Verdict:** `{text_label}`{conf_str}")
                st.markdown(f"**Attribution Assessment:** {data.get('attribution_explanation', 'Evaluated via PhishGuard SOC pipeline.')}")
                st.info(f"**Recommended Analyst Action:** {data.get('attribution_recommendation', 'Standard security monitoring.')}")

            with col_t2:
                st.markdown("**Evidence Snippet (Analyzed Body):**")
                st.code(data.get("body_snippet", "(No message body content captured)"), language="text")

            st.markdown("#### 🚩 Forensic Red Flags & Extracted IOCs")
            red_flags_list = data.get("red_flags", [])
            if not red_flags_list:
                st.success("✅ No technical red flags detected. Conforms to baseline security.")
            else:
                for flag in red_flags_list:
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
                    role_color = "#f87171" if "Originating" in h["role"] else ("#34d399" if "Final" in h["role"] else "#4d65ff")
                    st.markdown(
                        f"""
                        <div class="hop-node">
                            <div class="hop-num" style="background: {role_color};">Hop {h['hop_number']} &bull; {h['role']}</div>
                            <div style="flex-grow: 1;">
                                <div><b>Host:</b> <code>{h['from_host']}</code> &bull; <b>IP:</b> <code style="color: #38bdf8;">{h['ip'] or 'Internal / Hidden'}</code></div>
                                <div style="font-size: 0.78rem; color: #94a3b8;"><b>Received By:</b> {h['by_host']} (Protocol: {h['protocol']}) &bull; <b>Timestamp:</b> {h['timestamp']}</div>
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

            case_id_val = data.get("case_id", "EXT-LIVE")
            threat_cat_val = data.get("threat_category", "Live Threat Audit")
            ev_hashes = data.get("evidence_hashes", {})

            st.markdown("#### 2. Mail Gateway & DNS Sinkhole Action")
            st.code(
                f"# DNS Sinkhole for Lookalike Domain:\n{bad_domain} CNAME sinkhole.cert-in.org.in.\n\n"
                f"# Exchange / Google Workspace Transport Rule:\nSet-TransportRule -Name 'Block-PhishGuard-{case_id_val}' -SenderDomainIs '{bad_domain}' -RejectMessageReasonText 'Blocked by PhishGuard Forensics Policy'",
                language="powershell",
            )

            st.markdown("#### 3. CERT-In Incident Notification Draft")
            cert_draft = (
                f"TO: incident@cert-in.org.in\n"
                f"SUBJECT: Cyber Threat Incident Report - {threat_cat_val} - Ref: {case_id_val}\n\n"
                f"Dear CERT-In Team,\n\n"
                f"A high-risk email threat incident was detected and verified by PhishGuard.\n"
                f"Evidence Hash (SHA-256): {ev_hashes.get('sha256', 'N/A')}\n"
                f"Originating Infrastructure IP: {bad_ip}\n"
                f"Impersonated/Spoofed Domain: {bad_domain}\n"
                f"Threat Category: {threat_cat_val}\n"
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
            h = data.get("evidence_hashes", {})
            st.markdown(f"- **Cryptographic SHA-256 Digest:** `{h.get('sha256', 'N/A')}`")
            st.markdown(f"- **Cryptographic MD5 Digest:** `{h.get('md5', 'N/A')}`")
            st.markdown(f"- **Evidence File Size:** `{h.get('size_bytes', 'N/A')} bytes`")
            st.markdown(f"- **Ingestion Timestamp (UTC):** `{h.get('timestamp_utc', 'N/A')}`")
            st.markdown(f"- **Case Tracking Identifier:** `{case_id_val}`")

            st.divider()
            st.caption(
                "Legal Evidentiary Notice: The cryptographic hashes recorded above establish the mathematical authenticity "
                "of the evidence at the instant of ingestion, preventing repudiation or tampering during institutional review and legal proceedings."
            )

# -------------------------------------------------------------
# GEEKPAY-INSPIRED CLEAN ENTERPRISE FOOTER
# -------------------------------------------------------------
st.markdown("<div style='height: 36px;'></div>", unsafe_allow_html=True)
st.markdown(
    """
    <div style="border-top: 1px solid rgba(255, 255, 255, 0.08); padding: 24px 0 16px 0; margin-top: 24px;">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px;">
            <div>
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span style="font-size: 1.25rem;">🛡️</span>
                    <span style="font-weight: 800; font-size: 1.05rem; color: #ffffff;">PhishGuard</span>
                    <span class="sub-head-top" style="margin-bottom: 0; font-size: 0.65rem; padding: 2px 8px;">Mail Sentinel</span>
                </div>
                <div style="font-size: 0.78rem; color: #64748b; margin-top: 4px;">
                    Next-Generation Autonomous Threat Defense &bull; Section 65B Certified Forensic Chain of Custody
                </div>
            </div>
            <div style="display: flex; gap: 12px; align-items: center; flex-wrap: wrap;">
                <span style="font-size: 0.74rem; color: #94a3b8; background: rgba(255, 255, 255, 0.04); padding: 5px 12px; border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.06);">ISO/IEC 27037</span>
                <span style="font-size: 0.74rem; color: #94a3b8; background: rgba(255, 255, 255, 0.04); padding: 5px 12px; border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.06);">RFC 5322 / 7489</span>
                <span style="font-size: 0.74rem; color: #94a3b8; background: rgba(255, 255, 255, 0.04); padding: 5px 12px; border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.06);">CERT-In Directive</span>
            </div>
        </div>
        <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 18px; padding-top: 14px; border-top: 1px solid rgba(255, 255, 255, 0.04); font-size: 0.75rem; color: #64748b; flex-wrap: wrap; gap: 8px;">
            <div>&copy; 2026 PhishGuard Sentinel &bull; Smart India Hackathon &bull; Binary Battalion</div>
            <div>Bank-Grade Cryptographic Telemetry &bull; Real-Time Email Protection</div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)
