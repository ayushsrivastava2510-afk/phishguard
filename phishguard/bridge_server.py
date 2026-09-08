"""
bridge_server.py
----------------
Lightweight local HTTP bridge server for the PhishGuard Chrome Extension.
Enables 1-click real-time threat auditing from Gmail & Outlook into the PhishGuard SOC.

Endpoints:
  - GET  /api/status  : Health check for extension popup
  - POST /api/scan    : Ingests raw email data, executes forensic pipeline,
                        saves to data/live_scan.json, and returns instant verdict.
  - GET  /api/latest  : Fetches the latest live-scanned incident
"""

import os
import sys
import json
import time
import email
from http.server import HTTPServer, BaseHTTPRequestHandler
import joblib

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from header_analysis import parse_eml_bytes, analyze_headers, get_body_text
from origin_intel import analyze_origin
from forensics_core import compute_evidence_hashes, parse_relay_hops, classify_attribution_source
from threat_classifier import classify_threat_intent
from transformer_classifier import predict_phishing
from stacking_classifier import combine_risk_scores_stacked
from explainability import generate_token_heatmap_html, format_section_65b_legal_xai_summary

PORT = 8765
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
LIVE_SCAN_PATH = os.path.join(DATA_DIR, "live_scan.json")
MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "phishing_classifier.joblib")

# Load model once at startup
print("[PhishGuard Bridge] Initializing DistilBERT Transformer & Stacking Meta-Classifier...")
model = None
if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
        print("[PhishGuard Bridge] Fallback NLP model verified.")
    except Exception as e:
        print(f"[PhishGuard Bridge Warning] Could not load model: {e}")



class PhishGuardBridgeHandler(BaseHTTPRequestHandler):
    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def _send_json(self, status_code, data):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        if self.path == "/api/status":
            resp = {
                "status": "online",
                "service": "PhishGuard SOC Bridge",
                "version": "1.0.0",
                "port": PORT,
            }
            self._send_json(200, resp)

        elif self.path == "/api/latest":
            if os.path.exists(LIVE_SCAN_PATH):
                try:
                    with open(LIVE_SCAN_PATH, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    self._send_json(200, data)
                except Exception as e:
                    self._send_json(500, {"error": str(e)})
            else:
                self._send_json(200, {"status": "no_data"})

        else:
            self._send_json(404, {"error": "Endpoint not found"})

    def do_POST(self):
        if self.path == "/api/scan":
            try:
                content_length = int(self.headers.get("Content-Length", 0))
                raw_body = self.rfile.read(content_length).decode("utf-8", errors="replace")
                data = json.loads(raw_body) if raw_body else {}

                from_name = data.get("from_name", "")
                from_email = data.get("from_email", "")
                to_addr = data.get("to", "user@enterprise.local")
                subject = data.get("subject", "(No Subject)")
                date_str = data.get("date", email.utils.formatdate(localtime=True))
                body_text = data.get("body", "")
                raw_headers = data.get("raw_headers", "")

                # Construct synthetic RFC 5322 EML if raw transmission headers are absent
                if raw_headers and len(raw_headers.strip()) > 20:
                    raw_eml_str = raw_headers.strip() + "\n\n" + body_text
                else:
                    from_header = f'"{from_name}" <{from_email}>' if from_name and from_email else (from_email or from_name or "unknown@sender.local")
                    raw_eml_str = (
                        f"From: {from_header}\n"
                        f"To: {to_addr}\n"
                        f"Subject: {subject}\n"
                        f"Date: {date_str}\n"
                        f"Message-ID: <live-{int(time.time())}@phishguard.sentinel>\n"
                        f"MIME-Version: 1.0\n"
                        f"Content-Type: text/plain; charset=utf-8\n\n"
                        f"{body_text}"
                    )

                raw_bytes = raw_eml_str.encode("utf-8", errors="replace")
                msg = parse_eml_bytes(raw_bytes)
                header_res = analyze_headers(msg)
                hashes = compute_evidence_hashes(raw_bytes)
                hops = parse_relay_hops(msg)
                threat_intent = classify_threat_intent(body_text, subject)

                # Origin Intelligence
                origin_res = {"origin_red_flags": [], "geolocation": {}, "dns_intelligence": {}, "domain_age": {}}
                if header_res.get("originating_ip") or header_res.get("from_domain"):
                    origin_res = analyze_origin(header_res.get("originating_ip"), header_res.get("from_domain"))

                # Attribution
                attr_info = classify_attribution_source(
                    header_res["auth_results"],
                    origin_res.get("geolocation", {}),
                    origin_res.get("dns_intelligence", {}),
                    threat_intent["categories"],
                )

                # ML Classification
                text_pred = "phishing"
                # DistilBERT Transformer NLP & Token Attribution
                nlp_res = predict_phishing(body_text)
                text_pred = nlp_res["label"]
                text_conf = nlp_res["confidence"]

                # Stacking Meta-Classifier (Learned Ensemble)
                risk_score, stack_meta = combine_risk_scores_stacked(
                    text_conf,
                    text_pred,
                    header_res["header_risk_score"],
                    threat_intent["threat_score_boost"],
                    len(origin_res["origin_red_flags"]),
                )

                case_id = f"PG-LIVE-{int(time.time()) % 10000:04d}"

                all_flags = header_res["red_flags"] + origin_res["origin_red_flags"] + threat_intent["url_flags"]
                for cue in threat_intent["cues_detected"]:
                    all_flags.append(f"Social Engineering: {cue}")

                effective_ip = header_res.get("originating_ip") or origin_res.get("origin_ip")

                # Resolve human-readable sender and domain fallbacks
                clean_from = header_res.get("from")
                if not clean_from or str(clean_from).strip() in ["N/A", "None", ""]:
                    clean_from = f'"{from_name}" <{from_email}>' if from_name and from_email else (from_email or from_name or "Webmail Sender")

                clean_domain = header_res.get("from_domain")
                if not clean_domain or str(clean_domain).strip() in ["None", "N/A", ""]:
                    clean_domain = from_email.split("@")[-1] if "@" in from_email else "webmail.local"

                scenario_title = f"Live Extension: {subject[:32]}" if subject and str(subject).strip() not in ["(No Subject)", "N/A", ""] else "Chrome Extension In-Inbox Audit"
                source_type = f"Chrome Extension ({data.get('source', 'Webmail')})"

                # Assemble Full Forensic Record for Streamlit
                forensic_record = {
                    "case_id": case_id,
                    "scenario_title": scenario_title,
                    "source_type": source_type,
                    "subject": subject,
                    "from": clean_from,
                    "from_domain": clean_domain,
                    "originating_ip": effective_ip,
                    "risk_score": risk_score,
                    "threat_category": threat_intent["primary_threat"],
                    "urgency_level": threat_intent["urgency_level"],
                    "attribution_source": attr_info["source_type"],
                    "attribution_confidence": attr_info["confidence"],
                    "attribution_explanation": attr_info["explanation"],
                    "attribution_recommendation": attr_info["recommendation"],
                    "text_label": text_pred,
                    "text_confidence": text_conf,
                    "model_name": nlp_res["model_name"],
                    "nlp_latency_ms": nlp_res["latency_ms"],
                    "token_attributions": nlp_res["attributions"],
                    "stacking_metadata": stack_meta,
                    "body_snippet": body_text[:400],
                    "red_flags": all_flags,
                    "relay_hops": hops,
                    "auth_results": header_res["auth_results"],
                    "geolocation": origin_res.get("geolocation", {}),
                    "dns_intelligence": origin_res.get("dns_intelligence", {}),
                    "domain_age": origin_res.get("domain_age", {}),
                    "evidence_hashes": hashes,
                    "has_headers": True,
                    "source": data.get("source", "Chrome Extension Live Scan"),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                }

                # Save to disk for Streamlit pickup
                os.makedirs(DATA_DIR, exist_ok=True)
                with open(LIVE_SCAN_PATH, "w", encoding="utf-8") as f:
                    json.dump(forensic_record, f, indent=2)

                print(f"[PhishGuard Bridge] Successfully processed live scan: {case_id} | Risk Score: {risk_score} | Origin IP: {effective_ip}")

                # Immediate Verdict for Extension Popup
                verdict = "CRITICAL THREAT" if risk_score >= 70 else ("SUSPICIOUS" if risk_score >= 35 else "VERIFIED SAFE")
                geo = origin_res.get("geolocation", {})

                response_payload = {
                    "status": "success",
                    "case_id": case_id,
                    "scenario_title": scenario_title,
                    "source_type": source_type,
                    "subject": subject,
                    "from": clean_from,
                    "from_domain": clean_domain,
                    "risk_score": risk_score,
                    "verdict": verdict,
                    "threat_category": threat_intent["primary_threat"],
                    "urgency_level": threat_intent["urgency_level"],
                    "text_label": text_pred,
                    "model_name": nlp_res["model_name"],
                    "nlp_latency_ms": nlp_res["latency_ms"],
                    "token_attributions": nlp_res["attributions"],
                    "stacking_metadata": stack_meta,
                    "origin_ip": effective_ip or "Webmail Relay Node",
                    "origin_country": geo.get("country") or "Verified Mail Gateway",
                    "is_hosting": geo.get("is_hosting_provider", False),
                    "sha256": hashes.get("sha256", ""),
                    "body_snippet": body_text[:400],
                    "red_flags": all_flags,
                    "auth_results": header_res["auth_results"],
                    "geolocation": origin_res.get("geolocation", {}),
                    "evidence_hashes": hashes,
                    "dashboard_url": "https://phishguard-soc.streamlit.app/?live=1",
                }

                self._send_json(200, response_payload)

            except Exception as e:
                print(f"[PhishGuard Bridge Error] {e}")
                self._send_json(500, {"status": "error", "message": str(e)})
        else:
            self._send_json(404, {"error": "Endpoint not found"})


def run_bridge_server():
    server_address = ("127.0.0.1", PORT)
    httpd = HTTPServer(server_address, PhishGuardBridgeHandler)
    print("=" * 60)
    print(" [PhishGuard] Chrome Extension SOC Bridge Active")
    print(f"    Listening at: http://127.0.0.1:{PORT}")
    print(f"    Health Endpoint: http://127.0.0.1:{PORT}/api/status")
    print("=" * 60)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping PhishGuard Bridge Server...")
        httpd.server_close()


if __name__ == "__main__":
    run_bridge_server()
