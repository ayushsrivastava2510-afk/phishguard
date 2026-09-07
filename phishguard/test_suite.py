"""
test_suite.py
-------------
Automated verification test script for PhishGuard.
Tests all 5 sample scenarios through every layer of the platform.
"""

import os
import joblib
from header_analysis import parse_eml_file, analyze_headers, get_body_text
from threat_classifier import classify_threat_intent
from forensics_core import compute_evidence_hashes, parse_relay_hops, classify_attribution_source
from origin_intel import analyze_origin
from report_generator import generate_pdf_report, generate_json_report
from attribution_graph import build_attribution_graph, find_campaign_clusters

def run_tests():
    print("=" * 60)
    print("STARTING PHISHGUARD END-TO-END VERIFICATION TEST")
    print("=" * 60)

    model = joblib.load("models/phishing_classifier.joblib")
    sample_files = [
        ("Demo 1: PayPal Phishing", "sample_emails/phishing_sample.eml"),
        ("Demo 2: Microsoft Alert", "sample_emails/phishing_sample_2_same_campaign.eml"),
        ("Demo 3: SBI KYC Banking Fraud", "sample_emails/sbi_kyc_fraud.eml"),
        ("Demo 4: BEC Payment Diversion", "sample_emails/bec_payment_diversion.eml"),
        ("Demo 5: Legitimate Partner", "sample_emails/legit_sample.eml"),
    ]

    history = []

    for name, path in sample_files:
        print(f"\n--- Testing: {name} ({path}) ---")
        assert os.path.exists(path), f"File {path} not found!"

        with open(path, "rb") as f:
            raw_bytes = f.read()

        msg = parse_eml_file(path)
        body = get_body_text(msg) or ""
        hashes = compute_evidence_hashes(raw_bytes)
        headers = analyze_headers(msg)
        threat = classify_threat_intent(body, headers.get("subject", ""))
        hops = parse_relay_hops(msg)
        origin = analyze_origin(headers.get("originating_ip"), headers.get("from_domain"))

        # ML
        pred = model.predict([body])[0]
        conf = model.predict_proba([body]).max()

        attribution = classify_attribution_source(
            headers["auth_results"],
            origin["geolocation"],
            origin["dns_intelligence"],
            threat["categories"]
        )

        print(f"  Subject: {headers.get('subject')}")
        print(f"  SHA-256: {hashes['sha256'][:16]}...")
        print(f"  SPF: {headers['auth_results']['spf']} | DKIM: {headers['auth_results']['dkim']} | DMARC: {headers['auth_results']['dmarc']}")
        print(f"  Originating IP: {headers.get('originating_ip')}")
        print(f"  Relay Hops: {len(hops)} hops reconstructed")
        print(f"  Threat Category: {threat['primary_threat']}")
        print(f"  ML Verdict: {pred} ({conf:.1%})")
        print(f"  Attribution Source: {attribution['source_type']}")

        # Build analysis dict for report test
        analysis_dict = {
            "case_id": f"PG-TEST-{len(history)+1}",
            "subject": headers.get("subject"),
            "from": headers.get("from"),
            "risk_score": 85 if pred == "phishing" else 5,
            "threat_category": threat["primary_threat"],
            "urgency_level": threat["urgency_level"],
            "attribution_source": attribution["source_type"],
            "originating_ip": headers.get("originating_ip"),
            "auth_results": headers["auth_results"],
            "geolocation": origin["geolocation"],
            "domain_age": origin["domain_age"],
            "evidence_hashes": hashes,
            "relay_hops": hops,
            "red_flags": headers["red_flags"] + threat["cues_detected"],
        }

        # PDF & JSON test
        pdf_buf = generate_pdf_report(analysis_dict)
        assert pdf_buf.getbuffer().nbytes > 1000, "PDF buffer empty!"
        json_out = generate_json_report(analysis_dict)
        assert len(json_out) > 200, "JSON report empty!"

        history.append({
            "id": analysis_dict["case_id"],
            "subject": headers.get("subject"),
            "from_domain": headers.get("from_domain"),
            "originating_ip": headers.get("originating_ip"),
            "risk_score": analysis_dict["risk_score"],
        })

    # Campaign correlation test
    print("\n--- Testing Attribution Graph & Campaign Clustering ---")
    G = build_attribution_graph(history)
    clusters = find_campaign_clusters(G)
    print(f"  Nodes: {G.number_of_nodes()}, Edges: {G.number_of_edges()}")
    print(f"  Detected Campaign Clusters: {clusters}")
    assert len(clusters) >= 1, "Expected at least 1 campaign cluster!"

    print("\n" + "=" * 60)
    print("ALL TESTS PASSED SUCCESSFULLY! PLATFORM READY FOR SIH DEMO.")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
