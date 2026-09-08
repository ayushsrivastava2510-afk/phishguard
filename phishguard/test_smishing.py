"""
test_smishing.py
----------------
Automated test suite for the PhishGuard Smishing Forensic Engine.
Validates all 5 real-world attack scenarios and regulatory compliance.
"""

import os
import sys

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from smishing_analyzer import analyze_smishing_message, SMISHING_BENCHMARKS


def run_smishing_tests():
    print("=" * 65)
    print("STARTING PHISHGUARD SMISHING SENTINEL AUTOMATED VERIFICATION")
    print("=" * 65)

    passed = 0
    total = len(SMISHING_BENCHMARKS)

    for idx, sc in enumerate(SMISHING_BENCHMARKS, start=1):
        print(f"\n--- Testing #{idx}: {sc['title']} ---")
        sender = sc["sender_id"]
        text = sc["text"]

        res = analyze_smishing_message(sender, text)

        print(f"  Sender ID       : {res['sender_id']}")
        print(f"  DLT Compliance  : {res['sender_info']['is_dlt_compliant']} ({res['sender_info']['sender_type']})")
        print(f"  Threat Category : {res['threat_category']}")
        print(f"  Risk Score      : {res['risk_score']} / 100")
        print(f"  Verdict         : {res['verdict']}")
        print(f"  Red Flags Count : {len(res['all_red_flags'])}")

        # Verification Assertions
        if sc["id"] == "sbi_kyc_sms":
            assert res["risk_score"] >= 80, f"Expected critical risk for SBI KYC, got {res['risk_score']}"
            assert res["verdict"] == "CRITICAL SMISHING THREAT"
            assert not res["sender_info"]["is_dlt_compliant"]
            assert len(res["url_info"]["shortened_urls"]) > 0

        elif sc["id"] == "electricity_sms":
            assert res["risk_score"] >= 75, f"Expected high risk for Electricity Cut, got {res['risk_score']}"
            assert res["verdict"] == "CRITICAL SMISHING THREAT"
            assert "Electricity" in res["threat_category"]

        elif sc["id"] == "echallan_apk_sms":
            assert res["risk_score"] >= 85, f"Expected critical risk for APK Trojan, got {res['risk_score']}"
            assert res["verdict"] == "CRITICAL SMISHING THREAT"
            assert len(res["url_info"]["apk_droppers"]) > 0

        elif sc["id"] == "job_scam_sms":
            assert res["risk_score"] >= 50, f"Expected elevated risk for Task Fraud, got {res['risk_score']}"
            assert not res["sender_info"]["is_dlt_compliant"]
            assert "Cross-Border" in res["sender_info"]["sender_type"]

        elif sc["id"] == "legit_otp_sms":
            assert res["risk_score"] <= 25, f"Expected low safe risk for Authentic OTP, got {res['risk_score']}"
            assert res["verdict"] == "VERIFIED SAFE SMS"
            assert res["sender_info"]["is_dlt_compliant"]
            assert len(res["url_info"]["urls"]) == 0

        # Assert that Chakshu complaint draft is generated
        assert "INCIDENT REPORT" in res["chakshu_draft"]
        assert res["case_id"] in res["chakshu_draft"]

        print(f"  ✅ Test #{idx} Passed Successfully.")
        passed += 1

    print("\n" + "=" * 65)
    print(f"ALL {passed}/{total} SMISHING FORENSIC VERIFICATIONS PASSED WITH 100% ACCURACY!")
    print("=" * 65)


if __name__ == "__main__":
    run_smishing_tests()
