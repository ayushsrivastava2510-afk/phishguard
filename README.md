# 🛡️ PhishGuard Mail Sentinel & Autonomous Forensic SOC

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://streamlit.io)
[![Python Version](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Hackathon](https://img.shields.io/badge/Smart%20India%20Hackathon-2026-orange.svg)](https://www.sih.gov.in/)
[![Team](https://img.shields.io/badge/Team-Binary%20Battalion-purple.svg)]()

> **"From In-Inbox Threat Interception to Section 65B Bharatiya Sakshya Adhiniyam Digital Evidence in Under 2 Seconds"**

---

## 📌 Overview

Over **91% of successful cyber breaches and financial frauds in India** originate from a single weaponized email. Traditional spam filters act as passive black boxes that hide critical evidence, while enterprise security gateways cost lakhs of rupees without generating Indian court-admissible forensic documentation.

**PhishGuard** bridges the gap between everyday citizens and cyber law enforcement with a dual-tier architecture:
1. **In-Inbox Chrome Sentinel:** 1-click `"🛡️ Scan with PhishGuard"` button injected directly inside **Gmail** and **Outlook Web** — zero file uploads required.
2. **Autonomous Cyber Forensic SOC:** Deep-inspection platform executing **NLP semantic urgency analysis, cryptographic DNS audits (SPF/DKIM/DMARC), 3D global origin geolocation flight arcs, graph-theory syndicate clustering**, and automated **Section 65B BSA legal dossier generation**.

---

## 🌟 Key Features

| Capability | What It Does | Why It Wins |
| :--- | :--- | :--- |
| **🛡️ 1-Click In-Inbox Sentinel** | Scans live emails directly in Gmail / Outlook DOM | Zero friction for non-technical citizens |
| **🧠 AI Semantic NLP Classifier** | Detects panic coercion, fake KYC blocks & executive wire fraud | Catches zero-day social engineering attacks |
| **🌐 3D Origin Flight Trajectory** | Reconstructs relay hops & maps physical server coordinates | Visualizes physical attacker origin in 3D |
| **🕸️ Campaign Syndicate Graph** | Uses graph theory to link isolated emails sharing rogue IPs/ASNs | Unmasks organized transnational crime rings |
| **⚖️ Section 65B BSA Court Dossier** | Generates tamper-evident SHA-256 sealed PDF reports | Ready for immediate police FIR & magistrate review |
| **⚡ 1-Click Automated Playbooks** | Generates instant firewall rules (iptables, Cisco ASA) | Stops attacks across enterprise networks in seconds |

---

## 🚀 Live Demo & Interactive Scenarios

The platform includes 5 built-in, 1-click real-world threat scenarios for instant demonstration:
* **🚨 SBI Banking KYC Scam:** Panicking victims with a 24-hour account freeze notice coercing Aadhaar & PAN input.
* **🚨 PayPal Phishing:** Typosquatted lookalike domain (`paypa1.com`) with broken cryptographic SPF/DKIM records.
* **🚨 Microsoft 365 Attack:** Impersonated cloud login sharing the **exact same bulletproof hosting IP** (`45.155.204.12`) with the PayPal attack (instantly unmasked by the Campaign Syndicate Graph!).
* **⚠️ Executive BEC Wire Diversion:** CFO impersonation attempting an urgent offshore wire transfer to a foreign IBAN.
* **🟢 Legitimate Corporate Mail:** Fully authenticated baseline email passing 100% of cryptographic audits.

---

## 🏗️ System Architecture & 5-Step Forensic Pipeline

```
[1. Ingestion Layer]        Chrome Extension DOM Extractor OR RFC 5322 EML File
                                                │
                                                ▼
[2. Evidence Sealing]       Instant SHA-256 & MD5 Cryptographic Chain of Custody Hashing
                                                │
                                                ▼
[3. Cryptographic Audit]    Automated DNS Resolution: SPF, DKIM Signatures & DMARC Alignment
                                                │
                                                ▼
[4. AI NLP & 3D Geo-Trace]  Scikit-Learn Intent Scoring + Primary MX Gateway IP Coordinates
                                                │
                                                ▼
[5. Attribution & Output]   NetworkX Syndicate Clustering + 1-Click Court PDF (Section 65B BSA)
```

---

## 💻 Quickstart Guide (Local Development)

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/phishguard-soc.git
cd phishguard-soc
```

### 2. Set Up Virtual Environment & Dependencies
```bash
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 3. Launch PhishGuard
* **Windows (1-Click Batch):**
  Double click `RUN_PHISHGUARD.bat`
* **Or via Terminal:**
  ```bash
  streamlit run app.py
  ```
The SOC dashboard will launch automatically at `http://localhost:8501`.

---

## 🧩 Installing the Chrome Extension

1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **"Developer mode"** in the top-right corner.
3. Click **"Load unpacked"**.
4. Select the `extension/` folder in this repository.
5. Open [Gmail](https://mail.google.com) or [Outlook Web](https://outlook.live.com), click on any email, and see the **"🛡️ Scan with PhishGuard"** button appear automatically!

---

## 🏛️ Sovereign Legal & Regulatory Compliance

* **Section 65B Bharatiya Sakshya Adhiniyam (BSA, 2023):** Automates mandatory electronic evidence certification and tamper-evident SHA-256 cryptographic sealing.
* **Information Technology Act, 2000:** Maps evidentiary findings to Section 43 (Data Damage), Section 66C (Identity Theft), and Section 66D (Cheating by Personation).
* **CERT-In Directives:** Standardized machine-readable JSON IOC package export for national threat sharing.
* **IETF RFCs:** RFC 5322 (Internet Message Format), RFC 7208 (SPF), RFC 6376 (DKIM), and RFC 7489 (DMARC).
* **ISO/IEC 27037:** Digital evidence collection, preservation, and chain-of-custody integrity.

---

## 👥 Team "Binary Battalion"

Developed for **Smart India Hackathon (SIH 2026)** under the **Cybersecurity / Digital Forensics** division.

* **Team Name:** Binary Battalion
* **Category:** Software
* **Project:** PhishGuard Mail Sentinel

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
