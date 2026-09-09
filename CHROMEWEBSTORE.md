# Chrome Web Store Listing & Metadata: PhishGuard Sentinel & Study Lock

This document serves as the single source of truth for the Chrome Web Store listing, permissions justifications, privacy disclosures, and review readiness for **PhishGuard Sentinel — Security & Study Lock**.

---

## 1. Store Listing Metadata

- **Extension Name**: PhishGuard Sentinel — Security & Study Lock
- **Short Description (max 132 chars)**:
  Zero-tolerance parental control study lock & autonomous AI phishing sentinel. Blocks web distractions at network level.
- **Detailed Description**:
  ```markdown
  Protect children and students during study hours with zero-tolerance network-level distraction blocking, and defend against phishing threats in real time with PhishGuard Sentinel.

  🔒 PARENTAL CONTROL & STUDY LOCK:
  • Zero-Tolerance Network Blocking: Uses Manifest V3 Declarative Net Request to block distractions (Instagram, YouTube, Roblox, Discord, Snapchat, TikTok, etc.) before connection is made.
  • PIN-Protected Administrative Shield: Children cannot modify rules, disable Study Mode, or bypass restrictions without the parent's secret 4-digit PIN.
  • Immediate Block Screen: Displays a focused, distraction-free study screen with inspirational student motivation and quick links to safe educational resources (Khan Academy, NCERT, Wikipedia).
  • Parent Emergency Override: Allows parents to enter their PIN directly on the block screen for a temporary 15-minute study break.
  • Web SOC Synchronization: Easily sync blocklists with the PhishGuard Central SOC Platform.

  🛡️ EMAIL & PHISHING DEFENSE:
  • 1-Click Forensic Scanner: Audits open emails in Gmail and Outlook for credential harvesting, banking KYC scams, and business email compromise.
  • Real-Time Threat Intel: Discloses origin IP, relay geolocation, infrastructure type, and cryptographic chain-of-custody.

  ⚡ 100% PRIVATE & OFFLINE-READY:
  • All DNS and URL evaluations happen directly on your device.
  • Zero telemetry, zero tracking, and zero selling of user browsing data.
  ```
- **Category**: Productivity / Security
- **Language**: English
- **Pricing**: Free

---

## 2. Permissions Justification (Review Team Compliance)

Every permission declared in `manifest.json` serves an explicit, necessary purpose:

| Permission | Technical Need | Plain-English Review Justification |
| :--- | :--- | :--- |
| **`declarativeNetRequest`** | Network-level request interception | Required to enforce the parent's Study Mode blocklist at the browser network layer, blocking HTTP/HTTPS connections and redirecting navigation before any web page content or media can render. |
| **`storage`** | `chrome.storage.local` | Required to persistently save the parent's custom blocklist, parental control active state, hashed/stored 4-digit PIN, and temporary break timestamps across browser restarts without an external server. |
| **`tabs`** | Tab query and redirection | Required to redirect tabs to the safe `blocked.html` screen when a restricted domain is visited, and to inspect tab domains when running email forensics. |
| **`webNavigation`** | Pre-navigation event hooks | Required as a secondary safety net (`onBeforeNavigate`) to intercept navigation attempts to blocked domains (including subdomains) before DNS lookup begins. |
| **`scripting`** | Dynamic script injection | Used to inspect active mail client DOM when user explicitly requests an email audit. |
| **`alarms`** | Scheduled wakeups | Required to automatically expire temporary 15-minute study break exemptions and re-arm network blocks. |
| **Host Permission: `<all_urls>`** | Dynamic rule scope | Required because parents can specify arbitrary websites and entertainment domains (e.g. `instagram.com`, `roblox.com`, `twitch.tv`) to block during study hours. Without host permissions, Declarative Net Request dynamic rules cannot block arbitrary domains. |
| **Host Permission: `http://localhost:8501/*` & `https://phishguard-soc.streamlit.app/*`** | SOC Bridge | Required to enable 1-click synchronization of the parent's blocklist directly from the PhishGuard Web SOC dashboard into the extension. |

---

## 3. Privacy & Data Handling Disclosure

- **Single Purpose Policy**: The extension serves a single unified objective: safeguarding the user through parental study distraction blocking and email cyber fraud detection.
- **Data Collection**: **None**. PhishGuard does not collect, transmit, store, or sell personal browsing history, credentials, or child activity.
- **Local Execution**: All blocklist comparisons and forensic rule evaluations are executed 100% locally within the user's browser runtime.

---

## 4. Version History

- **v2.0.0 (Current)**:
  - Added Manifest V3 `declarativeNetRequest` dynamic filtering engine.
  - Added Parental Control Study Lock with 4-digit PIN security gate.
  - Added high-contrast Cyber Study Block Screen (`blocked.html`) with student motivational quotes and parent override.
  - Added real-time Web SOC synchronization bridge (`soc_sync.js`).
  - Added synchronous DOM blanking enforcer (`enforcer.js`).
  - Dual-mode popup interface supporting both Study Lock and Mail Sentinel.
- **v1.0.0**:
  - Initial release with Gmail & Outlook forensic threat scanner.
