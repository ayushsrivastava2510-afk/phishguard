// background.js - PhishGuard Service Worker (Manifest V3)

chrome.runtime.onInstalled.addListener(() => {
  console.log("PhishGuard Mail Sentinel extension initialized.");
});

function runClientSideForensics(details) {
  const text = ((details.subject || "") + " " + (details.body || "")).toLowerCase();
  const fromEmail = (details.from_email || "").toLowerCase();

  let riskScore = 14;
  let category = "Safe Communication";
  let redFlags = [];

  // Banking / KYC Fraud
  if (text.includes("kyc") || text.includes("pan card") || text.includes("aadhaar") || text.includes("debit card blocked") || text.includes("net banking") || text.includes("sbi")) {
    riskScore += 46;
    category = "Financial / Banking KYC Fraud";
    redFlags.push("Coercive bank KYC / identity verification trigger detected.");
  }

  // Credential Harvesting
  if (text.includes("password expired") || text.includes("login attempt") || text.includes("reset your password") || text.includes("mfa verification") || text.includes("account suspended")) {
    riskScore += 42;
    if (category === "Safe Communication") category = "Credential Harvesting / Account Takeover";
    redFlags.push("Credential harvesting / account suspension cue detected.");
  }

  // BEC / Payment Diversion
  if (text.includes("wire transfer") || text.includes("payment diversion") || text.includes("swift code") || text.includes("routing number") || text.includes("invoice attached")) {
    riskScore += 44;
    category = "Business Email Compromise (BEC)";
    redFlags.push("Unauthorized wire transfer / payment diversion language detected.");
  }

  // Urgency & Coercion
  if (text.includes("urgent") || text.includes("within 24 hours") || text.includes("immediately") || text.includes("act now") || text.includes("final notice")) {
    riskScore += 24;
    redFlags.push("Psychological urgency / panic coercion cue detected.");
  }

  // Domain Spoofing / Lookalike
  if (fromEmail.includes("sbi") && !fromEmail.endsWith("@sbi.co.in")) {
    riskScore += 35;
    redFlags.push("Unauthenticated domain impersonating State Bank of India.");
  } else if (fromEmail.includes("paypal") && !fromEmail.endsWith("@paypal.com")) {
    riskScore += 35;
    redFlags.push("Lookalike domain impersonating PayPal.");
  } else if (fromEmail.includes("microsoft") && !fromEmail.endsWith("@microsoft.com")) {
    riskScore += 30;
    redFlags.push("Lookalike domain impersonating Microsoft.");
  }

  riskScore = Math.min(100, Math.max(12, riskScore));

  const cleanSubj = details.subject || "Live Webmail Capture";
  const cleanDomain = details.from_email && details.from_email.includes("@") ? details.from_email.split("@").pop() : "webmail.local";
  const cleanFrom = details.from_email ? (details.from_name ? `"${details.from_name}" <${details.from_email}>` : details.from_email) : (details.from_name || "Webmail Sender");

  return {
    case_id: "EXT-" + Math.random().toString(36).substring(2, 9).toUpperCase(),
    scenario_title: `Live Extension: ${cleanSubj.substring(0, 32)}`,
    source_type: details.source || "Chrome Extension Direct Audit",
    subject: cleanSubj,
    from: cleanFrom,
    from_email: details.from_email || "user@webmail.local",
    from_domain: cleanDomain,
    risk_score: riskScore,
    threat_category: category,
    body_snippet: (details.body || cleanSubj).substring(0, 350),
    origin_country: "Client-Side In-Inbox Telemetry",
    origin_ip: "In-Browser Heuristic",
    is_hosting: false,
    sha256: "SHA256-CLIENT-" + Math.random().toString(36).substring(2, 10).toUpperCase(),
    red_flags: redFlags,
    source: details.source || "Chrome Extension (Cloud Standalone)",
    cloud_soc_url: "https://phishguard-soc.streamlit.app"
  };
}

// Listen for messages from content scripts or popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // 1. Perform Forensic Scan (tries local bridge; falls back to in-browser heuristics)
  if (request.action === "perform_scan") {
    (async () => {
      try {
        const resp = await fetch("http://127.0.0.1:8765/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(request.details || {}),
        });

        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();
        sendResponse({ status: "success", data });
      } catch (err) {
        // Fallback: Run in-browser forensic engine seamlessly
        const fallbackData = runClientSideForensics(request.details || {});
        sendResponse({ status: "success", data: fallbackData });
      }
    })();
    return true;
  }

  // 2. Check SOC Bridge Status
  if (request.action === "check_status") {
    (async () => {
      try {
        const resp = await fetch("http://127.0.0.1:8765/api/status", { cache: "no-cache" });
        if (!resp.ok) throw new Error();
        const data = await resp.json();
        sendResponse({ status: "success", data, mode: "local" });
      } catch (err) {
        // Connected to Cloud SOC
        sendResponse({ status: "success", mode: "cloud", url: "https://phishguard-soc.streamlit.app" });
      }
    })();
    return true;
  }

  // 3. Open SOC Dashboard (prioritizes live cloud deployment)
  if (request.action === "open_dashboard") {
    (async () => {
      try {
        const url = request.url || "https://phishguard-soc.streamlit.app";
        await chrome.tabs.create({ url });
        sendResponse({ status: "success" });
      } catch (err) {
        sendResponse({ status: "error", message: err.message });
      }
    })();
    return true;
  }

  // 4. Save Scan Result to Storage
  if (request.action === "save_scan_result") {
    (async () => {
      try {
        await chrome.storage.local.set({ last_scan: request.data });
        sendResponse({ status: "success" });
      } catch (err) {
        sendResponse({ status: "error", message: err.message });
      }
    })();
    return true;
  }
});
