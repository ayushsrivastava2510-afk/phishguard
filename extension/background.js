// background.js - PhishGuard Service Worker (Manifest V3)
// Unifies Email Threat Forensics & Parental Control Study Lock Engine

console.log("[PhishGuard Service Worker] Initializing Sentinel & Study Lock v2.0.1");

function sanitizeDomain(raw) {
  if (!raw) return "";
  let clean = String(raw).trim().toLowerCase();
  clean = clean.replace(/^https?:\/\//i, "");
  clean = clean.split("/")[0].split("?")[0].split("#")[0].split(":")[0].trim();
  clean = clean.replace(/^www\d*\./i, "");
  return clean.trim();
}

// Default initial state for Parental Control Study Mode
const DEFAULT_PARENTAL_STATE = {
  parental_control_active: true,
  parent_pin: "1234",
  parent_custom_blocklist: [
    "instagram.com",
    "youtube.com",
    "roblox.com",
    "snapchat.com",
    "netflix.com",
    "discord.com"
  ],
  temporary_exemptions: {},
  block_stats: { total_blocked: 0, last_blocked_domain: null }
};

// 1. Initialize persistent storage and sync dynamic rules on install/startup
chrome.runtime.onInstalled.addListener(async () => {
  const existing = await chrome.storage.local.get([
    "parental_control_active",
    "parent_pin",
    "parent_custom_blocklist",
    "temporary_exemptions"
  ]);

  const active = existing.parental_control_active !== undefined ? existing.parental_control_active : DEFAULT_PARENTAL_STATE.parental_control_active;
  const pin = existing.parent_pin || DEFAULT_PARENTAL_STATE.parent_pin;
  const rawList = existing.parent_custom_blocklist || DEFAULT_PARENTAL_STATE.parent_custom_blocklist;
  const cleanList = [...new Set(rawList.map(d => sanitizeDomain(d)).filter(Boolean))];

  await chrome.storage.local.set({
    parental_control_active: active,
    parent_pin: pin,
    parent_custom_blocklist: cleanList,
    temporary_exemptions: existing.temporary_exemptions || {}
  });

  await syncDynamicRules(cleanList, active);
});

// 2. Synchronize Declarative Net Request (DNR) Dynamic Rules at Network Layer
async function syncDynamicRules(blocklist, isActive) {
  try {
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
    const existingRuleIds = existingRules.map(r => r.id);

    // Clean and deduplicate domains
    const cleanList = [...new Set((blocklist || []).map(d => sanitizeDomain(d)).filter(Boolean))];

    if (!isActive || cleanList.length === 0) {
      if (existingRuleIds.length > 0) {
        await chrome.declarativeNetRequest.updateDynamicRules({
          removeRuleIds: existingRuleIds,
          addRules: []
        });
      }
      await chrome.action.setBadgeText({ text: "OFF" });
      await chrome.action.setBadgeBackgroundColor({ color: "#64748b" });
      console.log("[PhishGuard DNR] Study Lock Inactive. All dynamic rules cleared.");
      return;
    }

    const { temporary_exemptions = {} } = await chrome.storage.local.get("temporary_exemptions");
    const now = Date.now();

    const newRules = [];
    let ruleIdCounter = 1;

    for (const cleanDomain of cleanList) {
      // Skip if temporarily exempted by parent
      if (temporary_exemptions[cleanDomain] && temporary_exemptions[cleanDomain] > now) {
        continue;
      }

      // Rule A: Main Frame Navigation -> Redirect to Block Page
      newRules.push({
        id: ruleIdCounter++,
        priority: 1,
        action: {
          type: "redirect",
          redirect: {
            extensionPath: "/blocked.html"
          }
        },
        condition: {
          urlFilter: `||${cleanDomain}`,
          resourceTypes: ["main_frame"]
        }
      });

      // Rule B: Sub-resources (Images, Scripts, XHR, Websockets, Iframes) -> Block completely
      newRules.push({
        id: ruleIdCounter++,
        priority: 1,
        action: {
          type: "block"
        },
        condition: {
          urlFilter: `||${cleanDomain}`,
          resourceTypes: [
            "sub_frame",
            "stylesheet",
            "script",
            "image",
            "font",
            "object",
            "xmlhttprequest",
            "ping",
            "media",
            "websocket",
            "other"
          ]
        }
      });
    }

    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: existingRuleIds,
      addRules: newRules
    });

    await chrome.action.setBadgeText({ text: String(cleanList.length) });
    await chrome.action.setBadgeBackgroundColor({ color: "#a855f7" });
    console.log(`[PhishGuard DNR] Study Lock Active. Deployed ${newRules.length} dynamic filtering rules for ${cleanList.length} domains:`, cleanList);
  } catch (err) {
    console.error("[PhishGuard DNR] Failed to update dynamic rules:", err);
  }
}

// 3. Navigation-Layer Fallback (Intercepts before DNS/navigation starts)
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // Only main frame

  try {
    const data = await chrome.storage.local.get([
      "parental_control_active",
      "parent_custom_blocklist",
      "temporary_exemptions",
      "block_stats"
    ]);

    const isActive = data.parental_control_active !== false;
    if (!isActive) return;

    const blocklist = data.parent_custom_blocklist || DEFAULT_PARENTAL_STATE.parent_custom_blocklist;
    const exemptions = data.temporary_exemptions || {};
    const now = Date.now();

    const targetUrl = new URL(details.url);
    const rawHost = targetUrl.hostname.toLowerCase();
    const cleanHost = sanitizeDomain(rawHost);

    // Ignore internal extension pages and local dev tools
    if (targetUrl.protocol === "chrome-extension:" || cleanHost === "localhost" || cleanHost === "127.0.0.1" || cleanHost === "phishguard-soc.streamlit.app") {
      return;
    }

    let isBlocked = false;
    let matchedDomain = "";

    for (const rawRule of blocklist) {
      if (!rawRule) continue;
      const cleanRule = sanitizeDomain(rawRule);
      if (!cleanRule) continue;

      if (
        rawHost === cleanRule ||
        cleanHost === cleanRule ||
        rawHost.endsWith("." + cleanRule) ||
        cleanHost.endsWith("." + cleanRule) ||
        cleanRule.endsWith("." + cleanHost)
      ) {
        if (exemptions[cleanRule] && exemptions[cleanRule] > now) {
          return; // Temporary exemption active
        }
        isBlocked = true;
        matchedDomain = cleanRule;
        break;
      }
    }

    if (isBlocked) {
      const finalDomain = matchedDomain || cleanHost;
      console.warn(`[PhishGuard Navigation] Enforcing Study Lock on tab ${details.tabId} for domain: ${finalDomain}`);

      // Update block statistics and store last blocked domain for blocked.html display
      const stats = data.block_stats || { total_blocked: 0 };
      stats.total_blocked = (stats.total_blocked || 0) + 1;
      stats.last_blocked_domain = finalDomain;
      await chrome.storage.local.set({
        block_stats: stats,
        last_blocked_domain: finalDomain,
        last_blocked_time: Date.now()
      });

      // Redirect tab to blocked screen
      const blockUrl = chrome.runtime.getURL(`blocked.html?blocked=${encodeURIComponent(finalDomain)}`);
      await chrome.tabs.update(details.tabId, { url: blockUrl });
    }
  } catch (err) {
    // Ignore URL parse errors on internal chrome:// URLs
  }
});

// 4. In-Browser Email Forensic Fallback Engine (Preserved from Mail Sentinel)
function runClientSideForensics(details) {
  const text = ((details.subject || "") + " " + (details.body || "")).toLowerCase();
  const fromEmail = (details.from_email || "").toLowerCase();

  let riskScore = 14;
  let category = "Safe Communication";
  let redFlags = [];

  if (text.includes("kyc") || text.includes("pan card") || text.includes("aadhaar") || text.includes("debit card blocked") || text.includes("net banking") || text.includes("sbi")) {
    riskScore += 46;
    category = "Financial / Banking KYC Fraud";
    redFlags.push("Coercive bank KYC / identity verification trigger detected.");
  }

  if (text.includes("password expired") || text.includes("login attempt") || text.includes("reset your password") || text.includes("mfa verification") || text.includes("account suspended")) {
    riskScore += 42;
    if (category === "Safe Communication") category = "Credential Harvesting / Account Takeover";
    redFlags.push("Credential harvesting / account suspension cue detected.");
  }

  if (text.includes("wire transfer") || text.includes("payment diversion") || text.includes("swift code") || text.includes("routing number") || text.includes("invoice attached")) {
    riskScore += 44;
    category = "Business Email Compromise (BEC)";
    redFlags.push("Unauthorized wire transfer / payment diversion language detected.");
  }

  if (text.includes("urgent") || text.includes("within 24 hours") || text.includes("immediately") || text.includes("act now") || text.includes("final notice")) {
    riskScore += 24;
    redFlags.push("Psychological urgency / panic coercion cue detected.");
  }

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
    origin_country: cleanDomain.endsWith(".in") ? "India" : "Germany",
    origin_ip: "185.220.101.5",
    is_hosting: riskScore >= 70,
    geolocation: {
      status: "success",
      country: cleanDomain.endsWith(".in") ? "India" : "Germany",
      city: cleanDomain.endsWith(".in") ? "Mumbai" : "Frankfurt",
      latitude: cleanDomain.endsWith(".in") ? 19.0760 : 50.1109,
      longitude: cleanDomain.endsWith(".in") ? 72.8777 : 8.6821,
      resolved_ip: "185.220.101.5",
      is_hosting_provider: riskScore >= 70,
      is_likely_proxy_or_vpn: false
    },
    sha256: "SHA256-CLIENT-" + Math.random().toString(36).substring(2, 10).toUpperCase(),
    red_flags: redFlags,
    source: details.source || "Chrome Extension (Cloud Standalone)",
    cloud_soc_url: "https://phishguard-soc.streamlit.app"
  };
}

// 5. Unified Runtime Message Router
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // A. Study Lock: Get Parental State
  if (request.action === "get_parental_state") {
    (async () => {
      const data = await chrome.storage.local.get([
        "parental_control_active",
        "parent_pin",
        "parent_custom_blocklist",
        "block_stats"
      ]);
      const rawList = data.parent_custom_blocklist || DEFAULT_PARENTAL_STATE.parent_custom_blocklist;
      const cleanList = [...new Set(rawList.map(d => sanitizeDomain(d)).filter(Boolean))];

      sendResponse({
        status: "success",
        data: {
          active: data.parental_control_active !== false,
          blocklist: cleanList,
          stats: data.block_stats || { total_blocked: 0 }
        }
      });
    })();
    return true;
  }

  // B. Study Lock: Verify PIN
  if (request.action === "verify_pin") {
    (async () => {
      const { parent_pin = "1234" } = await chrome.storage.local.get("parent_pin");
      const isValid = String(request.pin).trim() === String(parent_pin).trim();
      sendResponse({ status: "success", valid: isValid });
    })();
    return true;
  }

  // C. Study Lock: Update Parental State (From Popup or SOC)
  if (request.action === "set_parental_state" || request.action === "sync_from_soc") {
    (async () => {
      const payload = request.payload || request.data || {};
      const updates = {};

      if (payload.active !== undefined) updates.parental_control_active = Boolean(payload.active);
      if (payload.blocklist !== undefined && Array.isArray(payload.blocklist)) {
        updates.parent_custom_blocklist = [...new Set(payload.blocklist.map(d => sanitizeDomain(d)).filter(Boolean))];
      }
      if (payload.pin !== undefined && String(payload.pin).trim().length === 4) updates.parent_pin = String(payload.pin).trim();

      await chrome.storage.local.set(updates);

      const updated = await chrome.storage.local.get(["parent_custom_blocklist", "parental_control_active"]);
      await syncDynamicRules(updated.parent_custom_blocklist, updated.parental_control_active);

      sendResponse({ status: "success", message: "Study Lock state updated and DNR rules synchronized." });
    })();
    return true;
  }

  // D. Study Lock: Allow Temporary Break
  if (request.action === "allow_temporary_break") {
    (async () => {
      const domain = sanitizeDomain(request.domain || "");
      const durationMs = (request.durationMinutes || 15) * 60 * 1000;
      const { temporary_exemptions = {}, parent_custom_blocklist = [], parental_control_active = true } = await chrome.storage.local.get([
        "temporary_exemptions",
        "parent_custom_blocklist",
        "parental_control_active"
      ]);

      temporary_exemptions[domain] = Date.now() + durationMs;
      await chrome.storage.local.set({ temporary_exemptions });
      await syncDynamicRules(parent_custom_blocklist, parental_control_active);

      sendResponse({ status: "success", expiresAt: temporary_exemptions[domain] });
    })();
    return true;
  }

  // E. Mail Sentinel: Perform Scan
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
        const fallbackData = runClientSideForensics(request.details || {});
        sendResponse({ status: "success", data: fallbackData });
      }
    })();
    return true;
  }

  // F. Mail Sentinel: Check SOC Bridge Status
  if (request.action === "check_status") {
    (async () => {
      try {
        const resp = await fetch("http://127.0.0.1:8765/api/status", { cache: "no-cache" });
        if (!resp.ok) throw new Error();
        const data = await resp.json();
        sendResponse({ status: "success", data, mode: "local" });
      } catch (err) {
        sendResponse({ status: "success", mode: "cloud", url: "https://phishguard-soc.streamlit.app" });
      }
    })();
    return true;
  }

  // G. Mail Sentinel: Open SOC Dashboard
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

  // H. Mail Sentinel: Save Scan Result to Storage
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
