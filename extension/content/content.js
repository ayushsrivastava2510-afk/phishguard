// content.js - PhishGuard Gmail & Outlook In-Page Scanner (Manifest V3)

console.log("[PhishGuard] Mail Sentinel content script active.");

function extractEmailDetails() {
  const isGmail = window.location.hostname.includes("mail.google.com");
  const isOutlook = window.location.hostname.includes("outlook.");

  let details = {
    from_name: "",
    from_email: "",
    to: "",
    subject: "",
    date: "",
    body: "",
    raw_headers: "",
    source: isGmail ? "Gmail Web" : (isOutlook ? "Outlook Web" : "Webmail"),
  };

  if (isGmail) {
    // Subject
    const subjEl = document.querySelector("h2.hP") || document.querySelector(".ha h2");
    if (subjEl) details.subject = subjEl.innerText.trim();

    // Sender
    const senderEl = document.querySelector("span.gD");
    if (senderEl) {
      details.from_name = senderEl.getAttribute("name") || senderEl.innerText.trim();
      details.from_email = senderEl.getAttribute("email") || "";
      if (!details.from_email) {
        const m = senderEl.innerText.match(/<([^>]+)>/);
        if (m) details.from_email = m[1];
      }
    }

    // Recipient
    const toEl = document.querySelector("span.g2") || document.querySelector("span.hb span[email]");
    if (toEl) {
      details.to = toEl.getAttribute("email") || toEl.innerText.trim();
    }

    // Date
    const dateEl = document.querySelector("span.g3[title]") || document.querySelector("span.g3");
    if (dateEl) {
      details.date = dateEl.getAttribute("title") || dateEl.innerText.trim();
    }

    // Body
    const bodyEls = document.querySelectorAll(".a3s.aiL, .ii.gt");
    if (bodyEls && bodyEls.length > 0) {
      // Pick the latest message in thread
      const lastBody = bodyEls[bodyEls.length - 1];
      details.body = lastBody.innerText.trim();
    }
  } else if (isOutlook) {
    // Subject
    const subjEl = document.querySelector('div[role="heading"][aria-level="2"]') || document.querySelector('div[aria-label*="Subject"]');
    if (subjEl) details.subject = subjEl.innerText.trim();

    // Sender
    const senderEl = document.querySelector('button[aria-label*="Sender"]') || document.querySelector('.personaTitle');
    if (senderEl) {
      details.from_name = senderEl.innerText.trim();
      const m = details.from_name.match(/<([^>]+)>/);
      if (m) details.from_email = m[1];
    }

    // Body
    const bodyEl = document.querySelector('div[aria-label="Message body"]') || document.querySelector('div[id*="UniqueMessageBody"]');
    if (bodyEl) details.body = bodyEl.innerText.trim();
  }

  // Fallback for subject from document title
  if (!details.subject) {
    const title = document.title;
    if (title && !title.startsWith("Inbox")) {
      details.subject = title.split(" - ")[0].trim();
    }
  }

  return details;
}

// Injects the sleek "Scan with PhishGuard" button in Gmail/Outlook
function injectScanButton() {
  const isGmail = window.location.hostname.includes("mail.google.com");
  
  if (isGmail) {
    // Check if button already injected
    if (document.getElementById("phishguard-injected-btn")) return;

    // Target Gmail action toolbar or subject header
    const targetContainer = document.querySelector(".nH.hx .gE.iv.gt") || 
                            document.querySelector(".ha") || 
                            document.querySelector(".ade");

    if (targetContainer) {
      const btn = document.createElement("button");
      btn.id = "phishguard-injected-btn";
      btn.className = "phishguard-scan-btn";
      btn.innerHTML = `
        <svg class="pg-shield-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="M9 12l2 2 4-4"/>
        </svg>
        <span>🛡️ Scan with PhishGuard</span>
      `;

      btn.addEventListener("click", handleInPageScan);
      targetContainer.appendChild(btn);
    }
  }
}

// Handles in-page scan click
async function handleInPageScan(e) {
  if (e) e.preventDefault();
  const btn = document.getElementById("phishguard-injected-btn");
  const originalText = btn ? btn.innerHTML : "";
  if (btn) {
    btn.innerHTML = "<span>⏳ Scanning PhishGuard SOC...</span>";
    btn.disabled = true;
  }

  try {
    const details = extractEmailDetails();
    if (!details.from_email && !details.subject && !details.body) {
      alert("PhishGuard: Please open an email first to perform a forensic audit.");
      if (btn) { btn.innerHTML = originalText; btn.disabled = false; }
      return;
    }

    // Dispatch via extension background service worker to bypass Mixed Content restrictions
    const response = await chrome.runtime.sendMessage({
      action: "perform_scan",
      details: details,
    });

    if (!response || response.status !== "success") {
      throw new Error(response ? response.message : "No response from background service worker");
    }

    renderInPageAlertCard(response.data);

  } catch (err) {
    console.error("[PhishGuard Error]", err);
    alert(`Could not connect to PhishGuard SOC Bridge at http://127.0.0.1:8765.\n\nMake sure PhishGuard SOC is running via RUN_PHISHGUARD.bat (http://localhost:8501)!\nError: ${err.message}`);
  } finally {
    if (btn) {
      btn.innerHTML = originalText;
      btn.disabled = false;
    }
  }
}

// Renders the alert card above email body
function renderInPageAlertCard(data) {
  // Remove existing alert if present
  const existing = document.getElementById("phishguard-alert-card");
  if (existing) existing.remove();

  const score = data.risk_score || 0;
  let alertType = "safe";
  let badgeColor = "#10b981";
  let verdictTitle = "VERIFIED SECURE";

  if (score >= 70) {
    alertType = "critical";
    badgeColor = "#ef4444";
    verdictTitle = "CRITICAL THREAT DETECTED";
  } else if (score >= 35) {
    alertType = "suspicious";
    badgeColor = "#f59e0b";
    verdictTitle = "SUSPICIOUS THREAT VECTOR";
  }

  const card = document.createElement("div");
  card.id = "phishguard-alert-card";
  card.className = `phishguard-alert-card phishguard-alert-${alertType}`;

  card.innerHTML = `
    <div class="pg-card-header">
      <div class="pg-card-title">
        <span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:${badgeColor};box-shadow:0 0 8px ${badgeColor};"></span>
        <span>PhishGuard SOC: ${verdictTitle} (Threat Score: ${score}/100)</span>
      </div>
      <button class="pg-close-btn" id="pg-card-close">&times;</button>
    </div>

    <div style="font-size: 12px; margin-bottom: 8px;">
      <b>Identified Threat:</b> <code style="color:${badgeColor}; font-weight:700;">${data.threat_category || "Standard Evaluation"}</code>
      &bull; <b>Verdict:</b> ${data.text_label ? data.text_label.toUpperCase() : "ANALYZED"}
    </div>

    <div class="pg-metrics-grid">
      <div class="pg-metric-box">
        <div class="pg-metric-label">Origin IP</div>
        <div class="pg-metric-value">${data.origin_ip || "Webmail Gateway"}</div>
      </div>
      <div class="pg-metric-box">
        <div class="pg-metric-label">Location</div>
        <div class="pg-metric-value">${data.origin_country || "Verified Node"}</div>
      </div>
      <div class="pg-metric-box">
        <div class="pg-metric-label">Infrastructure</div>
        <div class="pg-metric-value">${data.is_hosting ? "Cloud Datacenter" : "Standard Relay"}</div>
      </div>
      <div class="pg-metric-box">
        <div class="pg-metric-label">Evidence Hash</div>
        <div class="pg-metric-value">${data.sha256 ? data.sha256.substring(0, 10) + "..." : "Generated"}</div>
      </div>
    </div>

    <div style="display:flex; justify-content:space-between; align-items:center;">
      <button class="pg-launch-soc-btn" id="pg-open-soc-btn">
        <span>🚀 Launch 3D Forensic Investigation in SOC Dashboard</span>
      </button>
      <span style="font-size:10px; color:#94a3b8;">Section 65B BSA Certified Evidence</span>
    </div>
  `;

  // Attach event listeners
  card.querySelector("#pg-card-close").addEventListener("click", () => card.remove());
  card.querySelector("#pg-open-soc-btn").addEventListener("click", () => {
    chrome.runtime.sendMessage({
      action: "open_dashboard",
      url: `http://localhost:8501/?live=1`,
    });
  });

  // Inject above message body
  const bodyContainer = document.querySelector(".nH.hx") || document.querySelector(".a3s.aiL") || document.body;
  if (bodyContainer.parentNode) {
    bodyContainer.parentNode.insertBefore(card, bodyContainer);
  } else {
    document.body.appendChild(card);
  }
}

// Listen for messages from extension popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "extract_email") {
    const details = extractEmailDetails();
    sendResponse({ details });
    return true;
  }
});

// Periodic observer to inject button as user clicks between emails
setInterval(injectScanButton, 1500);
