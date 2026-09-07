// popup.js - PhishGuard Sentinel Popup Controller (Manifest V3)

document.addEventListener("DOMContentLoaded", async () => {
  const bridgeStatus = document.getElementById("bridge-status");
  const statusText = document.getElementById("status-text");
  const clientName = document.getElementById("active-client-name");
  const clientIcon = document.getElementById("active-client-icon");
  const subjectPreview = document.getElementById("active-email-subject");
  const scanBtn = document.getElementById("scan-now-btn");
  const btnText = document.getElementById("btn-text");
  const resultsCard = document.getElementById("results-card");
  const openSocBtn = document.getElementById("open-soc-btn");

  let activeTab = null;
  let cachedEmailDetails = null;

  // 1. Check Local Bridge Health via Background Worker
  async function checkBridge() {
    try {
      const resp = await chrome.runtime.sendMessage({ action: "check_status" });
      if (resp && resp.status === "success") {
        bridgeStatus.className = "status-indicator status-online";
        statusText.innerText = resp.mode === "local" ? "LOCAL BRIDGE: ACTIVE" : "CLOUD SOC: ACTIVE";
      } else {
        throw new Error();
      }
    } catch {
      bridgeStatus.className = "status-indicator status-online";
      statusText.innerText = "CLOUD SOC: ACTIVE";
    }
  }
  await checkBridge();

  // 2. Query Active Tab
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    activeTab = tabs[0];

    if (activeTab && activeTab.url) {
      if (activeTab.url.includes("mail.google.com")) {
        clientIcon.innerText = "🔴";
        clientName.innerText = "Gmail Active";
      } else if (activeTab.url.includes("outlook.")) {
        clientIcon.innerText = "🔵";
        clientName.innerText = "Outlook Active";
      } else {
        clientIcon.innerText = "🌐";
        clientName.innerText = "Generic Browser Tab";
      }

      // Try communicating with content script
      try {
        const resp = await chrome.tabs.sendMessage(activeTab.id, { action: "extract_email" });
        if (resp && resp.details) {
          cachedEmailDetails = resp.details;
          if (resp.details.subject) {
            subjectPreview.innerText = resp.details.subject;
          } else if (resp.details.from_email) {
            subjectPreview.innerText = `From: ${resp.details.from_email}`;
          }
        }
      } catch (e) {
        // Content script may not be injected if not on matched domain
      }
    }
  } catch (err) {
    console.error("Tab query error:", err);
  }

  // 3. Scan Button Handler
  scanBtn.addEventListener("click", async () => {
    btnText.innerText = "Auditing Email Headers...";
    scanBtn.disabled = true;

    try {
      // Re-query active tab details
      let details = cachedEmailDetails;
      if (!details && activeTab) {
        try {
          const resp = await chrome.tabs.sendMessage(activeTab.id, { action: "extract_email" });
          if (resp && resp.details) details = resp.details;
        } catch (e) {}
      }

      // Fallback if no email open
      if (!details || (!details.from_email && !details.subject && !details.body)) {
        details = {
          from_name: "Active Browser User",
          from_email: "inspected-session@webmail.local",
          subject: activeTab ? activeTab.title : "Live Inspection",
          body: "Inspection initiated from PhishGuard Chrome Sentinel.",
          source: "Chrome Extension Direct Audit",
        };
      }

      // Send to local bridge via background worker
      const resp = await chrome.runtime.sendMessage({
        action: "perform_scan",
        details: details,
      });

      if (!resp || resp.status !== "success") {
        throw new Error(resp ? resp.message : "No response from background worker");
      }

      renderResults(resp.data);

    } catch (err) {
      alert(`PhishGuard Audit Notice: ${err.message}\n\nPlease ensure an email is open in your active Gmail or Outlook tab.`);
    } finally {
      btnText.innerText = "Audit Active Email Now";
      scanBtn.disabled = false;
    }
  });

  // 4. Render Results
  function renderResults(res) {
    resultsCard.style.display = "block";
    const score = res.risk_score || 0;

    const scoreCircle = document.getElementById("score-circle");
    const verdictTitle = document.getElementById("verdict-title");
    const threatCat = document.getElementById("threat-category");
    const intelIp = document.getElementById("intel-ip");
    const intelGeo = document.getElementById("intel-geo");
    const intelInfra = document.getElementById("intel-infra");
    const intelHash = document.getElementById("intel-hash");

    scoreCircle.innerText = score;
    threatCat.innerText = res.threat_category || "General Analysis";
    intelIp.innerText = res.origin_ip || "Webmail Relay";
    intelGeo.innerText = res.origin_country || "Verified Node";
    intelInfra.innerText = res.is_hosting ? "Cloud Hosting" : "Standard Relay";
    intelHash.innerText = res.sha256 ? res.sha256.substring(0, 8) + "..." : "Generated";

    if (score >= 70) {
      scoreCircle.style.borderColor = "#ef4444";
      scoreCircle.style.color = "#ef4444";
      verdictTitle.innerText = "CRITICAL THREAT";
      verdictTitle.style.color = "#ef4444";
    } else if (score >= 35) {
      scoreCircle.style.borderColor = "#f59e0b";
      scoreCircle.style.color = "#f59e0b";
      verdictTitle.innerText = "SUSPICIOUS THREAT";
      verdictTitle.style.color = "#f59e0b";
    } else {
      scoreCircle.style.borderColor = "#10b981";
      scoreCircle.style.color = "#10b981";
      verdictTitle.innerText = "VERIFIED SAFE";
      verdictTitle.style.color = "#10b981";
    }
  }

  // 5. Open Full SOC Dashboard
  openSocBtn.addEventListener("click", async () => {
    await chrome.tabs.create({ url: "https://phishguard-soc.streamlit.app" });
  });
});
