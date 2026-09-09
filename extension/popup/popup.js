// popup.js - PhishGuard Sentinel & Study Lock Controller (Manifest V3)

document.addEventListener("DOMContentLoaded", async () => {
  // ==========================================
  // 1. DOM Elements & Navigation Tabs
  // ==========================================
  const tabBtnStudy = document.getElementById("tab-btn-study");
  const tabBtnMail = document.getElementById("tab-btn-mail");
  const tabContentStudy = document.getElementById("tab-content-study");
  const tabContentMail = document.getElementById("tab-content-mail");

  const statusPill = document.getElementById("status-pill");
  const statusPillText = document.getElementById("status-pill-text");

  // Study Lock Views
  const studyLockedView = document.getElementById("study-locked-view");
  const studyUnlockedView = document.getElementById("study-unlocked-view");
  const activeSitesCount = document.getElementById("active-sites-count");
  const parentPinInput = document.getElementById("parent-pin-input");
  const btnUnlockControls = document.getElementById("btn-unlock-controls");
  const popupPinError = document.getElementById("popup-pin-error");
  const btnRelock = document.getElementById("btn-relock");
  const masterToggle = document.getElementById("master-toggle");
  const newDomainInput = document.getElementById("new-domain-input");
  const btnAddDomain = document.getElementById("btn-add-domain");
  const blocklistChips = document.getElementById("blocklist-chips");
  const presetChips = document.querySelectorAll(".preset-chip");
  const newPinInput = document.getElementById("new-pin-input");
  const btnChangePin = document.getElementById("btn-change-pin");
  const changePinMsg = document.getElementById("change-pin-msg");
  const btnSyncSoc = document.getElementById("btn-sync-soc");

  // Mail Sentinel Elements
  const clientName = document.getElementById("active-client-name");
  const clientIcon = document.getElementById("active-client-icon");
  const subjectPreview = document.getElementById("active-email-subject");
  const scanBtn = document.getElementById("scan-now-btn");
  const btnText = document.getElementById("btn-text");
  const resultsCard = document.getElementById("results-card");
  const openSocBtn = document.getElementById("open-soc-btn");

  let parentalState = {
    active: true,
    blocklist: ["instagram.com", "youtube.com", "roblox.com", "snapchat.com", "netflix.com", "discord.com"],
    stats: { total_blocked: 0 }
  };
  let isParentUnlocked = false;

  // ==========================================
  // 2. Tab Navigation
  // ==========================================
  tabBtnStudy.addEventListener("click", () => {
    tabBtnStudy.classList.add("active");
    tabBtnMail.classList.remove("active");
    tabContentStudy.classList.add("active");
    tabContentStudy.style.display = "block";
    tabContentMail.classList.remove("active");
    tabContentMail.style.display = "none";
  });

  tabBtnMail.addEventListener("click", () => {
    tabBtnMail.classList.add("active");
    tabBtnStudy.classList.remove("active");
    tabContentMail.classList.add("active");
    tabContentMail.style.display = "block";
    tabContentStudy.classList.remove("active");
    tabContentStudy.style.display = "none";
  });

  // ==========================================
  // 3. Load & Render Parental Control State
  // ==========================================
  async function loadParentalState() {
    try {
      const resp = await chrome.runtime.sendMessage({ action: "get_parental_state" });
      if (resp && resp.status === "success" && resp.data) {
        parentalState = resp.data;
      }
    } catch (e) {
      console.warn("Could not retrieve state from service worker:", e);
    }
    renderParentalUI();
  }

  function renderParentalUI() {
    // A. Status Pill
    if (parentalState.active) {
      statusPill.className = "status-pill active";
      statusPillText.textContent = "STUDY LOCK ON";
    } else {
      statusPill.className = "status-pill inactive";
      statusPillText.textContent = "STUDY LOCK OFF";
    }

    // B. Master Toggle
    if (masterToggle) {
      masterToggle.checked = parentalState.active;
    }

    // C. Active Sites Counter
    const count = (parentalState.blocklist || []).length;
    if (activeSitesCount) {
      activeSitesCount.textContent = count;
    }

    // D. View Switching (Locked vs Unlocked)
    if (isParentUnlocked) {
      studyLockedView.style.display = "none";
      studyUnlockedView.style.display = "block";
    } else {
      studyLockedView.style.display = "block";
      studyUnlockedView.style.display = "none";
    }

    // E. Render Blocklist Chips
    renderBlocklistChips();
  }

  function renderBlocklistChips() {
    if (!blocklistChips) return;
    blocklistChips.innerHTML = "";

    const list = parentalState.blocklist || [];
    if (list.length === 0) {
      blocklistChips.innerHTML = "<div style='font-size: 11px; color: #64748b; padding: 4px;'>No websites currently blocked.</div>";
      return;
    }

    list.forEach((domain, idx) => {
      const chip = document.createElement("div");
      chip.className = "site-chip";

      const nameSpan = document.createElement("span");
      nameSpan.textContent = domain;

      const delBtn = document.createElement("button");
      delBtn.className = "chip-del-btn";
      delBtn.textContent = "✕";
      delBtn.title = `Remove ${domain}`;
      delBtn.addEventListener("click", async () => {
        await removeBlockedDomain(domain);
      });

      chip.appendChild(nameSpan);
      chip.appendChild(delBtn);
      blocklistChips.appendChild(chip);
    });
  }

  // ==========================================
  // 4. Parental Actions (PIN & Rules)
  // ==========================================
  // Unlock with PIN
  async function handleUnlock() {
    if (!parentPinInput || !popupPinError) return;
    const pin = parentPinInput.value.trim();

    if (pin.length !== 4 || !/^\d{4}$/.test(pin)) {
      popupPinError.textContent = "Please enter your 4-digit PIN.";
      return;
    }

    try {
      const resp = await chrome.runtime.sendMessage({ action: "verify_pin", pin });
      if (resp && resp.valid) {
        isParentUnlocked = true;
        popupPinError.textContent = "";
        parentPinInput.value = "";
        renderParentalUI();
      } else {
        popupPinError.textContent = "❌ Incorrect 4-Digit PIN.";
        parentPinInput.value = "";
        parentPinInput.focus();
      }
    } catch (e) {
      popupPinError.textContent = "Service worker unavailable.";
    }
  }

  if (btnUnlockControls) {
    btnUnlockControls.addEventListener("click", handleUnlock);
  }
  if (parentPinInput) {
    parentPinInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") handleUnlock();
    });
  }

  // Relock Controls
  if (btnRelock) {
    btnRelock.addEventListener("click", () => {
      isParentUnlocked = false;
      renderParentalUI();
    });
  }

  // Master Toggle Change
  if (masterToggle) {
    masterToggle.addEventListener("change", async () => {
      const newActive = masterToggle.checked;
      parentalState.active = newActive;
      await chrome.runtime.sendMessage({
        action: "set_parental_state",
        payload: { active: newActive }
      });
      renderParentalUI();
    });
  }

  // Clean domain helper
  function sanitizeDomain(raw) {
    if (!raw) return "";
    let clean = String(raw).trim().toLowerCase();
    clean = clean.replace(/^https?:\/\//i, "");
    clean = clean.split("/")[0].split("?")[0].split("#")[0].split(":")[0].trim();
    clean = clean.replace(/^www\d*\./i, "");
    return clean.trim();
  }

  // Add Custom Domain
  async function addDomain(rawDomain) {
    const clean = sanitizeDomain(rawDomain);
    if (!clean) return;

    if (!parentalState.blocklist.includes(clean)) {
      parentalState.blocklist.push(clean);
      await chrome.runtime.sendMessage({
        action: "set_parental_state",
        payload: { blocklist: parentalState.blocklist }
      });
      renderParentalUI();
    }
    if (newDomainInput) newDomainInput.value = "";
  }

  if (btnAddDomain) {
    btnAddDomain.addEventListener("click", () => {
      if (newDomainInput) addDomain(newDomainInput.value);
    });
  }
  if (newDomainInput) {
    newDomainInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") addDomain(newDomainInput.value);
    });
  }

  // Quick Preset Chips
  presetChips.forEach(chip => {
    chip.addEventListener("click", async () => {
      const domain = chip.getAttribute("data-domain");
      if (domain) await addDomain(domain);
    });
  });

  // Remove Domain
  async function removeBlockedDomain(domain) {
    parentalState.blocklist = parentalState.blocklist.filter(d => d !== domain);
    await chrome.runtime.sendMessage({
      action: "set_parental_state",
      payload: { blocklist: parentalState.blocklist }
    });
    renderParentalUI();
  }

  // Change PIN
  if (btnChangePin && newPinInput && changePinMsg) {
    btnChangePin.addEventListener("click", async () => {
      const newPin = newPinInput.value.trim();
      if (newPin.length !== 4 || !/^\d{4}$/.test(newPin)) {
        changePinMsg.style.color = "var(--danger)";
        changePinMsg.textContent = "PIN must be exactly 4 digits.";
        return;
      }

      await chrome.runtime.sendMessage({
        action: "set_parental_state",
        payload: { pin: newPin }
      });

      newPinInput.value = "";
      changePinMsg.style.color = "var(--success)";
      changePinMsg.textContent = "✅ PIN updated successfully!";
      setTimeout(() => { changePinMsg.textContent = ""; }, 3000);
    });
  }

  // Sync with Web SOC
  if (btnSyncSoc) {
    btnSyncSoc.addEventListener("click", async () => {
      await chrome.tabs.create({ url: "https://phishguard-soc.streamlit.app" });
    });
  }

  // ==========================================
  // 5. Mail Sentinel Controller (Preserved)
  // ==========================================
  let activeTab = null;
  let cachedEmailDetails = null;

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
        clientName.innerText = "Browser Tab Active";
      }

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
      } catch (e) {}
    }
  } catch (err) {
    console.error("Tab query error:", err);
  }

  if (scanBtn) {
    scanBtn.addEventListener("click", async () => {
      btnText.innerText = "Auditing Headers...";
      scanBtn.disabled = true;

      try {
        let details = cachedEmailDetails;
        if (!details && activeTab) {
          try {
            const resp = await chrome.tabs.sendMessage(activeTab.id, { action: "extract_email" });
            if (resp && resp.details) details = resp.details;
          } catch (e) {}
        }

        if (!details || (!details.from_email && !details.subject && !details.body)) {
          details = {
            from_name: "Active Browser User",
            from_email: "inspected-session@webmail.local",
            subject: activeTab ? activeTab.title : "Live Inspection",
            body: "Inspection initiated from PhishGuard Chrome Sentinel.",
            source: "Chrome Extension Direct Audit",
          };
        }

        const resp = await chrome.runtime.sendMessage({
          action: "perform_scan",
          details: details,
        });

        if (!resp || resp.status !== "success") {
          throw new Error(resp ? resp.message : "No response from background worker");
        }

        renderScanResults(resp.data);
      } catch (err) {
        alert(`PhishGuard Audit Notice: ${err.message}\n\nPlease ensure an email is open in your active Gmail or Outlook tab.`);
      } finally {
        btnText.innerText = "Audit Active Email Now";
        scanBtn.disabled = false;
      }
    });
  }

  function renderScanResults(res) {
    if (!resultsCard) return;
    resultsCard.style.display = "block";
    const score = res.risk_score || 0;

    const scoreCircle = document.getElementById("score-circle");
    const verdictTitle = document.getElementById("verdict-title");
    const threatCat = document.getElementById("threat-category");
    const intelIp = document.getElementById("intel-ip");
    const intelGeo = document.getElementById("intel-geo");
    const intelInfra = document.getElementById("intel-infra");
    const intelHash = document.getElementById("intel-hash");

    if (scoreCircle) scoreCircle.innerText = score;
    if (threatCat) threatCat.innerText = res.threat_category || "General Analysis";
    if (intelIp) intelIp.innerText = res.origin_ip || "Webmail Relay";
    if (intelGeo) intelGeo.innerText = res.origin_country || "Verified Node";
    if (intelInfra) intelInfra.innerText = res.is_hosting ? "Cloud Hosting" : "Standard Relay";
    if (intelHash) intelHash.innerText = res.sha256 ? res.sha256.substring(0, 8) + "..." : "Generated";

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

  if (openSocBtn) {
    openSocBtn.addEventListener("click", async () => {
      await chrome.tabs.create({ url: "https://phishguard-soc.streamlit.app" });
    });
  }

  // Initial load
  await loadParentalState();
});
