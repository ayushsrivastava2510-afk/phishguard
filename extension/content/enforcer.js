// enforcer.js - Synchronous Zero-Tolerance Study Lock Content Enforcer
// Runs at document_start across all webpages to prevent any DOM rendering on blocked sites

(function () {
  function sanitizeDomain(raw) {
    if (!raw) return "";
    let clean = String(raw).trim().toLowerCase();
    clean = clean.replace(/^https?:\/\//i, "");
    clean = clean.split("/")[0].split("?")[0].split("#")[0].split(":")[0].trim();
    clean = clean.replace(/^www\d*\./i, "");
    return clean.trim();
  }

  const rawHost = window.location.hostname.toLowerCase();
  const currentCleanHost = sanitizeDomain(rawHost);
  if (!currentCleanHost) return;

  // Query local storage directly for instant evaluation
  try {
    chrome.storage.local.get(["parental_control_active", "parent_custom_blocklist", "temporary_exemptions"], (data) => {
      const isActive = data.parental_control_active !== false; // Default is active
      if (!isActive) return;

      const blocklist = data.parent_custom_blocklist || [
        "instagram.com",
        "youtube.com",
        "roblox.com",
        "snapchat.com",
        "netflix.com",
        "discord.com"
      ];

      // Check for temporary parent study break exemption
      const exemptions = data.temporary_exemptions || {};
      if (exemptions[currentCleanHost] && exemptions[currentCleanHost] > Date.now()) {
        console.log(`[PhishGuard Study Lock] Temporary break active for ${currentCleanHost}`);
        return;
      }

      // Match domain or subdomain
      let isBlocked = false;
      let matchedRule = "";

      for (const rule of blocklist) {
        if (!rule) continue;
        const cleanRule = sanitizeDomain(rule);
        if (!cleanRule) continue;

        if (
          rawHost === cleanRule ||
          currentCleanHost === cleanRule ||
          rawHost.endsWith("." + cleanRule) ||
          currentCleanHost.endsWith("." + cleanRule) ||
          cleanRule.endsWith("." + currentCleanHost)
        ) {
          isBlocked = true;
          matchedRule = cleanRule;
          break;
        }
      }

      if (isBlocked) {
        console.warn(`[PhishGuard Study Lock] ZERO-TOLERANCE BLOCK TRIGGERED for ${currentCleanHost} (rule: ${matchedRule})`);

        // 1. Immediately halt page loading and wipe DOM
        try {
          window.stop();
        } catch (e) {}

        if (document.documentElement) {
          document.documentElement.innerHTML = "";
        }

        // 2. Redirect to dedicated Study Lock Screen
        const redirectUrl = chrome.runtime.getURL("blocked.html?blocked=" + encodeURIComponent(matchedRule || currentCleanHost));
        window.location.replace(redirectUrl);
      }
    });
  } catch (err) {
    // Non-fatal if extension context invalidated
  }
})();
