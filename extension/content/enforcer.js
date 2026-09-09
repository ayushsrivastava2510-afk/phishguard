// enforcer.js - Synchronous Zero-Tolerance Study Lock Content Enforcer
// Runs at document_start across all webpages to prevent any DOM rendering on blocked sites

(function () {
  const currentHost = window.location.hostname.toLowerCase().replace(/^www\./, "");
  if (!currentHost) return;

  // Query local storage directly for instant, synchronous-like evaluation
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
      if (exemptions[currentHost] && exemptions[currentHost] > Date.now()) {
        console.log(`[PhishGuard Study Lock] Temporary break active for ${currentHost}`);
        return;
      }

      // Match domain or subdomain
      let isBlocked = false;
      let matchedRule = "";

      for (const rule of blocklist) {
        if (!rule) continue;
        const cleanRule = rule.toLowerCase().replace(/^https?:\/\//, "").split("/")[0].replace(/^www\./, "").trim();
        if (!cleanRule) continue;

        if (currentHost === cleanRule || currentHost.endsWith("." + cleanRule)) {
          isBlocked = true;
          matchedRule = cleanRule;
          break;
        }
      }

      if (isBlocked) {
        console.warn(`[PhishGuard Study Lock] ZERO-TOLERANCE BLOCK TRIGGERED for ${currentHost} (rule: ${matchedRule})`);

        // 1. Immediately halt page loading and wipe DOM
        try {
          window.stop();
        } catch (e) {}

        if (document.documentElement) {
          document.documentElement.innerHTML = "";
        }

        // 2. Redirect to dedicated Study Lock Screen
        const redirectUrl = chrome.runtime.getURL("blocked.html?blocked=" + encodeURIComponent(currentHost));
        window.location.replace(redirectUrl);
      }
    });
  } catch (err) {
    // Non-fatal if extension context invalidated
  }
})();
