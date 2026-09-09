// soc_sync.js - Bridge between PhishGuard Web SOC Platform & Chrome Extension
// Automatically syncs custom parental blocklists in real time with zero manual effort

(function () {
  console.log("[PhishGuard Extension] Web SOC Bridge Active.");

  let lastSyncedPayloadString = "";

  function sanitizeDomain(raw) {
    if (!raw) return "";
    let clean = String(raw).trim().toLowerCase();
    clean = clean.replace(/^https?:\/\//i, "");
    clean = clean.split("/")[0].split("?")[0].split("#")[0].split(":")[0].trim();
    clean = clean.replace(/^www\d*\./i, "");
    return clean.trim();
  }

  // 1. Inject DOM Marker so Web App knows extension is present
  function injectMarker(status) {
    try {
      let el = document.getElementById("phishguard-extension-marker");
      if (!el && document.body) {
        el = document.createElement("div");
        el.id = "phishguard-extension-marker";
        el.style.display = "none";
        document.body.appendChild(el);
      }
      if (el) {
        el.setAttribute("data-installed", "true");
        el.setAttribute("data-version", "2.0.0");
        if (status) {
          el.setAttribute("data-active", String(status.active));
          el.setAttribute("data-count", String((status.blocklist || []).length));
        }
      }
    } catch (e) {}
  }

  // 2. Fetch initial state
  try {
    chrome.runtime.sendMessage({ action: "get_parental_state" }, (res) => {
      if (res && res.status === "success") {
        injectMarker(res.data);
      }
    });
  } catch (e) {}

  // 3. Process and Dispatch Sync to Background Worker
  function pushSync(active, rawBlocklist, pin) {
    if (!Array.isArray(rawBlocklist)) return;

    const cleanBlocklist = [...new Set(rawBlocklist.map(d => sanitizeDomain(d)).filter(Boolean))];
    const signature = JSON.stringify({ active: Boolean(active), blocklist: cleanBlocklist, pin: String(pin || "1234") });

    if (signature === lastSyncedPayloadString) {
      return; // Already in sync, avoid duplicate DNR calls
    }

    lastSyncedPayloadString = signature;
    console.log(`[PhishGuard Extension] Auto-syncing ${cleanBlocklist.length} custom domains to Study Lock:`, cleanBlocklist);

    try {
      chrome.runtime.sendMessage({
        action: "sync_from_soc",
        payload: {
          active: Boolean(active),
          blocklist: cleanBlocklist,
          pin: String(pin || "1234")
        }
      }, (response) => {
        injectMarker({ active, blocklist: cleanBlocklist });

        // Update bridge element attribute if present
        const bridgeEl = document.getElementById("phishguard-parental-bridge");
        if (bridgeEl) {
          bridgeEl.setAttribute("data-extension-synced", "true");
          bridgeEl.setAttribute("data-synced-count", String(cleanBlocklist.length));
        }
      });
    } catch (err) {
      console.warn("[PhishGuard Extension] Service worker message failed:", err);
    }
  }

  // 4. Poll DOM Bridge for Instant Reactivity
  function checkDomBridge() {
    const bridgeEl = document.getElementById("phishguard-parental-bridge");
    if (bridgeEl) {
      const activeAttr = bridgeEl.getAttribute("data-active");
      const blocklistAttr = bridgeEl.getAttribute("data-blocklist");
      const pinAttr = bridgeEl.getAttribute("data-pin") || "1234";

      if (blocklistAttr) {
        try {
          const parsed = JSON.parse(blocklistAttr);
          const active = activeAttr === "true" || activeAttr === true;
          pushSync(active, parsed, pinAttr);
        } catch (e) {}
      }
    }
  }

  // Set up polling interval + MutationObserver
  setInterval(checkDomBridge, 500);

  if (window.MutationObserver && document.documentElement) {
    const observer = new MutationObserver(() => {
      checkDomBridge();
    });
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["data-blocklist", "data-active"]
    });
  }

  // 5. Listen for window postMessages (from Streamlit iframe or top window)
  window.addEventListener("message", (event) => {
    if (!event.data || typeof event.data !== "object") return;

    // Ping / Pong
    if (event.data.type === "PHISHGUARD_PING") {
      try {
        chrome.runtime.sendMessage({ action: "get_parental_state" }, (res) => {
          const payload = {
            type: "PHISHGUARD_PONG",
            installed: true,
            version: "2.0.0",
            active: res && res.data ? res.data.active : true,
            count: res && res.data && res.data.blocklist ? res.data.blocklist.length : 0,
            blocklist: res && res.data ? res.data.blocklist : []
          };
          window.postMessage(payload, "*");
          if (window.parent && window.parent !== window) window.parent.postMessage(payload, "*");
        });
      } catch (e) {}
    }

    // Direct Push Message
    if (event.data.type === "PHISHGUARD_SYNC_BLOCKLIST") {
      const payload = event.data.payload || {};
      pushSync(payload.active, payload.blocklist, payload.pin);
    }
  });
})();
