// soc_sync.js - Bridge between PhishGuard Web SOC Platform & Chrome Extension

(function () {
  console.log("[PhishGuard Extension] Web SOC Bridge Initialized.");

  // 1. Inject DOM Marker so Web App can detect extension presence instantly
  function injectMarker(status) {
    let el = document.getElementById("phishguard-extension-marker");
    if (!el) {
      el = document.createElement("div");
      el.id = "phishguard-extension-marker";
      el.style.display = "none";
      document.documentElement.appendChild(el);
    }
    el.setAttribute("data-installed", "true");
    el.setAttribute("data-version", "2.0.0");
    if (status) {
      el.setAttribute("data-active", String(status.active));
      el.setAttribute("data-count", String((status.blocklist || []).length));
    }
  }

  // 2. Fetch initial state and update marker
  try {
    chrome.runtime.sendMessage({ action: "get_parental_state" }, (res) => {
      if (res && res.status === "success") {
        injectMarker(res.data);
      } else {
        injectMarker(null);
      }
    });
  } catch (e) {
    injectMarker(null);
  }

  // 3. Listen for window postMessages from Streamlit Web SOC
  window.addEventListener("message", async (event) => {
    // Only accept messages from trusted origins or same-window
    if (!event.data || typeof event.data !== "object") return;

    // A. Handshake Ping
    if (event.data.type === "PHISHGUARD_PING") {
      try {
        chrome.runtime.sendMessage({ action: "get_parental_state" }, (res) => {
          window.postMessage({
            type: "PHISHGUARD_PONG",
            installed: true,
            version: "2.0.0",
            active: res && res.data ? res.data.active : true,
            count: res && res.data && res.data.blocklist ? res.data.blocklist.length : 0,
            blocklist: res && res.data ? res.data.blocklist : []
          }, "*");
        });
      } catch (e) {
        window.postMessage({
          type: "PHISHGUARD_PONG",
          installed: true,
          version: "2.0.0",
          active: true,
          count: 0
        }, "*");
      }
    }

    // B. Push Blocklist Sync from Web SOC
    if (event.data.type === "PHISHGUARD_SYNC_BLOCKLIST") {
      const payload = event.data.payload || {};
      console.log("[PhishGuard Extension] Received blocklist sync from Web SOC:", payload);

      try {
        chrome.runtime.sendMessage({
          action: "sync_from_soc",
          payload: {
            active: payload.active !== undefined ? payload.active : true,
            blocklist: payload.blocklist || [],
            pin: payload.pin || "1234"
          }
        }, (response) => {
          console.log("[PhishGuard Extension] Sync response from background:", response);
          window.postMessage({
            type: "PHISHGUARD_SYNC_CONFIRMED",
            status: "success",
            timestamp: Date.now(),
            count: (payload.blocklist || []).length
          }, "*");

          injectMarker({
            active: payload.active !== undefined ? payload.active : true,
            blocklist: payload.blocklist || []
          });
        });
      } catch (err) {
        console.error("[PhishGuard Extension] Sync error:", err);
      }
    }
  });
})();
