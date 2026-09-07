// background.js - PhishGuard Service Worker (Manifest V3)

chrome.runtime.onInstalled.addListener(() => {
  console.log("PhishGuard Mail Sentinel extension initialized.");
});

// Listen for messages from content scripts or popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // 1. Perform Forensic Scan (bypasses webpage HTTPS Mixed Content restrictions)
  if (request.action === "perform_scan") {
    (async () => {
      try {
        const resp = await fetch("http://127.0.0.1:8765/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(request.details || {}),
        });

        if (!resp.ok) {
          throw new Error(`SOC Bridge returned HTTP ${resp.status}`);
        }

        const data = await resp.json();
        sendResponse({ status: "success", data });
      } catch (err) {
        console.error("[PhishGuard Background Scan Error]", err);
        sendResponse({ status: "error", message: err.message });
      }
    })();
    return true; // Keep channel open for async sendResponse
  }

  // 2. Check SOC Bridge Status
  if (request.action === "check_status") {
    (async () => {
      try {
        const resp = await fetch("http://127.0.0.1:8765/api/status", { cache: "no-cache" });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();
        sendResponse({ status: "success", data });
      } catch (err) {
        sendResponse({ status: "error", message: err.message });
      }
    })();
    return true;
  }

  // 3. Open SOC Dashboard
  if (request.action === "open_dashboard") {
    (async () => {
      try {
        const url = request.url || "http://localhost:8501/?live=1";
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
