// blocked.js - Enforces Study Lock Screen & Handles Parent Override

const STUDY_QUOTES = [
  "\"Focus on your goals. Every distraction avoided today is an achievement tomorrow.\"",
  "\"The secret of getting ahead is getting started. Stay locked in on your studies!\"",
  "\"Self-discipline is the bridge between goals and accomplishments.\"",
  "\"Eliminate distractions until only progress remains. Your future self will thank you.\"",
  "\"Great things come from hard work and perseverance. Stay on track!\""
];

document.addEventListener("DOMContentLoaded", async () => {
  // 1. Parse Blocked URL / Domain from Query Parameters
  const params = new URLSearchParams(window.location.search);
  let blockedTarget = params.get("blocked") || params.get("url") || "Distraction Website";

  // Clean domain display
  try {
    if (blockedTarget.startsWith("http://") || blockedTarget.startsWith("https://")) {
      const parsed = new URL(blockedTarget);
      blockedTarget = parsed.hostname;
    }
  } catch (e) {}

  blockedTarget = blockedTarget.replace(/^www\./i, "");
  const domainEl = document.getElementById("blocked-domain");
  if (domainEl) {
    domainEl.textContent = blockedTarget;
  }

  // 2. Random Study Quote
  const quoteEl = document.getElementById("quote-text");
  if (quoteEl) {
    const randomQuote = STUDY_QUOTES[Math.floor(Math.random() * STUDY_QUOTES.length)];
    quoteEl.textContent = randomQuote;
  }

  // 3. Parent Override Accordion
  const toggleBtn = document.getElementById("override-toggle");
  const overrideBody = document.getElementById("override-body");
  const toggleArrow = document.getElementById("toggle-arrow");
  const pinInput = document.getElementById("override-pin");
  const submitPinBtn = document.getElementById("btn-submit-override");
  const pinFeedback = document.getElementById("pin-feedback");

  if (toggleBtn && overrideBody && toggleArrow) {
    toggleBtn.addEventListener("click", () => {
      const isVisible = overrideBody.style.display === "block";
      overrideBody.style.display = isVisible ? "none" : "block";
      toggleArrow.textContent = isVisible ? "▼" : "▲";
      if (!isVisible && pinInput) {
        pinInput.focus();
      }
    });
  }

  // 4. Submit PIN for Override
  async function handlePinVerification() {
    if (!pinInput || !pinFeedback) return;
    const pin = pinInput.value.trim();

    if (pin.length !== 4 || !/^\d{4}$/.test(pin)) {
      pinFeedback.className = "pin-feedback error";
      pinFeedback.textContent = "Please enter a valid 4-digit numeric PIN.";
      return;
    }

    try {
      const response = await chrome.runtime.sendMessage({
        action: "verify_pin",
        pin: pin
      });

      if (response && response.valid) {
        pinFeedback.className = "pin-feedback success";
        pinFeedback.textContent = "✅ Parent PIN Verified! Temporary 15-minute access granted. Redirecting...";

        // Send temporary break exemption to service worker
        await chrome.runtime.sendMessage({
          action: "allow_temporary_break",
          domain: blockedTarget,
          durationMinutes: 15
        });

        setTimeout(() => {
          let originalUrl = params.get("blocked") || params.get("url");
          if (!originalUrl || !originalUrl.startsWith("http")) {
            originalUrl = "https://" + blockedTarget;
          }
          window.location.href = originalUrl;
        }, 1200);
      } else {
        pinFeedback.className = "pin-feedback error";
        pinFeedback.textContent = "❌ Incorrect Parent PIN. Access remains locked.";
        pinInput.value = "";
        pinInput.focus();
      }
    } catch (err) {
      pinFeedback.className = "pin-feedback error";
      pinFeedback.textContent = "Error verifying PIN. Please try from the extension icon.";
    }
  }

  if (submitPinBtn) {
    submitPinBtn.addEventListener("click", handlePinVerification);
  }

  if (pinInput) {
    pinInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        handlePinVerification();
      }
    });
  }
});
