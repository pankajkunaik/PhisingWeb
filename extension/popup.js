// Backend URL — configurable via chrome.storage or defaults to localhost
const DEFAULT_BACKEND_URL = "http://localhost:8000";
let BACKEND_URL = DEFAULT_BACKEND_URL;

// Load stored backend URL and auth token from chrome.storage
async function loadSettings() {
  if (typeof chrome !== "undefined" && chrome.storage) {
    return new Promise((resolve) => {
      chrome.storage.local.get(["backend_url", "auth_token"], (result) => {
        if (result.backend_url) BACKEND_URL = result.backend_url;
        resolve(result.auth_token || null);
      });
    });
  }
  return null;
}


document.addEventListener("DOMContentLoaded", async () => {
  const currentUrlEl = document.getElementById("current-url");
  const scanBtn = document.getElementById("scan-btn");
  const dashboardBtn = document.getElementById("dashboard-btn");
  
  const statusDot = document.getElementById("status-dot");
  const statusText = document.getElementById("status-text");
  
  const riskContainer = document.getElementById("risk-score-container");
  const riskScoreVal = document.getElementById("risk-score-value");
  const riskBadge = document.getElementById("risk-badge");
  
  // Diags
  const sslIcon = document.getElementById("diag-ssl-icon");
  const sslText = document.getElementById("diag-ssl-text");
  
  const whoisIcon = document.getElementById("diag-whois-icon");
  const whoisText = document.getElementById("diag-whois-text");
  
  const feedIcon = document.getElementById("diag-feed-icon");
  const feedText = document.getElementById("diag-feed-text");
  
  const typoIcon = document.getElementById("diag-typo-icon");
  const typoText = document.getElementById("diag-typo-text");

  let activeTabUrl = "";

  // 1. Get current tab URL
  if (typeof chrome !== "undefined" && chrome.tabs) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        activeTabUrl = tabs[0].url;
        currentUrlEl.textContent = activeTabUrl;
        
        // Auto check if URL is standard web page
        if (!activeTabUrl.startsWith("http://") && !activeTabUrl.startsWith("https://")) {
          currentUrlEl.textContent = "Cannot scan this page type";
          scanBtn.disabled = true;
          statusText.textContent = "Unsupported Page";
        }
      }
    });
  } else {
    // Development mockup fallback
    activeTabUrl = "https://paypal-security-update.com/login";
    currentUrlEl.textContent = activeTabUrl;
  }

  // 2. Scan Button click
  scanBtn.addEventListener("click", async () => {
    if (!activeTabUrl) return;
    
    // Reset UI state
    statusDot.className = "dot gray";
    statusText.textContent = "Scanning...";
    scanBtn.disabled = true;
    riskContainer.classList.add("hidden");
    
    // Set pending statuses
    setDiagnosticPending();

    try {
      const response = await fetch(`${BACKEND_URL}/api/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ url: activeTabUrl })
      });

      if (!response.ok) {
        throw new Error("Scan request failed");
      }

      const result = await response.json();
      
      // Update UI with results
      displayResults(result);
      
    } catch (error) {
      console.error(error);
      statusText.textContent = "Server Offline";
      statusDot.className = "dot gray";
      scanBtn.disabled = false;
      alert("PhishGuard AI Backend is offline. Please make sure the FastAPI server is running at http://localhost:8000.");
    }
  });

  // 3. Dashboard Button click
  dashboardBtn.addEventListener("click", () => {
    if (typeof chrome !== "undefined" && chrome.tabs) {
      chrome.tabs.create({ url: "http://localhost:3000" });
    } else {
      window.open("http://localhost:3000", "_blank");
    }
  });

  function setDiagnosticPending() {
    const icons = [sslIcon, whoisIcon, feedIcon, typoIcon];
    const texts = [sslText, whoisText, feedText, typoText];
    
    icons.forEach(i => i.textContent = "⏳");
    texts.forEach(t => {
      t.textContent = "Checking...";
      t.className = "diag-status";
    });
  }

  function displayResults(result) {
    scanBtn.disabled = false;
    
    // 1. Core rating
    const score = Math.round(result.risk_score);
    const pred = result.prediction; // Safe, Suspicious, Phishing
    
    riskScoreVal.textContent = score;
    riskBadge.textContent = pred;
    riskBadge.className = `badge ${pred.toLowerCase()}`;
    riskContainer.classList.remove("hidden");
    
    // 2. Status Dot
    if (pred === "Safe") {
      statusDot.className = "dot green";
      statusText.textContent = "Secure Site";
    } else if (pred === "Suspicious") {
      statusDot.className = "dot yellow";
      statusText.textContent = "Suspicious Page";
    } else {
      statusDot.className = "dot red";
      statusText.textContent = "Phishing Warning!";
    }
    
    // 3. SSL Diagnostic
    const sslValid = result.ssl_info.valid && !result.ssl_info.error;
    if (sslValid) {
      sslIcon.textContent = "✅";
      sslText.textContent = "HTTPS Valid";
      sslText.className = "diag-status success";
    } else {
      sslIcon.textContent = "❌";
      sslText.textContent = "Insecure";
      sslText.className = "diag-status danger";
    }
    
    // 4. WHOIS Age Diagnostic
    const ageDays = result.whois_info.domain_age_days;
    if (ageDays >= 90) {
      whoisIcon.textContent = "✅";
      whoisText.textContent = "Established";
      whoisText.className = "diag-status success";
    } else {
      whoisIcon.textContent = "⚠️";
      whoisText.textContent = "New Domain";
      whoisText.className = "diag-status warning";
    }
    
    // 5. Threat feeds Diagnostic
    const feedFlagged = result.threat_feeds.flagged;
    if (!feedFlagged) {
      feedIcon.textContent = "✅";
      feedText.textContent = "Clean";
      feedText.className = "diag-status success";
    } else {
      feedIcon.textContent = "❌";
      feedText.textContent = "Blacklisted";
      feedText.className = "diag-status danger";
    }
    
    // 6. Typosquatting Diagnostic
    const isTypo = result.reasons.some(r => r.toLowerCase().includes("typosquatting"));
    if (!isTypo) {
      typoIcon.textContent = "✅";
      typoText.textContent = "Legitimate";
      typoText.className = "diag-status success";
    } else {
      typoIcon.textContent = "❌";
      typoText.textContent = "Impersonation";
      typoText.className = "diag-status danger";
    }
  }
});
