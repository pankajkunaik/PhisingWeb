// Background service worker for PhishGuard AI extension
chrome.runtime.onInstalled.addListener(() => {
  console.log("PhishGuard AI Threat Detector Extension installed.");
});

// Listener for future background scanning options
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getScanStatus") {
    // Background scans could be orchestrated here
    sendResponse({ status: "active" });
  }
  return true;
});
