/**
 * SENTINEL-X Chrome Extension Service Worker (Manifest V3)
 * Handles side-panel enablement, badge updates, and message routing.
 */

chrome.runtime.onInstalled.addListener(() => {
  console.log('[SENTINEL-X] Security Companion installed.');
  
  // Set default settings in storage if not already present
  chrome.storage.local.get(['backendUrl', 'apiKey'], (result) => {
    if (!result.backendUrl) {
      chrome.storage.local.set({ backendUrl: 'http://127.0.0.1:8000' });
    }
  });

  // Enable side panel on action click if API is supported
  if (chrome.sidePanel && chrome.sidePanel.setPanelBehavior) {
    chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: false }).catch(() => {
      // Graceful fallback
    });
  }
});

// Listener for messages from popup or content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'PING_BACKEND') {
    chrome.storage.local.get(['backendUrl', 'apiKey'], async (result) => {
      const url = result.backendUrl || 'http://127.0.0.1:8000';
      try {
        const resp = await fetch(`${url}/api/v1/health`, { method: 'GET' });
        const data = await resp.json();
        sendResponse({ success: resp.ok, status: resp.status, data });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    });
    return true; // Keep message channel open for async response
  }
});
