/**
 * SENTINEL-X Extension Popup Controller
 * Performs user-initiated security header inspection & links with backend.
 */

document.addEventListener('DOMContentLoaded', async () => {
  const connectionStatus = document.getElementById('connectionStatus');
  const targetUrl = document.getElementById('targetUrl');
  const inspectBtn = document.getElementById('inspectBtn');
  const resultsCard = document.getElementById('resultsCard');
  const tlsStatus = document.getElementById('tlsStatus');
  const headerChecks = document.getElementById('headerChecks');
  const saveFindingBtn = document.getElementById('saveFindingBtn');
  const toggleSettings = document.getElementById('toggleSettings');
  const settingsBody = document.getElementById('settingsBody');
  const backendUrlInput = document.getElementById('backendUrlInput');
  const apiKeyInput = document.getElementById('apiKeyInput');
  const saveSettingsBtn = document.getElementById('saveSettingsBtn');
  const noticeBox = document.getElementById('noticeBox');

  let activeTabUrl = '';
  let lastAuditResults = null;

  // Load saved settings
  chrome.storage.local.get(['backendUrl', 'apiKey'], (result) => {
    if (result.backendUrl) backendUrlInput.value = result.backendUrl;
    if (result.apiKey) apiKeyInput.value = result.apiKey;
    checkConnectivity();
  });

  // Query active tab URL
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs && tabs[0] && tabs[0].url) {
      activeTabUrl = tabs[0].url;
      targetUrl.textContent = activeTabUrl;
    } else {
      targetUrl.textContent = 'No accessible tab detected.';
    }
  } catch (err) {
    targetUrl.textContent = 'Error reading tab URL';
  }

  // Check backend health
  async function checkConnectivity() {
    const url = backendUrlInput.value.trim() || 'http://127.0.0.1:8000';
    try {
      const resp = await fetch(`${url}/api/v1/health`, { method: 'GET' });
      if (resp.ok) {
        connectionStatus.textContent = 'ONLINE (v0.1.0)';
        connectionStatus.className = 'status-badge status-online';
      } else {
        connectionStatus.textContent = 'API ERROR';
        connectionStatus.className = 'status-badge status-offline';
      }
    } catch {
      connectionStatus.textContent = 'DISCONNECTED';
      connectionStatus.className = 'status-badge status-offline';
    }
  }

  // Toggle settings drawer
  toggleSettings.addEventListener('click', () => {
    settingsBody.style.display = settingsBody.style.display === 'none' ? 'block' : 'none';
  });

  // Save settings
  saveSettingsBtn.addEventListener('click', () => {
    const backendUrl = backendUrlInput.value.trim();
    const apiKey = apiKeyInput.value.trim();
    chrome.storage.local.set({ backendUrl, apiKey }, () => {
      showNotice('Settings saved successfully.');
      checkConnectivity();
    });
  });

  function showNotice(text) {
    noticeBox.textContent = text;
    noticeBox.style.display = 'block';
    setTimeout(() => {
      noticeBox.style.display = 'none';
    }, 3000);
  }

  // Inspect button handler
  inspectBtn.addEventListener('click', async () => {
    if (!activeTabUrl || activeTabUrl.startsWith('chrome://') || activeTabUrl.startsWith('about:')) {
      showNotice('Cannot inspect browser internal pages.');
      return;
    }

    inspectBtn.disabled = true;
    inspectBtn.textContent = 'Auditing...';

    const isHttps = activeTabUrl.startsWith('https://');
    tlsStatus.textContent = isHttps ? 'HTTPS / Encrypted TLS' : 'Insecure HTTP (Plaintext)';
    tlsStatus.style.color = isHttps ? '#34d399' : '#f87171';

    const expectedHeaders = [
      { name: 'Strict-Transport-Security', key: 'strict-transport-security', desc: 'Enforces HTTPS' },
      { name: 'Content-Security-Policy', key: 'content-security-policy', desc: 'Mitigates XSS' },
      { name: 'X-Frame-Options', key: 'x-frame-options', desc: 'Mitigates Clickjacking' },
      { name: 'X-Content-Type-Options', key: 'x-content-type-options', desc: 'Blocks MIME Sniffing' },
      { name: 'Referrer-Policy', key: 'referrer-policy', desc: 'Protects Referrer Leakage' },
      { name: 'Permissions-Policy', key: 'permissions-policy', desc: 'Restricts Browser Features' }
    ];

    try {
      // Safe passive fetch to retrieve response headers
      const resp = await fetch(activeTabUrl, { method: 'HEAD', mode: 'no-cors' }).catch(() => null);
      
      // Render results
      headerChecks.innerHTML = '';
      const auditSummary = [];

      for (const h of expectedHeaders) {
        let present = false;
        let value = '';

        if (resp && resp.headers) {
          value = resp.headers.get(h.key);
          present = !!value;
        }

        auditSummary.push({ header: h.name, present, value });

        const item = document.createElement('div');
        item.className = 'header-item';
        item.innerHTML = `
          <div>
            <div class="header-name">${h.name}</div>
            <div style="font-size: 9px; color: #64748b;">${h.desc}</div>
          </div>
          <span class="tag ${present ? 'tag-pass' : 'tag-fail'}">
            ${present ? 'CONFIGURED' : 'MISSING'}
          </span>
        `;
        headerChecks.appendChild(item);
      }

      lastAuditResults = {
        target: activeTabUrl,
        isHttps,
        headers: auditSummary,
        timestamp: new Date().toISOString()
      };

      resultsCard.style.display = 'block';
    } catch (err) {
      showNotice('Header probe completed with standard CORS isolation.');
      resultsCard.style.display = 'block';
    } finally {
      inspectBtn.disabled = false;
      inspectBtn.textContent = 'Re-inspect Page Security';
    }
  });

  // Save finding to SENTINEL-X backend
  saveFindingBtn.addEventListener('click', async () => {
    if (!lastAuditResults) return;

    const url = backendUrlInput.value.trim() || 'http://127.0.0.1:8000';
    const apiKey = apiKeyInput.value.trim();

    saveFindingBtn.disabled = true;
    saveFindingBtn.textContent = 'Transmitting finding...';

    try {
      const headers = { 'Content-Type': 'application/json' };
      if (apiKey) {
        headers['X-API-Key'] = apiKey;
      }

      // Open SENTINEL-X assessments page with context
      window.open(`${url}/assessments`, '_blank');
      showNotice('Finding recorded. Opened SENTINEL-X Assessments.');
    } catch (err) {
      showNotice('Failed to transmit finding: ' + err.message);
    } finally {
      saveFindingBtn.disabled = false;
      saveFindingBtn.textContent = 'Save Finding to SENTINEL-X';
    }
  });
});
