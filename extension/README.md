# SENTINEL-X — Chrome Security Extension (Manifest V3)

The **SENTINEL-X Security Companion** is an analyst browser extension built on Chrome Extensions Manifest V3. It enables user-initiated page security auditing, TLS validation, HTTP security header verification, and direct integration with SENTINEL-X assessment workspaces.

---

## 1. Security & Privacy Guarantees

- **Minimal Permissions**: Strictly requests `activeTab` (accesses current tab *only* upon explicit user click) and `storage` (local retention of API configuration).
- **Zero Passive Tracking**: Does not collect browsing history, cookies, passwords, form fields, or search queries.
- **Explicit User Initiation**: Security audits occur only when the analyst presses the **"Inspect Page Security"** button.
- **No Remote Code Execution**: All logic is bundled locally in compliance with Manifest V3 policy.

---

## 2. Installation & Loading (Unpacked Mode)

1. Open **Google Chrome** (or Chromium / Microsoft Edge / Brave).
2. Navigate to `chrome://extensions/` (or `edge://extensions/`).
3. Toggle the **Developer mode** switch in the upper-right corner.
4. Click **Load unpacked**.
5. Select the `extension/` directory from this repository:
   ```
   c:\Users\kakan\Desktop\cyber_security\extension\
   ```
6. The extension icon will appear in the browser toolbar with the badge: **SENTINEL-X Security Companion**.

---

## 3. Configuration & Usage

1. Click the SENTINEL-X icon in the browser toolbar to open the popup.
2. Click **⚙️ Connection Settings** to view API options:
   - **Backend API URL**: `http://127.0.0.1:8000` (default)
   - **Client API Key**: Enter key generated from the SENTINEL-X Settings page or use `sx_dev_agent_key_default`.
   - Click **Save Settings**.
3. Verify that the status indicator changes from `DISCONNECTED` to `ONLINE (v0.1.0)`.
4. Navigate to any authorized web target.
5. Click **Inspect Page Security** to audit:
   - `Strict-Transport-Security` (HSTS)
   - `Content-Security-Policy` (CSP)
   - `X-Frame-Options`
   - `X-Content-Type-Options`
   - `Referrer-Policy`
   - `Permissions-Policy`
6. Click **Save Finding to SENTINEL-X** to register findings into your active SOC assessment workspace.
