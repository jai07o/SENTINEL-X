"""
SENTINEL-X Desktop Window Launcher
Launches the SENTINEL-X SOC Console in dedicated desktop application window mode.
Supports native PyWebView when available or dedicated standalone application window.
"""
import sys
import os
import webbrowser
import subprocess
import time
import urllib.request

BACKEND_URL = os.environ.get("SENTINELX_BACKEND_URL", "http://127.0.0.1:8000")
FRONTEND_DEV_URL = os.environ.get("SENTINELX_FRONTEND_URL", "http://127.0.0.1:5173")


def check_service(url: str, timeout: float = 2.0) -> bool:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SentinelX-Desktop-Probe"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status < 500
    except Exception:
        return False


def main():
    print("=" * 60)
    print("  SENTINEL-X — Dedicated SOC Desktop Console")
    print(f"  Target Backend: {BACKEND_URL}")
    print("=" * 60)

    # Check backend health
    is_backend_online = check_service(f"{BACKEND_URL}/api/v1/health")
    if is_backend_online:
        print("[+] Backend health status: ONLINE (HTTP 200)")
    else:
        print("[-] Backend not detected on 127.0.0.1:8000.")
        print("    Please ensure backend is started: python -m uvicorn backend.app.main:app --port 8000")

    # Try launching via PyWebView if installed
    try:
        import webview
        print("[+] Launching native PyWebView desktop container...")
        window = webview.create_window(
            title="SENTINEL-X — Defensive Cybersecurity SOC Console",
            url=FRONTEND_DEV_URL if check_service(FRONTEND_DEV_URL) else f"{BACKEND_URL}/docs",
            width=1440,
            height=900,
            min_size=(1024, 700),
            background_color="#090d16"
        )
        webview.start()
        return
    except ImportError:
        pass

    # Fallback to Chromium/Edge application mode
    target_url = FRONTEND_DEV_URL if check_service(FRONTEND_DEV_URL) else f"{BACKEND_URL}/docs"
    print(f"[+] Launching dedicated application window for: {target_url}")

    # Detect common browsers with --app flag
    app_launchers = [
        ["msedge", f"--app={target_url}", "--new-window"],
        ["chrome", f"--app={target_url}", "--new-window"],
        ["chromium", f"--app={target_url}", "--new-window"],
    ]

    launched = False
    for cmd in app_launchers:
        try:
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"[+] Started desktop window with: {cmd[0]}")
            launched = True
            break
        except Exception:
            continue

    if not launched:
        print("[*] Opening default system browser window...")
        webbrowser.open(target_url)


if __name__ == "__main__":
    main()
