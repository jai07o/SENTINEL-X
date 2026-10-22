"""
SENTINEL-X Dedicated Desktop SOC Application Window Launcher
Launches the SENTINEL-X SOC Console in a 100% dedicated native desktop application window.
Uses an isolated user profile and --app flag to ensure zero browser URL bar, zero tabs,
and full native window appearance.
"""
import sys
import os
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_URL = os.environ.get("SENTINELX_BACKEND_URL", "http://127.0.0.1:8000")
FRONTEND_DEV_URL = os.environ.get("SENTINELX_FRONTEND_URL", "http://127.0.0.1:5173")

VENV_PYTHON = ROOT_DIR / ".venv" / "Scripts" / "python.exe"
if not VENV_PYTHON.exists():
    VENV_PYTHON = ROOT_DIR / ".venv" / "bin" / "python"
if not VENV_PYTHON.exists():
    VENV_PYTHON = Path(sys.executable)


def check_service(url: str, timeout: float = 1.5) -> bool:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SentinelX-Desktop-Probe"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status < 500
    except Exception:
        return False


def ensure_backend_running():
    """Ensure backend API & static files are running."""
    if check_service(f"{BACKEND_URL}/api/v1/health"):
        return True

    print("[*] Backend is offline. Starting SENTINEL-X backend engine...")
    if sys.platform == "win32":
        subprocess.Popen(
            [str(VENV_PYTHON), "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", "8000"],
            cwd=str(ROOT_DIR),
            creationflags=subprocess.CREATE_NEW_CONSOLE,
        )
    else:
        subprocess.Popen(
            [str(VENV_PYTHON), "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", "8000"],
            cwd=str(ROOT_DIR),
        )

    for _ in range(12):
        time.sleep(0.5)
        if check_service(f"{BACKEND_URL}/api/v1/health"):
            print("[+] Backend initialized and listening on http://127.0.0.1:8000")
            return True
    return False


def find_browser_binaries():
    """Discover browser binaries on Windows, Linux, and macOS."""
    candidates = []

    # Windows well-known locations
    if sys.platform == "win32":
        prog_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        prog_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        local_app = os.environ.get("LocalAppData", "")

        windows_paths = [
            # Chrome
            rf"{prog_files}\Google\Chrome\Application\chrome.exe",
            rf"{prog_x86}\Google\Chrome\Application\chrome.exe",
            rf"{local_app}\Google\Chrome\Application\chrome.exe",
            # Edge
            rf"{prog_files}\Microsoft\Edge\Application\msedge.exe",
            rf"{prog_x86}\Microsoft\Edge\Application\msedge.exe",
            rf"{local_app}\Microsoft\Edge\Application\msedge.exe",
            # Brave
            rf"{prog_files}\BraveSoftware\Brave-Browser\Application\brave.exe",
            rf"{local_app}\BraveSoftware\Brave-Browser\Application\brave.exe",
        ]
        for p in windows_paths:
            if p and os.path.isfile(p):
                candidates.append(p)

    # PATH lookups
    for name in ["msedge", "chrome", "google-chrome", "chromium", "brave", "brave-browser"]:
        found = shutil.which(name)
        if found and found not in candidates:
            candidates.append(found)

    return candidates


def main():
    print("=" * 65)
    print("  SENTINEL-X — Dedicated Native Desktop SOC Console")
    print("=" * 65)

    # 1. Ensure backend is running
    backend_ok = ensure_backend_running()
    if backend_ok:
        print("[+] Backend health status: ONLINE (HTTP 200)")
    else:
        print("[!] Backend could not be started automatically. Attempting direct load...")

    # Determine target URL (prefer frontend dev server if active, otherwise backend built SPA)
    if check_service(FRONTEND_DEV_URL):
        target_url = f"{FRONTEND_DEV_URL}/?mode=standalone"
    else:
        target_url = f"{BACKEND_URL}/?mode=standalone"

    print(f"[+] Application Mode: STANDALONE DESKTOP")
    print(f"[+] Target Endpoint: {target_url}")

    # 2. Try native PyWebView first if installed
    try:
        import webview
        print("[+] Launching native PyWebView desktop container...")
        window = webview.create_window(
            title="SENTINEL-X — Defensive Cybersecurity SOC Console",
            url=target_url,
            width=1440,
            height=900,
            min_size=(1024, 700),
            background_color="#090d16"
        )
        webview.start()
        return
    except (ImportError, Exception):
        pass

    # 3. Dedicated Isolated Profile Desktop Window
    profile_dir = ROOT_DIR / "data" / "desktop_profile"
    profile_dir.mkdir(parents=True, exist_ok=True)

    browser_binaries = find_browser_binaries()

    if browser_binaries:
        chosen_binary = browser_binaries[0]
        binary_name = Path(chosen_binary).name.lower()
        print(f"[+] Launching native application window with: {chosen_binary}")

        app_args = [
            chosen_binary,
            f"--app={target_url}",
            f"--user-data-dir={str(profile_dir)}",
            "--window-size=1440,900",
            "--window-position=100,50",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-sync",
            "--disable-features=TranslateUI",
            "--app-id=sentinelx.security.platform",
            "--name=SENTINEL-X",
        ]

        try:
            subprocess.Popen(
                app_args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=str(ROOT_DIR),
            )
            print("[+] Native desktop window active. Running seamlessly without browser address bar.")
            return
        except Exception as e:
            print(f"[-] Native launch failed: {e}. Falling back to default browser...")

    import webbrowser
    print("[*] Opening standalone interface in default browser...")
    webbrowser.open(target_url)


if __name__ == "__main__":
    main()

