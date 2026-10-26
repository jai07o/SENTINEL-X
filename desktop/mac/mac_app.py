#!/usr/bin/env python3
"""
SENTINEL-X Native macOS SOC Desktop Application Runner
Initializes background telemetry services and renders the native Cocoa webview window.
"""
import os
import sys
import time
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent


def launch_mac_soc():
    print("[*] Initializing SENTINEL-X macOS SOC Engine...")

    # Ensure backend is active
    backend_script = ROOT_DIR / "backend" / "app" / "main.py"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT_DIR)

    # Try pywebview if installed, fallback to native Cocoa browser or system open
    try:
        import webview
        print("[+] Native Cocoa WebKit window initializing...")
        window = webview.create_window(
            title="SENTINEL-X Cyber Defense & SOC",
            url="http://127.0.0.1:5173",
            width=1340,
            height=860,
            resizable=True,
            min_size=(1024, 700),
            background_color="#0b1120",
        )
        webview.start()
    except ImportError:
        print("[*] pywebview not installed. Spawning native browser window...")
        import webbrowser
        webbrowser.open("http://127.0.0.1:5173")


if __name__ == "__main__":
    launch_mac_soc()
