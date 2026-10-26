#!/usr/bin/env python3
"""
SENTINEL-X Unified Interactive Control & Platform Launcher
Provides menu-driven and CLI-driven execution for all SENTINEL-X modules:
  1. Web Platform (FastAPI Backend + Vite Dashboard)
  2. Dedicated Desktop SOC Console
  3. Endpoint Monitoring Agent
  4. Telemetry & Attack Simulator
  5. EWCC Detection Benchmark
  6. Automated Test Suite (pytest)
  7. Chrome Extension Info & Instructions
"""
import os
import sys
import time
import subprocess
import webbrowser
import urllib.request
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
VENV_PYTHON = ROOT_DIR / ".venv" / "Scripts" / "python.exe"
if not VENV_PYTHON.exists():
    VENV_PYTHON = ROOT_DIR / ".venv" / "bin" / "python"
if not VENV_PYTHON.exists():
    VENV_PYTHON = Path(sys.executable)


def check_url(url: str, timeout: float = 2.0) -> bool:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SentinelX-Probe"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status < 500
    except Exception:
        return False


def start_web_platform():
    try:
        import psutil
        import socket
        import platform
        hname = socket.gethostname()
        battery = psutil.sensors_battery()
        dev_type = "Laptop" if battery else "Desktop PC"
        bat_str = f" [Battery: {round(battery.percent)}% {'Charging' if battery.power_plugged else 'Battery'}]" if battery else " [AC Power]"
        print(f"\n[+] Active Host Detected: {hname} ({dev_type} - {platform.system()} {platform.release()}){bat_str}")
        print("[+] Connecting Live Telemetry & In-Depth Real-Time OS Scanner...")
    except Exception:
        pass

    print("\n[+] Launching SENTINEL-X Web Platform...")
    backend_running = check_url("http://127.0.0.1:8000/api/v1/health")
    frontend_running = check_url("http://127.0.0.1:5173/")

    if not backend_running:
        print("[*] Spawning Backend Server (http://127.0.0.1:8000)...")
        if sys.platform == "win32":
            subprocess.Popen(
                [str(VENV_PYTHON), "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", "8000", "--reload"],
                cwd=str(ROOT_DIR),
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
        else:
            subprocess.Popen(
                [str(VENV_PYTHON), "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", "8000", "--reload"],
                cwd=str(ROOT_DIR),
            )
    else:
        print("[+] Backend Server is already running on http://127.0.0.1:8000")

    if not frontend_running:
        print("[*] Spawning Frontend Dev Server (http://127.0.0.1:5173)...")
        frontend_dir = ROOT_DIR / "frontend"
        if sys.platform == "win32":
            subprocess.Popen(
                ["cmd", "/k", "npm run dev"],
                cwd=str(frontend_dir),
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
        else:
            subprocess.Popen(["npm", "run", "dev"], cwd=str(frontend_dir))
    else:
        print("[+] Frontend Dev Server is already running on http://127.0.0.1:5173")

    print("\n[*] Waiting for servers to initialize...")
    time.sleep(3)
    target_url = "http://127.0.0.1:5173/"
    print(f"[+] Opening browser at: {target_url}")
    webbrowser.open(target_url)
    try:
        from backend.app.core.system_credentials import get_or_create_system_credentials
        c = get_or_create_system_credentials()
        creds_str = f"User: {c['host_username']} (or admin) | Pass: {c['system_password']}"
    except Exception:
        creds_str = "Generated dynamically in data/system_credentials.json"

    print("\n" + "=" * 65)
    print("  SENTINEL-X SOC Platform Running:")
    print("    - Web Console: http://127.0.0.1:5173/")
    print("    - API Docs:    http://127.0.0.1:8000/docs")
    print(f"    - Credentials: {creds_str}")
    print("=" * 65 + "\n")


def stop_all_services():
    """
    Cleanly and gracefully terminates all active SENTINEL-X platform services:
    - FastAPI Backend (Port 8000)
    - Vite React SOC Dashboard (Port 5173)
    - Sentinel Agent, Guardian Watchdog, and Simulator processes
    - Closes labeled terminal windows on Windows
    """
    print("\n" + "=" * 65)
    print("  STOPPING ALL SENTINEL-X SERVICES (CLEAN SHUTDOWN)")
    print("=" * 65)

    target_ports = {8000, 5173}
    stopped_pids = set()
    stopped_details = []

    # 1. Terminate processes listening on port 8000 and 5173
    try:
        import psutil
        for p in psutil.process_iter(['pid', 'name']):
            try:
                conns = p.net_connections(kind='inet') if hasattr(p, 'net_connections') else []
                for c in conns:
                    if c.laddr and c.laddr.port in target_ports and p.pid > 4 and p.pid != os.getpid():
                        if p.pid not in stopped_pids:
                            stopped_pids.add(p.pid)
                            pname = p.name()
                            p.terminate()
                            stopped_details.append(f"{pname} (PID: {p.pid}) on Port {c.laddr.port}")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception:
        pass

    # Windows netstat fallback to ensure no socket listeners are missed
    if sys.platform == "win32":
        try:
            out = subprocess.check_output("netstat -ano -p tcp", shell=True, text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                for port in target_ports:
                    if f":{port} " in line and "LISTENING" in line:
                        parts = line.strip().split()
                        if parts:
                            try:
                                pid = int(parts[-1])
                                if pid > 4 and pid != os.getpid() and pid not in stopped_pids:
                                    subprocess.run(f"taskkill /F /PID {pid}", shell=True, capture_output=True)
                                    stopped_pids.add(pid)
                                    stopped_details.append(f"Port {port} Listener (PID: {pid}) via netstat")
                            except ValueError:
                                pass
        except Exception:
            pass

    # 2. Terminate background SENTINEL-X script runners
    known_script_patterns = [
        "uvicorn backend.app.main:app",
        "agent.sentinel_agent.agent",
        "persistent_guardian_watchdog.py",
        "run_background_sentinel.py",
        "desktop/run_desktop.py",
    ]
    try:
        import psutil
        for p in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmd_str = " ".join(p.cmdline() or [])
                if any(pat in cmd_str for pat in known_script_patterns):
                    if p.pid > 4 and p.pid != os.getpid() and p.pid not in stopped_pids:
                        stopped_pids.add(p.pid)
                        pname = p.name()
                        p.terminate()
                        stopped_details.append(f"{pname} (PID: {p.pid}) - {cmd_str[:45]}...")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception:
        pass

    # 3. Clean up labeled terminal windows on Windows
    if sys.platform == "win32":
        try:
            subprocess.run('taskkill /FI "WINDOWTITLE eq SENTINEL-X Backend*" /T /F', shell=True, capture_output=True)
            subprocess.run('taskkill /FI "WINDOWTITLE eq SENTINEL-X Dashboard*" /T /F', shell=True, capture_output=True)
        except Exception:
            pass

    time.sleep(1)

    # 4. Report status
    if stopped_details:
        print("[+] Terminated the following active services:")
        for det in stopped_details:
            print(f"    - [OK] Stopped: {det}")
        print("\n[+] Success: All SENTINEL-X backend, frontend, and background tasks are STOPPED.")
        print("[+] Ports 8000 and 5173 have been cleanly freed.")
    else:
        print("[+] Verified: No active SENTINEL-X services or port listeners were running.")
        print("[+] System is already completely idle (Ports 8000 and 5173 are free).")
    print("=" * 65 + "\n")


def start_desktop_app():
    print("\n[+] Launching Dedicated SOC Desktop Application...")
    desktop_runner = ROOT_DIR / "desktop" / "run_desktop.py"
    subprocess.Popen([str(VENV_PYTHON), str(desktop_runner)], cwd=str(ROOT_DIR))


def start_agent():
    print("\n[+] Starting Endpoint Monitoring Agent...")
    if sys.platform == "win32":
        subprocess.Popen(
            [str(VENV_PYTHON), "-m", "agent.sentinel_agent.agent"],
            cwd=str(ROOT_DIR),
            creationflags=subprocess.CREATE_NEW_CONSOLE,
        )
    else:
        subprocess.Popen([str(VENV_PYTHON), "-m", "agent.sentinel_agent.agent"], cwd=str(ROOT_DIR))


def manage_applications_menu():
    print("\n" + "=" * 65)
    print("  CROSS-PLATFORM APPLICATION PACKAGING & BUILDS")
    print("=" * 65)
    print("  [1] Build Android Mobile Application & APK Package")
    print("      -> Output: dist/android/sentinel-x-security.apk")
    print("  [2] Build Native macOS Desktop Application (.app)")
    print("      -> Output: dist/mac/SENTINEL-X.app & SENTINEL-X-macOS.zip")
    print("  [3] Package Browser Security Companion Extension")
    print("      -> Output: dist/extension/sentinel-x-companion.zip (Manifest V3)")
    print("  [4] Build All Application Types (Android APK + Mac App + Browser Ext)")
    print("  [5] Return to Main Menu")
    c = input("Select an option [1-5] (default: 4): ").strip() or "4"
    if c == "1":
        subprocess.run([str(VENV_PYTHON), str(ROOT_DIR / "scripts" / "build_android_apk.py")], cwd=str(ROOT_DIR))
    elif c == "2":
        subprocess.run([str(VENV_PYTHON), str(ROOT_DIR / "scripts" / "build_mac_app.py")], cwd=str(ROOT_DIR))
    elif c == "3":
        subprocess.run([str(VENV_PYTHON), str(ROOT_DIR / "scripts" / "package_extension.py")], cwd=str(ROOT_DIR))
    elif c == "4":
        subprocess.run([str(VENV_PYTHON), str(ROOT_DIR / "scripts" / "build_android_apk.py")], cwd=str(ROOT_DIR))
        subprocess.run([str(VENV_PYTHON), str(ROOT_DIR / "scripts" / "build_mac_app.py")], cwd=str(ROOT_DIR))
        subprocess.run([str(VENV_PYTHON), str(ROOT_DIR / "scripts" / "package_extension.py")], cwd=str(ROOT_DIR))


def run_tests():
    print("\n[+] Executing Automated Test Suite (pytest)...")
    subprocess.run([str(VENV_PYTHON), "-m", "pytest", "-v"], cwd=str(ROOT_DIR))


def show_extension_guide():
    ext_dir = ROOT_DIR / "extension"
    print("\n" + "=" * 60)
    print("  CHROME / EDGE EXTENSION INSTALLATION GUIDE")
    print("=" * 60)
    print(f"Directory: {ext_dir}")
    print("\nSteps to install in Google Chrome, Brave, or Microsoft Edge:")
    print("  1. Open your browser and navigate to: chrome://extensions or edge://extensions")
    print("  2. Toggle ON 'Developer mode' in the top-right corner.")
    print("  3. Click 'Load unpacked' in the top-left menu.")
    print(f"  4. Select this directory: {ext_dir}")
    print("  5. The SENTINEL-X Security Sentinel extension icon will appear in your toolbar.")
    print("  6. Click the extension icon to view security posture, headers, and API health.\n")


try:
    if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


# ANSI Color Codes
RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
WHITE = "\033[97m"


def print_banner():
    try:
        import socket
        import platform
        import psutil
        hname = socket.gethostname()
        os_info = f"{platform.system()} {platform.release()} ({platform.machine()})"
        battery = psutil.sensors_battery()
        dev_type = "Mobile / Handheld" if os.path.exists("/data/data/com.termux") else ("Laptop" if battery else "Desktop PC")
        bat_str = f" | Battery: {round(battery.percent)}% {'[Charging]' if battery.power_plugged else '[Discharging]'}" if battery else " | Power: AC Line"
    except Exception:
        hname = "Connected Host"
        os_info = "Multi-OS Target"
        dev_type = "Physical Device"
        bat_str = ""

    banner = f"""{CYAN}{BOLD}
                   /\\                                    /\\  
                  /  \\  .------------------------.  /  \\ 
                 |    \\/   .----------------.   \\/    |
                 |    /   /   {BLUE}\\          /   {CYAN}\\   \\    |
                 |   |   |     {BLUE}\\        /     {CYAN}|   |   |
                 |   |   |   {GREEN}==[{BLUE}\\      /{GREEN}]==   {CYAN}|   |   |
                 |   |   |       {BLUE}\\    /       {CYAN}|   |   |
                 |   |   |        {BLUE}\\  /        {CYAN}|   |   |
                 |   |   |         {WHITE}><         {CYAN}|   |   |
                 |   |   |        {BLUE}/  \\        {CYAN}|   |   |
                 |   |   |       {BLUE}/    \\       {CYAN}|   |   |
                 |   |   |   {GREEN}==[{BLUE}/      \\{GREEN}]==   {CYAN}|   |   |
                 |   |   |     {BLUE}/        \\     {CYAN}|   |   |
                 |    \\   \\   {BLUE}/          \\   {CYAN}/   /    |
                 |    /\\   '----------------'   /\\    |
                  \\  /  \\                        /  \\  / 
                   \\/    '------------------------'    \\/

        ____  _____ _   _ _____ ___ _   _ _____ _     __  __ 
       / ___|| ____| \\ | |_   _|_ _| \\ | | ____| |    \\ \\/ / 
       \\___ \\|  _| |  \\| | | |  | ||  \\| |  _| | |     \\  /  
        ___) | |___| |\\  | | |  | || |\\  | |___| |___  /  \\  
       |____/|_____|_| \\_| |_| |___|_| \\_|_____|_____|/_/\\_\\ 
{RESET}========================================================================
 {WHITE}{BOLD}SENTINEL-X -- Unified Cyber Defense, Testing, Forensics & Investigation Platform{RESET}
 {WHITE}Architecture:{RESET} {YELLOW}Multi-OS Live Guard (Windows, Linux, Android & Chrome Extension){RESET}
 {WHITE}Edition:{RESET} {YELLOW}Enterprise SOC Control Center v2.4.0{RESET}
 {WHITE}Connected Host:{RESET} {CYAN}{BOLD}{hname}{RESET} ({dev_type}) | {WHITE}OS:{RESET} {os_info}{bat_str}
========================================================================"""
    print(banner)


def manage_ai_engine():
    cli_path = ROOT_DIR / "cli.py"
    print("\n" + "=" * 60)
    print("  SENTINEL-X AI SELF-LEARNING & RETRAINING HUB")
    print("=" * 60)
    print("  [1] Trigger Immediate AI Retraining (Optimize Loss & Safeguards)")
    print("  [2] View AI Neural Model Status, Convergence & Weights")
    print("  [3] Configure Automated Recurrence Schedule (Weekly, Monthly, 6 Months)")
    print("  [4] Return to Main Menu")
    c = input("Select an option [1-4] (default: 1): ").strip() or "1"
    if c == "1":
        subprocess.run([str(VENV_PYTHON), str(cli_path), "train-ai"], cwd=str(ROOT_DIR))
    elif c == "2":
        subprocess.run([str(VENV_PYTHON), str(cli_path), "ai-status"], cwd=str(ROOT_DIR))
    elif c == "3":
        print("\nSelect automated recurrence schedule:")
        print("  [1] Weekly (every 7 days - recommended for rapid zero-day evolution)")
        print("  [2] Monthly (every 30 days - enterprise baseline cadence)")
        print("  [3] 6 Months (every 180 days - long-term audit retraining)")
        sc = input("Select schedule [1-3] (default: 1): ").strip() or "1"
        rec_map = {"1": "weekly", "2": "monthly", "3": "6months"}
        rec = rec_map.get(sc, "weekly")
        subprocess.run([str(VENV_PYTHON), str(cli_path), "set-ai-schedule", "--recurrence", rec], cwd=str(ROOT_DIR))


def run_breach_forensics():
    cli_path = ROOT_DIR / "cli.py"
    print("\n[+] Initiating Real-World Deep Data Breach Forensic Discovery & Cryptographic Seal...")
    subprocess.run([str(VENV_PYTHON), str(cli_path), "breach-evidence"], cwd=str(ROOT_DIR))


def main():
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd not in ("cli", "terminal", "scan", "deep-scan", "system-scan", "repair", "fix", "system-repair", "connect", "sweep"):
            print_banner()
        if cmd in ("terminal", "cli"):
            cli_path = ROOT_DIR / "cli.py"
            subprocess.run([str(VENV_PYTHON), str(cli_path)] + sys.argv[2:], cwd=str(ROOT_DIR))
            return
        elif cmd in ("sweep", "connect", "connect-all", "connect-safeguard", "master"):
            cli_path = ROOT_DIR / "cli.py"
            subprocess.run([str(VENV_PYTHON), str(cli_path), "connect-safeguard"], cwd=str(ROOT_DIR))
            return
        elif cmd in ("scan", "deep-scan", "system-scan"):
            cli_path = ROOT_DIR / "cli.py"
            subprocess.run([str(VENV_PYTHON), str(cli_path), "system-scan"], cwd=str(ROOT_DIR))
            return
        elif cmd in ("repair", "fix", "system-repair"):
            cli_path = ROOT_DIR / "cli.py"
            subprocess.run([str(VENV_PYTHON), str(cli_path), "system-repair"], cwd=str(ROOT_DIR))
            return
        elif cmd in ("ports", "hardware-ports"):
            cli_path = ROOT_DIR / "cli.py"
            subprocess.run([str(VENV_PYTHON), str(cli_path), "list-ports"], cwd=str(ROOT_DIR))
            return
        elif cmd in ("safe-charging", "juice-jacking"):
            cli_path = ROOT_DIR / "cli.py"
            subprocess.run([str(VENV_PYTHON), str(cli_path), "safe-charging"], cwd=str(ROOT_DIR))
            return
        elif cmd in ("wifi", "scan-wifi"):
            cli_path = ROOT_DIR / "cli.py"
            subprocess.run([str(VENV_PYTHON), str(cli_path), "scan-wifi"], cwd=str(ROOT_DIR))
            return
        elif cmd in ("apk", "android"):
            subprocess.run([str(VENV_PYTHON), str(ROOT_DIR / "scripts" / "build_android_apk.py")], cwd=str(ROOT_DIR))
            return
        elif cmd in ("mac", "macos", "apple"):
            subprocess.run([str(VENV_PYTHON), str(ROOT_DIR / "scripts" / "build_mac_app.py")], cwd=str(ROOT_DIR))
            return
        elif cmd in ("ext", "extension", "chrome"):
            subprocess.run([str(VENV_PYTHON), str(ROOT_DIR / "scripts" / "package_extension.py")], cwd=str(ROOT_DIR))
            return
        elif cmd in ("build", "build-all", "apps", "package"):
            manage_applications_menu()
            return
        elif cmd in ("train-ai", "retrain-ai", "train"):
            subprocess.run([str(VENV_PYTHON), str(ROOT_DIR / "cli.py"), "train-ai"], cwd=str(ROOT_DIR))
            return
        elif cmd in ("ai-status", "weights"):
            subprocess.run([str(VENV_PYTHON), str(ROOT_DIR / "cli.py"), "ai-status"], cwd=str(ROOT_DIR))
            return
        elif cmd in ("ai-investigator", "threat-investigator", "investigate", "signals"):
            subprocess.run([str(VENV_PYTHON), str(ROOT_DIR / "cli.py"), "ai-investigator"] + sys.argv[2:], cwd=str(ROOT_DIR))
            return
        elif cmd in ("breach-evidence", "breach", "evidence"):
            subprocess.run([str(VENV_PYTHON), str(ROOT_DIR / "cli.py"), "breach-evidence"], cwd=str(ROOT_DIR))
            return
        elif cmd in ("clean-footprints", "clean-traces", "wipe-footprints", "anti-trace"):
            subprocess.run([str(VENV_PYTHON), str(ROOT_DIR / "cli.py"), "clean-footprints"], cwd=str(ROOT_DIR))
            return
        elif cmd in ("surveil-footprints", "recon", "surveil"):
            subprocess.run([str(VENV_PYTHON), str(ROOT_DIR / "cli.py"), "surveil-footprints"], cwd=str(ROOT_DIR))
            return
        elif cmd in ("mislead-footprints", "deception", "mislead"):
            subprocess.run([str(VENV_PYTHON), str(ROOT_DIR / "cli.py"), "mislead-footprints"], cwd=str(ROOT_DIR))
            return
        elif cmd in ("discover-footprints", "footprints"):
            subprocess.run([str(VENV_PYTHON), str(ROOT_DIR / "cli.py"), "discover-footprints"], cwd=str(ROOT_DIR))
            return
        elif cmd in ("forensic-investigation", "forensics", "investigate-breach", "cyber-detective"):
            subprocess.run([str(VENV_PYTHON), str(ROOT_DIR / "cli.py"), "forensic-investigation"] + sys.argv[2:], cwd=str(ROOT_DIR))
            return
        elif cmd in ("ethical-disengage", "safe-disengage", "disengage"):
            subprocess.run([str(VENV_PYTHON), str(ROOT_DIR / "cli.py"), "ethical-disengage"], cwd=str(ROOT_DIR))
            return
        elif cmd in ("stop-third-party", "stop-intruder"):

            subprocess.run([str(VENV_PYTHON), str(ROOT_DIR / "cli.py")] + sys.argv[1:], cwd=str(ROOT_DIR))
            return
        elif cmd in ("web", "start", "run"):
            start_web_platform()
            return
        elif cmd in ("desktop", "desk"):
            start_desktop_app()
            return
        elif cmd in ("agent",):
            start_agent()
            return
        elif cmd in ("stop", "stop-all", "shutdown", "kill"):
            stop_all_services()
            return
        elif cmd in ("test", "tests"):
            run_tests()
            return

    while True:
        print_banner()
        print("  [1]  ⚡ DIRECT TERMINAL THREAT HUNT & SAFEGUARD SUITE (Zero Web Links - Direct Terminal)")
        print("  [2]  ⚡ MASTER CONNECT & SAFEGUARD EVERYTHING (Wired, Wireless, Chargers, Pendrives & OS)")
        print("  [3]  LIVE SYSTEM CONNECT & IN-DEPTH VIRUS SCAN (Active Host Laptop/PC/Android)")
        print("  [4]  ONE-CLICK COMPLETE SYSTEM REPAIR & PROBLEM SOLVER (Solve All Problems Completely)")
        print("  [5]  HARDWARE PORTS, CONNECTED DEVICES & SAFE CHARGING CLAMP (Juice-Jacking Lock)")
        print("  [6]  WI-FI ROGUE AP, EVIL TWIN & NETWORK SECURITY ARMOR (Airwaves Shield)")
        print("  [7]  ACTIVE NETWORK SOCKETS & BACKDOOR TROJAN HUNTER (RATs, C2 Channels)")
        print("  [8]  CONTINUOUS AI RETRAINING & SELF-EVOLVING SAFEGUARDS (Weekly/Monthly/6-Months)")
        print("  [8B] 🤖 AI LINUX THREAT INVESTIGATOR (Processes, Logins, Modified Files & Sockets)")
        print("  [9]  DEEP DATA BREACH FORENSIC DISCOVERY & CRYPTOGRAPHIC SEAL (Zero Dummy Data)")
        print("  [9B] 🕵️ DIGITAL FORENSICS CYBER DETECTIVE (4-Stage Attack Timeline Reconstruction & MFT/RAM)")
        print("  [9C] 🛡️ ETHICAL HACKER SAFE DISENGAGEMENT (Purge Operator Traces & Certificate)")
        print("  [10] SURVEIL RECONNAISSANCE & FOOTPRINTING (Detect Port Sweeps & OS Fingerprinting)")
        print("  [11] 🎭 MISLEAD ATTACKER PATH & FOOTPRINTS (Deceptive OS, Honeypaths & Canaries)")
        print("  [12] 🧹 CLEAN & SHRED ALL OPERATOR FOOTPRINTS COMPLETELY (Anti-Trace Zero-Remanence)")
        print("  [13] 🛑 STOP THIRD-PARTY INTRUDER & COLLECT ORIGIN EVIDENCE (Freeze & Firewall Block)")
        print("  [14] CROSS-PLATFORM APPS: BUILD ANDROID APK, MAC APP & BROWSER EXTENSION PACKAGES")
        print("  [15] Launch Web Platform (Optional GUI Dashboard)")
        print("  [16] Dedicated SOC Desktop Console Window")
        print("  [17] Stop All Running Services (Clean Shutdown: Backend, Frontend, Watchdogs)")
        print("  [18] Exit")
        print("=" * 65)

        choice = input("Select an option [1-18, 9B, 9C]: ").strip()

        cli_path = ROOT_DIR / "cli.py"

        if choice == "1":
            subprocess.run([str(VENV_PYTHON), str(cli_path)], cwd=str(ROOT_DIR))
            input("\nPress Enter to continue...")
        elif choice == "2":
            subprocess.run([str(VENV_PYTHON), str(cli_path), "connect-safeguard"], cwd=str(ROOT_DIR))
            input("\nPress Enter to continue...")
        elif choice == "3":
            subprocess.run([str(VENV_PYTHON), str(cli_path), "system-scan"], cwd=str(ROOT_DIR))
            input("\nPress Enter to continue...")
        elif choice == "4":
            subprocess.run([str(VENV_PYTHON), str(cli_path), "system-repair"], cwd=str(ROOT_DIR))
            input("\nPress Enter to continue...")
        elif choice == "5":
            print("\n  [A] Show All Connected Hardware Ports (USB, RJ-45, HDMI, Audio)")
            print("  [B] Toggle Safe Charging Clamp (Juice-Jacking Lockout)")
            sub_c = input("  Select action [A/B, default A]: ").strip().upper()
            if sub_c == "B":
                subprocess.run([str(VENV_PYTHON), str(cli_path), "safe-charging"], cwd=str(ROOT_DIR))
            else:
                subprocess.run([str(VENV_PYTHON), str(cli_path), "list-ports"], cwd=str(ROOT_DIR))
            input("\nPress Enter to continue...")
        elif choice == "6":
            subprocess.run([str(VENV_PYTHON), str(cli_path), "scan-wifi"], cwd=str(ROOT_DIR))
            input("\nPress Enter to continue...")
        elif choice == "7":
            subprocess.run([str(VENV_PYTHON), str(cli_path), "guard-sockets"], cwd=str(ROOT_DIR))
            input("\nPress Enter to continue...")
        elif choice == "8":
            manage_ai_engine()
            input("\nPress Enter to continue...")
        elif choice.upper() in ("8B", "AI5", "AI-INVESTIGATOR", "THREAT-INVESTIGATOR", "SIGNALS"):
            subprocess.run([str(VENV_PYTHON), str(cli_path), "ai-investigator"], cwd=str(ROOT_DIR))
            input("\nPress Enter to continue...")
        elif choice == "9":
            run_breach_forensics()
            input("\nPress Enter to continue...")
        elif choice.upper() in ("9B", "DET1", "FORENSICS", "CYBER-DETECTIVE"):
            subprocess.run([str(VENV_PYTHON), str(cli_path), "forensic-investigation"], cwd=str(ROOT_DIR))
            input("\nPress Enter to continue...")
        elif choice.upper() in ("9C", "DET2", "DISENGAGE"):
            subprocess.run([str(VENV_PYTHON), str(cli_path), "ethical-disengage"], cwd=str(ROOT_DIR))
            input("\nPress Enter to continue...")

        elif choice == "10":
            subprocess.run([str(VENV_PYTHON), str(cli_path), "surveil-footprints"], cwd=str(ROOT_DIR))
            input("\nPress Enter to continue...")
        elif choice == "11":
            subprocess.run([str(VENV_PYTHON), str(cli_path), "mislead-footprints"], cwd=str(ROOT_DIR))
            input("\nPress Enter to continue...")
        elif choice == "12":
            subprocess.run([str(VENV_PYTHON), str(cli_path), "clean-footprints"], cwd=str(ROOT_DIR))
            input("\nPress Enter to continue...")
        elif choice == "13":
            targ = input("Enter intruder Remote IP or Target PID to intercept: ").strip()
            if targ:
                subprocess.run([str(VENV_PYTHON), str(cli_path), "stop-third-party", targ], cwd=str(ROOT_DIR))
            input("\nPress Enter to continue...")
        elif choice == "14":
            manage_applications_menu()
            input("\nPress Enter to continue...")
        elif choice == "15":
            start_web_platform()
            break
        elif choice == "16":
            start_desktop_app()
            break
        elif choice == "17":
            stop_all_services()
            input("\nPress Enter to continue...")
        elif choice in ("18", "q", "exit"):
            print("Exiting.")
            break
        else:
            print("Invalid selection.")


if __name__ == "__main__":
    main()
