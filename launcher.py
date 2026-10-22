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


def run_simulator():
    print("\n[+] Running Telemetry & Attack Simulator...")
    print("Choose simulator action:")
    print("  1. Run Controlled Attack Simulation Pipeline (Kali RAT, Windows Shell, Mobile Spyware)")
    print("     [Verifies: Live Telemetry -> Attack Detection -> Forensic Vault Seal -> Containment]")
    print("  2. Run Detection & EWCC Benchmark")
    print("  3. Inject SSH Brute-Force & PrivEsc Scenarios into live backend")
    choice = input("Enter option [1, 2, or 3] (default: 1): ").strip() or "1"

    if choice == "1":
        print("\nSelect target platform:")
        print("  [1] Kali Linux (Remote Access Trojan & Meterpreter C2)")
        print("  [2] Windows Host (Encoded PowerShell Reverse Shell)")
        print("  [3] Mobile Companion (Background Spyware & Sensor Hijack)")
        print("  [4] All Platforms (Sequential Full Matrix)")
        p_choice = input("Select platform [1-4] (default: 1): ").strip() or "1"
        plat_map = {"1": "kali", "2": "windows", "3": "mobile", "4": "all"}
        target = plat_map.get(p_choice, "kali")
        
        cli_path = ROOT_DIR / "cli.py"
        if target == "all":
            for p in ("kali", "windows", "mobile"):
                subprocess.run([str(VENV_PYTHON), str(cli_path), "simulate-hack", "--platform", p], cwd=str(ROOT_DIR))
        else:
            subprocess.run([str(VENV_PYTHON), str(cli_path), "simulate-hack", "--platform", target], cwd=str(ROOT_DIR))

    elif choice == "2":
        subprocess.run([str(VENV_PYTHON), "-m", "simulator.benchmark"], cwd=str(ROOT_DIR))
    else:
        script = """
import httpx
from simulator.generator import LabTelemetrySimulator

sim = LabTelemetrySimulator()
events = sim.generate_ssh_brute_force_scenario(num_failures=6) + sim.generate_privilege_escalation_scenario()
print(f"Injecting {len(events)} synthetic events into http://127.0.0.1:8000/api/v1/events/ingest ...")
for ev in events:
    payload = ev.model_dump(mode="json")
    try:
        r = httpx.post("http://127.0.0.1:8000/api/v1/events/ingest", json=payload, headers={"X-Sentinel-Key": "sx_dev_agent_key_default"}, timeout=3.0)
        print(f"  [+] Ingested {ev.event_id}: HTTP {r.status_code}")
    except Exception as e:
        print(f"  [-] Failed to connect: {e}")
        break
print("Completed injection. Check http://127.0.0.1:5173/incidents for generated alerts.")
"""
        subprocess.run([str(VENV_PYTHON), "-c", script], cwd=str(ROOT_DIR))


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
 {WHITE}Author & Creator:{RESET} {GREEN}{BOLD}K. Jaideep Raj (Student & Security Enthusiast){RESET} via {CYAN}{BOLD}Google Antigravity{RESET}
 {WHITE}Architecture:{RESET} {YELLOW}Multi-OS Live Guard (Windows, Linux, Android & Chrome Extension){RESET}
 {WHITE}Edition:{RESET} {YELLOW}Enterprise SOC Control Center v2.4.0{RESET}
 {WHITE}Connected Host:{RESET} {CYAN}{BOLD}{hname}{RESET} ({dev_type}) | {WHITE}OS:{RESET} {os_info}{bat_str}
========================================================================"""
    print(banner)


def main():
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd not in ("cli", "terminal", "scan", "deep-scan", "system-scan", "repair", "fix", "system-repair"):
            print_banner()
        if cmd in ("web", "start", "run"):
            start_web_platform()
            return
        elif cmd in ("desktop", "desk"):
            start_desktop_app()
            return
        elif cmd in ("agent",):
            start_agent()
            return
        elif cmd in ("simulator", "sim"):
            run_simulator()
            return
        elif cmd in ("cli", "terminal"):
            cli_path = ROOT_DIR / "cli.py"
            subprocess.run([str(VENV_PYTHON), str(cli_path)] + sys.argv[2:], cwd=str(ROOT_DIR))
            return
        elif cmd in ("scan", "deep-scan", "system-scan"):
            cli_path = ROOT_DIR / "cli.py"
            subprocess.run([str(VENV_PYTHON), str(cli_path), "system-scan"], cwd=str(ROOT_DIR))
            return
        elif cmd in ("repair", "fix", "system-repair"):
            cli_path = ROOT_DIR / "cli.py"
            subprocess.run([str(VENV_PYTHON), str(cli_path), "system-repair"], cwd=str(ROOT_DIR))
            return
        elif cmd in ("test", "tests"):
            run_tests()
            return
        elif cmd in ("ext", "extension"):
            show_extension_guide()
            return

    while True:
        print_banner()
        print("  [1] Start Web Platform (Backend + Frontend + Open Browser)")
        print("  [2] Open Dedicated Desktop SOC Console")
        print("  [3] Direct Terminal: Live Host Connect, Deep Virus Scan & Complete Repair")
        print("  [4] Direct Terminal Threat Analyzer & Safeguard Suite (cli.py)")
        print("  [5] Start Endpoint Monitoring Agent")
        print("  [6] Run Threat Simulator & Scenarios")
        print("  [7] Run EWCC Benchmark")
        print("  [8] Run Automated Tests (pytest)")
        print("  [9] How to load Chrome/Edge Extension")
        print("  [10] Exit")
        print("=" * 65)

        choice = input("Select an option [1-10]: ").strip()
        if choice == "1":
            start_web_platform()
            break
        elif choice == "2":
            start_desktop_app()
            break
        elif choice == "3":
            cli_path = ROOT_DIR / "cli.py"
            print("\n  [A] Real-Time Deep OS Virus Scan (Inspect Active Host & Devices)")
            print("  [B] Real-Time Scan & Complete System Repair (Auto-Solve All Issues)")
            sub_c = input("  Select action [A/B, default A]: ").strip().upper()
            if sub_c == "B":
                subprocess.run([str(VENV_PYTHON), str(cli_path), "system-repair"], cwd=str(ROOT_DIR))
            else:
                subprocess.run([str(VENV_PYTHON), str(cli_path), "system-scan"], cwd=str(ROOT_DIR))
            input("\nPress Enter to continue...")
        elif choice == "4":
            cli_path = ROOT_DIR / "cli.py"
            subprocess.run([str(VENV_PYTHON), str(cli_path)], cwd=str(ROOT_DIR))
            input("\nPress Enter to continue...")
        elif choice == "5":
            start_agent()
            break
        elif choice == "6":
            run_simulator()
            input("\nPress Enter to continue...")
        elif choice == "7":
            subprocess.run([str(VENV_PYTHON), "-m", "simulator.benchmark"], cwd=str(ROOT_DIR))
            input("\nPress Enter to continue...")
        elif choice == "8":
            run_tests()
            input("\nPress Enter to continue...")
        elif choice == "9":
            show_extension_guide()
            input("\nPress Enter to continue...")
        elif choice in ("10", "q", "exit"):
            print("Exiting.")
            break

        else:
            print("Invalid selection.")


if __name__ == "__main__":
    main()
