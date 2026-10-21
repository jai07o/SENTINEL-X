#!/usr/bin/env python3
"""
SENTINEL-X Direct Terminal Threat Analysis & Security CLI
Allows direct terminal analysis of:
  - Links & deep software paths (payloads, redirects, PE binaries, archive unpacks)
  - Files & executables (entropy, double extensions, VBA macros, PDF actions)
  - Pictures & images (polyglots, post-EOF executables, EXIF shellcode)
  - QR codes (OpenCV quishing decode & target inspection)
  - Connected Sockets (inbound C2 trojans, suspicious listeners)
  - Camera & Mic handles (background spyware detection)
  - Cable-Connected Hardware Devices & USB drives (autorun worms, BadUSB, port quarantine)
  - Data Management & Universal Storage Purge (direct terminal wipe)
"""
import os
import sys
import argparse
import asyncio
import json
from pathlib import Path

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


# ANSI Color Codes
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"


def print_banner():
    banner = f"""{CYAN}{BOLD}
======================================================================
  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
            SENTINEL-X DIRECT TERMINAL THREAT ANALYZER               
======================================================================{RESET}"""
    print(banner)


def format_verdict(is_clean: bool, verdict: str = "") -> str:
    if is_clean:
        return f"{GREEN}{BOLD}[CLEAN / PASS]{RESET}"
    else:
        v = verdict or "MALICIOUS / THREAT DETECTED"
        return f"{RED}{BOLD}[{v.upper()}]{RESET}"


# ---------------------------------------------------------
# Command 1: Scan Link
# ---------------------------------------------------------
def cmd_scan_link(url: str):
    print(f"\n{CYAN}[*] Analyzing Link:{RESET} {url}")
    from backend.app.services.omni_scanner_service import omni_threat_scanner
    res = asyncio.run(omni_threat_scanner.scan_link(url))

    verdict_badge = format_verdict(res.get("threat_verdict") == "CLEAN", res.get("threat_verdict", ""))
    print(f"\n{BOLD}Verdict:{RESET} {verdict_badge}")
    print(f"{BOLD}Final Destination URL:{RESET} {res.get('final_destination_url')}")
    print(f"{BOLD}Risk Score:{RESET} {res.get('risk_score')}/100")
    print(f"{BOLD}Is Redirected:{RESET} {res.get('is_redirected')}")

    redirects = res.get("redirect_chain", [])
    if redirects:
        print(f"\n{YELLOW}{BOLD}Redirect Chain ({len(redirects)} hops):{RESET}")
        for i, hop in enumerate(redirects, 1):
            print(f"  {i}. {hop}")

    threats = res.get("threat_indicators", [])
    if threats:
        print(f"\n{RED}{BOLD}Threat Indicators Identified ({len(threats)}):{RESET}")
        for t in threats:
            print(f"  - {RED}{BOLD}[INDICATOR]{RESET} {t}")
    else:
        print(f"\n{GREEN}[+] No threats detected. Link is clean.{RESET}")


# ---------------------------------------------------------
# Command 2: Deep Path & Software Scan
# ---------------------------------------------------------
def cmd_deep_scan(url: str):
    print(f"\n{MAGENTA}[*] Executing Deep Path & Software Payload Analysis:{RESET} {url}")
    print(f"{YELLOW}[*] Tracing redirect chain, streaming binary payloads, inspecting PE headers & archives...{RESET}")
    from backend.app.services.omni_scanner_service import omni_threat_scanner
    res = asyncio.run(omni_threat_scanner.scan_deep_link_and_software(url))

    verdict_badge = format_verdict(res.get("threat_verdict") == "CLEAN", res.get("threat_verdict", ""))
    print(f"\n{BOLD}Path Hygiene Verdict:{RESET} {verdict_badge}")
    print(f"{BOLD}Risk Score:{RESET} {res.get('risk_score')}/100")
    print(f"{BOLD}Total Traversed Hops:{RESET} {len(res.get('redirect_chain', []))}")
    print(f"{BOLD}Software Payloads Discovered:{RESET} {res.get('software_count', 0)}")

    audit_trail = res.get("audit_trail", [])
    if audit_trail:
        print(f"\n{CYAN}{BOLD}Step-by-Step Path Traversal Audit:{RESET}")
        for step in audit_trail:
            print(f"  - {step}")

    software_list = res.get("software_payloads_analyzed", [])
    if software_list:
        print(f"\n{MAGENTA}{BOLD}Software Payload Analysis ({len(software_list)} items):{RESET}")
        for sw in software_list:
            print(f"  - File Name: {sw.get('filename')}")
            print(f"    Content Type: {sw.get('content_type')}")
            print(f"    Downloaded Bytes: {sw.get('stream_bytes_downloaded')} bytes")
            print(f"    SHA-256: {sw.get('sha256')}")
            print(f"    Shannon Entropy: {sw.get('entropy')}")
            print(f"    Is PE Executable: {sw.get('is_pe_executable')}")
            print(f"    Is Archive/ZIP: {sw.get('is_archive')}")
            if sw.get("archive_file_list"):
                print(f"    Archive Contents: {sw.get('archive_file_list')[:5]}")

    threats = res.get("threat_indicators", [])
    if threats:
        print(f"\n{RED}{BOLD}Threats Intercepted in Path/Software ({len(threats)}):{RESET}")
        for t in threats:
            print(f"  - {RED}{BOLD}[ALERT]{RESET} {t}")
    else:
        print(f"\n{GREEN}[+] Full path and payload verified completely clean.{RESET}")


# ---------------------------------------------------------
# Command 3: Scan Local File / Software
# ---------------------------------------------------------
def cmd_scan_file(file_path: str):
    p = Path(file_path)
    if not p.exists():
        print(f"{RED}[-] Error: File '{file_path}' does not exist.{RESET}")
        return

    print(f"\n{CYAN}[*] Scanning File / Software Binary:{RESET} {p.resolve()}")
    from backend.app.services.omni_scanner_service import omni_threat_scanner
    file_bytes = p.read_bytes()
    res = omni_threat_scanner.scan_file(file_bytes, p.name)

    verdict_badge = format_verdict(res.get("threat_verdict") == "CLEAN", res.get("threat_verdict", ""))
    print(f"\n{BOLD}Verdict:{RESET} {verdict_badge}")
    print(f"{BOLD}File Name:{RESET} {res.get('filename')}")
    print(f"{BOLD}Size:{RESET} {res.get('file_size_formatted')} ({res.get('file_size_bytes')} bytes)")
    print(f"{BOLD}SHA-256:{RESET} {res.get('sha256')}")
    print(f"{BOLD}Shannon Entropy:{RESET} {res.get('entropy')}/8.0")
    print(f"{BOLD}Risk Score:{RESET} {res.get('risk_score')}/100")

    threats = res.get("threat_indicators", [])
    if threats:
        print(f"\n{RED}{BOLD}Threat Indicators Identified ({len(threats)}):{RESET}")
        for t in threats:
            print(f"  - {RED}{BOLD}[ALERT]{RESET} {t}")
    else:
        print(f"\n{GREEN}[+] File verified clean. No macros, polyglots, or binary anomalies.{RESET}")


# ---------------------------------------------------------
# Command 4: Scan Picture / Image
# ---------------------------------------------------------
def cmd_scan_picture(image_path: str):
    p = Path(image_path)
    if not p.exists():
        print(f"{RED}[-] Error: Image '{image_path}' does not exist.{RESET}")
        return

    print(f"\n{CYAN}[*] Auditing Image Polyglot & Post-EOF Payload:{RESET} {p.resolve()}")
    from backend.app.services.omni_scanner_service import omni_threat_scanner
    image_bytes = p.read_bytes()
    res = omni_threat_scanner.scan_picture(image_bytes, p.name)

    verdict_badge = format_verdict(res.get("threat_verdict") == "CLEAN", res.get("threat_verdict", ""))
    print(f"\n{BOLD}Verdict:{RESET} {verdict_badge}")
    print(f"{BOLD}File Name:{RESET} {res.get('filename')}")
    print(f"{BOLD}Size:{RESET} {res.get('total_size_bytes')} bytes")
    print(f"{BOLD}Shannon Entropy:{RESET} {res.get('entropy')}/8.0")
    print(f"{BOLD}Is Polyglot Carrier:{RESET} {res.get('is_polyglot')}")
    if res.get("hidden_payload_type"):
        print(f"{BOLD}Hidden Appended Payload:{RESET} {res.get('hidden_payload_type')}")

    threats = res.get("threat_indicators", [])
    if threats:
        print(f"\n{RED}{BOLD}Polyglot / Embedded Exploits Detected ({len(threats)}):{RESET}")
        for t in threats:
            print(f"  - {RED}{BOLD}[ALERT]{RESET} {t}")
    else:
        print(f"\n{GREEN}[+] Picture verified clean. No hidden archives, EXIF shellcode, or polyglots.{RESET}")


# ---------------------------------------------------------
# Command 5: Scan QR Code
# ---------------------------------------------------------
def cmd_scan_qr(qr_path: str):
    p = Path(qr_path)
    if not p.exists():
        print(f"{RED}[-] Error: QR image '{qr_path}' does not exist.{RESET}")
        return

    print(f"\n{CYAN}[*] Decoding QR Code & Scanning Destination Payload:{RESET} {p.resolve()}")
    from backend.app.services.omni_scanner_service import omni_threat_scanner
    image_bytes = p.read_bytes()
    res = asyncio.run(omni_threat_scanner.scan_qr_code(image_bytes, p.name))

    verdict_badge = format_verdict(res.get("threat_verdict") == "CLEAN", res.get("threat_verdict", ""))
    print(f"\n{BOLD}Verdict:{RESET} {verdict_badge}")
    print(f"{BOLD}Decoded QR Text / Link:{RESET} {res.get('decoded_payload')}")
    print(f"{BOLD}Is Remote URL:{RESET} {res.get('is_url')}")
    print(f"{BOLD}Risk Score:{RESET} {res.get('risk_score')}/100")

    threats = res.get("threat_indicators", [])
    if threats:
        print(f"\n{RED}{BOLD}Threats Intercepted ({len(threats)}):{RESET}")
        for t in threats:
            print(f"  - {RED}{BOLD}[ALERT]{RESET} {t}")
    else:
        print(f"\n{GREEN}[+] QR Code payload verified clean.{RESET}")



# ---------------------------------------------------------
# Command 6: Scan Connected Sockets & C2
# ---------------------------------------------------------
def cmd_scan_sockets():
    print(f"\n{CYAN}[*] Auditing Active Network Sockets & Inbound C2 Trojans...{RESET}")
    from backend.app.services.socket_service import socket_monitor_service
    sockets = socket_monitor_service.get_active_sockets()

    print(f"\n{BOLD}Total Active Sockets Monitored:{RESET} {len(sockets)}")
    suspicious = [s for s in sockets if s.get("risk_score", 0) >= 50]

    if suspicious:
        print(f"\n{RED}{BOLD}Suspicious / High-Risk Connections Found ({len(suspicious)}):{RESET}")
        for s in suspicious:
            color = RED if s.get("risk_score", 0) >= 70 else YELLOW
            print(f"  {color}[Risk {s.get('risk_score')}/100]{RESET} PID {s.get('pid')} ({s.get('process_name')}) -> {s.get('remote_ip')}:{s.get('remote_port')} [{s.get('threat_category')}]")
    else:
        print(f"\n{GREEN}[+] All active network sockets verified normal. No inbound C2 trojans found.{RESET}")


# ---------------------------------------------------------
# Command 7: Scan Camera & Microphone Privacy
# ---------------------------------------------------------
def cmd_scan_camera():
    print(f"\n{CYAN}[*] Checking Webcam & Microphone Privacy Handles...{RESET}")
    from backend.app.services.privacy_service import privacy_sentinel_service
    data = privacy_sentinel_service.get_webcam_activity()
    summary = data.get("summary", {})

    print(f"\n{BOLD}Laptop Camera Hardware:{RESET} {summary.get('laptop_webcam_status')}")
    print(f"{BOLD}Apps Currently Accessing Camera:{RESET} {summary.get('total_apps_accessing_camera')}")
    violations = summary.get("unauthorized_background_violations", 0)

    if violations > 0:
        print(f"\n{RED}{BOLD}CRITICAL PRIVACY VIOLATIONS DETECTED ({violations} occurrences):{RESET}")
        for evt in data.get("all_events", []):
            if evt.get("is_background"):
                print(f"  - {RED}{BOLD}{evt.get('app_name')}{RESET} ({evt.get('device_type')}) - {evt.get('threat_reason')}")
    else:
        print(f"\n{GREEN}[+] No unauthorized background camera access detected.{RESET}")



# ---------------------------------------------------------
# Command 8: Scan Cable-Connected Hardware Devices & USB Ports
# ---------------------------------------------------------
def cmd_scan_cables(target_path: str = None, auto_quarantine: bool = True):
    print(f"\n{CYAN}[*] Enumerating Cable-Connected Devices & Hardware Ports...{RESET}")
    from backend.app.services.hardware_port_service import hardware_port_service
    devices = hardware_port_service.list_connected_cable_devices()

    print(f"\n{BOLD}Connected Cable Devices Found:{RESET} {len(devices)}")
    for i, dev in enumerate(devices, 1):
        status_color = RED if dev.get("quarantined") else GREEN
        mount = f" [{dev.get('mount_point')}]" if dev.get("mount_point") else ""
        print(f"  {i}. {BOLD}{dev.get('name')}{RESET}{mount} ({dev.get('device_type')}) - Status: {status_color}{dev.get('status')}{RESET}")

    # Determine what to scan: default only to non-system / removable drives
    scan_targets = []
    if target_path:
        scan_targets.append((target_path, None))
    else:
        for dev in devices:
            # Exclude C: system drive from auto-scan to avoid touching OS system files
            if dev.get("mount_point") and not dev.get("is_system_drive"):
                scan_targets.append((dev.get("mount_point"), dev.get("device_id")))

    if not scan_targets:
        print(f"\n{YELLOW}[*] No external/removable cable storage drives currently connected to scan.{RESET}")
        print(f"{YELLOW}[*] To scan a specific drive or path directly, run: python cli.py scan-cables --path <DriveLetter>:{RESET}")
        return

    for path, dev_id in scan_targets:
        print(f"\n{CYAN}[*] Deep Scanning Cable Device / Volume:{RESET} {path}")
        print(f"{YELLOW}[*] Scanning for autorun.inf, worm shortcuts, double extensions, macros, and entropy...{RESET}")
        res = hardware_port_service.scan_path_or_device(path, dev_id, auto_quarantine=auto_quarantine)

        verdict_badge = format_verdict(res.get("is_clean", True), res.get("verdict", ""))
        print(f"\n{BOLD}Port Scan Verdict:{RESET} {verdict_badge}")
        print(f"{BOLD}Files Scanned:{RESET} {res.get('files_scanned')}")

        threats = res.get("threats", [])
        if threats:
            print(f"\n{RED}{BOLD}[!] VIRUS / MALWARE FOUND ON CABLE PORT ({len(threats)} threats):{RESET}")
            for t in threats:
                print(f"  - {RED}{BOLD}[{t.get('threat_type')} - {t.get('severity')}]{RESET} {t.get('details')} (in: {t.get('file_path')})")

            if res.get("auto_quarantine_triggered"):
                print(f"\n{RED}{BOLD}[ALERT] IMMEDIATE PORT QUARANTINE EXECUTED!{RESET}")
                print(f"  - Volume dismounted and ejected immediately.")
                print(f"  - Device hardware disabled at driver level.")
                print(f"  - Port is locked to prevent any virus transmission.")
        else:
            print(f"\n{GREEN}[+] Device and cable port verified clean. Safe to use.{RESET}")



# ---------------------------------------------------------
# Command 9: Quarantine / Stop Port Manually
# ---------------------------------------------------------
def cmd_quarantine_port(target_or_device: str, reason: str = "Manual Terminal Port Quarantine"):
    print(f"\n{RED}[*] Executing Immediate Port Quarantine on:{RESET} {target_or_device}")
    from backend.app.services.hardware_port_service import hardware_port_service
    res = hardware_port_service.quarantine_port(target_or_device, reason)
    print(f"{BOLD}Result:{RESET} {res.get('message')}")
    for act in res.get("record", {}).get("actions_log", []):
        print(f"  - {act}")


# ---------------------------------------------------------
# Command 10: Release Port
# ---------------------------------------------------------
def cmd_release_port(target_or_device: str):
    print(f"\n{GREEN}[*] Releasing Port from Quarantine:{RESET} {target_or_device}")
    from backend.app.services.hardware_port_service import hardware_port_service
    res = hardware_port_service.release_port(target_or_device)
    print(f"{BOLD}Result:{RESET} {res.get('message')}")


# ---------------------------------------------------------
# Command 11: Host OS USB AutoRun Immunization
# ---------------------------------------------------------
def cmd_immunize_host():
    print(f"\n{CYAN}[*] Auditing and Applying Windows Host AutoRun Immunization...{RESET}")
    from backend.app.services.hardware_port_service import hardware_port_service
    res = hardware_port_service.apply_host_usb_immunization()
    status_color = GREEN if res.get("success") else RED
    print(f"\n{BOLD}Immunization Status:{RESET} {status_color}{res.get('status')}{RESET}")
    print(f"{BOLD}Message:{RESET} {res.get('message')}")
    for act in res.get("details", {}).get("actions", []):
        print(f"  - {GREEN}[+]{RESET} {act}")


# ---------------------------------------------------------
# Command 12: Vaccinate Connected Pendrive / Drive
# ---------------------------------------------------------
def cmd_vaccinate_drive(drive_letter: str):
    print(f"\n{CYAN}[*] Vaccinating Pendrive / Removable Drive:{RESET} {drive_letter}")
    from backend.app.services.hardware_port_service import hardware_port_service
    res = hardware_port_service.vaccinate_drive(drive_letter)
    if res.get("success"):
        print(f"\n{GREEN}{BOLD}[+] DRIVE VACCINATION SUCCESSFUL!{RESET}")
        print(f"  - Drive: {res.get('drive')}")
        print(f"  - Vaccine Path: {res.get('vaccine_path')}")
        print(f"  - {res.get('message')}")
        for act in res.get("actions", []):
            print(f"    * {act}")
        print(f"{GREEN}[+] Immune lock active. Viruses cannot create autorun.inf on this drive.{RESET}")
    else:
        print(f"\n{RED}{BOLD}[!] Vaccination Failed:{RESET} {res.get('message')}")


# ---------------------------------------------------------
# Command 13: Live Real-Time USB Insertion Watcher & Guard
# ---------------------------------------------------------
def cmd_watch_usb():
    print(f"\n{CYAN}{BOLD}======================================================================{RESET}")
    print(f"{CYAN}{BOLD}  SENTINEL-X REAL-TIME USB PENDRIVE INSERTION INTERCEPTOR & GUARD     {RESET}")
    print(f"{CYAN}{BOLD}======================================================================{RESET}")
    print(f"{YELLOW}[*] Live Watcher engaged. Plug any USB pendrive or cable device into this PC.{RESET}")
    print(f"{YELLOW}[*] The instant a pendrive is plugged in, SENTINEL-X will intercept it,{RESET}")
    print(f"{YELLOW}[*] scan all files, and IMMEDIATELY dismount/halt the port if a virus is found.{RESET}")
    print(f"{YELLOW}[*] Press Ctrl+C anytime to stop watching.{RESET}\n")

    from backend.app.services.hardware_port_service import hardware_port_service
    import time

    known_drives = {
        d.get("drive_letter") for d in hardware_port_service.list_connected_cable_devices()
        if d.get("is_removable") and d.get("drive_letter")
    }
    print(f"[*] Initial active removable drives tracked: {list(known_drives) if known_drives else 'None'}")
    print(f"{GREEN}[+] Standing guard... Watching for USB plug-in events...{RESET}\n")

    try:
        while True:
            time.sleep(1.5)
            devices = hardware_port_service.list_connected_cable_devices()
            current_drives = {
                d.get("drive_letter") for d in devices
                if d.get("is_removable") and d.get("drive_letter")
            }
            new_drives = current_drives - known_drives
            if new_drives:
                for nd in new_drives:
                    dev_info = next((d for d in devices if d.get("drive_letter") == nd), None)
                    print(f"\n{YELLOW}{BOLD}[ALERT] USB PENDRIVE INSERTION DETECTED: Drive {nd} ({dev_info.get('name') if dev_info else 'USB Device'}){RESET}")
                    print(f"{CYAN}[*] Intercepting before virus injection... Deep scanning all files and scripts...{RESET}")

                    intercept_res = hardware_port_service.intercept_device_insertion(dev_info or {"drive_letter": nd, "mount_point": f"{nd}\\"})
                    scan_res = intercept_res.get("scan_result", {})

                    if intercept_res.get("is_threat"):
                        print(f"\n{RED}{BOLD}======================================================================{RESET}")
                        print(f"{RED}{BOLD}[CRITICAL VIRUS DETECTED ON PENDRIVE {nd}] - INJECTION HALTED!{RESET}")
                        print(f"{RED}{BOLD}======================================================================{RESET}")
                        for t in scan_res.get("threats", []):
                            print(f"  - {RED}{BOLD}[{t.get('threat_type')}]{RESET} {t.get('details')} (file: {t.get('file_path')})")
                        print(f"\n{RED}{BOLD}[PORT QUARANTINE EXECUTED]:{RESET}")
                        print(f"  - Volume {nd} immediately force-dismounted ({scan_res.get('drive_letter')}).")
                        print(f"  - Disk taken offline at kernel level.")
                        print(f"  - Device hardware disabled at driver level.")
                        print(f"  - {RED}VIRUS BLOCKED! Your laptop is completely safe.{RESET}\n")
                    else:
                        print(f"\n{GREEN}{BOLD}[+] PENDRIVE {nd} VERIFIED CLEAN & SAFE TO USE!{RESET}")
                        print(f"  - Files audited: {scan_res.get('files_scanned', 0)}")
                        print(f"  - No autorun worms, hidden droppers, or BadUSB scripts found.\n")

            known_drives = current_drives
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[*] USB Real-time Watcher stopped.{RESET}")


# ---------------------------------------------------------
# Command 14: Purge / Wipe Operational Data
# ---------------------------------------------------------
def cmd_purge_data(category: str = "all", confirm: bool = False):
    if not confirm:
        print(f"\n{YELLOW}{BOLD}WARNING: You are about to permanently delete records for category: '{category}'.{RESET}")
        ans = input("Are you sure you want to proceed? Type 'DELETE' to confirm: ").strip()
        if ans != "DELETE":
            print(f"{RED}[*] Deletion aborted.{RESET}")
            return

    print(f"\n{RED}[*] Purging database records for category: {category}...{RESET}")
    from backend.app.database import async_session_factory
    from backend.app.services.data_management_service import data_management_service

    async def _do_purge():
        async with async_session_factory() as db:
            return await data_management_service.purge_category(db, category)

    res = asyncio.run(_do_purge())
    print(f"\n{GREEN}{BOLD}[+] Purge Complete!{RESET}")
    print(f"  - Category: {res.get('category')}")
    print(f"  - Total Records Deleted: {res.get('total_deleted')}")
    print(f"  - Details: {json.dumps(res.get('deleted_records'), indent=2)}")


# ---------------------------------------------------------
# Interactive Menu Mode
# ---------------------------------------------------------
def run_interactive_menu():
    while True:
        print_banner()
        print("  [1]  Scan Web Link / URL")
        print("  [2]  Deep Path & Binary Software Analysis (Redirects, Payloads, Archives)")
        print("  [3]  Scan Local File / Executable (Entropy, Macros, Double Extension)")
        print("  [4]  Scan Picture / Image (Polyglot, Post-EOF Executables, EXIF)")
        print("  [5]  Scan QR Code Image (Quishing & Payload Decode)")
        print("  [6]  Audit Active Network Sockets & Inbound C2 Trojans")
        print("  [7]  Audit Camera & Microphone Privacy Handles")
        print("  [8]  Scan Cable-Connected Hardware Devices & USB Ports (Auto-Quarantine)")
        print("  [9]  Immediately Quarantine / Block a Hardware Port")
        print("  [10] Release / Re-enable a Quarantined Port")
        print("  [11] Live Watch & Guard USB Pendrive Plug-in Events (Instant Intercept)")
        print("  [12] Immunize Host Laptop (Disable AutoRun / AutoPlay Injections)")
        print("  [13] Vaccinate a Pendrive / Removable Drive (Lock autorun.inf)")
        print("  [14] Purge / Delete Operational Data (Wipe Tables)")
        print("  [15] Exit")
        print("=" * 70)

        choice = input("Select an option [1-15]: ").strip()

        if choice == "1":
            url = input("Enter URL to scan: ").strip()
            if url:
                cmd_scan_link(url)
            input("\nPress Enter to return to menu...")
        elif choice == "2":
            url = input("Enter Link/Software URL for Deep Analysis: ").strip()
            if url:
                cmd_deep_scan(url)
            input("\nPress Enter to return to menu...")
        elif choice == "3":
            fp = input("Enter file path: ").strip().strip('"')
            if fp:
                cmd_scan_file(fp)
            input("\nPress Enter to return to menu...")
        elif choice == "4":
            ip = input("Enter picture path: ").strip().strip('"')
            if ip:
                cmd_scan_picture(ip)
            input("\nPress Enter to return to menu...")
        elif choice == "5":
            qp = input("Enter QR code image path: ").strip().strip('"')
            if qp:
                cmd_scan_qr(qp)
            input("\nPress Enter to return to menu...")
        elif choice == "6":
            cmd_scan_sockets()
            input("\nPress Enter to return to menu...")
        elif choice == "7":
            cmd_scan_camera()
            input("\nPress Enter to return to menu...")
        elif choice == "8":
            target = input("Enter drive letter/path (e.g. 'E:\\', or leave blank for all connected devices): ").strip().strip('"')
            cmd_scan_cables(target or None)
            input("\nPress Enter to return to menu...")
        elif choice == "9":
            target = input("Enter drive letter or device ID to quarantine (e.g. 'E:', 'G:'): ").strip()
            if target:
                cmd_quarantine_port(target)
            input("\nPress Enter to return to menu...")
        elif choice == "10":
            target = input("Enter drive letter or device ID to release: ").strip()
            if target:
                cmd_release_port(target)
            input("\nPress Enter to return to menu...")
        elif choice == "11":
            cmd_watch_usb()
            input("\nPress Enter to return to menu...")
        elif choice == "12":
            cmd_immunize_host()
            input("\nPress Enter to return to menu...")
        elif choice == "13":
            dl = input("Enter pendrive drive letter to vaccinate (e.g. 'G:' or 'E:\\'): ").strip().strip('"')
            if dl:
                cmd_vaccinate_drive(dl)
            input("\nPress Enter to return to menu...")
        elif choice == "14":
            cat = input("Enter category to purge (events, incidents, malware, forensics, all): ").strip()
            cmd_purge_data(cat or "all")
            input("\nPress Enter to return to menu...")
        elif choice in ("15", "q", "exit"):
            print("Exiting SENTINEL-X CLI.")
            break
        else:
            print("Invalid selection.")


def main():
    parser = argparse.ArgumentParser(
        description="SENTINEL-X Direct Terminal Threat Analysis CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # scan-link
    p_link = subparsers.add_parser("scan-link", help="Analyze URL for phishing, redirects, and malware")
    p_link.add_argument("url", help="Target URL")

    # deep-scan
    p_deep = subparsers.add_parser("deep-scan", help="Recursive deep path & binary software payload inspection")
    p_deep.add_argument("url", help="Target URL to deep inspect")

    # scan-file
    p_file = subparsers.add_parser("scan-file", help="Scan local file or software binary")
    p_file.add_argument("path", help="Path to file")

    # scan-picture
    p_pic = subparsers.add_parser("scan-picture", help="Audit image for polyglots, hidden archives, and EXIF shellcode")
    p_pic.add_argument("path", help="Path to picture")

    # scan-qr
    p_qr = subparsers.add_parser("scan-qr", help="Decode QR code and inspect destination URL")
    p_qr.add_argument("path", help="Path to QR code image")

    # scan-sockets
    subparsers.add_parser("scan-sockets", help="Audit active network sockets and inbound C2 trojans")

    # scan-camera
    subparsers.add_parser("scan-camera", help="Audit camera and microphone handles for unauthorized access")

    # scan-cables
    p_cables = subparsers.add_parser("scan-cables", help="Scan cable-connected devices & USB ports with auto-quarantine")
    p_cables.add_argument("--path", default=None, help="Specific drive letter or path to scan (e.g. 'E:\\')")
    p_cables.add_argument("--no-quarantine", action="store_true", help="Disable automatic port quarantine on threat detection")

    # quarantine-port
    p_quar = subparsers.add_parser("quarantine-port", help="Immediately dismount and block a hardware port / device")
    p_quar.add_argument("target", help="Drive letter (e.g. 'E:') or device hardware instance ID")

    # release-port
    p_rel = subparsers.add_parser("release-port", help="Release and re-enable a quarantined hardware port")
    p_rel.add_argument("target", help="Drive letter or device ID to unblock")

    # watch-usb
    subparsers.add_parser("watch-usb", help="Real-time live watcher that intercepts pendrive insertions and blocks virus injection")

    # immunize-host
    subparsers.add_parser("immunize-host", help="Apply host laptop Windows registry immunization against USB AutoRun/AutoPlay injections")

    # vaccinate-drive
    p_vacc = subparsers.add_parser("vaccinate-drive", help="Vaccinate a pendrive with an immutable autorun.inf lock")
    p_vacc.add_argument("drive", help="Drive letter (e.g. 'G:' or 'E:\\')")

    # purge-data
    p_purge = subparsers.add_parser("purge-data", help="Purge or wipe operational data directly from database")
    p_purge.add_argument("--category", default="all", help="Category: events, incidents, malware, forensics, all")
    p_purge.add_argument("--yes", action="store_true", help="Skip confirmation prompt")

    # interactive
    subparsers.add_parser("interactive", help="Launch interactive menu console")

    args = parser.parse_args()

    if not args.command or args.command == "interactive":
        run_interactive_menu()
    elif args.command == "scan-link":
        cmd_scan_link(args.url)
    elif args.command == "deep-scan":
        cmd_deep_scan(args.url)
    elif args.command == "scan-file":
        cmd_scan_file(args.path)
    elif args.command == "scan-picture":
        cmd_scan_picture(args.path)
    elif args.command == "scan-qr":
        cmd_scan_qr(args.path)
    elif args.command == "scan-sockets":
        cmd_scan_sockets()
    elif args.command == "scan-camera":
        cmd_scan_camera()
    elif args.command == "scan-cables":
        cmd_scan_cables(args.path, auto_quarantine=not args.no_quarantine)
    elif args.command == "quarantine-port":
        cmd_quarantine_port(args.target)
    elif args.command == "release-port":
        cmd_release_port(args.target)
    elif args.command == "watch-usb":
        cmd_watch_usb()
    elif args.command == "immunize-host":
        cmd_immunize_host()
    elif args.command == "vaccinate-drive":
        cmd_vaccinate_drive(args.drive)
    elif args.command == "purge-data":
        cmd_purge_data(args.category, confirm=args.yes)


if __name__ == "__main__":
    main()
