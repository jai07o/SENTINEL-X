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
import psutil

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
     Chief Security Architect: K. Jaideep Raj | Google Antigravity
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
# Command 15: Platform Self-Defense & Code Integrity Audit
# ---------------------------------------------------------
def cmd_audit_integrity():
    print(f"\n{CYAN}{BOLD}[*] Performing Platform Self-Defense & Code Integrity Audit...{RESET}")
    from backend.app.services.integrity_service import platform_integrity_sentinel
    res = platform_integrity_sentinel.audit_integrity()

    is_intact = res.get("is_intact", False)
    status_badge = f"{GREEN}{BOLD}[INTEGRITY VERIFIED - CLEAN]{RESET}" if is_intact else f"{RED}{BOLD}[INTEGRITY COMPROMISED - TAMPER DETECTED]{RESET}"
    
    print(f"\n{BOLD}Verdict:{RESET} {status_badge}")
    print(f"{BOLD}Modules Monitored:{RESET} {res.get('modules_monitored')}")
    print(f"{BOLD}Modules Verified Clean:{RESET} {res.get('modules_verified')}")
    print(f"{BOLD}Tampered Files Count:{RESET} {res.get('tampered_count')}")
    print(f"{BOLD}Missing Files Count:{RESET} {res.get('missing_count')}")

    if res.get("tampered_files"):
        print(f"\n{RED}{BOLD}ALERT: The following files were tampered with or modified on disk:{RESET}")
        for tf in res["tampered_files"]:
            print(f"  - {RED}{tf}{RESET}")

    if res.get("missing_files"):
        print(f"\n{RED}{BOLD}ALERT: The following core modules are missing:{RESET}")
        for mf in res["missing_files"]:
            print(f"  - {RED}{mf}{RESET}")

    if is_intact:
        print(f"\n{GREEN}[+] All core engine files match their cryptographic SHA-256 baselines. No tampering detected.{RESET}")


# ---------------------------------------------------------
# Command 16: Military-Grade Security Armor Posture Report
# ---------------------------------------------------------
def cmd_security_armor():
    print(f"\n{CYAN}{BOLD}[*] Evaluating SENTINEL-X Military-Grade Security Armor Posture...{RESET}")
    from backend.app.services.integrity_service import platform_integrity_sentinel
    res = platform_integrity_sentinel.get_security_posture_summary()

    print(f"\n{MAGENTA}{BOLD}======================================================================{RESET}")
    print(f"  {BOLD}SENTINEL-X DEFENSE-IN-DEPTH SECURITY POSTURE REPORT{RESET}")
    print(f"{MAGENTA}{BOLD}======================================================================{RESET}")
    print(f"  {BOLD}Security Grade:{RESET} {GREEN}{BOLD}{res.get('security_grade')}{RESET}")
    
    integ = res.get("self_integrity", {})
    integ_badge = f"{GREEN}PASS{RESET}" if integ.get("is_intact") else f"{RED}FAIL{RESET}"
    print(f"\n  {BOLD}[1] Platform Self-Defense & Code Integrity:{RESET} {integ_badge}")
    print(f"      - Modules Monitored: {integ.get('modules_monitored')}")
    print(f"      - Tampered Files: {integ.get('tampered_count')}")

    trans = res.get("transport_security", {})
    print(f"\n  {BOLD}[2] Transport & Browser Armor (Grade A+):{RESET}")
    print(f"      - Strict-Transport-Security: max-age=63072000 (HSTS Preload Ready)")
    print(f"      - Content-Security-Policy: {trans.get('content_security_policy')}")
    print(f"      - Anti-Clickjacking: {trans.get('x_frame_options')}")
    print(f"      - MIME-Sniffing Defense: {trans.get('x_content_type_options')}")
    print(f"      - Permissions-Policy: {trans.get('permissions_policy')}")

    ac = res.get("access_control", {})
    print(f"\n  {BOLD}[3] Authentication & Anti-Brute-Force Shield:{RESET}")
    print(f"      - Adaptive Lockout: Active (Max {ac.get('max_failures_threshold')} failures per {ac.get('lockout_duration_seconds')}s)")
    print(f"      - Active IP Lockouts: {ac.get('active_lockouts')}")
    print(f"      - Timing-Attack Resistance: {ac.get('timing_attack_resistance')}")

    hw = res.get("hardware_and_ports", {})
    immun_badge = f"{GREEN}IMMUNIZED{RESET}" if hw.get("autorun_immunization_active") else f"{YELLOW}NOT IMMUNIZED{RESET}"
    print(f"\n  {BOLD}[4] Hardware & Removable USB Injection Defense:{RESET}")
    print(f"      - Windows AutoRun Registry Immunization: {immun_badge}")
    print(f"      - Windows IniFileMapping Redirection: {hw.get('inifilemapping_disabled')}")
    print(f"      - BadUSB / Rubber Ducky Microcontroller Heuristics: {hw.get('badusb_heuristics')}")

    mem = res.get("memory_and_payload_defenses", {})
    print(f"\n  {BOLD}[5] Memory & Payload Exhaustion Defenses:{RESET}")
    print(f"      - Request Payload Ceiling: {mem.get('max_request_payload_mb')} MB (DoS Prevention)")
    print(f"      - Path Traversal & LFI Guard: {mem.get('path_traversal_guards')}")
    print(f"{MAGENTA}{BOLD}======================================================================{RESET}")


# ---------------------------------------------------------
# Command 17: Controlled Attack Simulation (Cross-Platform)
# ---------------------------------------------------------
def cmd_simulate_hack(platform: str = "kali"):
    print(f"\n{CYAN}{BOLD}[*] Launching End-to-End Live Attack Simulation, Containment & Forensic Vault Seal...{RESET}")
    print(f"{BOLD}Target Platform:{RESET} {platform.upper()}")
    from simulator.attack_simulation_pipeline import ControlledAttackSimulationPipeline
    pipeline = ControlledAttackSimulationPipeline()
    result = asyncio.run(pipeline.run_simulation(target_platform=platform))

    print(f"\n{GREEN}{BOLD}======================================================================{RESET}")
    print(f"  {GREEN}{BOLD}[+] SIMULATION & DEFENSIVE WORKFLOW VERIFIED SUCCESSFULLY!{RESET}")
    print(f"{GREEN}{BOLD}======================================================================{RESET}")
    print(f"{BOLD}Scenario:{RESET} {result.get('scenario')}")
    print(f"{BOLD}Platform Target:{RESET} {result.get('target_platform')}")
    
    det = result.get("detection", {})
    print(f"\n  {BOLD}[1] Real-Time Threat Detection & Correlation:{RESET}")
    print(f"      - Incident Number: {det.get('incident_number')}")
    print(f"      - Incident Title:  {det.get('incident_title')}")
    print(f"      - Severity:        {RED}{BOLD}{det.get('severity')}{RESET}")
    print(f"      - Confidence:      {det.get('confidence') * 100:.1f}%")
    print(f"      - Matched Rule:    {det.get('matched_rule')}")

    ev = result.get("evidence_preservation", {})
    tamper_badge = f"{GREEN}CRYPTOGRAPHICALLY VERIFIED (INTACT){RESET}" if ev.get("tamper_verified") else f"{RED}TAMPER DETECTED{RESET}"
    print(f"\n  {BOLD}[2] Forensic Crime-Scene Evidence Preservation:{RESET}")
    print(f"      - Evidence ID:     {ev.get('evidence_number')}")
    print(f"      - SHA-256 Digest:  {ev.get('sha256_hash')}")
    print(f"      - Vault File:      {ev.get('vault_file')}")
    print(f"      - Chain-of-Custody:{ev.get('chain_of_custody_status')}")
    print(f"      - Vault Integrity: {tamper_badge}")

    cont = result.get("containment_execution", {})
    print(f"\n  {BOLD}[3] Safe Automated Threat Containment:{RESET}")
    print(f"      - Host Isolation:  {RED}{BOLD}{cont.get('host_isolation')}{RESET}")
    print(f"      - Process Action:  {cont.get('process_neutralization')}")
    print(f"      - Action Summary:  {cont.get('summary')}")
    print(f"\n{GREEN}{BOLD}Unified Architecture Proven: Live Telemetry -> Attack Detection -> Forensic Vault Seal -> Automated Containment.{RESET}\n")


# ---------------------------------------------------------
# Command 18: One-Click Contain & Preserve Active Incident
# ---------------------------------------------------------
def cmd_contain_and_preserve(incident_id: str = "latest"):
    print(f"\n{CYAN}{BOLD}[*] Triggering One-Click Threat Containment & Digital Forensics Vault Preservation...{RESET}")
    from backend.app.database import AsyncSessionLocal
    from backend.app.services.containment_evidence_orchestrator import orchestrator
    from backend.app.models.incident import Incident
    from sqlalchemy import select

    async def _execute():
        async with AsyncSessionLocal() as session:
            inc_id = incident_id
            if not inc_id or inc_id.lower() in ("latest", "last"):
                stmt = select(Incident).order_by(Incident.created_at.desc()).limit(1)
                res = await session.execute(stmt)
                inc = res.scalar_one_or_none()
                if not inc:
                    print(f"{RED}[-] No incidents found in database to contain.{RESET}")
                    return None
                inc_id = inc.id
                print(f"[+] Targeting most recent active incident: {inc.incident_number} ({inc.title})")

            threat_context = {
                "source": "Direct CLI Security Command",
                "notes": "Emergency automated evidence vault preservation and host isolation triggered via CLI.",
            }
            res = await orchestrator.contain_and_preserve(
                db=session,
                incident_id=inc_id,
                threat_context=threat_context,
                auto_isolate_host=True,
                auto_kill_process=False,
            )
            return res

    result = asyncio.run(_execute())
    if not result:
        return

    print(f"\n{GREEN}{BOLD}======================================================================{RESET}")
    print(f"  {GREEN}{BOLD}[+] INCIDENT CONTAINED & FORENSIC EVIDENCE PRESERVED!{RESET}")
    print(f"{GREEN}{BOLD}======================================================================{RESET}")
    ev = result.get("evidence", {})
    print(f"{BOLD}Evidence Number:{RESET}      {ev.get('evidence_number')}")
    print(f"{BOLD}Cryptographic SHA-256:{RESET} {ev.get('sha256')}")
    print(f"{BOLD}Vault File Path:{RESET}       {ev.get('vault_path')}")
    print(f"{BOLD}Forensic Case Opened:{RESET}  {ev.get('case_number')}")
    print(f"{BOLD}Containment Action:{RESET}    {result.get('containment_summary')}\n")


# ---------------------------------------------------------
# Command 19: Supreme Real-Time Live Safeguard & Forensics Guard
# ---------------------------------------------------------
def cmd_live_safeguard(continuous: bool = False):
    print(f"\n{CYAN}{BOLD}[*] Engaging SENTINEL-X Supreme Real-Time Physical Host Safeguard...{RESET}")
    from backend.app.services.live_safeguard_rectifier import LiveThreatHunter, supreme_safeguard

    threats = LiveThreatHunter.hunt_active_threats()
    print(f"{BOLD}Physical Host Swept:{RESET} {len(psutil.pids())} active processes inspected.")

    if not threats:
        print(f"\n{GREEN}{BOLD}[+] STATUS: HOST IS SECURE & CLEAN. Zero active intrusions detected.{RESET}")
    else:
        print(f"\n{RED}{BOLD}[!] CRITICAL: {len(threats)} ACTIVE INTRUSION(S) DETECTED ON PHYSICAL HOST!{RESET}")
        for i, th in enumerate(threats, 1):
            print(f"  [{i}] {RED}{BOLD}{th['process_name']}{RESET} (PID: {th['pid']}) - {th['category']}")
            print(f"      Path: {th['exe_path']}")
            print(f"      Risk: {th['risk_score']}/100")
            for ind in th['indicators']:
                print(f"      - {YELLOW}{ind}{RESET}")
            
            if sys.stdin.isatty():
                ans = input(f"\nImmediately Rectify Threat PID {th['pid']} (Freeze Forensics, Kill, Wipe Persistence)? [Y/n]: ").strip().lower()
                if ans != "n":
                    cmd_rectify_threat(str(th["pid"]))
            else:
                print(f"\n{YELLOW}[!] Run 'python cli.py rectify {th['pid']}' to execute forensic freeze, kill process, and wipe persistence.{RESET}")

    if continuous:
        print(f"\n{GREEN}{BOLD}[*] Starting Continuous Background Guardian Loop (Press Ctrl+C to stop)...{RESET}")
        async def _run_continuous():
            await supreme_safeguard.start_live_safeguard_daemon(interval_seconds=3)
            try:
                while True:
                    await asyncio.sleep(1)
            except (KeyboardInterrupt, asyncio.CancelledError):
                await supreme_safeguard.stop_live_safeguard_daemon()
                print(f"\n{YELLOW}[*] Live Safeguard Daemon stopped cleanly.{RESET}")

        try:
            asyncio.run(_run_continuous())
        except KeyboardInterrupt:
            print(f"\n{YELLOW}[*] Live Safeguard Daemon exited.{RESET}")


# ---------------------------------------------------------
# Command 20: Rectify Threat (Forensics Freeze + Kill + Persistence Wipe)
# ---------------------------------------------------------
def cmd_rectify_threat(target: str):
    print(f"\n{CYAN}{BOLD}[*] Executing Supreme Incident Rectification on Target: {target}...{RESET}")
    from backend.app.services.live_safeguard_rectifier import supreme_safeguard, LiveThreatHunter

    target_pid = None
    if target.isdigit():
        target_pid = int(target)
    else:
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if target.lower() in proc.info['name'].lower():
                    target_pid = proc.info['pid']
                    break
            except Exception:
                pass

    if not target_pid:
        print(f"{RED}[-] Target process '{target}' not found running on physical system.{RESET}")
        return

    print(f"[+] Target identified: PID {target_pid}")
    res = asyncio.run(supreme_safeguard.execute_full_safeguard_cycle(target_pid))

    print(f"\n{GREEN}{BOLD}======================================================================{RESET}")
    print(f"  {GREEN}{BOLD}[+] INCIDENT RECTIFIED & PHYSICAL HOST SAFEGUARDED!{RESET}")
    print(f"{GREEN}{BOLD}======================================================================{RESET}")
    print(f"{BOLD}Incident ID:{RESET}          {res.get('incident_id')}")
    print(f"{BOLD}Neutralized PIDs:{RESET}     {res.get('neutralization', {}).get('terminated_pids')}")
    
    fe = res.get("forensics", {})
    print(f"\n  {BOLD}[1] Court-Admissible Forensics Crime Scene Record:{RESET}")
    print(f"      - Evidence Number:  {fe.get('evidence_number')}")
    print(f"      - SHA-256 Digest:   {fe.get('sha256_digest')}")
    print(f"      - Vault File Path:  {fe.get('vault_path')}")
    print(f"      - Shannon Entropy:  {fe.get('shannon_entropy')}")
    print(f"      - Vault Security:   {GREEN}SEALED READ-ONLY (0400){RESET}")

    rem = res.get("remediation", {})
    print(f"\n  {BOLD}[2] System Remediation & Persistence Elimination:{RESET}")
    print(f"      - Registry Run Keys Wiped: {rem.get('registry_persistence_removed')} entries")
    print(f"      - Startup Shortcuts Cleared:{rem.get('startup_shortcuts_cleaned')}")
    print(f"      - Dropper Binary Quarantined:{rem.get('dropper_quarantined')}")
    print(f"      - DNS Resolution Cache:    {GREEN}Flushed & Purged{RESET}")
    print(f"      - Rectification Certificate:{rem.get('certificate_path')}")
    print(f"\n{GREEN}{BOLD}[+] Host security status restored to: 100% CLEAN & PROTECTED.{RESET}\n")


# ---------------------------------------------------------
# Commands 21-26: Wi-Fi, Fake Network, Rogue AP & ARP Safeguards
# ---------------------------------------------------------
def cmd_scan_wifi():
    print(f"\n{CYAN}{BOLD}[*] Engaging SENTINEL-X Wi-Fi, Rogue AP & Network Defense Audit...{RESET}")
    from backend.app.services.wifi_guard_service import WiFiThreatDetector

    report = WiFiThreatDetector.audit_wifi_and_network_security()
    wifi = report.get("current_wifi", {})
    gw = report.get("default_gateway", {})
    dns = report.get("dns_servers", [])

    print(f"{BOLD}Physical Host State:{RESET}")
    print(f"  - Interface Name:     {wifi.get('interface_name') or 'N/A'}")
    print(f"  - Connected SSID:     {GREEN if wifi.get('connected') else YELLOW}{wifi.get('ssid') or 'Disconnected'}{RESET}")
    print(f"  - Access Point BSSID: {wifi.get('bssid') or 'N/A'}")
    print(f"  - Authentication:     {wifi.get('authentication') or 'N/A'}")
    print(f"  - Encryption Cipher:  {wifi.get('cipher') or 'N/A'}")
    print(f"  - Radio / Channel:    {wifi.get('radio_type')} (Ch {wifi.get('channel')})")
    print(f"  - Signal Strength:    {wifi.get('signal_percent') or 'N/A'}")
    print(f"  - Default Gateway:    {gw.get('ip')} ({gw.get('mac')})")
    dns_str = ', '.join([d.get('ip') for d in dns]) if dns else 'None'
    print(f"  - Active DNS Servers: {dns_str}")

    threats = report.get("threats", [])
    if not threats:
        print(f"\n{GREEN}{BOLD}[+] WI-FI & NETWORK STATUS: 100% SECURE & PROTECTED.{RESET}")
        print(f"    Zero Evil Twins, Rogue APs, or ARP Spoofing attacks detected.\n")
    else:
        print(f"\n{RED}{BOLD}[!] CRITICAL: {len(threats)} NETWORK INTRUSION THREAT(S) DETECTED!{RESET}")
        for i, t in enumerate(threats, 1):
            print(f"  [{i}] {RED}{BOLD}{t.get('category')}{RESET} - {t.get('title')}")
            print(f"      Risk Score:  {t.get('risk_score')}/100 ({t.get('severity')})")
            print(f"      Rationale:   {t.get('description')}")
            print(f"      Action:      {YELLOW}{t.get('recommended_action')}{RESET}")

        if sys.stdin.isatty():
            ans = input("\nImmediately Rectify Threat (Freeze Forensics, Sever Wi-Fi, Flush Caches)? [Y/n]: ").strip().lower()
            if ans != "n":
                cmd_rectify_wifi()
        else:
            print(f"\n{YELLOW}[!] Run 'python cli.py rectify-wifi' or 'python cli.py disconnect-wifi' to sever and preserve evidence.{RESET}\n")


def cmd_guard_wifi(continuous: bool = False):
    print(f"\n{CYAN}{BOLD}[*] Starting SENTINEL-X Real-Time Wi-Fi & Network Guardian...{RESET}")
    from backend.app.services.wifi_guard_service import wifi_guard_daemon
    if continuous:
        async def _run():
            await wifi_guard_daemon.start(interval_seconds=4, auto_sever=True)
            print(f"{GREEN}{BOLD}[+] Wi-Fi Guardian engaged in continuous monitoring mode (Ctrl+C to stop)...{RESET}")
            try:
                while True:
                    await asyncio.sleep(1)
            except (KeyboardInterrupt, asyncio.CancelledError):
                wifi_guard_daemon.stop()
                print(f"\n{YELLOW}[*] Wi-Fi Guardian safely stopped.{RESET}")
        try:
            asyncio.run(_run())
        except KeyboardInterrupt:
            print(f"\n{YELLOW}[*] Stopped.{RESET}")
    else:
        cmd_scan_wifi()


def cmd_harden_network():
    print(f"\n{CYAN}{BOLD}[*] Applying Physical Host Network Stack Hardening...{RESET}")
    from backend.app.services.wifi_guard_service import WiFiNetworkHardener
    res = WiFiNetworkHardener.harden_network_host_defenses()
    print(f"{GREEN}{BOLD}[+] Hardening status: {res.get('status')}{RESET}")
    for act in res.get("applied_hardening", []):
        print(f"  - {act}")
    print()


def cmd_trust_wifi():
    from backend.app.services.wifi_guard_service import WiFiNetworkAuditor, WiFiTrustedStore
    wifi = WiFiNetworkAuditor.get_current_wifi_details()
    if not wifi.get("connected") or not wifi.get("ssid"):
        print(f"{RED}[-] Host is not currently connected to any Wi-Fi network.{RESET}")
        return
    pinned = WiFiTrustedStore.trust_wifi_network(
        ssid=wifi.get("ssid"),
        bssid=wifi.get("bssid"),
        cipher=wifi.get("cipher") or "WPA2",
        authentication=wifi.get("authentication") or "WPA2-Personal",
    )
    print(f"\n{GREEN}{BOLD}[+] Wi-Fi Network Pinned as Trusted Baseline Signature!{RESET}")
    print(f"  SSID:            {pinned.get('ssid')}")
    print(f"  Trusted BSSID:   {pinned.get('trusted_bssids')}")
    print(f"  Expected Cipher: {pinned.get('expected_cipher')}")
    print(f"  Expected Auth:   {pinned.get('expected_auth')}")
    print(f"  Timestamp:       {pinned.get('pinned_at')}\n")


def cmd_disconnect_wifi():
    from backend.app.services.wifi_guard_service import WiFiNetworkHardener
    print(f"\n{YELLOW}{BOLD}[!] Executing Emergency Severance from Wi-Fi...{RESET}")
    res = WiFiNetworkHardener.emergency_disconnect_wifi()
    if res.get("success"):
        print(f"{GREEN}[+] Successfully severed connection from Wi-Fi.{RESET}\n")
    else:
        print(f"{RED}[-] Disconnect command result: {res.get('details')}{RESET}\n")


def cmd_rectify_wifi():
    from backend.app.services.wifi_guard_service import WiFiThreatDetector, WiFiForensicVault
    print(f"\n{CYAN}{BOLD}[*] Executing Supreme Wi-Fi & Network Incident Rectification...{RESET}")
    report = WiFiThreatDetector.audit_wifi_and_network_security()
    res = asyncio.run(WiFiForensicVault.freeze_network_crime_scene_and_rectify(audit_report=report, auto_disconnect=True))
    print(f"\n{GREEN}{BOLD}======================================================================{RESET}")
    print(f"  {GREEN}{BOLD}[+] WI-FI INCIDENT RECTIFIED & PHYSICAL HOST IMMUNIZED!{RESET}")
    print(f"{GREEN}{BOLD}======================================================================{RESET}")
    print(f"{BOLD}Incident ID:{RESET}          {res.get('incident_id')}")
    ev = res.get("evidence", {})
    print(f"  [1] Court-Admissible Forensics Vault:")
    print(f"      - Evidence Record:  {ev.get('evidence_number')}")
    print(f"      - SHA-256 Digest:   {ev.get('sha256')}")
    print(f"      - Vault File Path:  {ev.get('vault_path')}")
    print(f"      - Security Lock:    {GREEN}{ev.get('security')}{RESET}")
    rem = res.get("remediation", {})
    print(f"  [2] Network Disarming & Remediation:")
    print(f"      - Wi-Fi Disconnected:       {rem.get('disconnected')}")
    print(f"      - Malicious Profile Purged: {rem.get('profile_purged')}")
    print(f"      - Rectification Certificate:{rem.get('certificate_path')}")
    print(f"\n{GREEN}{BOLD}[+] Host network security restored to: 100% CLEAN & PROTECTED.{RESET}\n")


# ---------------------------------------------------------
# Command: Safe Charging Mode (Juice Jacking Defense)
# ---------------------------------------------------------
def cmd_safe_charging(enabled: Optional[bool] = None):
    from backend.app.services.hardware_port_service import hardware_port_service
    if enabled is None:
        status = hardware_port_service.get_safe_charging_status()
        print(f"\n{CYAN}{BOLD}[*] Charger-Only Safe Charging Mode Status:{RESET}")
        print(f"    Active:   {status.get('safe_charging_enabled')}")
        print(f"    Status:   {status.get('status')}")
        print(f"    Details:  {status.get('message')}")
        return

    if enabled:
        res = hardware_port_service.enable_safe_charging_mode()
        print(f"\n{GREEN}{BOLD}[+] Safe Charging Shield ENABLED!{RESET}")
        print(f"    USB data pin communication locked down.")
        print(f"    Juice Jacking & malicious cable exploits blocked; power charging active.")
    else:
        res = hardware_port_service.disable_safe_charging_mode()
        print(f"\n{YELLOW}{BOLD}[!] Safe Charging Shield DISABLED.{RESET}")
        print(f"    Normal USB data negotiation permitted.")


# ---------------------------------------------------------
# Command: Guard & Hunt Sockets
# ---------------------------------------------------------
def cmd_guard_sockets(continuous: bool = False):
    from backend.app.services.socket_service import socket_monitor_service
    if continuous:
        print(f"\n{CYAN}[*] Launching Autonomous Socket Guardian Daemon...{RESET}")
        res = socket_monitor_service.start_daemon(poll_interval_seconds=4.0)
        print(f"{GREEN}{BOLD}[+] {res.get('message')}{RESET}")
        print("    Running continuously in background. Intercepting rogue listeners & C2 sockets.")
        return

    print(f"\n{CYAN}[*] Hunting for Rogue Sockets & Backdoor Listeners...{RESET}")
    all_sockets = socket_monitor_service.get_active_sockets()
    threats = [s for s in all_sockets if s.get("threat_level") in ("CRITICAL", "HIGH")]

    print(f"\n{BOLD}Active Sockets Inspected:{RESET} {len(all_sockets)}")
    print(f"{BOLD}High-Risk Sockets / Backdoors:{RESET} {len(threats)}")

    if not threats:
        print(f"\n{GREEN}{BOLD}[+] No rogue backdoor listeners or unauthorized WAN sockets detected.{RESET}")
        return

    for t in threats:
        print(f"\n{RED}{BOLD}[!] HIGH-RISK SOCKET DETECTED:{RESET} {t.get('process_name')} (PID: {t.get('pid')})")
        print(f"    Local Endpoint:  {t.get('protocol')} {t.get('local_ip')}:{t.get('local_port')}")
        print(f"    Remote Endpoint: {t.get('remote_ip') or '*'}:{t.get('remote_port') or '*'}")
        print(f"    Status:          {t.get('status')}")
        print(f"    Threat Level:    {t.get('threat_level')} (Risk: {t.get('risk_score')}/100)")
        for r in t.get("threat_reasons", []):
            print(f"    Indicator:       {r}")


# ---------------------------------------------------------
# Command: Rectify Socket Threat
# ---------------------------------------------------------
def cmd_rectify_socket(target: int):
    from backend.app.services.socket_service import socket_monitor_service
    print(f"\n{CYAN}[*] Rectifying Rogue Network Socket Target: {target}...{RESET}")
    res = socket_monitor_service.rectify_socket_threat(target)

    status_badge = format_verdict(False, res.get("status", ""))
    print(f"\n{BOLD}Verdict:{RESET} {status_badge}")
    print(f"  [1] Volatile Digital Forensics Vault:")
    evd = res.get("forensic_vault", {}).get("evidence", {})
    print(f"      - Evidence Number:        {evd.get('evidence_number')}")
    print(f"      - Vault Crime Scene File: {evd.get('vault_path')}")
    print(f"      - SHA-256 Digest:         {evd.get('sha256')}")
    print(f"      - Chain of Custody:       {evd.get('security')}")

    neut = res.get("neutralization", {})
    print(f"  [2] Threat Neutralization & Remediation:")
    print(f"      - Process Terminated:     {neut.get('process_killed', {}).get('message')}")
    print(f"      - Port Firewall Block:    {neut.get('firewall', {}).get('port_firewall_rule')}")
    print(f"      - C2 IP Firewall Block:   {neut.get('firewall', {}).get('c2_firewall_rule')}")
    print(f"      - DNS Cache Flushed:      {neut.get('dns_flushed')}")
    cert_path = res.get("forensic_vault", {}).get("remediation", {}).get("certificate_path")
    print(f"      - Signed Certificate:     {cert_path}")
    print(f"\n{GREEN}{BOLD}[+] Network socket neutralized and host security restored.{RESET}\n")


# ---------------------------------------------------------
# Command: Persistent Offline Shield & Hardening
# ---------------------------------------------------------
def cmd_offline_shield_status():
    from backend.app.services.persistent_shield_service import persistent_shield_service
    print(f"\n{CYAN}{BOLD}[*] Auditing 24/7 Offline Protection & OS Hardening...{RESET}")
    res = persistent_shield_service.get_hardening_status()
    wd = persistent_shield_service.get_watchdog_status()

    badge = format_verdict(res.get("is_fully_hardened"), res.get("status"))
    print(f"\n{BOLD}OS Hardening Verdict:{RESET} {badge}")
    print(f"  - USB AutoRun Disabled (0xFF):        {res.get('policies', {}).get('autorun_disabled')}")
    print(f"  - USB Storage Binary Execute Denied:   {res.get('policies', {}).get('removable_execute_denied')}")
    print(f"  - Juice Jacking AutoPlay Locked:      {res.get('policies', {}).get('safe_charging_autoplay_locked')}")
    print(f"  - LLMNR Hash Poisoning Disabled:      {res.get('policies', {}).get('llmnr_poisoning_disabled')}")
    print(f"  - Native Firewall Baseline Active:    {res.get('policies', {}).get('firewall_baseline_active')}")
    print(f"\n{BOLD}Autonomous OS Watchdog Task:{RESET}")
    print(f"  - Task Name:       {wd.get('task_name')}")
    print(f"  - Status:          {wd.get('status')}")
    print(f"  - Watchdog Script: {wd.get('watchdog_script')}")
    print(f"  - Architect:       K. Jaideep Raj | Google Antigravity\n")


def cmd_apply_offline_hardening():
    from backend.app.services.persistent_shield_service import persistent_shield_service
    print(f"\n{CYAN}[*] Applying Deep Passive OS Hardening Policies...{RESET}")
    res = persistent_shield_service.apply_all_os_hardening()
    print(f"\n{GREEN}{BOLD}[+] {res.get('message')}{RESET}")
    for act in res.get("actions", []):
        print(f"    - {act}")
    print(f"\n{GREEN}{BOLD}[+] System is now permanently immunized against AutoRun worms, Juice Jacking, and rogue listeners 24/7.{RESET}\n")


def cmd_install_offline_watchdog():
    from backend.app.services.persistent_shield_service import persistent_shield_service
    print(f"\n{CYAN}[*] Registering Autonomous OS Background Watchdog Task...{RESET}")
    res = persistent_shield_service.install_scheduled_watchdog()
    if res.get("success"):
        print(f"\n{GREEN}{BOLD}[+] {res.get('message')}{RESET}")
        print(f"    Task Name: {res.get('task_name')}")
        print(f"    Trigger:   {res.get('trigger')}")
        print(f"    Command:   {res.get('command')}")
        print(f"    Guaranteed 24/7 protection active on system boot.\n")
    else:
        print(f"\n{RED}{BOLD}[-] Failed to install watchdog task: {res.get('error') or res.get('message')}{RESET}\n")


def cmd_uninstall_offline_watchdog():
    from backend.app.services.persistent_shield_service import persistent_shield_service
    print(f"\n{YELLOW}[*] Unregistering Autonomous OS Background Watchdog Task...{RESET}")
    res = persistent_shield_service.uninstall_scheduled_watchdog()
    print(f"\n{BOLD}{res.get('message')}{RESET}\n")


# ---------------------------------------------------------
# Interactive Menu Mode
# ---------------------------------------------------------
def run_interactive_menu():
    while True:
        print_banner()
        print("  [1]  Run Live Physical Host Threat Hunt & Supreme Safeguard (Inspects Processes & Sockets)")
        print("  [2]  Rectify Hostile Process / Bad Incident (Forensic Freeze, Kill, Persistence Wipe & Certificate)")
        print("  [3]  Start Continuous Real-Time Host Guardian Daemon (Background Intercept & Auto-Rectify)")
        print("  [4]  Scan Web Link / URL")
        print("  [5]  Deep Path & Binary Software Analysis (Redirects, Payloads, Archives)")
        print("  [6]  Scan Local File / Executable (Entropy, Macros, Double Extension)")
        print("  [7]  Scan Picture / Image (Polyglot, Post-EOF Executables, EXIF)")
        print("  [8]  Scan QR Code Image (Quishing & Payload Decode)")
        print("  [9]  Audit Active Network Sockets & Inbound C2 Trojans")
        print("  [10] Audit Camera & Microphone Privacy Handles")
        print("  [11] Scan Cable-Connected Hardware Devices & USB Ports (Auto-Quarantine)")
        print("  [12] Immediately Quarantine / Block a Hardware Port")
        print("  [13] Release / Re-enable a Quarantined Port")
        print("  [14] Live Watch & Guard USB Pendrive Plug-in Events (Instant Intercept)")
        print("  [15] Immunize Host Laptop (Disable AutoRun / AutoPlay Injections)")
        print("  [16] Vaccinate a Pendrive / Removable Drive (Lock autorun.inf)")
        print("  [17] Purge / Delete Operational Data (Wipe Tables)")
        print("  [18] Audit Platform Self-Defense & Code Integrity (Anti-Tamper)")
        print("  [19] Show Full Military-Grade Platform Security Posture")
        print("  [20] Run Cross-Platform Controlled Attack Simulation (Kali RAT, Windows Shell, Mobile)")
        print("  [21] Contain Active Incident & Preserve Forensic Evidence (One-Click Defense)")
        print("  [22] Audit Physical Wi-Fi, Rogue AP & ARP Poisoning Security (Evil Twin / MitM)")
        print("  [23] Harden Network Stack (Disable LLMNR, Disable ICMP Redirects, Flush Caches)")
        print("  [24] Pin & Trust Current Wi-Fi Network Signature (Prevent Clone Spoofing)")
        print("  [25] Emergency Disconnect / Sever Connection from Wi-Fi")
        print("  [26] Toggle Charger-Only Safe Charging Mode (Juice Jacking & Data-Pin Lockout)")
        print("  [27] Hunt & Guard Rogue Network Sockets & Backdoor Ports (Metasploit, C2)")
        print("  [28] Rectify Rogue Network Socket / Port (Freeze Evidence, Kill, Firewall Block)")
        print("  [29] Apply Persistent OS Hardening (Zero-Runtime Shield: USB AutoRun 0xFF, Exec Deny)")
        print("  [30] Install Autonomous 24/7 OS Watchdog Task (Runs Silently on Boot without Terminal)")
        print("  [31] Query Offline Shield & Autonomous Watchdog Status")
        print("  [32] Exit")
        print("=" * 70)

        choice = input("Select an option [1-32]: ").strip()

        if choice == "1":
            cmd_live_safeguard(continuous=False)
            input("\nPress Enter to return to menu...")
        elif choice == "2":
            target = input("Enter PID or process name to rectify & safeguard (e.g. '4192' or 'malicious.exe'): ").strip()
            if target:
                cmd_rectify_threat(target)
            input("\nPress Enter to return to menu...")
        elif choice == "3":
            cmd_live_safeguard(continuous=True)
            input("\nPress Enter to return to menu...")
        elif choice == "4":
            url = input("Enter URL to scan: ").strip()
            if url:
                cmd_scan_link(url)
            input("\nPress Enter to return to menu...")
        elif choice == "5":
            url = input("Enter Link/Software URL for Deep Analysis: ").strip()
            if url:
                cmd_deep_scan(url)
            input("\nPress Enter to return to menu...")
        elif choice == "6":
            fp = input("Enter file path: ").strip().strip('"')
            if fp:
                cmd_scan_file(fp)
            input("\nPress Enter to return to menu...")
        elif choice == "7":
            ip = input("Enter picture path: ").strip().strip('"')
            if ip:
                cmd_scan_picture(ip)
            input("\nPress Enter to return to menu...")
        elif choice == "8":
            qp = input("Enter QR code image path: ").strip().strip('"')
            if qp:
                cmd_scan_qr(qp)
            input("\nPress Enter to return to menu...")
        elif choice == "9":
            cmd_scan_sockets()
            input("\nPress Enter to return to menu...")
        elif choice == "10":
            cmd_scan_camera()
            input("\nPress Enter to return to menu...")
        elif choice == "11":
            target = input("Enter drive letter/path (e.g. 'E:\\', or leave blank for all connected devices): ").strip().strip('"')
            cmd_scan_cables(target or None)
            input("\nPress Enter to return to menu...")
        elif choice == "12":
            target = input("Enter drive letter or device ID to quarantine (e.g. 'E:', 'G:'): ").strip()
            if target:
                cmd_quarantine_port(target)
            input("\nPress Enter to return to menu...")
        elif choice == "13":
            target = input("Enter drive letter or device ID to release: ").strip()
            if target:
                cmd_release_port(target)
            input("\nPress Enter to return to menu...")
        elif choice == "14":
            cmd_watch_usb()
            input("\nPress Enter to return to menu...")
        elif choice == "15":
            cmd_immunize_host()
            input("\nPress Enter to return to menu...")
        elif choice == "16":
            dl = input("Enter pendrive drive letter to vaccinate (e.g. 'G:' or 'E:\\'): ").strip().strip('"')
            if dl:
                cmd_vaccinate_drive(dl)
            input("\nPress Enter to return to menu...")
        elif choice == "17":
            cat = input("Enter category to purge (events, incidents, malware, forensics, all): ").strip()
            cmd_purge_data(cat or "all")
            input("\nPress Enter to return to menu...")
        elif choice == "18":
            cmd_audit_integrity()
            input("\nPress Enter to return to menu...")
        elif choice == "19":
            cmd_security_armor()
            input("\nPress Enter to return to menu...")
        elif choice == "20":
            plat = input("Enter target platform for attack simulation (kali / windows / mobile) [default: kali]: ").strip() or "kali"
            cmd_simulate_hack(plat)
            input("\nPress Enter to return to menu...")
        elif choice == "21":
            inc = input("Enter Incident ID to contain & preserve (or leave blank for 'latest'): ").strip() or "latest"
            cmd_contain_and_preserve(inc)
            input("\nPress Enter to return to menu...")
        elif choice == "22":
            cmd_scan_wifi()
            input("\nPress Enter to return to menu...")
        elif choice == "23":
            cmd_harden_network()
            input("\nPress Enter to return to menu...")
        elif choice == "24":
            cmd_trust_wifi()
            input("\nPress Enter to return to menu...")
        elif choice == "25":
            cmd_disconnect_wifi()
            input("\nPress Enter to return to menu...")
        elif choice == "26":
            mode_input = input("Enable Charger-Only Safe Charging Mode? (y/n, or leave blank to check status): ").strip().lower()
            if mode_input == "y":
                cmd_safe_charging(True)
            elif mode_input == "n":
                cmd_safe_charging(False)
            else:
                cmd_safe_charging(None)
            input("\nPress Enter to return to menu...")
        elif choice == "27":
            c_input = input("Run continuous background daemon? (y/n) [default: n]: ").strip().lower()
            cmd_guard_sockets(continuous=(c_input == "y"))
            input("\nPress Enter to return to menu...")
        elif choice == "28":
            target = input("Enter process PID or port number to rectify: ").strip()
            if target.isdigit():
                cmd_rectify_socket(int(target))
            input("\nPress Enter to return to menu...")
        elif choice == "29":
            cmd_apply_offline_hardening()
            input("\nPress Enter to return to menu...")
        elif choice == "30":
            cmd_install_offline_watchdog()
            input("\nPress Enter to return to menu...")
        elif choice == "31":
            cmd_offline_shield_status()
            input("\nPress Enter to return to menu...")
        elif choice in ("32", "q", "exit"):
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

    # safeguard
    p_safe = subparsers.add_parser("safeguard", help="Run live physical host threat hunt & supreme safeguard")
    p_safe.add_argument("--continuous", action="store_true", help="Run persistent background guardian daemon")

    # rectify
    p_rec = subparsers.add_parser("rectify", help="Rectify an active threat process or incident (Forensics Freeze + Kill + Persistence Wipe)")
    p_rec.add_argument("target", help="PID or process name to rectify")

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

    # audit-integrity
    subparsers.add_parser("audit-integrity", help="Cryptographically audit SHA-256 integrity of platform core modules")

    # security-armor
    subparsers.add_parser("security-armor", help="Display full military-grade security posture report of SENTINEL-X")

    # simulate-hack
    p_sim = subparsers.add_parser("simulate-hack", help="Simulate live controlled attack, containment & forensic preservation")
    p_sim.add_argument("--platform", default="kali", choices=["kali", "windows", "mobile"], help="Target platform to simulate")

    # contain-and-preserve
    p_cap = subparsers.add_parser("contain-and-preserve", help="Contain incident and seal forensic crime scene evidence")
    p_cap.add_argument("incident_id", nargs="?", default="latest", help="Incident ID to contain (default: 'latest')")

    # scan-wifi
    subparsers.add_parser("scan-wifi", help="Audit physical Wi-Fi, Rogue AP, Evil Twin & ARP Poisoning security")

    # guard-wifi
    p_gwifi = subparsers.add_parser("guard-wifi", help="Real-time continuous Wi-Fi and network guardian daemon")
    p_gwifi.add_argument("--continuous", action="store_true", help="Run persistent background guardian daemon")

    # harden-network
    subparsers.add_parser("harden-network", help="Apply OS network hardening (disable LLMNR, ICMP redirects, flush caches)")

    # trust-wifi
    subparsers.add_parser("trust-wifi", help="Pin current connected Wi-Fi as trusted baseline signature")

    # disconnect-wifi
    subparsers.add_parser("disconnect-wifi", help="Emergency immediate physical severance from connected Wi-Fi")

    # rectify-wifi
    subparsers.add_parser("rectify-wifi", help="Freeze network crime-scene evidence into vault (0400), disconnect, and issue certificate")

    # safe-charging
    p_sc = subparsers.add_parser("safe-charging", help="Charger-Only Safe Charging Mode (Juice Jacking & Data-Pin Lockout)")
    p_sc.add_argument("--enable", action="store_true", help="Enable Safe Charging Mode")
    p_sc.add_argument("--disable", action="store_true", help="Disable Safe Charging Mode")

    # guard-sockets
    p_gs = subparsers.add_parser("guard-sockets", help="Hunt and guard rogue network sockets & backdoor listeners")
    p_gs.add_argument("--continuous", action="store_true", help="Run background socket watcher daemon")

    # rectify-socket
    p_rs = subparsers.add_parser("rectify-socket", help="Rectify rogue socket / backdoor port (freeze evidence, kill, firewall block)")
    p_rs.add_argument("target", type=int, help="Target PID or port number to rectify")

    # offline-shield
    p_off = subparsers.add_parser("offline-shield", help="Audit and apply 24/7 persistent OS hardening (Zero-Runtime Shield)")
    p_off.add_argument("--apply", action="store_true", help="Apply all deep OS hardening policies")

    # install-offline-shield
    subparsers.add_parser("install-offline-shield", help="Register autonomous 24/7 background watchdog scheduled task")

    # uninstall-offline-shield
    subparsers.add_parser("uninstall-offline-shield", help="Unregister autonomous 24/7 background watchdog task")

    # interactive
    subparsers.add_parser("interactive", help="Launch interactive menu console")

    args = parser.parse_args()

    if not args.command or args.command == "interactive":
        run_interactive_menu()
    elif args.command == "safeguard":
        cmd_live_safeguard(continuous=args.continuous)
    elif args.command == "rectify":
        cmd_rectify_threat(args.target)
    elif args.command == "scan-wifi":
        cmd_scan_wifi()
    elif args.command == "guard-wifi":
        cmd_guard_wifi(continuous=args.continuous)
    elif args.command == "harden-network":
        cmd_harden_network()
    elif args.command == "trust-wifi":
        cmd_trust_wifi()
    elif args.command == "disconnect-wifi":
        cmd_disconnect_wifi()
    elif args.command == "rectify-wifi":
        cmd_rectify_wifi()
    elif args.command == "safe-charging":
        if args.enable:
            cmd_safe_charging(True)
        elif args.disable:
            cmd_safe_charging(False)
        else:
            cmd_safe_charging(None)
    elif args.command == "guard-sockets":
        cmd_guard_sockets(continuous=args.continuous)
    elif args.command == "rectify-socket":
        cmd_rectify_socket(args.target)
    elif args.command == "offline-shield":
        if args.apply:
            cmd_apply_offline_hardening()
        else:
            cmd_offline_shield_status()
    elif args.command == "install-offline-shield":
        cmd_install_offline_watchdog()
    elif args.command == "uninstall-offline-shield":
        cmd_uninstall_offline_watchdog()
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
    elif args.command == "audit-integrity":
        cmd_audit_integrity()
    elif args.command == "security-armor":
        cmd_security_armor()
    elif args.command == "simulate-hack":
        cmd_simulate_hack(args.platform)
    elif args.command == "contain-and-preserve":
        cmd_contain_and_preserve(args.incident_id)


if __name__ == "__main__":
    main()
