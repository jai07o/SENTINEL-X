"""
SENTINEL-X Autonomous Persistent Hardware & Socket Watchdog
Creator & Developer: K. Jaideep Raj (Student & Security Enthusiast)
Platform: Google Antigravity

Runs autonomously 24/7 as an OS background service / scheduled task.
Guarantees physical host protection even when the user is not actively running
the main SENTINEL-X UI or CLI:
- Intercepts pendrive insertions, malicious cables, and juice-jacking chargers
- Intercepts rogue listening sockets, backdoor ports, and reverse shells
- Preserves volatile digital crime scenes (0400) and produces court-admissible certificates
"""
import os
import sys
import time
import logging
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.config import DATA_DIR
from backend.app.services.hardware_port_service import hardware_port_service
from backend.app.services.socket_service import socket_monitor_service

# Setup autonomous watchdog log
LOG_FILE = DATA_DIR / "sentinel_watchdog.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [SENTINEL-X Watchdog] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("SENTINELX_WATCHDOG")


def run_watchdog_loop(poll_interval: float = 4.0):
    logger.info("=" * 70)
    logger.info("SENTINEL-X Autonomous Persistent Perimeter Watchdog Started")
    logger.info("Architect & Creator: K. Jaideep Raj | Google Antigravity")
    logger.info(f"Target: {os.environ.get('COMPUTERNAME') or 'LOCAL_HOST'} ({sys.platform})")
    logger.info(f"Logging to: {LOG_FILE}")
    logger.info("=" * 70)

    # Initial state tracking
    known_drives = set()
    try:
        for d in hardware_port_service.list_connected_cable_devices():
            dl = d.get("drive_letter")
            if dl:
                known_drives.add(dl.upper())
    except Exception as e:
        logger.warning(f"Initial hardware audit error: {e}")

    logger.info(f"Baseline hardware drives tracked: {known_drives}")

    while True:
        try:
            # 1. Sweep Hardware Ports, Cables, and Removable Drives
            current_devices = hardware_port_service.list_connected_cable_devices()
            current_drives = set()
            for dev in current_devices:
                dl = dev.get("drive_letter")
                if dl:
                    dl_up = dl.upper()
                    current_drives.add(dl_up)
                    # New insertion detected!
                    if dl_up not in known_drives and dl_up != "C:":
                        logger.critical(f"NEW HARDWARE INSERTION INTERCEPTED on {dl_up} ({dev.get('name')})")
                        res = hardware_port_service.intercept_device_insertion(dev)
                        logger.info(f"Insertion Interception Result: {res.get('verdict')} - {res.get('message')}")
                        if res.get("is_threat"):
                            logger.critical(f"THREAT BLOCKED! Port quarantined, volatile evidence vaulted.")

            known_drives = current_drives

            # 2. Check for BadUSB / Microcontroller HID Keystroke Injectors
            badusb_devices = hardware_port_service.check_badusb_devices()
            if badusb_devices:
                for b in badusb_devices:
                    logger.critical(f"BADUSB / RUBBER DUCKY DETECTED: {b.get('device_name')} ({b.get('instance_id')})")
                    hardware_port_service.quarantine_port(b.get("instance_id"), "BadUSB / Rubber Ducky hardware device quarantined.")

            # 3. Sweep Active Network Sockets & Rogue Ports
            active_sockets = socket_monitor_service.get_active_sockets()
            for s in active_sockets:
                if s.get("threat_level") in ("CRITICAL", "HIGH"):
                    pid = s.get("pid")
                    lport = s.get("local_port")
                    pname = s.get("process_name")
                    logger.critical(f"HIGH-RISK ROGUE SOCKET DETECTED: {pname} (PID: {pid}) on Port {lport}")
                    rect_res = socket_monitor_service.rectify_socket_threat(pid or lport)
                    logger.info(f"Socket Rectification Result: {rect_res.get('status')} - Process killed & port blocked.")

        except Exception as e:
            logger.error(f"Watchdog sweep error: {e}")

        time.sleep(poll_interval)


if __name__ == "__main__":
    run_watchdog_loop()
