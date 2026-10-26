"""
SENTINEL-X Active System & Connected Devices REST API.
Author: K. Jaideep Raj (Student & Security Enthusiast) via Google Antigravity.

Provides endpoints to:
1. Get live active host profile (Laptop vs Desktop, battery status, CPU/RAM, IP, MAC).
2. Trigger real-time In-Depth OS Deep Scan.
3. List connected devices (Mobile phones, USB storage, Bluetooth, local Wi-Fi neighbors).
4. Execute targeted deep scan on a connected mobile device or USB drive.
5. Resync local host identity with database inventory.
"""

from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Body
from pydantic import BaseModel

from backend.app.core.permissions import require_viewer, require_analyst
from backend.app.services.active_system_service import active_system_guardian

router = APIRouter(prefix="/system", tags=["Active System & Connected Devices"])


class DeviceScanRequest(BaseModel):
    device_id: str
    device_type: Optional[str] = "mobile"


@router.get("/active-host")
async def get_active_host_profile(
    current_user=Depends(require_viewer),
) -> Dict[str, Any]:
    """
    Returns live hardware, battery, and operating system profile of the machine
    where SENTINEL-X is executing (Laptop vs Desktop, CPU/RAM load, network identity).
    """
    return active_system_guardian.get_system_profile()


@router.post("/deep-scan")
async def trigger_deep_os_scan(
    current_user=Depends(require_analyst),
) -> Dict[str, Any]:
    """
    Executes a real-time, in-depth deep scan of the active host OS:
    - Analyzes running processes for suspicious paths and miner spikes
    - Inspects open listening sockets for rogue backdoors
    - Checks temporary and download directories for obfuscated/double-extension payloads
    - Audits connected mobile devices and removable storage
    - Returns overall Security Health Score and remediation recommendations.
    """
    return active_system_guardian.execute_deep_os_scan()


@router.get("/connected-devices")
async def get_connected_devices(
    current_user=Depends(require_viewer),
) -> Dict[str, Any]:
    """
    Discovers all physical and wireless devices connected to the active host:
    - Mobile Smartphones (Android / iOS via USB MTP, ADB, or Tethering)
    - Removable USB drives and external storage
    - Connected Bluetooth and USB peripherals (BadUSB check)
    - Local network / Wi-Fi peers (ARP table)
    - All Physical Hardware Ports (USB, Ethernet Cable, HDMI, Audio Jacks)
    """
    return active_system_guardian.detect_connected_devices()


@router.get("/hardware-ports-full")
async def get_hardware_ports_full(
    current_user=Depends(require_viewer),
) -> Dict[str, Any]:
    """
    Returns complete physical & hardware port inventory of the active host:
    - USB & Type-C Ports (controllers, root hubs, attached devices, safe charging status)
    - Network Cable Ports (RJ-45 Ethernet LAN, Wi-Fi 6E, link speed, cable plugged status)
    - Display & Video Ports (Internal eDP display, External HDMI 2.0/2.1, DisplayPort over Type-C)
    - Audio & Sound Jack Ports (3.5mm Headphone Jack, HDMI audio, USB audio DAC)
    - Expansion & Bus Ports (PCIe, Thunderbolt, COM)
    """
    return active_system_guardian.enumerate_all_hardware_ports()


@router.post("/scan-connected-device")
async def scan_connected_device(
    payload: DeviceScanRequest,
    current_user=Depends(require_analyst),
) -> Dict[str, Any]:
    """
    Executes a targeted deep scan on a chosen connected device:
    - Mobile phone: Verifies Juice-Jacking protection, debug bridge exposure, and storage safety
    - USB drive: Inspects files, verifies entropy, detects autorun exploits, and auto-immunizes.
    """
    return active_system_guardian.scan_connected_device(
        device_id=payload.device_id,
        device_type=payload.device_type or "mobile",
    )


@router.post("/sync-local-host")
async def sync_local_host_with_db(
    current_user=Depends(require_analyst),
) -> Dict[str, Any]:
    """
    Registers or refreshes the active local host in the database inventory table.
    """
    return await active_system_guardian.auto_connect_and_register()


@router.post("/repair")
async def repair_active_system(
    current_user=Depends(require_analyst),
) -> Dict[str, Any]:
    """
    Executes a complete, real-time system repair on the active connected machine:
    - Freezes volatile findings into read-only evidence vault (0400)
    - Terminates rogue processes and crypto miner threads
    - Quarantines malware droppers into data/quarantine/ (0000)
    - Blocks hostile ports and flushes DNS & ARP poison mappings
    - Applies 24/7 persistent OS hardening and Juice-Jacking Shield
    - Generates signed court-admissible Master Repair Certificate
    - Restores security score to 100.0% SECURE.
    """
    username = getattr(current_user, "username", "operator")
    return active_system_guardian.repair_system_completely(analyst_id=username)


@router.post("/connect-and-safeguard-all")
async def connect_and_safeguard_all(
    current_user=Depends(require_analyst),
) -> Dict[str, Any]:
    """
    Master Connect & Safeguard Sweep:
    Executes an automated defensive job on the active machine and all connected items:
    - Wired: Juice-Jacking Safe Charging mode, Pendrive autorun vaccination & scan,
      mobile device isolation, hardware port auditing (Ethernet, HDMI, audio, BadUSB).
    - Wireless: Wi-Fi Evil Twin & ARP poisoning verification, Bluetooth devices, subnet peers.
    - Privacy: Camera and microphone hardware handles.
    - Host OS: In-depth processes and files sanitization.
    - Database: Persists live host state to database.
    - Certificate: Issues cryptographically sealed safeguard report.
    """
    return await active_system_guardian.connect_and_safeguard_all()


