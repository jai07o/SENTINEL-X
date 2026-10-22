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
    """
    return active_system_guardian.detect_connected_devices()


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
