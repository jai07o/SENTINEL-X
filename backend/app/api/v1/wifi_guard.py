"""
FastAPI Router for SENTINEL-X Supreme Wi-Fi, Rogue AP & Network Defense Subsystem.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

from backend.app.core.permissions import get_current_user, require_admin, require_analyst, require_viewer
from backend.app.models.auth import User
from backend.app.services.wifi_guard_service import (
    WiFiNetworkAuditor,
    WiFiThreatDetector,
    WiFiNetworkHardener,
    WiFiForensicVault,
    WiFiTrustedStore,
    wifi_guard_daemon,
)

router = APIRouter(prefix="/wifi-guard", tags=["Supreme Wi-Fi & Network Guardian"])


class TrustNetworkRequest(BaseModel):
    ssid: Optional[str] = Field(None, description="SSID to trust (defaults to active connected SSID)")
    bssid: Optional[str] = Field(None, description="BSSID to trust (defaults to active connected BSSID)")


class DaemonControlRequest(BaseModel):
    interval_seconds: int = Field(5, ge=1, le=60, description="Audit frequency in seconds")
    auto_sever: bool = Field(True, description="Automatically sever network connection upon threat detection")


class RectifyRequest(BaseModel):
    auto_disconnect: bool = Field(True, description="Sever Wi-Fi connection upon rectification")


@router.get("/status")
async def get_wifi_guard_status(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Returns the real-time operational status, background daemon health, and pulse metrics.
    """
    daemon_status = wifi_guard_daemon.get_status()
    current_wifi = WiFiNetworkAuditor.get_current_wifi_details()
    return {
        "status": "OPERATIONAL",
        "guardian_daemon": daemon_status,
        "active_wifi": current_wifi,
    }


@router.get("/audit")
async def execute_wifi_security_audit(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Executes an on-demand, deep physical Wi-Fi & network security sweep:
    - BSSID authenticity & Evil Twin detection
    - Unencrypted open Wi-Fi honeypot hazard
    - Duplicate SSID collisions in proximity
    - ARP Poisoning & Gateway MAC hijacking
    - Rogue DNS server configurations
    """
    report = WiFiThreatDetector.audit_wifi_and_network_security()
    return report


@router.post("/trust")
async def trust_current_wifi_network(
    payload: Optional[TrustNetworkRequest] = None,
    current_user: User = Depends(require_analyst),
) -> Dict[str, Any]:
    """
    Pins the specified (or currently connected) Wi-Fi SSID, BSSID, and Cipher
    as an authorized baseline signature. Detects future Evil Twin clone attacks.
    """
    current_wifi = WiFiNetworkAuditor.get_current_wifi_details()
    ssid = (payload.ssid if payload and payload.ssid else current_wifi.get("ssid"))
    bssid = (payload.bssid if payload and payload.bssid else current_wifi.get("bssid"))

    if not ssid or not bssid:
        raise HTTPException(status_code=400, detail="Cannot pin network: host is not connected to a Wi-Fi network and no parameters provided.")

    cipher = current_wifi.get("cipher") or "WPA2"
    auth = current_wifi.get("authentication") or "WPA2-Personal"

    pinned = WiFiTrustedStore.trust_wifi_network(
        ssid=ssid,
        bssid=bssid,
        cipher=cipher,
        authentication=auth,
    )
    return {
        "status": "WIFI_SIGNATURE_PINNED_AND_TRUSTED",
        "pinned_signature": pinned,
    }


@router.post("/harden")
async def harden_host_network_defenses(current_user: User = Depends(require_admin)) -> Dict[str, Any]:
    """
    Applies OS-level physical network stack hardening:
    - Disables LLMNR (defeating Responder / Inveigh credential sniffing)
    - Disables ICMP Redirects (defeating routing manipulation)
    - Clears and flushes ARP cache and DNS resolver
    """
    hardened = WiFiNetworkHardener.harden_network_host_defenses()
    return hardened


@router.post("/disconnect")
async def emergency_disconnect(current_user: User = Depends(require_admin)) -> Dict[str, Any]:
    """
    Emergency immediate physical severance from the connected Wi-Fi network.
    """
    res = WiFiNetworkHardener.emergency_disconnect_wifi()
    return {
        "status": "EMERGENCY_DISCONNECT_EXECUTED",
        "result": res,
    }


@router.post("/rectify")
async def rectify_network_incident(
    payload: RectifyRequest,
    current_user: User = Depends(require_admin),
) -> Dict[str, Any]:
    """
    Atomically preserves volatile network crime-scene evidence (BSSID, ARP, DNS, sockets)
    into the immutable vault (`0400`), executes emergency network severance, purges
    malicious Wi-Fi profiles, flushes caches, and issues a signed Rectification Certificate.
    """
    audit_report = WiFiThreatDetector.audit_wifi_and_network_security()
    res = await WiFiForensicVault.freeze_network_crime_scene_and_rectify(
        audit_report=audit_report,
        auto_disconnect=payload.auto_disconnect,
    )
    return res


@router.post("/daemon/start")
async def start_wifi_guardian_daemon(
    payload: DaemonControlRequest,
    current_user: User = Depends(require_admin),
) -> Dict[str, Any]:
    """
    Starts the continuous background Wi-Fi and network guardian loop.
    """
    await wifi_guard_daemon.start(
        interval_seconds=payload.interval_seconds,
        auto_sever=payload.auto_sever,
    )
    return {
        "status": "DAEMON_STARTED",
        "guardian_state": wifi_guard_daemon.get_status(),
    }


@router.post("/daemon/stop")
async def stop_wifi_guardian_daemon(current_user: User = Depends(require_admin)) -> Dict[str, Any]:
    """
    Stops the continuous background Wi-Fi and network guardian loop cleanly.
    """
    wifi_guard_daemon.stop()
    return {
        "status": "DAEMON_STOPPED",
        "guardian_state": wifi_guard_daemon.get_status(),
    }
