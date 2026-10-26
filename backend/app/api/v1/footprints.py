"""
API Endpoints for Ethical Hacker Footprint Surveillance, Deception/Misdirection,
Anti-Trace Sanitization, and Third-Party Intrusion Containment.
"""
from typing import Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from backend.app.services.footprint_sanitizer_service import footprint_sanitizer
from backend.app.core.permissions import get_current_user
from backend.app.models.auth import User

router = APIRouter(prefix="/footprints", tags=["Ethical Hacking Footprint & Intrusion Guard"])


class IntrusionStopRequest(BaseModel):
    remote_ip: str
    target_pid: Optional[int] = None
    remote_port: Optional[int] = None
    description: Optional[str] = "Unauthorized Third-Party Remote Access Incursion"


class MisleadRequest(BaseModel):
    fake_os_identity: Optional[str] = "DECOY_LEGACY_UNIX"
    deploy_honeypaths: Optional[bool] = True


@router.get("/surveil")
async def surveil_footprinting(current_user: User = Depends(get_current_user)):
    """
    Actively surveils for external reconnaissance and footprinting activities:
    identifies stealth port scans (SYN/FIN), OS fingerprinting, and banner grabs.
    """
    return footprint_sanitizer.surveil_active_footprinting()


@router.post("/mislead")
async def mislead_reconnaissance(
    req: MisleadRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Deploys dynamic cyber deception to mislead third-party attackers and scanners:
    feeds deceptive OS banners, arms honeypath latency tarpits, and seeds canary files.
    """
    return footprint_sanitizer.mislead_attacker_footprints(
        fake_os_identity=req.fake_os_identity or "DECOY_LEGACY_UNIX",
        deploy_honeypaths=req.deploy_honeypaths if req.deploy_honeypaths is not None else True,
    )


@router.get("/discover")
async def discover_footprints(current_user: User = Depends(get_current_user)):
    """
    Inventories all operator footprints, shell histories (PowerShell, Bash, Zsh, Python),
    temporary payload droppers, recent documents, and network caches.
    """
    return footprint_sanitizer.discover_operator_footprints()


@router.post("/clean-all")
async def clean_all_footprints(current_user: User = Depends(get_current_user)):
    """
    Completely shreds and purges all operator footprints with zero forensic remanence:
    zeroes shell histories, clears explorer RunMRU, shreds droppers, flushes DNS/ARP,
    clears clipboard, and generates a signed Disengagement Certificate.
    """
    return footprint_sanitizer.clean_and_purge_all_footprints()


@router.post("/stop-intrusion")
async def stop_third_party_intrusion(
    req: IntrusionStopRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Immediately stops an unauthorized third-party intruder:
    collects volatile evidence of origin, seals into encrypted vault (chmod 0400),
    blocks remote IP in firewall, kills hostile process, and issues signed certificate.
    """
    return footprint_sanitizer.intercept_third_party_intrusion(
        remote_ip=req.remote_ip,
        target_pid=req.target_pid,
        remote_port=req.remote_port,
        threat_description=req.description or "Unauthorized Third-Party Incursion",
    )
