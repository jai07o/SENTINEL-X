"""
SENTINEL-X Persistent Offline Shield & 24/7 OS Watchdog Router
Architect & Creator: K. Jaideep Raj
Platform: Google Antigravity
"""
from fastapi import APIRouter, Depends, HTTPException
from backend.app.core.permissions import get_current_user, require_role
from backend.app.models.auth import User
from backend.app.services.persistent_shield_service import persistent_shield_service

router = APIRouter(prefix="/offline-shield", tags=["Persistent Offline OS Shield"])


@router.get("/status")
async def get_offline_shield_status(
    current_user: User = Depends(get_current_user),
):
    """
    Audits 24/7 OS persistent hardening policies and background watchdog task registration.
    Verifies that the physical host remains guarded even when the SENTINEL-X app is not running.
    """
    hardening = persistent_shield_service.get_hardening_status()
    watchdog = persistent_shield_service.get_watchdog_status()
    return {
        "hardening_policies": hardening,
        "autonomous_watchdog": watchdog,
        "architect": "K. Jaideep Raj",
        "engineering_environment": "Google Antigravity",
    }


@router.post("/apply-hardening")
async def apply_os_hardening_endpoint(
    current_user: User = Depends(require_role(["admin", "analyst"])),
):
    """
    Applies deep passive OS hardening policies:
    1. USB AutoRun/AutoPlay disabled system-wide (0xFF)
    2. Removable Storage execution block (Deny_Execute)
    3. Juice-Jacking AutoPlay lock for portable devices
    4. LLMNR Multicast network poisoning disabled
    5. Native Firewall rules blocking high-risk backdoor listener ports
    """
    return persistent_shield_service.apply_all_os_hardening()


@router.post("/install-watchdog")
async def install_watchdog_endpoint(
    current_user: User = Depends(require_role(["admin", "analyst"])),
):
    """
    Registers the Autonomous Background Watchdog as a native Windows Scheduled Task.
    Executes automatically on machine boot/logon with highest privileges.
    """
    res = persistent_shield_service.install_scheduled_watchdog()
    if not res.get("success"):
        raise HTTPException(status_code=500, detail=res.get("error") or res.get("message"))
    return res


@router.post("/uninstall-watchdog")
async def uninstall_watchdog_endpoint(
    current_user: User = Depends(require_role(["admin", "analyst"])),
):
    """Unregisters the autonomous background watchdog scheduled task."""
    return persistent_shield_service.uninstall_scheduled_watchdog()
