"""
SENTINEL-X Cable-Connected Hardware & Port Quarantine API Router
Provides endpoints to list connected cable devices, deep scan files,
trigger immediate port quarantine, and release blocked ports.
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database import get_db
from backend.app.core.permissions import get_current_user, require_role
from backend.app.models.auth import User

from backend.app.services.hardware_port_service import hardware_port_service

router = APIRouter(prefix="/hardware-ports", tags=["Hardware & Cable Port Sentinel"])


class PortScanRequest(BaseModel):
    target_path: str = Field(..., description="Drive letter or path to scan (e.g. 'E:\\', 'G:\\', '/mnt/usb')")
    device_id: Optional[str] = Field(None, description="Optional hardware device ID")
    auto_quarantine: Optional[bool] = Field(True, description="Whether to immediately dismount and block port if threat detected")


class PortQuarantineRequest(BaseModel):
    target_or_device: str = Field(..., description="Drive letter, volume, or device hardware instance ID to block")
    reason: Optional[str] = Field("Manual Security Analyst Quarantine", description="Operational justification")


class PortReleaseRequest(BaseModel):
    target_or_device: str = Field(..., description="Drive letter or device hardware ID to unblock and re-enable")


class AutoQuarantineToggleRequest(BaseModel):
    enabled: bool = Field(..., description="Whether auto-quarantine on threat is enabled")


@router.get("/devices")
async def list_connected_devices(
    current_user: User = Depends(get_current_user),
):
    """Enumerates all physically connected cable devices, USB drives, and ports."""
    devices = hardware_port_service.list_connected_cable_devices()
    return {
        "devices": devices,
        "count": len(devices),
        "quarantined_count": sum(1 for d in devices if d.get("quarantined")),
    }


@router.get("/status")
async def get_port_quarantine_status(
    current_user: User = Depends(get_current_user),
):
    """Retrieves real-time port quarantine lock state and active blocked ports."""
    return hardware_port_service.get_quarantine_status()


@router.post("/scan")
async def scan_cable_device(
    request: PortScanRequest,
    current_user: User = Depends(require_role(["admin", "analyst"])),
):
    """
    Deep-scans a cable-connected device or storage volume for viruses, autorun worms,
    and dangerous payloads. If threats are found and auto_quarantine is true,
    immediately shuts down and blocks that port!
    """
    result = hardware_port_service.scan_path_or_device(
        target_path=request.target_path,
        device_id=request.device_id,
        auto_quarantine=request.auto_quarantine,
    )
    return result


@router.post("/quarantine")
async def quarantine_port_endpoint(
    request: PortQuarantineRequest,
    current_user: User = Depends(require_role(["admin", "analyst"])),
):
    """
    Immediately stops and quarantines a hardware port / device:
    dismounts volume and disables device at driver level.
    """
    result = hardware_port_service.quarantine_port(
        target_or_device=request.target_or_device,
        reason=request.reason,
    )
    return result


@router.post("/release")
async def release_port_endpoint(
    request: PortReleaseRequest,
    current_user: User = Depends(require_role(["admin", "analyst"])),
):
    """Re-enables and releases a quarantined port or cable device."""
    result = hardware_port_service.release_port(
        target_or_device=request.target_or_device,
    )
    return result


class DriveVaccinateRequest(BaseModel):
    drive_letter: str = Field(..., description="Drive letter or path to vaccinate (e.g. 'G:', 'E:\\')")


class InterceptInsertionRequest(BaseModel):
    drive_letter: str = Field(..., description="Drive letter or mount point of inserted device")
    device_id: Optional[str] = Field(None, description="Optional hardware instance ID")


@router.post("/toggle-auto-quarantine")
async def toggle_auto_quarantine(
    request: AutoQuarantineToggleRequest,
    current_user: User = Depends(require_role(["admin", "analyst"])),
):
    """Toggles automatic port shutdown upon threat detection."""
    new_state = hardware_port_service.set_auto_quarantine(request.enabled)
    return {"auto_quarantine_enabled": new_state}


@router.get("/immunization")
async def get_usb_immunization_status(
    current_user: User = Depends(get_current_user),
):
    """Retrieves host laptop AutoRun/AutoPlay immunization status."""
    return hardware_port_service.get_host_usb_immunization_status()


@router.post("/immunize-host")
async def apply_host_usb_immunization_endpoint(
    current_user: User = Depends(require_role(["admin", "analyst"])),
):
    """
    Applies strong defensive registry policies to prevent Windows from ever automatically
    executing code from inserted pendrives, flash disks, or cable devices.
    """
    return hardware_port_service.apply_host_usb_immunization()


@router.post("/vaccinate-drive")
async def vaccinate_drive_endpoint(
    request: DriveVaccinateRequest,
    current_user: User = Depends(require_role(["admin", "analyst"])),
):
    """
    Vaccinates a pendrive or removable drive to permanently prevent viruses
    from creating or replacing autorun.inf.
    """
    return hardware_port_service.vaccinate_drive(request.drive_letter)


@router.get("/badusb")
async def get_badusb_status(
    current_user: User = Depends(get_current_user),
):
    """Audits connected devices for BadUSB keystroke injector indicators."""
    flagged = hardware_port_service.check_badusb_devices()
    return {
        "badusb_devices": flagged,
        "count": len(flagged),
        "is_safe": len(flagged) == 0,
    }


@router.post("/intercept")
async def intercept_insertion_endpoint(
    request: InterceptInsertionRequest,
    current_user: User = Depends(require_role(["admin", "analyst"])),
):
    """Directly triggers real-time insertion interception on a connected drive."""
    res = hardware_port_service.intercept_device_insertion({
        "drive_letter": request.drive_letter,
        "device_id": request.device_id,
        "mount_point": request.drive_letter if "\\" in request.drive_letter else f"{request.drive_letter}\\",
    })
    return res


class SafeChargingToggleRequest(BaseModel):
    enabled: bool = Field(..., description="Enable or disable Charger-Only Safe Charging Mode (Data-Pin Lockout)")


class ChargerAuditRequest(BaseModel):
    name: Optional[str] = Field("USB Cable / Charger", description="Name or label of cable/charger")
    device_id: Optional[str] = Field("PORT_CABLE_CHARGER", description="Hardware interface ID")
    device_type: Optional[str] = Field("USB Cable Charger", description="Reported device class / interface")


@router.get("/safe-charging")
async def get_safe_charging_status_endpoint(
    current_user: User = Depends(get_current_user),
):
    """Retrieves Safe Charging Shield status (Juice Jacking & Data-Pin Lockout)."""
    return hardware_port_service.get_safe_charging_status()


@router.post("/safe-charging")
async def toggle_safe_charging_endpoint(
    request: SafeChargingToggleRequest,
    current_user: User = Depends(require_role(["admin", "analyst"])),
):
    """Enables or disables Charger-Only Safe Charging Mode (Data-Pin Lockout)."""
    if request.enabled:
        return hardware_port_service.enable_safe_charging_mode()
    else:
        return hardware_port_service.disable_safe_charging_mode()


@router.post("/audit-charger")
async def audit_charger_endpoint(
    request: ChargerAuditRequest,
    current_user: User = Depends(require_role(["admin", "analyst"])),
):
    """Audits a plugged-in charger or USB cable for unauthorized data handshakes / juice-jacking."""
    return hardware_port_service.audit_charger_connection({
        "name": request.name,
        "device_id": request.device_id,
        "device_type": request.device_type,
    })

