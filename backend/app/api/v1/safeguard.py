from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

from backend.app.core.permissions import get_current_user, require_role
from backend.app.models.auth import User
from backend.app.services.live_safeguard_rectifier import (
    supreme_safeguard,
    LiveThreatHunter,
    LiveForensicInvestigator,
    LiveThreatNeutralizer,
    LiveIncidentRectifier,
)

router = APIRouter(prefix="/safeguard", tags=["Supreme Live Safeguard & Forensics"])


class RectifyRequest(BaseModel):
    pid: int = Field(..., description="Target process PID to investigate, neutralize, and rectify")
    reason: Optional[str] = Field("Manual Operator Incident Rectification", description="Reason for containment")
    isolate_network: bool = Field(True, description="Whether to block external C2 IP in firewall")


@router.get("/status")
async def get_safeguard_status(
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Returns real-time status of the Supreme Safeguard & Forensics Engine."""
    return {
        "is_daemon_running": supreme_safeguard.is_running,
        "stats": supreme_safeguard.stats,
        "recent_rectifications": supreme_safeguard.rectification_history[:10],
    }


@router.get("/hunt")
async def hunt_live_host_threats(
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Scans the physical host in real time for live threats:
    RATs, reverse shells, C2 socket beacons, masqueraded binaries, cryptominers.
    """
    threats = LiveThreatHunter.hunt_active_threats()
    return {
        "threats_found_count": len(threats),
        "threats": threats,
        "status": "THREATS_DETECTED" if threats else "CLEAN",
    }


@router.post("/daemon/start")
async def start_safeguard_daemon(
    interval_seconds: int = Query(3, ge=1, le=60),
    current_user: User = Depends(require_role(["admin", "analyst"])),
) -> Dict[str, Any]:
    """Engages the continuous real-time physical host guardian daemon."""
    res = await supreme_safeguard.start_live_safeguard_daemon(interval_seconds=interval_seconds)
    return res


@router.post("/daemon/stop")
async def stop_safeguard_daemon(
    current_user: User = Depends(require_role(["admin", "analyst"])),
) -> Dict[str, Any]:
    """Stops the real-time physical host guardian daemon."""
    res = await supreme_safeguard.stop_live_safeguard_daemon()
    return res


@router.post("/rectify")
async def rectify_live_threat(
    payload: RectifyRequest,
    current_user: User = Depends(require_role(["admin", "analyst"])),
) -> Dict[str, Any]:
    """
    Executes the complete Supreme Safeguard, Forensic Scene Freeze, Process Kill,
    Persistence Wipe, and Incident Rectification workflow on a live PID.
    """
    threat_info = {
        "pid": payload.pid,
        "process_name": f"Target Process PID {payload.pid}",
        "category": "OPERATOR_IDENTIFIED_THREAT",
        "severity": "CRITICAL",
        "indicators": [payload.reason],
    }
    result = await supreme_safeguard.execute_full_safeguard_cycle(
        pid=payload.pid,
        threat_info=threat_info,
    )
    return result
