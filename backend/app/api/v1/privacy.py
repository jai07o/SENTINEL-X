from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Body
from pydantic import BaseModel

from backend.app.services.privacy_service import privacy_sentinel_service
from backend.app.core.permissions import get_current_user
from backend.app.models.auth import User

router = APIRouter()


class MobileTelemetryInbound(BaseModel):
    device_type: str = "Mobile (Android)"
    device_name: str
    app_name: str
    package_id: str
    sensor_type: str = "CAMERA"
    is_background: bool = True
    duration_seconds: int = 0


class TerminateAppRequest(BaseModel):
    pid: int


@router.get("/camera-status")
async def get_privacy_camera_status(current_user: User = Depends(get_current_user)):
    """
    Returns real-time status of laptop webcam and mobile sensors,
    flagging any app that opens camera or microphone while not in foreground.
    """
    return privacy_sentinel_service.get_all_privacy_telemetry()


@router.post("/mobile-telemetry")
async def ingest_mobile_privacy_telemetry(
    payload: MobileTelemetryInbound,
    current_user: User = Depends(get_current_user),
):
    """
    Ingests background camera/microphone access telemetry from mobile devices.
    """
    return privacy_sentinel_service.add_mobile_telemetry(payload.model_dump())


@router.post("/terminate-app")
async def terminate_camera_violator(
    req: TerminateAppRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Kills the process executing unauthorized camera access.
    """
    res = privacy_sentinel_service.terminate_privacy_violator(req.pid)
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("message"))
    return res
