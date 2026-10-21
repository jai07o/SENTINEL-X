from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from backend.app.services.process_service import process_monitor_service
from backend.app.core.permissions import get_current_user
from backend.app.models.auth import User

router = APIRouter()


class KillProcessRequest(BaseModel):
    pid: int


@router.get("/")
async def list_running_processes(
    background_only: bool = Query(False, description="Filter for background applications and daemons only"),
    limit: int = Query(250, description="Max processes to return"),
    current_user: User = Depends(get_current_user),
):
    """
    Returns running system and user processes categorized by background status,
    resource usage, and anomaly heuristics.
    """
    return process_monitor_service.get_processes(filter_background_only=background_only, limit=limit)


@router.post("/kill")
async def kill_process(
    req: KillProcessRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Terminates a specific process by PID.
    """
    res = process_monitor_service.kill_process(req.pid)
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("message"))
    return res
