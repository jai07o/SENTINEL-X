from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from backend.app.services.socket_service import socket_monitor_service
from backend.app.core.permissions import get_current_user
from backend.app.models.auth import User

router = APIRouter()


class KillProcessRequest(BaseModel):
    pid: int


@router.get("/")
async def list_active_sockets(
    external_only: bool = Query(False, description="Filter for external WAN connections only"),
    high_risk_only: bool = Query(False, description="Filter for elevated C2/virus risk sockets only"),
    limit: int = Query(150, description="Max sockets to return"),
    current_user: User = Depends(get_current_user),
):
    """
    Returns live connected TCP/UDP network sockets with virus, reverse shell, and C2 risk evaluations.
    """
    all_sockets = socket_monitor_service.get_active_sockets()

    if external_only:
        all_sockets = [s for s in all_sockets if s["is_external"]]
    if high_risk_only:
        all_sockets = [s for s in all_sockets if s["threat_level"] in ("CRITICAL", "HIGH", "SUSPICIOUS")]

    total_count = len(all_sockets)
    listening_count = sum(1 for s in all_sockets if s["status"] == "LISTEN")
    established_count = sum(1 for s in all_sockets if s["status"] == "ESTABLISHED")
    high_risk_count = sum(1 for s in all_sockets if s["threat_level"] in ("CRITICAL", "HIGH"))

    return {
        "summary": {
            "total_sockets": total_count,
            "listening_sockets": listening_count,
            "established_connections": established_count,
            "high_risk_c2_sockets": high_risk_count,
        },
        "sockets": all_sockets[:limit],
    }


@router.post("/kill-process")
async def terminate_socket_process(
    req: KillProcessRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Terminates the process holding a suspicious or malicious connected socket.
    """
    res = socket_monitor_service.terminate_socket_process(req.pid)
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("message"))
    return res
