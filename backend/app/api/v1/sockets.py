from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from backend.app.services.socket_service import socket_monitor_service
from backend.app.core.permissions import get_current_user, require_role
from backend.app.models.auth import User

router = APIRouter()


class KillProcessRequest(BaseModel):
    pid: int


class SocketRectifyRequest(BaseModel):
    target: int = Field(..., description="Process ID (PID) or local port number to rectify and contain")


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


@router.get("/hunt")
async def hunt_socket_threats(
    current_user: User = Depends(get_current_user),
):
    """
    Hunts specifically for rogue listening ports, backdoor listeners (Metasploit, Cobalt Strike, Netcat),
    and reverse shell connections established to remote attacker C2s.
    """
    all_sockets = socket_monitor_service.get_active_sockets()
    threats = [s for s in all_sockets if s["threat_level"] in ("CRITICAL", "HIGH")]
    suspicious = [s for s in all_sockets if s["threat_level"] == "SUSPICIOUS"]

    return {
        "threats_count": len(threats),
        "suspicious_count": len(suspicious),
        "is_safe": len(threats) == 0,
        "threats": threats,
        "suspicious": suspicious,
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


@router.post("/rectify")
async def rectify_socket_incident(
    req: SocketRectifyRequest,
    current_user: User = Depends(require_role(["admin", "analyst"])),
):
    """
    Executes end-to-end Socket & Rogue Port Containment, Forensics, and Rectification:
    1. Freezes volatile socket crime scene evidence into data/evidence/SOCKET_SCENE_*.json (0400).
    2. Terminates hostile process tree.
    3. Enforces native firewall blocking on the rogue port and C2 IP.
    4. Wipes persistence and flushes DNS cache.
    5. Issues signed court-admissible Incident Rectification Certificate in data/reports/.
    """
    return socket_monitor_service.rectify_socket_threat(req.target)


@router.get("/daemon/status")
async def get_socket_daemon_status(
    current_user: User = Depends(get_current_user),
):
    """Returns real-time status of the background Socket Guardian Daemon."""
    return socket_monitor_service.get_daemon_status()


@router.post("/daemon/start")
async def start_socket_daemon(
    current_user: User = Depends(require_role(["admin", "analyst"])),
):
    """Starts autonomous real-time background Socket Guardian Daemon."""
    return socket_monitor_service.start_daemon()


@router.post("/daemon/stop")
async def stop_socket_daemon(
    current_user: User = Depends(require_role(["admin", "analyst"])),
):
    """Stops background Socket Guardian Daemon."""
    return socket_monitor_service.stop_daemon()
