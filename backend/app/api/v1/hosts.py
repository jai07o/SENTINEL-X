from datetime import datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from backend.app.database import get_db
from backend.app.core.permissions import get_current_user, require_viewer
from backend.app.models.host import Host, CollectorHealth
from backend.app.schemas.host import (
    HostCreate,
    HostHeartbeat,
    HostResponse,
    CollectorHealthResponse,
)

router = APIRouter(prefix="/hosts", tags=["Host & Endpoint Inventory"])


@router.post("/register", response_model=HostResponse)
async def register_or_update_host(
    host_in: HostCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    Registers or updates host telemetry metadata from agent.
    """
    result = await db.execute(
        select(Host).options(selectinload(Host.collectors)).where(Host.hostname == host_in.hostname)
    )
    host = result.scalar_one_or_none()

    if host:
        host.ip_address = host_in.ip_address
        host.os_distro = host_in.os_distro
        host.os_version = host_in.os_version
        host.kernel_version = host_in.kernel_version
        host.architecture = host_in.architecture
        host.agent_version = host_in.agent_version
        host.status = "ONLINE"
        host.last_heartbeat = datetime.utcnow()
    else:
        host = Host(
            hostname=host_in.hostname,
            ip_address=host_in.ip_address,
            mac_address=host_in.mac_address,
            os_distro=host_in.os_distro,
            os_version=host_in.os_version,
            kernel_version=host_in.kernel_version,
            architecture=host_in.architecture,
            agent_version=host_in.agent_version,
            status="ONLINE",
        )
        db.add(host)

    await db.commit()
    await db.refresh(host)
    
    # Reload with collectors
    res = await db.execute(
        select(Host).options(selectinload(Host.collectors)).where(Host.id == host.id)
    )
    return res.scalar_one()


@router.post("/heartbeat")
async def process_heartbeat(
    heartbeat: HostHeartbeat,
    db: AsyncSession = Depends(get_db),
):
    """
    Processes agent heartbeats and updates individual collector health metrics.
    """
    res = await db.execute(select(Host).where(Host.hostname == heartbeat.hostname))
    host = res.scalar_one_or_none()
    if not host:
        raise HTTPException(status_code=404, detail="Host not registered")

    host.last_heartbeat = datetime.utcnow()
    host.status = "ONLINE"

    # Update collector states
    for c_update in heartbeat.collectors:
        c_res = await db.execute(
            select(CollectorHealth).where(
                CollectorHealth.host_id == host.id,
                CollectorHealth.collector_name == c_update.collector_name,
            )
        )
        c_obj = c_res.scalar_one_or_none()
        if c_obj:
            c_obj.status = c_update.status
            c_obj.events_collected += c_update.events_collected
            c_obj.errors_count += c_update.errors_count
            c_obj.last_error_message = c_update.last_error_message
            c_obj.last_heartbeat = datetime.utcnow()
        else:
            c_obj = CollectorHealth(
                host_id=host.id,
                collector_name=c_update.collector_name,
                status=c_update.status,
                events_collected=c_update.events_collected,
                errors_count=c_update.errors_count,
                last_error_message=c_update.last_error_message,
            )
            db.add(c_obj)

    await db.commit()
    return {"status": "heartbeat_acknowledged", "hostname": host.hostname}


@router.get("/", response_model=List[HostResponse])
async def list_hosts(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_viewer),
):
    """List all monitored hosts and collector statuses."""
    result = await db.execute(
        select(Host).options(selectinload(Host.collectors)).order_by(Host.last_heartbeat.desc())
    )
    return result.scalars().all()


@router.get("/{host_id}", response_model=HostResponse)
async def get_host(
    host_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_viewer),
):
    """Retrieve details for a specific host."""
    result = await db.execute(
        select(Host).options(selectinload(Host.collectors)).where(Host.id == host_id)
    )
    host = result.scalar_one_or_none()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    return host


@router.delete("/{host_id}")
async def delete_host(
    host_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_viewer),
):
    """Delete a monitored host and its collector telemetry."""
    from backend.app.services.data_management_service import data_management_service
    deleted = await data_management_service.delete_host(db, host_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Host not found")
    return {"success": True, "message": f"Host {host_id} deleted"}

