from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from backend.app.database import get_db
from backend.app.core.permissions import get_current_user, require_analyst, require_viewer
from backend.app.models.auth import User
from backend.app.models.host import Host
from backend.app.models.network import NetworkObservation
from backend.app.schemas.network import (
    NetworkObservationCreate,
    NetworkObservationResponse,
    NetworkAnomalySummary,
)
from backend.app.services.network_service import network_service

router = APIRouter(prefix="/network", tags=["Network Telemetry & Zeek Anomaly Analysis"])


@router.post("/ingest-zeek")
async def ingest_zeek_log_file(
    hostname: str = Query(...),
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Ingests Zeek conn.log or dns.log file, normalizes connections, and scores anomalies.
    """
    # Lookup host
    h_res = await db.execute(select(Host).where(Host.hostname == hostname))
    host = h_res.scalar_one_or_none()
    if not host:
        host = Host(hostname=hostname, ip_address="127.0.0.1", os_distro="linux", os_version="unknown")
        db.add(host)
        await db.flush()

    contents = (await file.read()).decode("utf-8", errors="ignore")
    lines = contents.splitlines()

    parsed_count = 0
    anomalies_detected = 0

    for line in lines:
        obs = network_service.parse_zeek_conn_log_line(line)
        if obs:
            eval_res = network_service.evaluate_network_anomaly(obs)
            model = NetworkObservation(
                host_id=host.id,
                source_type=obs["source_type"],
                protocol=obs["protocol"],
                src_ip=obs["src_ip"],
                src_port=obs["src_port"],
                dst_ip=obs["dst_ip"],
                dst_port=obs["dst_port"],
                service=obs.get("service"),
                duration_seconds=obs.get("duration_seconds", 0.0),
                bytes_orig=obs.get("bytes_orig", 0),
                bytes_resp=obs.get("bytes_resp", 0),
                is_outbound=obs.get("is_outbound", True),
                is_anomalous=eval_res["is_anomalous"],
                anomaly_score=eval_res["anomaly_score"],
                anomaly_reason=eval_res["anomaly_reason"],
            )
            db.add(model)
            parsed_count += 1
            if eval_res["is_anomalous"]:
                anomalies_detected += 1

    await db.commit()
    return {
        "status": "success",
        "lines_processed": len(lines),
        "observations_ingested": parsed_count,
        "anomalies_detected": anomalies_detected,
    }


@router.get("/observations", response_model=List[NetworkObservationResponse])
async def list_network_observations(
    anomalous_only: bool = Query(False),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
):
    """List recent network connections and anomaly flags."""
    query = select(NetworkObservation).order_by(desc(NetworkObservation.timestamp))
    if anomalous_only:
        query = query.where(NetworkObservation.is_anomalous == True)
    query = query.limit(limit)

    res = await db.execute(query)
    return res.scalars().all()


@router.get("/anomalies", response_model=NetworkAnomalySummary)
async def get_network_anomaly_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
):
    """Retrieve network traffic distribution and anomalous destination breakdown."""
    all_res = await db.execute(select(NetworkObservation))
    observations = all_res.scalars().all()

    anomalous = [o for o in observations if o.is_anomalous]

    # Aggregate top ports
    port_counts: dict[int, int] = {}
    ip_counts: dict[str, int] = {}
    dns_count = 0

    for o in observations:
        port_counts[o.dst_port] = port_counts.get(o.dst_port, 0) + 1
        if o.is_outbound:
            ip_counts[o.dst_ip] = ip_counts.get(o.dst_ip, 0) + 1
        if o.dns_query:
            dns_count += 1

    top_ports = [{"port": p, "count": c} for p, c in sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:5]]
    top_ips = [{"ip": ip, "count": c} for ip, c in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]]

    return NetworkAnomalySummary(
        total_observations=len(observations),
        anomalous_observations=len(anomalous),
        top_dst_ports=top_ports,
        top_outbound_ips=top_ips,
        dns_queries_count=dns_count,
    )
