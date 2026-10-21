import uuid
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from sqlalchemy.orm import selectinload

from backend.app.database import get_db
from backend.app.core.permissions import get_current_user, require_viewer, require_analyst
from backend.app.models.host import Host

from backend.app.models.event import NormalizedEvent
from backend.app.models.rule import DetectionRule
from backend.app.models.incident import Incident, IncidentEventLink
from backend.app.schemas.event import RawEventIngest, NormalizedEventSchema, EventFilterParams
from backend.app.schemas.common import PaginatedResponse
from backend.app.engine.normalization import EventNormalizer
from backend.app.engine.rules_engine import rules_engine
from backend.app.engine.ewcc_engine import ewcc_engine
from backend.app.api.v1.websockets import ws_manager

router = APIRouter(prefix="/events", tags=["Event Ingestion & Telemetry"])
normalizer = EventNormalizer()


@router.post("/ingest")
async def ingest_events(
    events_in: List[RawEventIngest],
    db: AsyncSession = Depends(get_db),
):
    """
    Ingests, normalizes, deduplicates, and evaluates telemetry events against detection rules.
    Correlates triggered events into explainable Incidents.
    """
    if not events_in:
        return {"ingested": 0, "suppressed_duplicates": 0, "incidents_created": 0}

    ingested_count = 0
    duplicate_count = 0
    created_incidents = []

    # Cache hosts lookup by hostname
    hosts_map: dict[str, Host] = {}

    for raw_event in events_in:
        hostname = raw_event.hostname or "unknown-host"
        if hostname not in hosts_map:
            res = await db.execute(select(Host).where(Host.hostname == hostname))
            host_obj = res.scalar_one_or_none()
            if not host_obj:
                host_obj = Host(
                    hostname=hostname,
                    ip_address=raw_event.src_ip or "127.0.0.1",
                    os_distro="linux",
                    os_version="unknown",
                    status="ONLINE",
                )
                db.add(host_obj)
                await db.flush()
            hosts_map[hostname] = host_obj

        host_obj = hosts_map[hostname]

        # 1. Normalization & Deduplication
        norm_dict, is_dup = normalizer.normalize(raw_event)
        if is_dup:
            duplicate_count += 1
            continue

        # 2. Store Normalized Event
        event_model = NormalizedEvent(
            event_id=norm_dict["event_id"],
            timestamp=norm_dict["timestamp"],
            host_id=host_obj.id,
            source=norm_dict["source"],
            event_category=norm_dict["event_category"],
            severity=norm_dict["severity"],
            confidence=1.0,
            account_user=norm_dict["account_user"],
            account_uid=norm_dict["account_uid"],
            target_user=norm_dict["target_user"],
            process_name=norm_dict["process_name"],
            process_pid=norm_dict["process_pid"],
            process_parent_pid=norm_dict["process_parent_pid"],
            process_cmdline=norm_dict["process_cmdline"],
            file_path=norm_dict["file_path"],
            file_sha256=norm_dict["file_sha256"],
            src_ip=norm_dict["src_ip"],
            src_port=norm_dict["src_port"],
            dst_ip=norm_dict["dst_ip"],
            dst_port=norm_dict["dst_port"],
            evidence_hash=norm_dict["evidence_hash"],
            raw_payload=norm_dict["raw_payload"],
        )
        db.add(event_model)
        await db.flush()
        ingested_count += 1

        # 3. Correlation & Rule Processing
        triggered = rules_engine.process_event(host_id=host_obj.id, event=norm_dict)
        for trig in triggered:
            rule_id_str = trig["rule_id"]
            
            # Find rule model
            rule_res = await db.execute(select(DetectionRule).where(DetectionRule.rule_id == rule_id_str))
            rule_model = rule_res.scalar_one_or_none()
            rule_db_id = rule_model.id if rule_model else None

            # Check if open incident exists for this host & rule
            inc_res = await db.execute(
                select(Incident).where(
                    Incident.host_id == host_obj.id,
                    Incident.rule_id == rule_db_id,
                    Incident.status.in_(["New", "Triaged", "Investigating"]),
                )
            )
            existing_incident = inc_res.scalar_one_or_none()

            # Run EWCC evaluation for calibrated confidence
            ewcc_res = ewcc_engine.evaluate_correlation(
                events=trig["matched_events"],
                base_rule_confidence=trig["base_confidence"],
                window_seconds=trig["window_seconds"],
                os_distro=host_obj.os_distro,
            )

            if existing_incident:
                # Link current event to existing incident
                link = IncidentEventLink(
                    incident_id=existing_incident.id,
                    event_id=event_model.id,
                    correlation_role="TRIGGER",
                )
                db.add(link)
                existing_incident.updated_at = datetime.utcnow()
                existing_incident.confidence = ewcc_res["ewcc_confidence"]
            else:
                # Create brand new Incident
                incident_number = f"INC-{datetime.utcnow().strftime('%Y')}-{uuid.uuid4().hex[:4].upper()}"
                new_incident = Incident(
                    incident_number=incident_number,
                    title=trig["title"],
                    description=trig["description"],
                    status="New",
                    severity=trig["severity"],
                    confidence=ewcc_res["ewcc_confidence"],
                    rule_id=rule_db_id,
                    host_id=host_obj.id,
                    affected_account=trig["affected_account"],
                )
                db.add(new_incident)
                await db.flush()

                # Link matched events
                link = IncidentEventLink(
                    incident_id=new_incident.id,
                    event_id=event_model.id,
                    correlation_role="TRIGGER",
                )
                db.add(link)

                created_incidents.append({
                    "incident_number": incident_number,
                    "title": new_incident.title,
                    "severity": new_incident.severity,
                    "confidence": new_incident.confidence,
                    "host": host_obj.hostname,
                })

                # Broadcast live incident alert
                await ws_manager.broadcast({
                    "type": "NEW_INCIDENT",
                    "incident_number": incident_number,
                    "title": new_incident.title,
                    "severity": new_incident.severity,
                    "confidence": new_incident.confidence,
                    "hostname": host_obj.hostname,
                    "timestamp": datetime.utcnow().isoformat(),
                })

        # Broadcast live event
        await ws_manager.broadcast({
            "type": "NEW_EVENT",
            "event_id": norm_dict["event_id"],
            "event_category": norm_dict["event_category"],
            "severity": norm_dict["severity"],
            "hostname": host_obj.hostname,
            "timestamp": norm_dict["timestamp"].isoformat(),
        })

    await db.commit()

    return {
        "status": "success",
        "ingested": ingested_count,
        "suppressed_duplicates": duplicate_count,
        "incidents_created": len(created_incidents),
        "incidents": created_incidents,
    }


@router.get("/", response_model=PaginatedResponse[NormalizedEventSchema])
async def list_events(
    category: Optional[str] = None,
    host_id: Optional[str] = None,
    severity: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_viewer),
):
    """Query normalized events with filtering and pagination."""
    query = select(NormalizedEvent).order_by(desc(NormalizedEvent.timestamp))
    if category:
        query = query.where(NormalizedEvent.event_category == category.upper())
    if host_id:
        query = query.where(NormalizedEvent.host_id == host_id)
    if severity:
        query = query.where(NormalizedEvent.severity == severity.upper())

    # Count total
    total_res = await db.execute(select(NormalizedEvent))
    total_items = len(total_res.scalars().all())

    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    items = result.scalars().all()

    total_pages = (total_items + page_size - 1) // page_size if total_items > 0 else 1

    return PaginatedResponse(
        items=items,
        total=total_items,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/{event_id}", response_model=NormalizedEventSchema)
async def get_event(
    event_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_viewer),
):
    """Retrieve full normalized event detail and cryptographic evidence hash."""
    res = await db.execute(select(NormalizedEvent).where(NormalizedEvent.event_id == event_id))
    event = res.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.delete("/{event_id}")
async def delete_single_event(
    event_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_analyst),
):
    """Delete a single normalized event."""
    from backend.app.services.data_management_service import data_management_service
    deleted = await data_management_service.delete_event(db, event_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Event not found")
    return {"success": True, "message": f"Event {event_id} deleted"}


@router.delete("/")
async def purge_all_events(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_analyst),
):
    """Purge all telemetry events."""
    from backend.app.services.data_management_service import data_management_service
    res = await data_management_service.purge_category(db, "events")
    return res

