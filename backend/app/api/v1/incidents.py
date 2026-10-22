import json
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from sqlalchemy.orm import selectinload

from backend.app.database import get_db
from backend.app.core.permissions import get_current_user, require_analyst, require_viewer
from backend.app.models.auth import User
from backend.app.models.incident import Incident, IncidentEventLink, ResponseAction
from backend.app.models.event import NormalizedEvent
from backend.app.schemas.incident import (
    IncidentResponse,
    IncidentDetailResponse,
    IncidentUpdate,
    AnalystNoteCreate,
    ResponseActionCreate,
    ResponseActionResponse,
)
from backend.app.schemas.common import PaginatedResponse
from backend.app.services.report_service import report_service

router = APIRouter(prefix="/incidents", tags=["Incidents & Investigation"])


@router.get("/", response_model=PaginatedResponse[IncidentResponse])
async def list_incidents(
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = None,
    host_id: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
):
    """List incidents with lifecycle and severity filtering."""
    query = (
        select(Incident)
        .options(
            selectinload(Incident.response_actions),
            selectinload(Incident.event_links),
        )
        .order_by(desc(Incident.created_at))
    )
    if status_filter:
        query = query.where(Incident.status == status_filter)
    if severity:
        query = query.where(Incident.severity == severity.upper())
    if host_id:
        query = query.where(Incident.host_id == host_id)

    all_res = await db.execute(query)
    all_items = all_res.scalars().all()
    total = len(all_items)

    paginated = all_items[(page - 1) * page_size : page * page_size]
    
    # Enrich with event count
    response_items = []
    for inc in paginated:
        resp = IncidentResponse.from_orm(inc)
        resp.event_count = len(inc.event_links)
        response_items.append(resp)

    total_pages = (total + page_size - 1) // page_size if total > 0 else 1

    return PaginatedResponse(
        items=response_items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/{incident_id}", response_model=IncidentDetailResponse)
async def get_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
):
    """Retrieve full incident investigation workspace, timeline, and correlated telemetry."""
    res = await db.execute(
        select(Incident)
        .options(
            selectinload(Incident.response_actions),
            selectinload(Incident.event_links).selectinload(IncidentEventLink.event),
        )
        .where(Incident.id == incident_id)
    )
    incident = res.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    events = [link.event for link in incident.event_links if link.event]
    
    detail = IncidentDetailResponse.from_orm(incident)
    detail.event_count = len(events)
    detail.events = events
    return detail


@router.patch("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: str,
    inc_update: IncidentUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Update incident status (New -> Triaged -> Investigating -> Contained -> Resolved -> Closed)."""
    res = await db.execute(
        select(Incident)
        .options(selectinload(Incident.response_actions), selectinload(Incident.event_links))
        .where(Incident.id == incident_id)
    )
    incident = res.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    if inc_update.title:
        incident.title = inc_update.title
    if inc_update.description:
        incident.description = inc_update.description
    if inc_update.status:
        incident.status = inc_update.status
        if inc_update.status in ("Resolved", "Closed"):
            incident.closed_at = datetime.utcnow()
    if inc_update.severity:
        incident.severity = inc_update.severity.upper()
    if inc_update.confidence is not None:
        incident.confidence = inc_update.confidence
    if inc_update.assigned_to:
        incident.assigned_to = inc_update.assigned_to
    if inc_update.resolution_notes:
        incident.resolution_notes = inc_update.resolution_notes

    incident.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(incident)

    resp = IncidentResponse.from_orm(incident)
    resp.event_count = len(incident.event_links)
    return resp


@router.post("/{incident_id}/notes")
async def add_analyst_note(
    incident_id: str,
    note_in: AnalystNoteCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Append investigation note to incident record."""
    res = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = res.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    notes_list = []
    if incident.analyst_notes:
        try:
            notes_list = json.loads(incident.analyst_notes)
        except Exception:
            notes_list = []

    note_entry = {
        "author": current_user.username,
        "text": note_in.text,
        "timestamp": datetime.utcnow().isoformat(),
    }
    notes_list.append(note_entry)
    incident.analyst_notes = json.dumps(notes_list)
    incident.updated_at = datetime.utcnow()

    await db.commit()
    return {"status": "note_added", "note": note_entry}


@router.post("/{incident_id}/actions", response_model=ResponseActionResponse)
async def request_containment_action(
    incident_id: str,
    action_in: ResponseActionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Request a human-authorized response action (ISOLATE_HOST, KILL_PROCESS, DISABLE_ACCOUNT).
    Initially queued in PENDING_APPROVAL status.
    """
    res = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = res.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    new_action = ResponseAction(
        incident_id=incident.id,
        action_type=action_in.action_type,
        parameters=json.dumps(action_in.parameters),
        requested_by=current_user.id,
        status="PENDING_APPROVAL",
    )
    db.add(new_action)
    await db.commit()
    await db.refresh(new_action)

    return new_action


@router.post("/{incident_id}/actions/{action_id}/approve", response_model=ResponseActionResponse)
async def approve_containment_action(
    incident_id: str,
    action_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Explicitly approve and execute a containment action with audit logging.
    """
    res = await db.execute(
        select(ResponseAction).where(
            ResponseAction.id == action_id,
            ResponseAction.incident_id == incident_id,
        )
    )
    action = res.scalar_one_or_none()
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")

    action.approved_by = current_user.id
    action.status = "EXECUTED"
    action.executed_at = datetime.utcnow()
    action.outcome_details = f"Action {action.action_type} successfully authorized by {current_user.username}."

    await db.commit()
    await db.refresh(action)
    return action


from backend.app.services.containment_evidence_orchestrator import orchestrator


@router.post("/{incident_id}/contain-and-preserve")
async def contain_and_preserve_incident(
    incident_id: str,
    threat_override: Optional[dict] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Unified Automated Threat Containment & Digital Forensics Evidence Preservation.
    Simultaneously:
    1. Captures volatile digital forensic evidence at the scene of the hack.
    2. Seals evidence with SHA-256 in the Digital Forensics Vault with Chain of Custody.
    3. Safely terminates rogue malware/RAT processes and isolates the affected host.
    """
    res = await db.execute(
        select(Incident)
        .options(selectinload(Incident.event_links).selectinload(IncidentEventLink.event))
        .where(Incident.id == incident_id)
    )
    incident = res.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    context = threat_override or {}
    if not context and incident.event_links:
        ev = incident.event_links[0].event
        if ev:
            context = {
                "process_pid": ev.process_pid,
                "process_name": ev.process_name,
                "process_cmdline": ev.process_cmdline,
                "src_ip": ev.src_ip,
                "dst_ip": ev.dst_ip,
                "dst_port": ev.dst_port,
                "category": ev.event_category,
                "title": incident.title,
            }

    try:
        result = await orchestrator.contain_and_preserve(
            db=db,
            incident_id=incident_id,
            threat_context=context,
            executed_by_id=current_user.id,
            auto_isolate_host=True,
            auto_kill_process=True,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Containment and preservation error: {e}")


@router.get("/{incident_id}/export")
async def export_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
):
    """Generate and export a publication-ready Incident Investigation Dossier."""
    res = await db.execute(
        select(Incident)
        .options(
            selectinload(Incident.response_actions),
            selectinload(Incident.event_links).selectinload(IncidentEventLink.event),
        )
        .where(Incident.id == incident_id)
    )
    incident = res.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident_dict = {
        "incident_number": incident.incident_number,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "confidence": incident.confidence,
        "status": incident.status,
        "host_id": incident.host_id,
        "resolution_notes": incident.resolution_notes,
        "response_actions": [
            {
                "action_type": a.action_type,
                "status": a.status,
                "requested_by": a.requested_by,
                "approved_by": a.approved_by,
                "outcome_details": a.outcome_details,
            }
            for a in incident.response_actions
        ],
    }

    events = [
        {
            "event_id": l.event.event_id,
            "timestamp": l.event.timestamp,
            "event_category": l.event.event_category,
            "source": l.event.source,
            "process_name": l.event.process_name,
            "account_user": l.event.account_user,
            "evidence_hash": l.event.evidence_hash,
        }
        for l in incident.event_links
        if l.event
    ]

    report = report_service.generate_incident_report(
        incident_data=incident_dict,
        events=events,
        analyst_username=current_user.username,
    )
    return report


@router.delete("/{incident_id}")
async def delete_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Permanently delete an incident and cascade-clean its links."""
    from backend.app.services.data_management_service import data_management_service
    deleted = await data_management_service.delete_incident(db, incident_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"success": True, "message": f"Incident {incident_id} successfully deleted"}

