from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from backend.app.database import get_db
from backend.app.core.permissions import get_current_user, require_analyst
from backend.app.models.auth import User
from backend.app.models.incident import Incident, IncidentEventLink
from backend.app.models.rule import DetectionRule
from backend.app.schemas.ai import AIExplanationRequest, AIInvestigationReport
from backend.app.services.ai_service import ai_service

router = APIRouter(prefix="/ai", tags=["AI-Assisted Investigation & Explanation"])


@router.post("/explain-incident", response_model=AIInvestigationReport)
async def explain_incident_with_ai(
    req: AIExplanationRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Produces schema-validated AI explanation of a confirmed incident.
    Cites exact internal event IDs, redacts credentials/secrets, and suggests safe diagnostic actions.
    """
    res = await db.execute(
        select(Incident)
        .options(
            selectinload(Incident.rule),
            selectinload(Incident.event_links).selectinload(IncidentEventLink.event),
        )
        .where(Incident.id == req.incident_id)
    )
    incident = res.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    events = [
        {
            "event_id": l.event.event_id,
            "source": l.event.source,
            "event_category": l.event.event_category,
            "account_user": l.event.account_user,
            "process_name": l.event.process_name,
            "process_parent_pid": l.event.process_parent_pid,
            "dst_ip": l.event.dst_ip,
            "file_sha256": l.event.file_sha256,
            "evidence_hash": l.event.evidence_hash,
            "raw_payload": l.event.raw_payload,
        }
        for l in incident.event_links
        if l.event
    ]

    rule_name = incident.rule.name if incident.rule else "Correlated Threat Rule"
    mitre_tech = incident.rule.mitre_technique_id if incident.rule else "T1078"
    mitre_tactic = incident.rule.mitre_tactic if incident.rule else "Initial Access"

    report = ai_service.generate_investigation_report(
        incident_id=incident.incident_number,
        incident_title=incident.title,
        rule_name=rule_name,
        mitre_technique_id=mitre_tech or "T1078",
        mitre_tactic=mitre_tactic or "Defense Evasion",
        correlated_events=events,
        target_audience=req.target_audience,
    )

    return report


@router.post("/threat-investigator")
async def run_ai_threat_investigator(
    current_user: User = Depends(require_analyst),
):
    """
    SENTINEL-X — AI Linux Threat Investigator:
    Correlates suspicious processes, login attempts, modified system files (FIM), and unusual network connections.
    Explains suspicious behavior, produces an incident timeline, and recommends safe remediation.
    """
    from backend.app.services.ai_threat_investigator_service import ai_threat_investigator
    results = ai_threat_investigator.correlate_and_investigate()
    return results


@router.get("/threat-investigator/latest")
async def get_latest_ai_threat_investigation(
    current_user: User = Depends(require_analyst),
):
    """Retrieves the latest AI Linux Threat Investigation dossier and timeline."""
    import json
    from backend.app.services.ai_threat_investigator_service import EVIDENCE_DIR
    cases = sorted(EVIDENCE_DIR.glob("AI-INVESTIGATION-*.json"), reverse=True)
    if not cases:
        raise HTTPException(status_code=404, detail="No AI threat investigation cases recorded yet.")
    try:
        with open(cases[0], "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load latest investigation: {str(e)}")


@router.get("/threat-investigator/signals")
async def get_live_threat_signals(
    current_user: User = Depends(require_analyst),
):
    """Directly queries and returns the 4 live threat signals without full sealing."""
    from backend.app.services.ai_threat_investigator_service import ai_threat_investigator
    return {
        "processes": ai_threat_investigator.audit_suspicious_processes(),
        "logins": ai_threat_investigator.audit_login_attempts(),
        "files": ai_threat_investigator.audit_modified_system_files(),
        "network": ai_threat_investigator.audit_unusual_network_connections()
    }
