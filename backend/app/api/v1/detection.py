from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.app.database import get_db
from backend.app.core.permissions import get_current_user, require_analyst, require_viewer
from backend.app.models.rule import DetectionRule
from backend.app.schemas.rule import DetectionRuleCreate, DetectionRuleResponse
from backend.app.engine.rules_engine import rules_engine
from backend.app.engine.ewcc_engine import ewcc_engine

router = APIRouter(prefix="/detection", tags=["Detection Rules & EWCC Research Engine"])


@router.get("/rules", response_model=List[DetectionRuleResponse])
async def list_detection_rules(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_viewer),
):
    """List active and custom detection rules with MITRE ATT&CK mapping."""
    result = await db.execute(select(DetectionRule).order_by(DetectionRule.rule_id))
    rules = result.scalars().all()
    
    # If database rules table is empty, seed from rules_engine default rules
    if not rules:
        for r in rules_engine.rules:
            new_r = DetectionRule(
                rule_id=r["rule_id"],
                name=r["name"],
                description=r["description"],
                severity=r["severity"],
                base_confidence=r.get("base_confidence", 0.85),
                mitre_tactic=r.get("mitre_tactic"),
                mitre_technique_id=r.get("mitre_technique_id"),
                mitre_technique_name=r.get("mitre_technique_name"),
                event_category=r["event_category"],
                filter_criteria=str(r.get("filter_criteria", {})),
                window_seconds=r.get("window_seconds", 60),
                threshold=r.get("threshold", 1),
                is_active=r.get("is_active", True),
                version=r.get("version", "1.0.0"),
            )
            db.add(new_r)
        await db.commit()
        result = await db.execute(select(DetectionRule).order_by(DetectionRule.rule_id))
        rules = result.scalars().all()

    return rules


@router.post("/evaluate-ewcc")
async def evaluate_ewcc_research_metric(
    events: List[Dict[str, Any]] = Body(...),
    base_confidence: float = 0.85,
    window_seconds: int = 60,
    os_distro: str = "ubuntu",
    current_user=Depends(require_analyst),
):
    """
    Evaluates proposed Evidence-Weighted Cross-Distribution Correlation (EWCC) against rule baseline.
    Returns source reliability, identity consistency, evidence completeness, and calibrated confidence.
    """
    if not events:
        raise HTTPException(status_code=400, detail="Event array cannot be empty")

    evaluation = ewcc_engine.evaluate_correlation(
        events=events,
        base_rule_confidence=base_confidence,
        window_seconds=window_seconds,
        os_distro=os_distro,
    )
    return evaluation
