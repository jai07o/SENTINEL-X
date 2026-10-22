"""
SENTINEL-X AI Self-Training, Model Evolution & Breach Forensics API Router
"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from backend.app.services.ai_training_service import ai_training_service
from backend.app.services.breach_forensics_service import breach_forensics_service

router = APIRouter(prefix="/ai-training", tags=["AI Training & Continuous Safeguards"])


class ScheduleUpdateRequest(BaseModel):
    cadence: str = Field(..., description="Cadence option: 'weekly', 'monthly', or '6months'")
    auto_update_enabled: bool = Field(True, description="Enable automatic scheduled retraining in background")


class RetrainRequest(BaseModel):
    trigger_source: Optional[str] = Field("web_ui", description="Source or reason for triggering retraining")


@router.get("/status")
def get_ai_training_status():
    """Returns AI model version, training metrics, schedule cadence, and next automated update."""
    return ai_training_service.get_status()


@router.post("/schedule")
def update_ai_training_schedule(req: ScheduleUpdateRequest):
    """Sets the recurring AI retraining cadence to 'weekly', 'monthly', or '6months'."""
    try:
        res = ai_training_service.set_update_schedule(
            cadence=req.cadence,
            auto_update=req.auto_update_enabled
        )
        return res
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/retrain")
def trigger_ai_retraining(req: RetrainRequest = RetrainRequest()):
    """Triggers immediate AI model retraining, weight optimization, and safeguard evolution."""
    res = ai_training_service.execute_retraining_and_safeguard_evolution(trigger_source=req.trigger_source)
    return res


@router.get("/breach-evidence")
def run_breach_forensics_discovery():
    """
    Executes deep forensic discovery for signs of data breaches:
    memory injection footprints, browser token snooping, VSS deletion, and exfiltration paths.
    """
    evidence = breach_forensics_service.run_master_breach_investigation()
    return evidence


@router.get("/history")
def get_ai_training_history():
    """Retrieves the history of past AI training runs, accuracy improvements, and discovered safeguards."""
    history_file = ai_training_service.MODELS_DIR / "training_history.json"
    if history_file.exists():
        try:
            import json
            with open(history_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []
