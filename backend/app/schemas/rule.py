from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class DetectionRuleBase(BaseModel):
    rule_id: str
    name: str
    description: str
    severity: str = "MEDIUM"
    base_confidence: float = 0.85
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    event_category: str
    filter_criteria: str = "{}"
    window_seconds: int = 60
    threshold: int = 1
    is_active: bool = True
    version: str = "1.0.0"


class DetectionRuleCreate(DetectionRuleBase):
    pass


class DetectionRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    base_confidence: Optional[float] = None
    filter_criteria: Optional[str] = None
    window_seconds: Optional[int] = None
    threshold: Optional[int] = None
    is_active: Optional[bool] = None
    version: Optional[str] = None


class DetectionRuleResponse(DetectionRuleBase):
    id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
