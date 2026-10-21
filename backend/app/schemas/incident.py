from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
from backend.app.schemas.event import NormalizedEventSchema


class AnalystNoteCreate(BaseModel):
    author: str
    text: str


class ResponseActionCreate(BaseModel):
    action_type: str  # ISOLATE_HOST, KILL_PROCESS, DISABLE_ACCOUNT, NOTIFY_SOC
    parameters: Dict[str, Any] = Field(default_factory=dict)


class ResponseActionResponse(BaseModel):
    id: str
    incident_id: str
    action_type: str
    parameters: str
    requested_by: str
    approved_by: Optional[str] = None
    status: str
    outcome_details: Optional[str] = None
    execution_error: Optional[str] = None
    created_at: datetime
    executed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class IncidentCreate(BaseModel):
    title: str
    description: str
    severity: str = "MEDIUM"
    confidence: float = 0.85
    rule_id: Optional[str] = None
    host_id: str
    affected_account: Optional[str] = None
    event_ids: List[str] = []


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None  # New, Triaged, Investigating, Contained, Resolved, Closed
    severity: Optional[str] = None
    confidence: Optional[float] = None
    assigned_to: Optional[str] = None
    resolution_notes: Optional[str] = None


class IncidentResponse(BaseModel):
    id: str
    incident_number: str
    title: str
    description: str
    status: str
    severity: str
    confidence: float
    rule_id: Optional[str] = None
    host_id: str
    affected_account: Optional[str] = None
    assigned_to: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime] = None
    analyst_notes: str
    resolution_notes: Optional[str] = None
    event_count: int = 0
    response_actions: List[ResponseActionResponse] = []

    class Config:
        from_attributes = True


class IncidentDetailResponse(IncidentResponse):
    events: List[NormalizedEventSchema] = []
