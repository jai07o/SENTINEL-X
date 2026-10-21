from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel
from backend.app.schemas.evidence import EvidenceItemResponse


class ForensicNoteCreate(BaseModel):
    title: str
    content: str


class ForensicNoteResponse(BaseModel):
    id: str
    case_id: str
    analyst_id: str
    title: str
    content: str
    created_at: datetime

    class Config:
        from_attributes = True


class TimelineItemCreate(BaseModel):
    timestamp: datetime
    title: str
    description: str
    source_type: str  # LOG, ARTIFACT, HOST_MEMORY, NETWORK_FLOW
    evidence_id: Optional[str] = None


class TimelineItemResponse(BaseModel):
    id: str
    case_id: str
    timestamp: datetime
    title: str
    description: str
    source_type: str
    evidence_id: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ForensicCaseCreate(BaseModel):
    title: str
    description: str
    priority: str = "MEDIUM"


class ForensicCaseUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    summary_findings: Optional[str] = None


class ForensicCaseResponse(BaseModel):
    id: str
    case_number: str
    title: str
    description: str
    status: str
    priority: str
    lead_analyst_id: str
    created_at: datetime
    closed_at: Optional[datetime] = None
    summary_findings: Optional[str] = None
    evidence_items: List[EvidenceItemResponse] = []
    timeline_items: List[TimelineItemResponse] = []
    notes: List[ForensicNoteResponse] = []

    class Config:
        from_attributes = True
