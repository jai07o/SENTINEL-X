from typing import Optional, Any, Dict
from datetime import datetime
from pydantic import BaseModel, Field


class RawEventIngest(BaseModel):
    event_id: Optional[str] = None
    timestamp: Optional[datetime] = None
    hostname: str
    source: str  # systemd_journal, auth_log, fim, auditd, zeek
    event_category: str
    severity: Optional[str] = "INFORMATIONAL"
    account_user: Optional[str] = None
    account_uid: Optional[int] = None
    target_user: Optional[str] = None
    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    process_parent_pid: Optional[int] = None
    process_cmdline: Optional[str] = None
    file_path: Optional[str] = None
    file_sha256: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    raw_payload: Dict[str, Any] = Field(default_factory=dict)


class NormalizedEventSchema(BaseModel):
    id: str
    event_id: str
    timestamp: datetime
    ingested_at: datetime
    host_id: str
    source: str
    event_category: str
    severity: str
    confidence: float
    account_user: Optional[str] = None
    account_uid: Optional[int] = None
    target_user: Optional[str] = None
    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    process_parent_pid: Optional[int] = None
    process_cmdline: Optional[str] = None
    file_path: Optional[str] = None
    file_sha256: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    evidence_hash: str
    raw_payload: str

    class Config:
        from_attributes = True


class EventFilterParams(BaseModel):
    host_id: Optional[str] = None
    event_category: Optional[str] = None
    severity: Optional[str] = None
    account_user: Optional[str] = None
    process_name: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = 50
    offset: int = 0
