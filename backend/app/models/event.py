import uuid
from datetime import datetime
from typing import TYPE_CHECKING
from sqlalchemy import String, DateTime, Integer, Text, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database import Base

if TYPE_CHECKING:
    from backend.app.models.host import Host
    from backend.app.models.incident import IncidentEventLink


class NormalizedEvent(Base):
    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)  # Unique source/client event hash
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True, nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    
    host_id: Mapped[str] = mapped_column(String(36), ForeignKey("hosts.id"), index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)  # systemd_journal, auth_log, fim, auditd, zeek
    event_category: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    # Categories:
    # - AUTH_FAILURE, AUTH_SUCCESS, AUTH_ANOMALY
    # - PROCESS_SPAWN, PRIVILEGE_ESCALATION
    # - FILE_MODIFICATION, SERVICE_CHANGE, SCHEDULED_TASK_CHANGE
    # - NETWORK_OUTBOUND_UNUSUAL, SECURITY_SERVICE_FAILURE
    
    severity: Mapped[str] = mapped_column(String(20), default="INFORMATIONAL", index=True) # LOW, MEDIUM, HIGH, CRITICAL
    confidence: Mapped[float] = mapped_column(default=1.0)  # 0.0 to 1.0 (source reliability & certainty)
    
    # Metadata fields
    account_user: Mapped[str] = mapped_column(String(64), nullable=True, index=True)
    account_uid: Mapped[int] = mapped_column(Integer, nullable=True)
    target_user: Mapped[str] = mapped_column(String(64), nullable=True)
    
    process_name: Mapped[str] = mapped_column(String(128), nullable=True, index=True)
    process_pid: Mapped[int] = mapped_column(Integer, nullable=True)
    process_parent_pid: Mapped[int] = mapped_column(Integer, nullable=True)
    process_cmdline: Mapped[str] = mapped_column(Text, nullable=True)
    
    file_path: Mapped[str] = mapped_column(String(512), nullable=True)
    file_sha256: Mapped[str] = mapped_column(String(64), nullable=True)
    
    src_ip: Mapped[str] = mapped_column(String(45), nullable=True)
    src_port: Mapped[int] = mapped_column(Integer, nullable=True)
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=True)
    dst_port: Mapped[int] = mapped_column(Integer, nullable=True)
    
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA256 of raw event payload
    raw_payload: Mapped[str] = mapped_column(Text, nullable=False)          # Full JSON string of raw telemetry
    
    host: Mapped["Host"] = relationship(back_populates="events")
    incident_links: Mapped[list["IncidentEventLink"]] = relationship(back_populates="event")  # noqa: F821

    __table_args__ = (
        Index("ix_events_host_timestamp", "host_id", "timestamp"),
        Index("ix_events_category_timestamp", "event_category", "timestamp"),
    )
