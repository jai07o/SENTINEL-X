import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Float, Text, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_number: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False) # e.g., 'INC-2026-0001'
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    
    # Lifecycle: New -> Triaged -> Investigating -> Contained -> Resolved -> Closed
    status: Mapped[str] = mapped_column(String(32), default="New", index=True)
    severity: Mapped[str] = mapped_column(String(20), default="MEDIUM", index=True) # LOW, MEDIUM, HIGH, CRITICAL
    confidence: Mapped[float] = mapped_column(Float, default=0.85)                 # Inferred correlation confidence
    
    rule_id: Mapped[str] = mapped_column(String(36), ForeignKey("detection_rules.id"), nullable=True)
    host_id: Mapped[str] = mapped_column(String(36), ForeignKey("hosts.id"), index=True, nullable=False)
    affected_account: Mapped[str] = mapped_column(String(64), nullable=True)
    
    assigned_to: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    closed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    
    # Forensic & Analyst Notes
    analyst_notes: Mapped[str] = mapped_column(Text, default="[]")       # JSON array of notes
    resolution_notes: Mapped[str] = mapped_column(Text, nullable=True)
    
    # Relationships
    rule: Mapped["DetectionRule"] = relationship(back_populates="incidents") # noqa: F821
    host: Mapped["Host"] = relationship(back_populates="incidents")          # noqa: F821
    assigned_user: Mapped["User"] = relationship()                           # noqa: F821
    event_links: Mapped[list["IncidentEventLink"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    response_actions: Mapped[list["ResponseAction"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )


class IncidentEventLink(Base):
    __tablename__ = "incident_event_links"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("incidents.id"), index=True, nullable=False)
    event_id: Mapped[str] = mapped_column(String(36), ForeignKey("events.id"), index=True, nullable=False)
    correlation_role: Mapped[str] = mapped_column(String(64), default="TRIGGER")  # TRIGGER, SUPPORTING, CONTEXT
    added_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    incident: Mapped["Incident"] = relationship(back_populates="event_links")
    event: Mapped["NormalizedEvent"] = relationship(back_populates="incident_links") # noqa: F821


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("incidents.id"), index=True, nullable=False)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)  # ISOLATE_HOST, KILL_PROCESS, DISABLE_ACCOUNT, NOTIFY_SOC
    parameters: Mapped[str] = mapped_column(Text, default="{}")           # JSON parameters
    
    # Human Approval Flow
    requested_by: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    approved_by: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="PENDING_APPROVAL")  # PENDING_APPROVAL, APPROVED, REJECTED, EXECUTED, FAILED
    outcome_details: Mapped[str] = mapped_column(Text, nullable=True)
    execution_error: Mapped[str] = mapped_column(Text, nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    executed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    incident: Mapped["Incident"] = relationship(back_populates="response_actions")
