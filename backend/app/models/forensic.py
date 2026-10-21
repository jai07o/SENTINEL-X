import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database import Base


class ForensicCase(Base):
    __tablename__ = "forensic_cases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_number: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False) # e.g., 'CASE-2026-001'
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="ACTIVE") # ACTIVE, ARCHIVED, CLOSED
    priority: Mapped[str] = mapped_column(String(20), default="MEDIUM") # LOW, MEDIUM, HIGH, CRITICAL
    
    lead_analyst_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    closed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    summary_findings: Mapped[str] = mapped_column(Text, nullable=True)

    lead_analyst: Mapped["User"] = relationship() # noqa: F821
    evidence_items: Mapped[list["EvidenceItem"]] = relationship(back_populates="case") # noqa: F821
    timeline_items: Mapped[list["CaseTimelineItem"]] = relationship(
        back_populates="case", cascade="all, delete-orphan"
    )
    notes: Mapped[list["ForensicNote"]] = relationship(
        back_populates="case", cascade="all, delete-orphan"
    )


class CaseTimelineItem(Base):
    __tablename__ = "case_timeline_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id: Mapped[str] = mapped_column(String(36), ForeignKey("forensic_cases.id"), index=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    source_type: Mapped[str] = mapped_column(String(64), nullable=False) # LOG, ARTIFACT, HOST_MEMORY, NETWORK_FLOW
    evidence_id: Mapped[str] = mapped_column(String(36), ForeignKey("evidence_items.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    case: Mapped["ForensicCase"] = relationship(back_populates="timeline_items")
    evidence: Mapped["EvidenceItem"] = relationship() # noqa: F821


class ForensicNote(Base):
    __tablename__ = "forensic_notes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id: Mapped[str] = mapped_column(String(36), ForeignKey("forensic_cases.id"), index=True, nullable=False)
    analyst_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(128), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    case: Mapped["ForensicCase"] = relationship(back_populates="notes")
    analyst: Mapped["User"] = relationship() # noqa: F821
