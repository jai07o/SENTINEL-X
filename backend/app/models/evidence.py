import uuid
from datetime import datetime
from typing import TYPE_CHECKING
from sqlalchemy import String, Integer, DateTime, Text, ForeignKey, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database import Base

if TYPE_CHECKING:
    from backend.app.models.auth import User
    from backend.app.models.forensic import ForensicCase


class EvidenceItem(Base):
    __tablename__ = "evidence_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    evidence_number: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False) # e.g., 'EV-2026-0001'
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    source_description: Mapped[str] = mapped_column(Text, nullable=False)  # Disk image, pcap, memory dump, auth log
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    
    # Cryptographic Hashes for Tamper Detection
    sha256_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    md5_hash: Mapped[str] = mapped_column(String(32), nullable=True)
    file_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(128), default="application/octet-stream")
    
    storage_path: Mapped[str] = mapped_column(String(512), nullable=False) # Path in isolated evidence directory
    is_read_only: Mapped[bool] = mapped_column(Boolean, default=True)      # Immutable original flag
    is_derived_artifact: Mapped[bool] = mapped_column(Boolean, default=False)
    parent_evidence_id: Mapped[str] = mapped_column(String(36), nullable=True) # If derived from original
    
    acquired_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    acquired_by_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    case_id: Mapped[str] = mapped_column(String(36), ForeignKey("forensic_cases.id"), nullable=True)

    acquired_by: Mapped["User"] = relationship()                                  # noqa: F821
    custody_records: Mapped[list["ChainOfCustodyRecord"]] = relationship(
        back_populates="evidence", cascade="all, delete-orphan"
    )
    case: Mapped["ForensicCase"] = relationship(back_populates="evidence_items")  # noqa: F821


class ChainOfCustodyRecord(Base):
    __tablename__ = "chain_of_custody_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    evidence_id: Mapped[str] = mapped_column(String(36), ForeignKey("evidence_items.id"), index=True, nullable=False)
    analyst_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    
    action: Mapped[str] = mapped_column(String(64), nullable=False)  # INTAKE, HASH_VERIFIED, COPY_CREATED, EXPORTED, ARCHIVED
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    verified_hash: Mapped[str] = mapped_column(String(64), nullable=False) # Verification hash at time of action
    hash_matched: Mapped[bool] = mapped_column(Boolean, default=True)
    notes: Mapped[str] = mapped_column(Text, nullable=True)

    evidence: Mapped["EvidenceItem"] = relationship(back_populates="custody_records")
    analyst: Mapped["User"] = relationship() # noqa: F821
