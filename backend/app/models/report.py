import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Text, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database import Base


class SecurityReport(Base):
    __tablename__ = "security_reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    report_number: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False) # e.g., 'RPT-2026-001'
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    report_type: Mapped[str] = mapped_column(String(64), nullable=False) # INCIDENT_DOSSIER, VULN_ASSESSMENT, FORENSIC_CASE, COMPLIANCE_SUMMARY
    
    generated_by_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    
    content_markdown: Mapped[Text] = mapped_column(Text, nullable=False)
    content_json: Mapped[Text] = mapped_column(Text, nullable=False)
    export_filepath: Mapped[str] = mapped_column(String(512), nullable=True)

    generator: Mapped["User"] = relationship() # noqa: F821


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    actor_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    actor_username: Mapped[str] = mapped_column(String(64), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=True)
    
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True) # USER_LOGIN, SCOPE_CREATED, EVIDENCE_ACCESSED, ACTION_APPROVED, EXPORT_REPORT
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)      # INCIDENT, EVIDENCE, TARGET_SCOPE, MALWARE_SAMPLE
    resource_id: Mapped[str] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="SUCCESS")          # SUCCESS, DENIED, FAILED
    details_json: Mapped[str] = mapped_column(Text, default="{}")

    actor: Mapped["User"] = relationship() # noqa: F821

    __table_args__ = (
        Index("ix_audit_action_time", "action", "timestamp"),
    )
