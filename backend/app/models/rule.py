import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, Integer, Float, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database import Base


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    rule_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)  # e.g., 'SX-R-AUTH-001'
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    
    severity: Mapped[str] = mapped_column(String(20), default="MEDIUM")   # LOW, MEDIUM, HIGH, CRITICAL
    base_confidence: Mapped[float] = mapped_column(Float, default=0.85)  # 0.0 to 1.0
    
    # MITRE ATT&CK Mapping
    mitre_tactic: Mapped[str] = mapped_column(String(64), nullable=True)          # e.g., 'Credential Access'
    mitre_technique_id: Mapped[str] = mapped_column(String(32), nullable=True)    # e.g., 'T1110.001'
    mitre_technique_name: Mapped[str] = mapped_column(String(128), nullable=True) # e.g., 'Password Guessing'
    
    # Matching Criteria
    event_category: Mapped[str] = mapped_column(String(64), nullable=False)
    filter_criteria: Mapped[str] = mapped_column(Text, default="{}")    # JSON query criteria
    window_seconds: Mapped[int] = mapped_column(Integer, default=60)     # Correlation sliding window
    threshold: Mapped[int] = mapped_column(Integer, default=1)           # Trigger threshold
    
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[str] = mapped_column(String(16), default="1.0.0")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    incidents: Mapped[list["Incident"]] = relationship(back_populates="rule")  # noqa: F821
