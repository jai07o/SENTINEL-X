import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, Integer, Float, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database import Base


class AssessmentProject(Base):
    __tablename__ = "assessment_projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_code: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False) # e.g., 'ASSESS-2026-01'
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    created_by_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)

    creator: Mapped["User"] = relationship() # noqa: F821
    target_scopes: Mapped[list["TargetScope"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )
    findings: Mapped[list["VulnerabilityFinding"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class TargetScope(Base):
    __tablename__ = "target_scopes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("assessment_projects.id"), index=True, nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False) # Domain, CIDR, or URL (e.g., 'testphp.vulnweb.com', '192.168.1.100')
    target_type: Mapped[str] = mapped_column(String(32), default="DOMAIN") # DOMAIN, IP_RANGE, SINGLE_IP, URL
    
    # Scope Authorization Records (MANDATORY)
    owner_organization: Mapped[str] = mapped_column(String(255), nullable=False)
    authorization_reference: Mapped[str] = mapped_column(String(128), nullable=False) # Contract or ROE document ref
    approved_by: Mapped[str] = mapped_column(String(128), nullable=False)
    valid_from: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False) # Strict expiration gate
    
    # Allowed Testing Constraints
    allowed_methods: Mapped[str] = mapped_column(Text, default='["HTTP_HEADERS", "TLS_CIPHERS", "PORT_SCAN_SAFE", "VERSION_AUDIT"]')
    excluded_targets: Mapped[str] = mapped_column(Text, default="[]") # JSON list of subnets/paths to strictly exclude
    rate_limit_rps: Mapped[int] = mapped_column(Integer, default=5) # Maximum safe requests per second
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    project: Mapped["AssessmentProject"] = relationship(back_populates="target_scopes")


class VulnerabilityFinding(Base):
    __tablename__ = "vulnerability_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False) # e.g., 'VULN-2026-0042'
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("assessment_projects.id"), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    
    severity: Mapped[str] = mapped_column(String(20), default="MEDIUM", index=True) # INFO, LOW, MEDIUM, HIGH, CRITICAL
    cvss_score: Mapped[float] = mapped_column(Float, default=5.0)
    confidence: Mapped[float] = mapped_column(Float, default=0.90)
    
    owasp_category: Mapped[str] = mapped_column(String(128), nullable=True) # e.g., 'WSTG-CONF-07: Testing HTTP Strict Transport Security'
    cwe_id: Mapped[str] = mapped_column(String(32), nullable=True)          # e.g., 'CWE-319'
    
    description: Mapped[Text] = mapped_column(Text, nullable=False)
    evidence_data: Mapped[Text] = mapped_column(Text, nullable=True)        # Sanitized HTTP response or banner
    remediation: Mapped[Text] = mapped_column(Text, nullable=False)
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    project: Mapped["AssessmentProject"] = relationship(back_populates="findings")
