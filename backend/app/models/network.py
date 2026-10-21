import uuid
from datetime import datetime
from sqlalchemy import String, Integer, Float, DateTime, Boolean, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database import Base


class NetworkObservation(Base):
    __tablename__ = "network_observations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    host_id: Mapped[str] = mapped_column(String(36), ForeignKey("hosts.id"), index=True, nullable=False)
    
    source_type: Mapped[str] = mapped_column(String(32), default="ZEEK_CONN") # ZEEK_CONN, ZEEK_DNS, LINUX_PROC_NET
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)        # TCP, UDP, ICMP
    
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    src_port: Mapped[int] = mapped_column(Integer, nullable=False)
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    dst_port: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    service: Mapped[str] = mapped_column(String(32), nullable=True)          # http, ssh, dns, ssl, unknown
    
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    bytes_orig: Mapped[int] = mapped_column(Integer, default=0)
    bytes_resp: Mapped[int] = mapped_column(Integer, default=0)
    dns_query: Mapped[str] = mapped_column(String(255), nullable=True, index=True)
    
    # Baseline Anomaly Scoring
    is_outbound: Mapped[bool] = mapped_column(Boolean, default=True)
    is_anomalous: Mapped[bool] = mapped_column(Boolean, default=False)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0)         # 0.0 to 1.0 (statistical outlier deviation)
    anomaly_reason: Mapped[str] = mapped_column(String(255), nullable=True)

    host: Mapped["Host"] = relationship() # noqa: F821

    __table_args__ = (
        Index("ix_net_host_time", "host_id", "timestamp"),
        Index("ix_net_dst_port", "dst_ip", "dst_port"),
    )
