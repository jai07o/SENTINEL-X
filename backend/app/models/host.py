import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, Integer, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database import Base


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    hostname: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)  # IPv4 or IPv6
    mac_address: Mapped[str] = mapped_column(String(32), nullable=True)
    os_distro: Mapped[str] = mapped_column(String(64), nullable=False)   # Ubuntu, Debian, Kali, Parrot, Fedora
    os_version: Mapped[str] = mapped_column(String(64), nullable=False)
    kernel_version: Mapped[str] = mapped_column(String(128), nullable=True)
    architecture: Mapped[str] = mapped_column(String(32), default="x86_64")
    agent_version: Mapped[str] = mapped_column(String(32), default="1.0.0")
    status: Mapped[str] = mapped_column(String(32), default="ONLINE")  # ONLINE, DEGRADED, OFFLINE
    is_isolated: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_heartbeat: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    collectors: Mapped[list["CollectorHealth"]] = relationship(back_populates="host", cascade="all, delete-orphan")
    events: Mapped[list["NormalizedEvent"]] = relationship(back_populates="host")  # noqa: F821
    incidents: Mapped[list["Incident"]] = relationship(back_populates="host")      # noqa: F821


class CollectorHealth(Base):
    __tablename__ = "collector_health"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    host_id: Mapped[str] = mapped_column(String(36), ForeignKey("hosts.id"), index=True, nullable=False)
    collector_name: Mapped[str] = mapped_column(String(64), nullable=False)  # auth_log, journal, fim, proc, net
    status: Mapped[str] = mapped_column(String(32), default="HEALTHY")       # HEALTHY, WARNING, FAILED, DISABLED
    events_collected: Mapped[int] = mapped_column(Integer, default=0)
    errors_count: Mapped[int] = mapped_column(Integer, default=0)
    last_error_message: Mapped[str] = mapped_column(Text, nullable=True)
    last_heartbeat: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    host: Mapped["Host"] = relationship(back_populates="collectors")
