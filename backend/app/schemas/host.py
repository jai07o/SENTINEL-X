from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field


class CollectorHealthUpdate(BaseModel):
    collector_name: str
    status: str = "HEALTHY"  # HEALTHY, WARNING, FAILED, DISABLED
    events_collected: int = 0
    errors_count: int = 0
    last_error_message: Optional[str] = None


class CollectorHealthResponse(BaseModel):
    id: str
    collector_name: str
    status: str
    events_collected: int
    errors_count: int
    last_error_message: Optional[str] = None
    last_heartbeat: datetime

    class Config:
        from_attributes = True


class HostCreate(BaseModel):
    hostname: str
    ip_address: str
    mac_address: Optional[str] = None
    os_distro: str  # Ubuntu, Debian, Kali, Parrot, Fedora
    os_version: str
    kernel_version: Optional[str] = None
    architecture: str = "x86_64"
    agent_version: str = "1.0.0"


class HostHeartbeat(BaseModel):
    hostname: str
    ip_address: str
    collectors: List[CollectorHealthUpdate] = []


class HostResponse(BaseModel):
    id: str
    hostname: str
    ip_address: str
    mac_address: Optional[str] = None
    os_distro: str
    os_version: str
    kernel_version: Optional[str] = None
    architecture: str
    agent_version: str
    status: str
    is_isolated: bool
    first_seen: datetime
    last_heartbeat: datetime
    collectors: List[CollectorHealthResponse] = []

    class Config:
        from_attributes = True
