from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel


class NetworkObservationCreate(BaseModel):
    hostname: str
    source_type: str = "ZEEK_CONN"  # ZEEK_CONN, ZEEK_DNS, LINUX_PROC_NET
    protocol: str = "TCP"
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    service: Optional[str] = None
    duration_seconds: float = 0.0
    bytes_orig: int = 0
    bytes_resp: int = 0
    dns_query: Optional[str] = None
    is_outbound: bool = True


class NetworkObservationResponse(BaseModel):
    id: str
    timestamp: datetime
    host_id: str
    source_type: str
    protocol: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    service: Optional[str] = None
    duration_seconds: float
    bytes_orig: int
    bytes_resp: int
    dns_query: Optional[str] = None
    is_outbound: bool
    is_anomalous: bool
    anomaly_score: float
    anomaly_reason: Optional[str] = None

    class Config:
        from_attributes = True


class NetworkAnomalySummary(BaseModel):
    total_observations: int
    anomalous_observations: int
    top_dst_ports: List[dict]
    top_outbound_ips: List[dict]
    dns_queries_count: int
