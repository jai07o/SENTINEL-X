from typing import Generic, List, TypeVar, Optional
from pydantic import BaseModel

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    items: List[T]
    total: int
    page: int
    page_size: int
    total_pages: int


class MessageResponse(BaseModel):
    message: str
    status: str = "success"
    details: Optional[dict] = None


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    database_connected: bool
    active_hosts: int
    open_incidents: int
