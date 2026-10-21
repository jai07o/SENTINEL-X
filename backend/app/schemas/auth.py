from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field


class RoleResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    permissions: str

    class Config:
        from_attributes = True


class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    email: str = Field(..., max_length=120)
    full_name: Optional[str] = None


class UserCreate(UserBase):
    password: str = Field(..., min_length=8)
    role_name: str = "analyst"  # admin, analyst, viewer


class UserLogin(BaseModel):
    username: str
    password: str


class UserResponse(UserBase):
    id: str
    is_active: bool
    role: RoleResponse
    created_at: datetime
    last_login: Optional[datetime] = None

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class TokenPayload(BaseModel):
    sub: str
    username: str
    role: str
    exp: int


class ApiKeyCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    expires_days: Optional[int] = 30


class ApiKeyResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    raw_api_key: Optional[str] = None  # Returned only upon initial creation
    created_at: datetime
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None

    class Config:
        from_attributes = True
