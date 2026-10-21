import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Any
import jwt
import bcrypt
from backend.app.config import settings


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


def create_access_token(
    data: dict, expires_delta: Optional[timedelta] = None
) -> str:
    """Create a signed JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> dict:
    """Decode and validate a JWT access token."""
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])


def generate_api_key() -> tuple[str, str, str]:
    """
    Generate a secure random API key.
    Returns: (raw_key, key_prefix, hashed_key)
    """
    raw_secret = secrets.token_urlsafe(32)
    raw_key = f"sx_{raw_secret}"
    key_prefix = raw_key[:10]
    hashed_key = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    return raw_key, key_prefix, hashed_key


def verify_api_key(raw_key: str, hashed_key: str) -> bool:
    """Verify a raw API key against its SHA-256 hash."""
    calculated = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    return secrets.compare_digest(calculated, hashed_key)
