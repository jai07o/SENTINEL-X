from datetime import datetime, timedelta
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from backend.app.database import get_db
from backend.app.config import settings
from backend.app.core.security import (
    verify_password,
    hash_password,
    create_access_token,
    generate_api_key,
)
from backend.app.core.permissions import get_current_user, require_admin
from backend.app.models.auth import User, Role, ApiKey
from backend.app.schemas.auth import (
    UserCreate,
    UserResponse,
    UserLogin,
    Token,
    ApiKeyCreate,
    ApiKeyResponse,
)

router = APIRouter(prefix="/auth", tags=["Authentication & Access Control"])


@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticate user via OAuth2 password form and issue signed JWT.
    """
    result = await db.execute(
        select(User).options(selectinload(User.role)).where(User.username == form_data.username)
    )
    user = result.scalar_one_or_none()

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user account")

    user.last_login = datetime.utcnow()
    await db.commit()

    token_data = {
        "sub": user.id,
        "username": user.username,
        "role": user.role.name if user.role else "viewer",
    }
    access_token = create_access_token(
        data=token_data,
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=user,
    )


@router.post("/register", response_model=UserResponse)
async def register_user(
    user_in: UserCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    Register new analyst or admin. Initial user bootstraps as admin if no users exist.
    """
    # Check if username or email exists
    existing = await db.execute(
        select(User).where((User.username == user_in.username) | (User.email == user_in.email))
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username or email already registered")

    # Check total users count to bootstrap admin
    user_count_res = await db.execute(select(User))
    all_users = user_count_res.scalars().all()
    
    role_to_assign = user_in.role_name
    if len(all_users) == 0:
        role_to_assign = "admin"

    # Fetch role
    role_res = await db.execute(select(Role).where(Role.name == role_to_assign))
    role_obj = role_res.scalar_one_or_none()
    if not role_obj:
        # Create role if missing
        role_obj = Role(name=role_to_assign, description=f"{role_to_assign.capitalize()} role")
        db.add(role_obj)
        await db.flush()

    new_user = User(
        username=user_in.username,
        email=user_in.email,
        full_name=user_in.full_name,
        hashed_password=hash_password(user_in.password),
        role_id=role_obj.id,
        is_active=True,
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    # Reload with role
    user_with_role = await db.execute(
        select(User).options(selectinload(User.role)).where(User.id == new_user.id)
    )
    return user_with_role.scalar_one()


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    """Retrieve authenticated user identity and role permissions."""
    return current_user


@router.post("/api-keys", response_model=ApiKeyResponse)
async def create_api_key(
    key_in: ApiKeyCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate API Key for Agent or Extension authentication."""
    raw_key, prefix, hashed = generate_api_key()
    expires_at = datetime.utcnow() + timedelta(days=key_in.expires_days or 30)

    api_key = ApiKey(
        name=key_in.name,
        key_prefix=prefix,
        hashed_key=hashed,
        user_id=current_user.id,
        expires_at=expires_at,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    response = ApiKeyResponse.from_orm(api_key)
    response.raw_api_key = raw_key
    return response


@router.get("/api-keys", response_model=List[ApiKeyResponse])
async def list_api_keys(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List active API keys belonging to the current user."""
    result = await db.execute(
        select(ApiKey).where(ApiKey.user_id == current_user.id)
    )
    return result.scalars().all()
