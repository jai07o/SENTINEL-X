import pytest
import pytest_asyncio
from typing import AsyncGenerator
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy import select

from backend.app.database import Base, get_db
from backend.app.main import app
from backend.app.models.auth import Role, User
from backend.app.core.security import hash_password, create_access_token

# Test in-memory SQLite database
TEST_DB_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    future=True,
)

TestSessionLocal = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


@pytest_asyncio.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with TestSessionLocal() as session:
        # Seed test roles
        admin_role = Role(name="admin", description="Admin")
        analyst_role = Role(name="analyst", description="Analyst")
        viewer_role = Role(name="viewer", description="Viewer")
        session.add_all([admin_role, analyst_role, viewer_role])
        await session.commit()

        # Seed test users
        admin_user = User(
            username="test_admin",
            email="admin@sentinel-x.org",
            hashed_password=hash_password("AdminPass123!"),
            role_id=admin_role.id,
            is_active=True,
        )
        analyst_user = User(
            username="test_analyst",
            email="analyst@sentinel-x.org",
            hashed_password=hash_password("AnalystPass123!"),
            role_id=analyst_role.id,
            is_active=True,
        )
        session.add_all([admin_user, analyst_user])
        await session.commit()

        yield session

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture(scope="function")
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def admin_token(db_session: AsyncSession) -> str:
    res = await db_session.execute(select(User).where(User.username == "test_admin"))
    user = res.scalar_one()
    return create_access_token({"sub": user.id, "username": user.username, "role": "admin"})


@pytest_asyncio.fixture
async def analyst_token(db_session: AsyncSession) -> str:
    res = await db_session.execute(select(User).where(User.username == "test_analyst"))
    user = res.scalar_one()
    return create_access_token({"sub": user.id, "username": user.username, "role": "analyst"})
