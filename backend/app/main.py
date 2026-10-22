import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

logger = logging.getLogger("sentinel_x.main")

from backend.app.config import settings
from backend.app.database import engine, Base, AsyncSessionLocal, get_db
from backend.app.core.middleware import SecurityHeadersMiddleware
from backend.app.core.security import hash_password, generate_api_key
from backend.app.models.auth import Role, User, ApiKey
from backend.app.models.rule import DetectionRule
from backend.app.models.host import Host
from backend.app.models.incident import Incident
from backend.app.engine.rules_engine import rules_engine
from backend.app.api.v1.router import api_router
from backend.app.schemas.common import HealthResponse


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application startup and shutdown lifecycle management.
    Initializes database tables, bootstraps default roles and administrator account.
    """
    # 1. Initialize tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # 2. Seed initial roles & admin user if not existing
    async with AsyncSessionLocal() as session:
        # Check roles
        for r_name, r_desc in [
            ("admin", "Full platform administration and containment approval"),
            ("analyst", "Incident triage, investigation, evidence intake, and reporting"),
            ("viewer", "Read-only visibility for security audits"),
        ]:
            r_res = await session.execute(select(Role).where(Role.name == r_name))
            if not r_res.scalar_one_or_none():
                session.add(Role(name=r_name, description=r_desc))
        await session.commit()

        # 3. Synchronize Host-Derived Dynamic Credentials (No Default Passwords)
        from backend.app.core.system_credentials import sync_system_credentials_to_db
        sys_creds = await sync_system_credentials_to_db(session)
        logger.info(
            f"[*] Host-Derived System Credentials: User '{sys_creds['host_username']}' & 'admin' | "
            f"OS: {sys_creds['os_slug']} | Vault: {sys_creds['vault_path']}"
        )

        # Seed default agent API Key if missing
        admin_res = await session.execute(select(User).where(User.username == "admin"))
        admin_user = admin_res.scalar_one_or_none()
        if admin_user:
            dev_key_res = await session.execute(select(ApiKey).where(ApiKey.name == "Default Agent / Testing API Key"))
            if not dev_key_res.scalar_one_or_none():
                raw_key = "sx_dev_agent_key_default"
                import hashlib
                hashed_k = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
                dev_key = ApiKey(
                    name="Default Agent / Testing API Key",
                    key_prefix=raw_key[:10],
                    hashed_key=hashed_k,
                    user_id=admin_user.id,
                    is_active=True,
                )
                session.add(dev_key)
                await session.commit()

        # Seed detection rules
        for r in rules_engine.rules:
            rule_res = await session.execute(select(DetectionRule).where(DetectionRule.rule_id == r["rule_id"]))
            if not rule_res.scalar_one_or_none():
                rule_model = DetectionRule(
                    rule_id=r["rule_id"],
                    name=r["name"],
                    description=r["description"],
                    severity=r["severity"],
                    base_confidence=r.get("base_confidence", 0.85),
                    mitre_tactic=r.get("mitre_tactic"),
                    mitre_technique_id=r.get("mitre_technique_id"),
                    mitre_technique_name=r.get("mitre_technique_name"),
                    event_category=r["event_category"],
                    filter_criteria=str(r.get("filter_criteria", {})),
                    window_seconds=r.get("window_seconds", 60),
                    threshold=r.get("threshold", 1),
                    is_active=r.get("is_active", True),
                    version=r.get("version", "1.0.0"),
                )
                session.add(rule_model)
        # 4. Auto-connect to active local system (laptop/desktop) and register hardware identity
        try:
            from backend.app.services.active_system_service import active_system_guardian
            await active_system_guardian.auto_connect_and_register()
            active_system_guardian.start_realtime_daemon()
        except Exception:
            pass

    yield

    # Shutdown
    try:
        from backend.app.services.active_system_service import active_system_guardian
        await active_system_guardian.stop_daemon()
    except Exception:
        pass
    try:
        from backend.app.services.autonomous_sentinel_service import autonomous_sentinel_service
        await autonomous_sentinel_service.stop()
    except Exception:
        pass
    await engine.dispose()


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Unified Defensive Cybersecurity Detection, Testing, Forensics and Investigation Platform",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Production Security Headers Middleware
app.add_middleware(SecurityHeadersMiddleware)

# Mount API v1 router
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/api/v1/health", response_model=HealthResponse, tags=["Health & Status"])
async def health_check(db: AsyncSession = Depends(get_db)):
    """Operational health check and readiness probe."""
    hosts_res = await db.execute(select(Host))
    hosts = hosts_res.scalars().all()

    incidents_res = await db.execute(select(Incident).where(Incident.status.in_(["New", "Triaged", "Investigating"])))
    open_incidents = incidents_res.scalars().all()

    return HealthResponse(
        status="OPERATIONAL",
        version=settings.VERSION,
        environment=settings.ENV,
        database_connected=True,
        active_hosts=len(hosts),
        open_incidents=len(open_incidents),
    )


from backend.app.services.integrity_service import platform_integrity_sentinel


@app.get("/api/v1/health/integrity", tags=["Health & Status"])
async def verify_platform_integrity():
    """
    Self-Defense & Anti-Tamper Audit.
    Cryptographically verifies SHA-256 integrity of all core platform engine modules.
    Detects if any file in the tool has been modified by malware, an attacker, or a rootkit.
    """
    return platform_integrity_sentinel.audit_integrity()


@app.get("/api/v1/health/security-posture", tags=["Health & Status"])
async def get_platform_security_posture():
    """
    Returns full military-grade operational security posture report of SENTINEL-X.
    Audits self-integrity, transport headers, anti-brute-force state, and hardware shields.
    """
    return platform_integrity_sentinel.get_security_posture_summary()


@app.post("/api/v1/health/integrity/reanchor", tags=["Health & Status"])
async def reanchor_platform_integrity():
    """Re-anchor cryptographic SHA-256 baseline of core modules after an authorized update."""
    platform_integrity_sentinel.rebuild_baseline()
    return {"message": "Cryptographic baseline re-anchored successfully", "status": "success"}


# Mount Production Frontend SPA if compiled dist exists
from fastapi import HTTPException
from fastapi.staticfiles import StaticFiles
from starlette.responses import FileResponse
from backend.app.config import PROJECT_ROOT

FRONTEND_DIST = PROJECT_ROOT / "frontend" / "dist"
if FRONTEND_DIST.exists():
    assets_dir = FRONTEND_DIST / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="static-assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa_frontend(full_path: str):
        if full_path.startswith("api/") or full_path.startswith("docs") or full_path.startswith("redoc") or full_path.startswith("openapi.json"):
            raise HTTPException(status_code=404, detail="Not Found")
        target_file = FRONTEND_DIST / full_path
        if target_file.is_file():
            return FileResponse(str(target_file))
        return FileResponse(str(FRONTEND_DIST / "index.html"))

