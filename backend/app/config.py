from pathlib import Path
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import Field

# Base project directories
BASE_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BASE_DIR.parent
DATA_DIR = PROJECT_ROOT / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
EVIDENCE_DIR = DATA_DIR / "evidence"
REPORTS_DIR = DATA_DIR / "reports"
QUARANTINE_DIR = DATA_DIR / "quarantine"
RULES_DIR = BASE_DIR / "app" / "data"

for directory in (DATA_DIR, UPLOAD_DIR, EVIDENCE_DIR, REPORTS_DIR, QUARANTINE_DIR, RULES_DIR):
    directory.mkdir(parents=True, exist_ok=True)


class Settings(BaseSettings):
    """SENTINEL-X Configuration Settings."""

    PROJECT_NAME: str = "SENTINEL-X Cyber Defense Platform"
    VERSION: str = "0.1.0-alpha"
    API_V1_STR: str = "/api/v1"
    
    # Environment
    ENV: str = Field(default="development", description="development | staging | production")
    DEBUG: bool = Field(default=True)
    
    # Database
    DATABASE_URL: str = Field(
        default=f"sqlite+aiosqlite:///{PROJECT_ROOT}/sentinel_dev.db",
        description="Async SQLAlchemy database connection URL"
    )
    SYNC_DATABASE_URL: str = Field(
        default=f"sqlite:///{PROJECT_ROOT}/sentinel_dev.db",
        description="Sync SQLAlchemy database connection URL for Alembic/scripts"
    )
    
    # Security & JWT
    SECRET_KEY: str = Field(
        default="sentinel-x-super-secure-dev-secret-key-change-in-production-at-all-costs-1337!",
        description="Secret key for signing JWT tokens"
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    
    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:1420",     # Tauri dev default
        "tauri://localhost",
        "chrome-extension://*",
    ]
    
    # Storage Paths
    UPLOAD_PATH: Path = UPLOAD_DIR
    EVIDENCE_PATH: Path = EVIDENCE_DIR
    REPORTS_PATH: Path = REPORTS_DIR
    RULES_PATH: Path = RULES_DIR
    
    # Upload and Analysis Limits
    MAX_UPLOAD_SIZE_MB: int = 50
    ALLOW_DYNAMIC_SANDBOX: bool = False
    
    # AI-Assisted Explanation Settings
    ENABLE_EXTERNAL_AI: bool = False
    AI_PROVIDER: str = "local_mock"  # local_mock | ollama | openai_compatible
    AI_ENDPOINT: Optional[str] = None
    AI_API_KEY: Optional[str] = None
    AI_MODEL: str = "sentinel-defensive-llm-v1"

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


settings = Settings()
