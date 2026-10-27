import os
from pathlib import Path
from pydantic import field_validator
from pydantic_settings import BaseSettings

_BACKEND_DIR = Path(__file__).resolve().parent

def _resolve_default_db() -> str:
    is_serverless = bool(
        os.getenv("VERCEL")
        or os.getenv("VERCEL_ENV")
        or os.getenv("AWS_LAMBDA_FUNCTION_NAME")
    )
    custom_path = os.getenv("DATABASE_PATH")
    if is_serverless:
        # Vercel serverless filesystem is read-only except /tmp
        if custom_path and custom_path.startswith("/tmp"):
            return custom_path
        return "/tmp/secaudit.db"

    if custom_path:
        return custom_path

    local_db = _BACKEND_DIR / "secaudit.db"
    try:
        test_file = _BACKEND_DIR / ".write_test"
        test_file.touch()
        test_file.unlink()
        return str(local_db)
    except Exception:
        return "/tmp/secaudit.db"

_DEFAULT_DB = _resolve_default_db()
_ENV_FILE = str(_BACKEND_DIR / ".env")

class Settings(BaseSettings):
    APP_NAME: str = "Aura Glass - Autonomous Security Audit"
    VERSION: str = "1.0.0"
    DEBUG: bool = True
    DATABASE_PATH: str = _DEFAULT_DB
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-flash-lite-latest")
    DEMO_MODE: bool = True  # Allows demo targets, custom user links, and local lab testing
    ALLOW_LOCAL_LAB: bool = True  # Izinkan target lab lokal (0.0.0.0, 127.0.0.1, localhost) untuk pengujian mandiri
    DEFAULT_ENTROPY_THRESHOLD: float = 4.2
    AUTH_SECRET_KEY: str = os.getenv("AUTH_SECRET_KEY", "change-this-secret-key-in-production-sha256")
    AUTH_TOKEN_EXPIRE_HOURS: int = 72
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    @field_validator("DATABASE_PATH", mode="after")
    @classmethod
    def validate_database_path(cls, v: str) -> str:
        is_serverless = bool(
            os.getenv("VERCEL")
            or os.getenv("VERCEL_ENV")
            or os.getenv("AWS_LAMBDA_FUNCTION_NAME")
        )
        if is_serverless and not v.startswith("/tmp"):
            return "/tmp/secaudit.db"
        return v

    model_config = {
        "env_file": _ENV_FILE,
        "extra": "ignore",
    }

settings = Settings()
