import os
from pathlib import Path
from pydantic_settings import BaseSettings

_BACKEND_DIR = Path(__file__).resolve().parent
_DEFAULT_DB = "/tmp/secaudit.db" if os.getenv("VERCEL") == "1" else str(_BACKEND_DIR / "secaudit.db")
_ENV_FILE = str(_BACKEND_DIR / ".env")

class Settings(BaseSettings):
    APP_NAME: str = "Aura Glass - Autonomous Security Audit"
    VERSION: str = "1.0.0"
    DEBUG: bool = True
    DATABASE_PATH: str = os.getenv("DATABASE_PATH", _DEFAULT_DB)
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-flash-lite-latest")
    DEMO_MODE: bool = True  # Allows demo targets, custom user links, and local lab testing
    ALLOW_LOCAL_LAB: bool = True  # Izinkan target lab lokal (0.0.0.0, 127.0.0.1, localhost) untuk pengujian mandiri
    DEFAULT_ENTROPY_THRESHOLD: float = 4.2
    AUTH_SECRET_KEY: str = os.getenv("AUTH_SECRET_KEY", "change-this-secret-key-in-production-sha256")
    AUTH_TOKEN_EXPIRE_HOURS: int = 72
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    model_config = {
        "env_file": _ENV_FILE,
        "extra": "ignore",
    }

settings = Settings()
