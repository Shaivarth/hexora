"""
Centralized configuration. All tunables are read from environment variables
(with sane defaults) so the app can move between dev / VPS / Docker without
code changes.
"""
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent  # backend/


def _bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


class Settings:
    APP_NAME: str = os.getenv("APP_NAME", "Hexora")
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")

    # Storage — kept OUTSIDE any web-served / static directory on purpose.
    STORAGE_DIR: Path = Path(os.getenv("STORAGE_DIR", BASE_DIR / "storage"))
    UPLOAD_DIR: Path = STORAGE_DIR / "uploads"

    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", f"sqlite:///{STORAGE_DIR / 'hexora.db'}"
    )

    # Upload limits
    MAX_UPLOAD_SIZE_MB: int = int(os.getenv("MAX_UPLOAD_SIZE_MB", "100"))
    MAX_UPLOAD_SIZE_BYTES: int = MAX_UPLOAD_SIZE_MB * 1024 * 1024

    # How many bytes of a file we will scan for printable / suspicious
    # strings. Capped so a 5 GB file can't stall a request.
    STRINGS_SCAN_LIMIT_BYTES: int = int(
        os.getenv("STRINGS_SCAN_LIMIT_BYTES", str(8 * 1024 * 1024))
    )

    # CORS
    ALLOWED_ORIGINS: list = os.getenv("ALLOWED_ORIGINS", "*").split(",")

    # Optional lightweight API key gate for write endpoints (off by default
    # for local/demo use — see README for production guidance).
    API_KEY_ENABLED: bool = _bool("API_KEY_ENABLED", False)
    API_KEY: str = os.getenv("API_KEY", "")

    # Pagination defaults
    DEFAULT_PAGE_SIZE: int = int(os.getenv("DEFAULT_PAGE_SIZE", "20"))
    MAX_PAGE_SIZE: int = int(os.getenv("MAX_PAGE_SIZE", "100"))


settings = Settings()
settings.STORAGE_DIR.mkdir(parents=True, exist_ok=True)
settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
