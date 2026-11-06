"""Application settings, loaded from environment variables (or a .env file)."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

PACKAGE_DIR = Path(__file__).resolve().parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./vulncorrelator.db"
    # Redis is optional: without it the API still works, caching is a no-op and
    # async ingestion is unavailable (requests for it get a 503).
    redis_url: str | None = None
    cache_ttl_seconds: int = 60
    # When set, every request except /health must send "X-API-Key: <value>".
    api_key: str | None = None
    max_upload_mb: int = 20
    # Directory holding kev.json / epss.json / cve_catalog.json.
    intel_dir: Path = PACKAGE_DIR / "data"


def normalize_db_url(url: str) -> str:
    """Pin the Postgres driver to psycopg2 (SQLAlchemy 2.1+ would otherwise default to psycopg3)."""
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            return "postgresql+psycopg2://" + url[len(prefix) :]
    return url


@lru_cache
def get_settings() -> Settings:
    return Settings()
