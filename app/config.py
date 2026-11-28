"""Application settings, loaded from environment variables, a .env file or Docker secrets."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

PACKAGE_DIR = Path(__file__).resolve().parent
_SECRETS_DIR = "/run/secrets" if Path("/run/secrets").is_dir() else None


class Settings(BaseSettings):
    """Every secret (API keys, passwords) comes from the environment or /run/secrets - never from code."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", secrets_dir=_SECRETS_DIR)

    database_url: str = "sqlite:///./vulncorrelator.db"
    redis_url: str | None = None
    cache_ttl_seconds: int = 60

    # ---- authentication / authorization
    api_key: str | None = None  # role "admin": full access
    readonly_api_key: str | None = None  # role "reader": GET only
    # Secure default: with no key configured the API refuses requests. Opt out explicitly for local dev.
    auth_disabled: bool = False

    # ---- request limits (resource-exhaustion protection)
    max_upload_mb: int = 20
    max_request_body_mb: int = 25
    max_findings_per_host: int = 5000
    max_xml_elements: int = 3_000_000
    rate_limit_enabled: bool = True
    rate_limit_default_per_min: int = 240
    rate_limit_ingest_per_min: int = 20
    rate_limit_analysis_per_min: int = 12

    # ---- analysis
    inline_analysis_max_assets: int = 300  # larger estates are analysed by the worker only
    path_max_expansions: int = 200_000
    stale_evidence_days: int = 30
    risk_model_config_path: Path | None = None

    # ---- worker reliability
    stuck_report_minutes: int = 30
    max_report_attempts: int = 3

    # ---- threat intelligence
    intel_demo_data: bool = False  # load the bundled *demonstration* CVE catalog (clearly labelled origin=demo)
    intel_dir: Path = PACKAGE_DIR / "data"
    intel_live_sync: bool = True  # set false for air-gapped deployments
    nvd_api_key: str | None = None
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    epss_base_url: str = "https://api.first.org/data/v1/epss"
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    intel_http_timeout: float = 20.0
    intel_max_retries: int = 4
    intel_sync_interval_hours: int = 24
    kev_ttl_hours: int = 48
    epss_ttl_hours: int = 48
    nvd_ttl_hours: int = 24 * 7
    cpe_lookup_ttl_hours: int = 24 * 7


def normalize_db_url(url: str) -> str:
    """Pin the Postgres driver to psycopg2 (SQLAlchemy 2.1+ would otherwise default to psycopg3)."""
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            return "postgresql+psycopg2://" + url[len(prefix) :]
    return url


@lru_cache
def get_settings() -> Settings:
    return Settings()
