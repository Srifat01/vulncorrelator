import logging

from fastapi import FastAPI
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from app import database
from app.api import routes_analysis, routes_assets, routes_ingest
from app.config import PACKAGE_DIR, get_settings

logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="VulnCorrelator",
    version="1.0.0",
    description="Ingests scanner output, deduplicates and enriches findings, and surfaces high-risk attack chains.",
)
app.include_router(routes_ingest.router)
app.include_router(routes_assets.router)
app.include_router(routes_analysis.router)

# Operator dashboard: a static single-page app that talks to the API above over
# fetch(). Mounted under /ui (not "/") so it never shadows an API path; falls
# back to its own bundled sample data if it can't reach a live backend.
_dashboard_dir = PACKAGE_DIR / "static" / "dashboard"
if _dashboard_dir.is_dir():
    app.mount("/ui", StaticFiles(directory=_dashboard_dir, html=True), name="dashboard")


@app.get("/", include_in_schema=False)
def root():
    """Send browsers to the dashboard; API consumers should use /docs or the endpoints directly."""
    return RedirectResponse(url="/ui/")


@app.get("/health", tags=["meta"])
def health():
    """Liveness/readiness probe (unauthenticated)."""
    checks: dict[str, str] = {}
    try:
        with database.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "error"
    if get_settings().redis_url:
        from app.services.queue import get_queue

        try:
            get_queue().connection.ping()
            checks["redis"] = "ok"
        except Exception:
            checks["redis"] = "error"
    ok = all(v == "ok" for v in checks.values())
    return JSONResponse({"status": "ok" if ok else "degraded", **checks}, status_code=200 if ok else 503)
