import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app import database
from app.api import (
    routes_admin,
    routes_analysis,
    routes_assets,
    routes_graph,
    routes_ingest,
    routes_intel,
    routes_network,
    routes_paths,
    routes_risk,
)
from app.config import get_settings
from app.security import RequestContextMiddleware

logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="VulnCorrelator",
    version="2.0.0",
    description="Ingests scanner output, deduplicates and enriches findings, and surfaces high-risk attack chains.",
)
app.add_middleware(RequestContextMiddleware)
app.include_router(routes_ingest.router)
app.include_router(routes_assets.router)
app.include_router(routes_analysis.router)
for _r in (routes_paths, routes_graph, routes_network, routes_risk, routes_admin, routes_intel):
    app.include_router(_r.router)


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


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception) -> JSONResponse:
    """Never leak internals; correlate with logs through the request id."""
    rid = getattr(request.state, "request_id", None)
    logging.getLogger("vulncorrelator").exception("unhandled error request_id=%s", rid)
    return JSONResponse(
        {"detail": "internal server error", "request_id": rid},
        status_code=500,
        headers={"X-Request-ID": rid or ""},  # error responses bypass the request-context middleware
    )
