from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.intel.jobs import enqueue_sync
from app.intel.status import cve_view, intel_status
from app.intel.sync import SOURCES, build_clients, sync_all
from app.models import IntelSyncRun
from app.schemas import ORMModel
from app.security import audit_action, authorize
from app.services.intel import CVE_RE
from app.services.queue import INTEL_QUEUE, get_queue

router = APIRouter(tags=["intel"], dependencies=[Depends(authorize)])


class SyncRunOut(ORMModel):
    id: int
    source: str
    status: str
    origin: str
    started_at: datetime
    finished_at: datetime | None
    records_seen: int
    records_updated: int
    error: str | None
    watermark: dict


class SyncRequest(BaseModel):
    sources: list[Literal["kev", "epss", "nvd", "cpe"]] = Field(default_factory=lambda: list(SOURCES), min_length=1)
    force: bool = Field(default=False, description="ignore freshness windows and refetch")


@router.get("/intel/status")
def status(db: Annotated[Session, Depends(get_db)]):
    """Freshness of every intelligence source, coverage, and what kind of data (live/cached/demo/missing) we hold."""
    return intel_status(db)


@router.get("/intel/cves/{cve_id}")
def cve(
    cve_id: str,
    db: Annotated[Session, Depends(get_db)],
    history_limit: Annotated[int, Query(ge=0, le=500)] = 50,
):
    """Everything known about one CVE, per source, with attribution, age, data class, and value history."""
    if not CVE_RE.fullmatch(cve_id):
        raise HTTPException(422, "not a CVE id")
    view = cve_view(db, cve_id, history_limit=history_limit)
    if view is None:
        raise HTTPException(404, "no intelligence held for this CVE")
    return view


@router.get("/intel/sync-runs", response_model=list[SyncRunOut])
def sync_runs(
    db: Annotated[Session, Depends(get_db)],
    source: Literal["kev", "epss", "nvd", "cpe"] | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 30,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    q = select(IntelSyncRun)
    if source:
        q = q.where(IntelSyncRun.source == source)
    return db.scalars(q.order_by(IntelSyncRun.id.desc()).limit(limit).offset(offset)).all()


@router.post("/intel/sync", response_model=None)
def trigger_sync(
    body: SyncRequest,
    request: Request,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    async_mode: Annotated[
        bool | None, Query(description="true=queue, false=inline, unset=queue if a worker exists")
    ] = None,
):
    """Fetch fresh intelligence. Queued for the worker when one exists; otherwise runs inline (can be slow)."""
    if not get_settings().intel_live_sync:
        raise HTTPException(409, "live intelligence sync is disabled (INTEL_LIVE_SYNC=false)")
    has_worker = get_queue(INTEL_QUEUE) is not None
    if async_mode and not has_worker:
        raise HTTPException(503, "background sync unavailable: Redis is not configured")
    audit_action(request, request.state.principal, "intel.sync", detail=body.model_dump())
    if has_worker and async_mode is not False:
        enqueue_sync(body.sources, body.force)
        response.status_code = 202
        return {"queued": True, "sources": body.sources}
    clients = build_clients()
    try:
        runs = sync_all(db, clients, tuple(body.sources), force=body.force)
    finally:
        clients.close()
    return {"queued": False, "runs": [SyncRunOut.model_validate(r).model_dump(mode="json") for r in runs]}
