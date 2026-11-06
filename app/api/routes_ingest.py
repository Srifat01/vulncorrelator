from typing import Annotated, Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Response, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.api.deps import require_api_key
from app.config import get_settings
from app.database import get_db
from app.models import ReportStatus, ScanReport
from app.parsers import ParseError
from app.schemas import ReportIn, ReportOut
from app.services.ingest import run_report
from app.services.queue import enqueue_report, get_queue

router = APIRouter(tags=["ingest"], dependencies=[Depends(require_api_key)])


def _submit(
    db: Session,
    response: Response,
    *,
    source: str,
    fmt: str,
    raw: str,
    async_mode: bool,
    internet_facing: bool | None,
) -> ScanReport:
    queue = get_queue() if async_mode else None
    if async_mode and queue is None:
        raise HTTPException(503, "background ingestion unavailable: Redis is not configured")

    report = ScanReport(
        source=source,
        format=fmt,
        status=ReportStatus.pending.value,
        internet_facing=internet_facing,
        raw_payload=raw,
    )
    db.add(report)
    db.commit()

    if queue is not None:
        enqueue_report(queue, report.id)
        response.status_code = 202
        return report
    try:
        return run_report(db, report.id)
    except ParseError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.post("/ingest", response_model=ReportOut)
def ingest_json(
    payload: ReportIn,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    async_mode: Annotated[bool, Query(description="Queue for the background worker; returns 202")] = False,
    internet_facing: Annotated[bool | None, Query(description="Override for hosts that don't set it")] = None,
):
    """Ingest a pre-normalized report (see README for the schema)."""
    return _submit(
        db,
        response,
        source=payload.source,
        fmt="json",
        raw=payload.model_dump_json(),
        async_mode=async_mode,
        internet_facing=internet_facing,
    )


@router.post("/ingest/upload", response_model=ReportOut)
async def ingest_upload(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    file: Annotated[UploadFile, File(description="Nmap -oX XML or .nessus file")],
    format: Annotated[Literal["nmap", "nessus"], Form()],
    async_mode: Annotated[bool, Form()] = False,
    internet_facing: Annotated[bool | None, Form()] = None,
):
    """Upload a native scanner report; it is parsed and normalized server-side."""
    limit = get_settings().max_upload_mb * 1024 * 1024
    data = await file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(413, f"file exceeds {get_settings().max_upload_mb} MB limit")
    try:
        raw = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(422, "file must be UTF-8 encoded") from exc
    # Blocking work (DB + XML parsing) runs in a thread so the event loop stays free.
    return await run_in_threadpool(
        _submit,
        db,
        response,
        source=format,
        fmt=format,
        raw=raw,
        async_mode=async_mode,
        internet_facing=internet_facing,
    )


@router.get("/reports", response_model=list[ReportOut])
def list_reports(
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    q = select(ScanReport).order_by(ScanReport.id.desc()).limit(limit).offset(offset)
    return db.scalars(q).all()


@router.get("/reports/{report_id}", response_model=ReportOut)
def get_report(report_id: int, db: Annotated[Session, Depends(get_db)]):
    report = db.get(ScanReport, report_id)
    if report is None:
        raise HTTPException(404, "report not found")
    return report
