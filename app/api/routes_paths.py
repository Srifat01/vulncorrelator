from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.analysis.runner import AnalysisParams, is_stale, latest_completed, request_analysis
from app.database import get_db
from app.graph.schemas import PathList, PathOut
from app.models import AnalysisRun, AttackPath
from app.risk.config import load_risk_config
from app.schemas import ORMModel
from app.security import audit_action, authorize
from app.services.meta import get_data_version
from app.services.queue import ANALYSIS_QUEUE, get_queue

router = APIRouter(tags=["attack-paths"], dependencies=[Depends(authorize)])


class RunOut(ORMModel):
    id: int
    status: str
    trigger: str
    params: dict
    data_version: int | None
    paths_count: int
    stats: dict
    error: str | None
    created_at: object
    started_at: object | None
    finished_at: object | None


@router.post("/analysis/runs", response_model=RunOut)
def start_analysis(
    request: Request,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    params: AnalysisParams | None = None,
    async_mode: Annotated[
        bool | None, Query(description="true=queue (503 if no worker), false=inline, unset=auto")
    ] = None,
):
    """Build the graph, re-score vulnerabilities and discover attack paths. Queued to the worker when one exists."""
    if async_mode and get_queue(ANALYSIS_QUEUE) is None:
        raise HTTPException(503, "background analysis unavailable: Redis is not configured")
    run = request_analysis(db, "api", params or AnalysisParams(), async_mode)
    audit_action(request, request.state.principal, "analysis.start", f"run:{run.id}", detail=run.params)
    response.status_code = 202 if run.status in ("pending", "running") else 200
    return run


@router.get("/analysis/runs", response_model=list[RunOut])
def list_runs(
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    return db.scalars(select(AnalysisRun).order_by(AnalysisRun.id.desc()).limit(limit).offset(offset)).all()


@router.get("/analysis/runs/{run_id}", response_model=RunOut)
def get_run(run_id: int, db: Annotated[Session, Depends(get_db)]):
    run = db.get(AnalysisRun, run_id)
    if run is None:
        raise HTTPException(404, "analysis run not found")
    return run


@router.get("/analysis/status")
def analysis_status(db: Annotated[Session, Depends(get_db)]):
    """Is the stored analysis current? Reports staleness against the data version, and the active risk model."""
    run, cfg = latest_completed(db), load_risk_config()
    return {
        "latest_completed_run": RunOut.model_validate(run).model_dump(mode="json") if run else None,
        "current_data_version": get_data_version(db),
        "stale": is_stale(db, run),
        "risk_model": {"name": cfg.name, "version": cfg.version, "config_hash": cfg.config_hash()},
        "background_worker_available": get_queue(ANALYSIS_QUEUE) is not None,
    }


def _run_or_404(db: Session, run_id: int | None) -> AnalysisRun | None:
    if run_id is None:
        return latest_completed(db)
    run = db.get(AnalysisRun, run_id)
    if run is None:
        raise HTTPException(404, "analysis run not found")
    return run


@router.get("/attack-paths", response_model=PathList)
def list_attack_paths(
    db: Annotated[Session, Depends(get_db)],
    run_id: Annotated[int | None, Query(description="default: latest completed run")] = None,
    min_score: Annotated[float, Query(ge=0, le=10)] = 0,
    min_confidence: Annotated[float, Query(ge=0, le=1)] = 0,
    evidence_status: Literal["confirmed", "observed", "partially_inferred", "hypothetical"] | None = None,
    target_asset_id: int | None = None,
    asset_id: Annotated[int | None, Query(description="paths that touch this asset")] = None,
    entry: Literal["internet", "assumed_foothold"] | None = None,
    cve: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    """Ranked attack paths from a stored analysis run. Evidence class and confidence are reported per path."""
    run = _run_or_404(db, run_id)
    if run is None:
        return PathList(run=None, stale=True, total=0, limit=limit, offset=offset, items=[])
    q = select(AttackPath).where(AttackPath.run_id == run.id, AttackPath.score >= min_score)
    q = q.where(AttackPath.confidence >= min_confidence)
    if evidence_status:
        q = q.where(AttackPath.evidence_status == evidence_status)
    if target_asset_id is not None:
        q = q.where(AttackPath.target_asset_id == target_asset_id)
    if entry:
        q = (
            q.where(AttackPath.entry_label == "internet")
            if entry == "internet"
            else q.where(AttackPath.entry_label != "internet")
        )
    order = (AttackPath.score.desc(), AttackPath.confidence.desc(), AttackPath.path_id)
    python_filtered = asset_id is not None or cve is not None
    if python_filtered:  # JSON contents are filtered in Python; bounded by the run's max_paths (<= 5000)
        rows = [r.data for r in db.scalars(q.order_by(*order)).all()]
        if asset_id is not None:
            rows = [p for p in rows if any(s["asset_id"] == asset_id for s in p["steps"])]
        if cve:
            rows = [p for p in rows if cve.upper() in p["cves"]]
        total, items = len(rows), rows[offset : offset + limit]
    else:
        total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
        items = [r.data for r in db.scalars(q.order_by(*order).limit(limit).offset(offset)).all()]
    return PathList(
        run=RunOut.model_validate(run).model_dump(mode="json"),
        stale=is_stale(db, run),
        total=total,
        limit=limit,
        offset=offset,
        items=items,
    )


@router.get("/attack-paths/{path_id}", response_model=PathOut)
def get_attack_path(path_id: str, db: Annotated[Session, Depends(get_db)], run_id: int | None = None):
    """One path with its full explanation. Path ids are stable across runs while the underlying evidence is."""
    q = select(AttackPath).where(AttackPath.path_id == path_id)
    q = q.where(AttackPath.run_id == run_id) if run_id else q.order_by(AttackPath.run_id.desc())
    row = db.scalars(q).first()
    if row is None:
        raise HTTPException(404, "attack path not found (ids change when the underlying evidence changes)")
    return row.data
