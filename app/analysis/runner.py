"""Analysis runs: build the graph, score risk, discover attack paths, persist the results.

A run is a stored, inspectable unit of work (status, parameters, statistics, timings), so an expensive computation
can be queued to a worker, retried, audited, and compared with earlier runs. Only *standard* runs (default
reachability semantics, no what-if footholds) update the stored per-vulnerability risk; what-if runs
(`include_hypothetical`, assumed footholds, subnet assumptions) produce paths only.
"""

import logging
import time
from datetime import datetime, timedelta

from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from app import database
from app.config import get_settings
from app.graph.builder import GraphOptions, build_graph
from app.graph.explain import assemble_path
from app.graph.exposure import vulnerability_exposure
from app.graph.paths import PathParams, find_attack_paths
from app.graph.snapshot import load_snapshot
from app.models import AnalysisRun, Asset, AttackPath, IntelSyncRun, Vulnerability, utcnow
from app.risk.config import load_risk_config
from app.risk.model import RiskInputs, compute_risk
from app.services.cache import get_cache
from app.services.meta import get_data_version
from app.services.queue import ANALYSIS_QUEUE, enqueue_analysis, get_queue

log = logging.getLogger(__name__)
RETENTION = 5  # completed runs kept
DEBOUNCE = timedelta(minutes=15)


class AnalysisParams(BaseModel):
    max_steps: int = Field(default=5, ge=1, le=8, description="Maximum transitions (exploit/escalate/pivot) per path")
    max_paths: int = Field(default=500, ge=1, le=5000)
    include_hypothetical: bool = Field(default=False, description="Traverse hypothetical (assumed) links: a what-if")
    assume_subnet_reachability: bool = Field(default=False, description="Add HYPOTHETICAL same-subnet links")
    start_assets: list[int] = Field(default_factory=list, max_length=20, description="Assume these hosts compromised")
    target_asset_ids: list[int] | None = Field(default=None, max_length=50)
    target_min_criticality: int = Field(default=4, ge=1, le=5)
    min_edge_confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    @property
    def is_standard(self) -> bool:
        return not (self.include_hypothetical or self.assume_subnet_reachability or self.start_assets)


def kev_known(db: Session) -> bool:
    """True once the real CISA KEV feed has been synced, i.e. 'not in KEV' is an established fact."""
    return bool(
        db.scalar(
            select(func.count(IntelSyncRun.id)).where(
                IntelSyncRun.source == "kev", IntelSyncRun.status == "success", IntelSyncRun.origin == "live"
            )
        )
    )


def create_run(db: Session, params: AnalysisParams, trigger: str) -> AnalysisRun:
    run = AnalysisRun(status="pending", trigger=trigger, params=params.model_dump())
    db.add(run)
    db.commit()
    return run


def execute_run(db: Session, run_id: int) -> AnalysisRun:
    run = db.get(AnalysisRun, run_id)
    if run is None:
        raise LookupError(f"analysis run {run_id} not found")
    run.status, run.started_at, run.error = "running", utcnow(), None
    run.data_version = get_data_version(db)
    db.commit()
    try:
        _execute(db, run)
        run.status = "completed"
    except Exception as exc:
        db.rollback()
        log.exception("analysis run %s failed", run_id)
        run = db.get(AnalysisRun, run_id)
        run.status, run.error = "failed", f"{type(exc).__name__}: {exc}"[:2000]
    run.finished_at = utcnow()
    db.commit()
    get_cache().invalidate()
    return run


def _execute(db: Session, run: AnalysisRun) -> None:
    t0 = time.perf_counter()
    params, cfg, settings = AnalysisParams(**run.params), load_risk_config(), get_settings()
    snap = load_snapshot(db)
    built = build_graph(snap, GraphOptions(assume_subnet_reachability=params.assume_subnet_reachability))
    graph = built.graph
    assets = {a.id: a for a in snap.assets}
    kev_ok = kev_known(db)

    def inputs(v, relevance: str) -> RiskInputs:
        level, _ = vulnerability_exposure(graph, f"vuln:{v.id}")
        a = assets[v.asset_id]
        return RiskInputs(
            cvss_score=v.cvss_score,
            cvss_vector=v.cvss_vector,
            cvss_source=None,
            epss=v.epss,
            in_kev=v.in_kev,
            kev_known=kev_ok,
            asset_criticality=a.criticality,
            exposure_level=level,
            controls=a.controls,
            path_relevance=relevance,
        )

    # phase 1: per-finding threat (independent of path position); path scoring uses it
    live = [v for v in snap.vulns if v.asset_id in assets]
    for v in live:
        graph.node(f"vuln:{v.id}").attrs["threat"] = compute_risk(inputs(v, "not_on_path"), cfg).threat

    pp = PathParams(
        max_steps=params.max_steps,
        max_paths=params.max_paths,
        max_expansions=settings.path_max_expansions,
        include_hypothetical=params.include_hypothetical,
        min_edge_confidence=params.min_edge_confidence,
        start_internet=True,
        start_assets=params.start_assets,
        target_asset_ids=params.target_asset_ids,
        target_min_criticality=params.target_min_criticality,
    )
    found = find_attack_paths(graph, pp)

    # phase 2: final risk including attack-path relevance (standard runs only)
    scored = 0
    if params.is_standard:
        selected = {t.vuln.attrs["vuln_id"] for f in found.paths for t in f.transitions if t.vuln}
        alts = {a.attrs["vuln_id"] for f in found.paths for t in f.transitions for a in t.alternatives}
        rows = []
        for v in live:
            rel = "reaches_target" if v.id in selected else "on_attack_path" if v.id in alts else "not_on_path"
            r = compute_risk(inputs(v, rel), cfg)
            graph.node(f"vuln:{v.id}").attrs["risk_score"] = r.score
            rows.append(
                {
                    "id": v.id,
                    "risk_score": r.score,
                    "risk_band": r.band,
                    "risk_model_version": cfg.version,
                    "risk_components": r.components,
                }
            )
        if rows:
            db.execute(update(Vulnerability), rows)
        scored = len(rows)

    paths = [
        assemble_path(graph, f, cfg, pp, now=utcnow(), stale_days=settings.stale_evidence_days) for f in found.paths
    ]
    paths.sort(key=lambda p: (-p["priority_score"], -p["confidence"], p["path_id"]))
    for rank, p in enumerate(paths, 1):
        p["rank"], p["run_id"] = rank, run.id
        db.add(
            AttackPath(
                run_id=run.id,
                path_id=p["path_id"],
                score=p["priority_score"],
                confidence=p["confidence"],
                evidence_status=p["evidence_status"],
                entry_label=p["entry"]["label"][:120],
                target_asset_id=p["target_asset_id"],
                data=p,
            )
        )
    run.paths_count = len(paths)
    run.stats = {
        "graph": built.stats,
        "warnings": built.warnings
        + (["path search hit its work budget; results are incomplete"] if found.truncated else []),
        "search": {
            "expansions": found.expansions,
            "truncated": found.truncated,
            "pruned_dominated_paths": found.pruned_dominated,
            "target_mode": found.target_mode,
            "target_assets": found.target_assets,
        },
        "risk": {
            "updated": params.is_standard,
            "vulnerabilities_scored": scored,
            "model_version": cfg.version,
            "config_hash": cfg.config_hash(),
        },  # fmt: skip
        "duration_ms": round((time.perf_counter() - t0) * 1000, 1),
    }
    db.flush()
    _prune(db)


def _prune(db: Session) -> None:
    keep = db.scalars(
        select(AnalysisRun.id).where(AnalysisRun.status == "completed").order_by(AnalysisRun.id.desc()).limit(RETENTION)
    ).all()
    if len(keep) < RETENTION:
        return
    cutoff = min(keep)
    old = select(AnalysisRun.id).where(AnalysisRun.id < cutoff, AnalysisRun.status.in_(["completed", "failed"]))
    db.execute(delete(AttackPath).where(AttackPath.run_id.in_(old)))
    db.execute(delete(AnalysisRun).where(AnalysisRun.id < cutoff, AnalysisRun.status.in_(["completed", "failed"])))


def execute_run_job(run_id: int) -> None:
    """RQ entry point."""
    with database.SessionLocal() as db:
        execute_run(db, run_id)


def latest_completed(db: Session) -> AnalysisRun | None:
    return db.scalar(select(AnalysisRun).where(AnalysisRun.status == "completed").order_by(AnalysisRun.id.desc()))


def is_stale(db: Session, run: AnalysisRun | None) -> bool:
    return run is None or run.data_version is None or run.data_version < get_data_version(db)


def request_analysis(
    db: Session, trigger: str, params: AnalysisParams | None = None, async_mode: bool | None = None
) -> AnalysisRun:
    """Queue (or run inline) an analysis. Automatic triggers (no explicit params) coalesce onto an active run."""
    if params is None:
        active = db.scalar(
            select(AnalysisRun)
            .where(AnalysisRun.status.in_(["pending", "running"]), AnalysisRun.created_at > utcnow() - DEBOUNCE)
            .order_by(AnalysisRun.id.desc())
        )
        if active is not None:
            return active
    run = create_run(db, params or AnalysisParams(), trigger)
    queue = get_queue(ANALYSIS_QUEUE) if async_mode is not False else None
    if queue is not None:
        enqueue_analysis(queue, run.id)
        return run
    return execute_run(db, run.id)


def after_ingest(db: Session, trigger: str = "ingest") -> AnalysisRun | None:
    """Refresh analysis after data changed. Never raises: a failed analysis must not fail an ingestion."""
    try:
        if get_queue(ANALYSIS_QUEUE) is None:
            n_assets = db.scalar(select(func.count(Asset.id))) or 0
            if n_assets > get_settings().inline_analysis_max_assets:
                log.warning(
                    "analysis not run inline (%s assets > limit); POST /analysis/runs or start a worker", n_assets
                )
                return None
        return request_analysis(db, trigger)
    except Exception:
        log.exception("post-ingest analysis failed")
        db.rollback()
        return None


def age_hours(dt: datetime | None) -> float | None:
    if dt is None:
        return None
    return round((utcnow() - (dt if dt.tzinfo else dt.replace(tzinfo=utcnow().tzinfo))).total_seconds() / 3600, 2)
