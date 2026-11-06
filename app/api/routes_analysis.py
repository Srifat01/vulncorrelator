from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import require_api_key
from app.database import get_db
from app.models import Asset, Vulnerability
from app.schemas import ChainOut, StatsOut, VulnerabilityOut
from app.services.cache import get_cache
from app.services.chains import compute_chains

router = APIRouter(tags=["analysis"], dependencies=[Depends(require_api_key)])


def cached_chains(db: Session) -> list[dict]:
    cache = get_cache()
    chains = cache.get("chains")
    if chains is None:
        chains = compute_chains(db)
        cache.set("chains", chains)
    return chains


@router.get("/vulnerabilities", response_model=list[VulnerabilityOut])
def list_vulnerabilities(
    db: Annotated[Session, Depends(get_db)],
    min_risk: Annotated[float | None, Query(ge=0, le=10)] = None,
    severity: str | None = None,
    cve_id: str | None = None,
    kev_only: bool = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 10,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    """Network-wide view, highest risk first. The default limit of 10 is the 'top 10'."""
    q = select(Vulnerability)
    if min_risk is not None:
        q = q.where(Vulnerability.risk_score >= min_risk)
    if severity:
        q = q.where(Vulnerability.severity == severity.lower())
    if cve_id:
        q = q.where(Vulnerability.cve_id == cve_id.upper())
    if kev_only:
        q = q.where(Vulnerability.in_kev.is_(True))
    q = q.order_by(Vulnerability.risk_score.desc(), Vulnerability.id).limit(limit).offset(offset)
    return db.scalars(q).all()


@router.get("/chains", response_model=list[ChainOut])
def list_chains(
    db: Annotated[Session, Depends(get_db)],
    min_risk: Annotated[float, Query(ge=0, le=10)] = 0,
    asset_id: int | None = None,
    rule: str | None = None,
):
    """High-risk attack chains with an explanation of why each was flagged."""
    chains = [c for c in cached_chains(db) if c["risk_score"] >= min_risk]
    if asset_id is not None:
        chains = [c for c in chains if any(a["id"] == asset_id for a in c["assets"])]
    if rule:
        chains = [c for c in chains if c["rule"] == rule]
    return chains


@router.get("/chains/{chain_id}", response_model=ChainOut)
def get_chain(chain_id: str, db: Annotated[Session, Depends(get_db)]):
    for c in cached_chains(db):
        if c["id"] == chain_id:
            return c
    raise HTTPException(404, "chain not found (chain ids change when the underlying findings change)")


@router.get("/stats", response_model=StatsOut)
def stats(db: Annotated[Session, Depends(get_db)]):
    by_sev = dict(db.execute(select(Vulnerability.severity, func.count()).group_by(Vulnerability.severity)).all())
    chains = cached_chains(db)
    return StatsOut(
        assets=db.scalar(select(func.count(Asset.id))) or 0,
        vulnerabilities=sum(by_sev.values()),
        by_severity={k or "unknown": v for k, v in by_sev.items()},
        known_exploited=db.scalar(select(func.count()).where(Vulnerability.in_kev.is_(True))) or 0,
        chains=len(chains),
        critical_chains=sum(1 for c in chains if c["severity"] == "critical"),
    )
