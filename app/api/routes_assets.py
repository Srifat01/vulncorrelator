from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import require_api_key
from app.database import get_db
from app.models import Asset, Service, Vulnerability
from app.schemas import AssetOut, AssetPatch, ServiceOut, VulnerabilityOut
from app.services.cache import get_cache

router = APIRouter(tags=["assets"], dependencies=[Depends(require_api_key)])

Limit = Annotated[int, Query(ge=1, le=500)]
Offset = Annotated[int, Query(ge=0)]


def _asset_out(asset: Asset, count: int, max_risk: float | None) -> AssetOut:
    out = AssetOut.model_validate(asset)
    out.vulnerability_count, out.max_risk_score = count, max_risk
    return out


def _get_asset(db: Session, asset_id: int) -> Asset:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(404, "asset not found")
    return asset


@router.get("/assets", response_model=list[AssetOut])
def list_assets(
    db: Annotated[Session, Depends(get_db)],
    internet_facing: bool | None = None,
    min_risk: Annotated[float | None, Query(ge=0, le=10)] = None,
    limit: Limit = 50,
    offset: Offset = 0,
):
    """Assets with their vulnerability count and highest risk score, riskiest first."""
    max_risk = func.max(Vulnerability.risk_score)
    q = (
        select(Asset, func.count(Vulnerability.id), max_risk)
        .outerjoin(Vulnerability, Vulnerability.asset_id == Asset.id)
        .group_by(Asset.id)
        .order_by(max_risk.desc().nulls_last(), Asset.id)
        .limit(limit)
        .offset(offset)
    )
    if internet_facing is not None:
        q = q.where(Asset.internet_facing == internet_facing)
    if min_risk is not None:
        q = q.having(max_risk >= min_risk)
    return [_asset_out(a, c, m) for a, c, m in db.execute(q)]


@router.get("/assets/{asset_id}", response_model=AssetOut)
def get_asset(asset_id: int, db: Annotated[Session, Depends(get_db)]):
    asset = _get_asset(db, asset_id)
    count, max_risk = db.execute(
        select(func.count(Vulnerability.id), func.max(Vulnerability.risk_score)).where(
            Vulnerability.asset_id == asset_id
        )
    ).one()
    return _asset_out(asset, count, max_risk)


@router.patch("/assets/{asset_id}", response_model=AssetOut)
def patch_asset(asset_id: int, patch: AssetPatch, db: Annotated[Session, Depends(get_db)]):
    """Override scanner/heuristic data, e.g. mark a host as internet-facing (changes chains)."""
    asset = _get_asset(db, asset_id)
    for field, value in patch.model_dump(exclude_unset=True).items():
        if field == "internet_facing" and value is None:
            continue
        setattr(asset, field, value)
    db.commit()
    get_cache().invalidate()
    return get_asset(asset_id, db)


@router.get("/assets/{asset_id}/services", response_model=list[ServiceOut])
def asset_services(asset_id: int, db: Annotated[Session, Depends(get_db)]):
    _get_asset(db, asset_id)
    return db.scalars(select(Service).where(Service.asset_id == asset_id).order_by(Service.port)).all()


@router.get("/assets/{asset_id}/vulnerabilities", response_model=list[VulnerabilityOut])
def asset_vulnerabilities(
    asset_id: int,
    db: Annotated[Session, Depends(get_db)],
    min_risk: Annotated[float | None, Query(ge=0, le=10)] = None,
    severity: str | None = None,
    kev_only: bool = False,
    limit: Limit = 100,
    offset: Offset = 0,
):
    _get_asset(db, asset_id)
    q = select(Vulnerability).where(Vulnerability.asset_id == asset_id)
    if min_risk is not None:
        q = q.where(Vulnerability.risk_score >= min_risk)
    if severity:
        q = q.where(Vulnerability.severity == severity.lower())
    if kev_only:
        q = q.where(Vulnerability.in_kev.is_(True))
    q = q.order_by(Vulnerability.risk_score.desc(), Vulnerability.id).limit(limit).offset(offset)
    return db.scalars(q).all()
