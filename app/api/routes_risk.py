from dataclasses import asdict
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.intel.status import cve_view
from app.models import Asset, Vulnerability
from app.risk.config import load_risk_config
from app.risk.model import FORMULA
from app.schemas import VulnerabilityOut
from app.security import authorize

router = APIRouter(tags=["risk"], dependencies=[Depends(authorize)])


class VulnerabilityDetail(VulnerabilityOut):
    description: str | None = None
    cpe: str | None = None
    cvss_vector: str | None = None
    asset_criticality: int | None = None
    risk_components: dict | None = None
    evidence: dict = {}
    intel: dict | None = None  # per-source provenance for this CVE (live / cached / demo / missing)


@router.get("/risk/model")
def risk_model():
    """The active, versioned scoring methodology and every parameter in it."""
    cfg = load_risk_config()
    return {
        "name": cfg.name,
        "version": cfg.version,
        "config_hash": cfg.config_hash(),
        "formula": FORMULA,
        "parameters": asdict(cfg),
        "calibration": "NOT calibrated. The score ranks remediation work; it is not a probability of compromise.",
        "components": {
            "severity": "CVSS base score / 10 (intrinsic severity)",
            "likelihood": "max(KEV floor if on CISA KEV, EPSS); a flagged, documented prior if EPSS is missing",
            "exploitability": "CVSS v3 exploitability sub-score (attack vector, complexity, privileges, interaction)",
            "exposure": "strongest reachability evidence for the service (internet, internal, unknown)",
            "controls": "product of declared control multipliers (assumed effectiveness)",
            "business_impact": "asset criticality 1-5 mapped through the configured table",
            "path_relevance": "whether an attack path uses the finding, and whether that path reaches a target",
        },
    }


@router.get("/risk/priorities", response_model=list[VulnerabilityDetail])
def risk_priorities(
    db: Annotated[Session, Depends(get_db)],
    min_score: Annotated[float, Query(ge=0, le=10)] = 0,
    band: str | None = None,
    asset_id: int | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    """What to fix first, with the components that explain each score."""
    q = select(Vulnerability).where(Vulnerability.risk_score >= min_score)
    if band:
        q = q.where(Vulnerability.risk_band == band.lower())
    if asset_id is not None:
        q = q.where(Vulnerability.asset_id == asset_id)
    rows = db.scalars(q.order_by(Vulnerability.risk_score.desc(), Vulnerability.id).limit(limit).offset(offset)).all()
    return [_detail(db, v) for v in rows]


def _detail(db: Session, v: Vulnerability) -> VulnerabilityDetail:
    out = VulnerabilityDetail.model_validate(v)
    asset = db.get(Asset, v.asset_id)
    out.asset_criticality = asset.criticality if asset else None
    out.intel = cve_view(db, v.cve_id, history_limit=10) if v.cve_id else None
    return out


@router.get("/vulnerabilities/{vuln_id}", response_model=VulnerabilityDetail)
def vulnerability_detail(vuln_id: int, db: Annotated[Session, Depends(get_db)]):
    """One finding with its risk components and per-source evidence."""
    v = db.get(Vulnerability, vuln_id)
    if v is None:
        raise HTTPException(404, "vulnerability not found")
    return _detail(db, v)
