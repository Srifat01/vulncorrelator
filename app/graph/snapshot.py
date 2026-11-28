"""A plain-data picture of everything the graph is built from. Decouples graph construction from the ORM, so the
builder is a pure function (unit-testable, and benchmarkable without a database)."""

from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Asset, AssetObservation, Relationship, SecurityBoundary, Service, Vulnerability


@dataclass
class AssetRec:
    id: int
    ip: str
    hostname: str | None = None
    os: str | None = None
    internet_facing: bool = False
    exposure_source: str = "unknown"
    criticality: int = 3
    tags: list[str] = field(default_factory=list)
    controls: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    interfaces: list[tuple[str, datetime | None, datetime | None]] = field(default_factory=list)  # (ip, first, last)


@dataclass
class ServiceRec:
    asset_id: int
    port: int
    protocol: str = "tcp"
    name: str | None = None
    product: str | None = None
    version: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None


@dataclass
class VulnRec:
    id: int
    asset_id: int
    title: str
    cve_id: str | None = None
    port: int | None = None  # None = host-level finding
    protocol: str | None = None
    tags: list[str] = field(default_factory=list)
    cvss_score: float | None = None
    cvss_vector: str | None = None
    evidence_status: str = "observed"
    sources: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)
    epss: float | None = None
    in_kev: bool = False
    risk_score: float = 0.0
    threat: float | None = None  # 0..1 likelihood x attackability, filled in by the risk engine
    first_seen: datetime | None = None
    last_seen: datetime | None = None


@dataclass
class RelRec:
    id: int
    kind: str
    src: str
    dst: str
    evidence_status: str
    source: str
    port: int = 0
    protocol: str = "any"
    attrs: dict = field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None


@dataclass
class BoundaryRec:
    name: str
    cidrs: list[str]


@dataclass
class Snapshot:
    assets: list[AssetRec] = field(default_factory=list)
    services: list[ServiceRec] = field(default_factory=list)
    vulns: list[VulnRec] = field(default_factory=list)
    relationships: list[RelRec] = field(default_factory=list)
    boundaries: list[BoundaryRec] = field(default_factory=list)


def load_snapshot(db: Session) -> Snapshot:
    ifaces: dict[int, list[tuple[str, datetime | None, datetime | None]]] = {}
    for aid, ip, first, last in db.execute(
        select(
            AssetObservation.asset_id,
            AssetObservation.ip_address,
            func.min(AssetObservation.observed_at),
            func.max(AssetObservation.observed_at),
        ).group_by(AssetObservation.asset_id, AssetObservation.ip_address)
    ):
        ifaces.setdefault(aid, []).append((ip, first, last))

    snap = Snapshot()
    for a in db.scalars(select(Asset).order_by(Asset.id)):
        snap.assets.append(
            AssetRec(
                a.id, a.ip_address, a.hostname, a.os, a.internet_facing, a.exposure_source, a.criticality,
                list(a.tags or []), list(a.controls or []), a.first_seen, a.last_seen,
                ifaces.get(a.id) or [(a.ip_address, a.first_seen, a.last_seen)],
            )
        )  # fmt: skip
    for s in db.scalars(select(Service).order_by(Service.id)):
        snap.services.append(
            ServiceRec(s.asset_id, s.port, s.protocol, s.name, s.product, s.version, s.first_seen, s.last_seen)
        )
    for v in db.scalars(select(Vulnerability).order_by(Vulnerability.id)):
        comps = v.risk_components or {}
        snap.vulns.append(
            VulnRec(
                v.id, v.asset_id, v.title, v.cve_id, v.port, v.protocol, list(v.tags or []), v.cvss_score,
                v.cvss_vector, v.evidence_status, list(v.sources or []), v.evidence or {}, v.epss, bool(v.in_kev),
                v.risk_score, (comps.get("threat") or {}).get("value"), v.first_seen, v.last_seen,
            )
        )  # fmt: skip
    for r in db.scalars(select(Relationship).order_by(Relationship.id)):
        snap.relationships.append(
            RelRec(
                r.id, r.kind, r.src, r.dst, r.evidence_status, r.source, r.port, r.protocol, dict(r.attrs or {}),
                r.first_seen, r.last_seen,
            )
        )  # fmt: skip
    for b in db.scalars(select(SecurityBoundary).order_by(SecurityBoundary.id)):
        snap.boundaries.append(BoundaryRec(b.name, list(b.cidrs or [])))
    return snap
