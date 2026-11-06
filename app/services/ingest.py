"""Ingestion pipeline: parse -> normalize -> enrich -> upsert -> mark report."""

import ipaddress
import logging
from datetime import datetime

from sqlalchemy import insert as generic_insert
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import database
from app.models import Asset, ReportStatus, ScanReport, Service, Vulnerability, utcnow
from app.parsers import ParseError, parse_report
from app.schemas import HostIn, ReportIn, ServiceIn
from app.services.cache import get_cache
from app.services.intel import get_intel
from app.services.normalizer import NormalizedFinding, build_findings
from app.services.risk import risk_score, severity_from_score

log = logging.getLogger(__name__)
CHUNK = 200


def _insert(db: Session, model):
    """Dialect-specific INSERT supporting ON CONFLICT (Postgres and SQLite)."""
    name = db.get_bind().dialect.name
    if name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    elif name == "sqlite":
        from sqlalchemy.dialects.sqlite import insert
    else:  # pragma: no cover
        return generic_insert(model)
    return insert(model)


def _is_public(ip: str) -> bool:
    return ipaddress.ip_address(ip).is_global


def upsert_asset(db: Session, host: HostIn, override: bool | None, now: datetime) -> Asset:
    explicit = host.internet_facing if host.internet_facing is not None else override
    # ON CONFLICT DO NOTHING makes concurrent first-sightings of one IP safe.
    db.execute(
        _insert(db, Asset)
        .values(
            ip_address=host.ip_address,
            hostname=host.hostname,
            os=host.os,
            internet_facing=explicit if explicit is not None else _is_public(host.ip_address),
            first_seen=now,
            last_seen=now,
        )
        .on_conflict_do_nothing(index_elements=["ip_address"])
    )
    asset = db.scalars(select(Asset).where(Asset.ip_address == host.ip_address)).one()
    asset.last_seen = now
    asset.hostname = host.hostname or asset.hostname
    asset.os = host.os or asset.os
    if explicit is not None:
        asset.internet_facing = explicit
    return asset


def upsert_services(db: Session, asset: Asset, services: list[ServiceIn], now: datetime) -> None:
    existing = {(s.port, s.protocol): s for s in db.scalars(select(Service).where(Service.asset_id == asset.id))}
    for s in services:
        row = existing.get((s.port, s.protocol))
        if row is None:
            db.execute(
                _insert(db, Service)
                .values(
                    asset_id=asset.id,
                    port=s.port,
                    protocol=s.protocol,
                    name=s.name,
                    product=s.product,
                    version=s.version,
                    cpe=s.cpe,
                    first_seen=now,
                    last_seen=now,
                )
                .on_conflict_do_nothing(index_elements=["asset_id", "port", "protocol"])
            )
        else:
            row.name = s.name or row.name
            row.product = s.product or row.product
            row.version = s.version or row.version
            row.cpe = s.cpe or row.cpe
            row.last_seen = now


def _merge(existing: Vulnerability, f: NormalizedFinding, report_id: int, now: datetime) -> None:
    """Fold a re-sighting (possibly from another scanner) into the stored record."""
    existing.last_seen = now
    existing.last_report_id = report_id
    existing.cvss_score = max(filter(lambda x: x is not None, [existing.cvss_score, f.cvss_score]), default=None)
    existing.severity = severity_from_score(existing.cvss_score)
    existing.cvss_vector = existing.cvss_vector or f.cvss_vector
    existing.description = existing.description or f.description
    existing.service_name = existing.service_name or f.service_name
    existing.product = existing.product or f.product
    existing.version = f.version or existing.version  # newest scan wins for the version
    existing.cpe = existing.cpe or f.cpe
    existing.tags = sorted(set(existing.tags or []) | set(f.tags))
    existing.sources = sorted(set(existing.sources or []) | set(f.sources))
    existing.evidence = {**(existing.evidence or {}), **f.evidence}  # new object => change detected
    existing.epss, existing.in_kev = f.epss, f.in_kev  # always the latest intel
    existing.risk_score = risk_score(existing.cvss_score, existing.epss, existing.in_kev)


def upsert_findings(
    db: Session, asset: Asset, findings: list[NormalizedFinding], report_id: int, now: datetime
) -> tuple[int, int]:
    """Returns (new, updated). Uniqueness is enforced by the DB on `fingerprint`."""
    by_fp = {f.fingerprint: f for f in findings}
    existing: dict[str, Vulnerability] = {}
    fps = list(by_fp)
    for i in range(0, len(fps), 500):
        chunk = fps[i : i + 500]
        existing.update(
            {v.fingerprint: v for v in db.scalars(select(Vulnerability).where(Vulnerability.fingerprint.in_(chunk)))}
        )

    new_rows = []
    for fp, f in by_fp.items():
        if fp in existing:
            _merge(existing[fp], f, report_id, now)
        else:
            new_rows.append(
                dict(
                    fingerprint=fp,
                    asset_id=asset.id,
                    cve_id=f.cve_id,
                    title=f.title[:512],
                    description=f.description,
                    cvss_score=f.cvss_score,
                    cvss_vector=f.cvss_vector,
                    severity=f.severity,
                    port=f.port,
                    protocol=f.protocol,
                    service_name=f.service_name,
                    product=f.product,
                    version=f.version,
                    cpe=f.cpe,
                    tags=f.tags,
                    sources=f.sources,
                    evidence=f.evidence,
                    epss=f.epss,
                    in_kev=f.in_kev,
                    risk_score=f.risk_score,
                    first_seen=now,
                    last_seen=now,
                    last_report_id=report_id,
                )
            )
    for i in range(0, len(new_rows), CHUNK):
        db.execute(
            _insert(db, Vulnerability)
            .values(new_rows[i : i + CHUNK])
            .on_conflict_do_nothing(index_elements=["fingerprint"])
        )
    return len(new_rows), len(existing)


def ingest_report(db: Session, report: ScanReport, parsed: ReportIn) -> None:
    now, intel = utcnow(), get_intel()
    total = new = updated = 0
    for host in parsed.hosts:
        asset = upsert_asset(db, host, report.internet_facing, now)
        services, findings = build_findings(host, parsed.source, intel)
        upsert_services(db, asset, services, now)
        n, u = upsert_findings(db, asset, findings, report.id, now)
        total, new, updated = total + len(findings), new + n, updated + u
    report.hosts_count = len(parsed.hosts)
    report.findings_count, report.new_count, report.updated_count = total, new, updated


def run_report(db: Session, report_id: int) -> ScanReport:
    """Process a stored report. Used inline (sync API) and by the RQ worker."""
    report = db.get(ScanReport, report_id)
    if report is None:
        raise LookupError(f"report {report_id} not found")
    report.status = ReportStatus.processing.value
    db.commit()
    try:
        parsed = parse_report(report.format, report.raw_payload or "")
        report.source = parsed.source
        ingest_report(db, report, parsed)
        report.status = ReportStatus.completed.value
        report.completed_at = utcnow()
        db.commit()
    except ParseError as exc:
        db.rollback()
        _fail(db, report_id, str(exc)[:2000])
        raise
    except Exception:
        db.rollback()
        log.exception("report %s failed", report_id)
        _fail(db, report_id, "internal error while processing report")
        raise
    finally:
        get_cache().invalidate()
    return report


def _fail(db: Session, report_id: int, message: str) -> None:
    report = db.get(ScanReport, report_id)
    report.status = ReportStatus.failed.value
    report.error = message
    report.completed_at = utcnow()
    db.commit()


def process_report_job(report_id: int) -> None:
    """RQ entry point (see app/services/queue.py)."""
    with database.SessionLocal() as db:
        try:
            run_report(db, report_id)
        except ParseError:
            pass  # already recorded on the report; retrying cannot help
