"""Ingestion pipeline: parse -> resolve identity -> normalize -> enrich -> upsert -> record evidence.

Each host is processed in its own transaction (sorted by address, so concurrent reports lock in a consistent
order). The whole pipeline is idempotent, so a failed or retried report can simply be run again.
"""

import logging
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import database
from app.config import get_settings
from app.intel.provider import IntelProvider
from app.models import (
    EVIDENCE_RANK,
    Asset,
    ReportStatus,
    ScanReport,
    Service,
    Vulnerability,
    utcnow,
)
from app.parsers import ParseError, parse_report
from app.schemas import HostIn, ReportIn, ServiceIn
from app.services.cache import get_cache
from app.services.dbutil import dialect_insert
from app.services.identity import resolve_asset
from app.services.meta import bump_data_version
from app.services.netutil import is_public_ip
from app.services.normalizer import NormalizedFinding, build_findings
from app.services.relationships import upsert_relationship
from app.services.risk import severity_from_score

log = logging.getLogger(__name__)
CHUNK = 200


def update_exposure(asset: Asset, host: HostIn, report: ScanReport, services: list[ServiceIn]) -> None:
    """Decide `internet_facing` and *why* we believe it (the reason drives edge confidence later)."""
    explicit = host.internet_facing if host.internet_facing is not None else report.internet_facing
    if explicit is not None:
        asset.internet_facing, asset.exposure_source = explicit, "declared"
    elif report.vantage == "external" and services:  # services seen open from outside
        asset.internet_facing, asset.exposure_source = True, "scan_external"
    elif asset.exposure_source in ("unknown", "public_ip"):
        public = is_public_ip(host.ip_address)
        asset.internet_facing, asset.exposure_source = public, "public_ip" if public else "unknown"


def upsert_services(db: Session, asset: Asset, services: list[ServiceIn], now: datetime) -> None:
    existing = {(s.port, s.protocol): s for s in db.scalars(select(Service).where(Service.asset_id == asset.id))}
    for s in services:
        row = existing.get((s.port, s.protocol))
        if row is None:
            db.execute(
                dialect_insert(db, Service)
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


def merge_finding(existing: Vulnerability, f: NormalizedFinding, report_id: int | None, now: datetime) -> None:
    """Fold a re-sighting (possibly from another scanner) into the stored record."""
    existing.last_seen = now
    existing.last_report_id = report_id
    existing.cvss_score = max(filter(lambda x: x is not None, [existing.cvss_score, f.cvss_score]), default=None)
    existing.severity = severity_from_score(existing.cvss_score)
    existing.cvss_vector = existing.cvss_vector or f.cvss_vector
    existing.cvss_source = existing.cvss_source or f.cvss_source
    existing.description = existing.description or f.description
    existing.service_name = existing.service_name or f.service_name
    existing.product = existing.product or f.product
    existing.version = f.version or existing.version  # newest scan wins for the version
    existing.cpe = existing.cpe or f.cpe
    existing.tags = sorted(set(existing.tags or []) | set(f.tags))
    existing.sources = sorted(set(existing.sources or []) | set(f.sources))
    existing.evidence = {**(existing.evidence or {}), **f.evidence}  # new object => change detected
    if EVIDENCE_RANK[f.evidence_status] > EVIDENCE_RANK.get(existing.evidence_status, 0):
        existing.evidence_status = f.evidence_status  # corroboration can only strengthen
    existing.epss = f.epss if f.epss is not None else existing.epss
    existing.in_kev = bool(f.in_kev or existing.in_kev)


def upsert_findings(
    db: Session, asset: Asset, findings: list[NormalizedFinding], report_id: int | None, now: datetime
) -> tuple[int, int]:
    """Returns (new, updated). Uniqueness is enforced by the DB on `fingerprint`."""
    key = str(asset.id)
    by_fp = {f.fingerprint_for(key): f for f in findings}
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
            merge_finding(existing[fp], f, report_id, now)
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
                    cvss_source=f.cvss_source,
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
                    evidence_status=f.evidence_status,
                    epss=f.epss,
                    in_kev=f.in_kev,
                    risk_score=0.0,
                    first_seen=now,
                    last_seen=now,
                    last_report_id=report_id,
                )
            )
    for i in range(0, len(new_rows), CHUNK):
        db.execute(
            dialect_insert(db, Vulnerability)
            .values(new_rows[i : i + CHUNK])
            .on_conflict_do_nothing(index_elements=["fingerprint"])
        )
    return len(new_rows), len(existing)


def record_network_evidence(
    db: Session,
    asset: Asset,
    host: HostIn,
    services: list[ServiceIn],
    report: ScanReport,
    parsed: ReportIn,
    now: datetime,
) -> None:
    """Turn what the scan implies about connectivity into evidence-bearing relationships."""
    if report.vantage == "external":
        # An open port seen from outside is direct evidence of internet exposure for that service.
        for s in services:
            upsert_relationship(
                db,
                kind="CONNECTS_TO",
                src="internet",
                dst=f"asset:{asset.id}",
                port=s.port,
                protocol=s.protocol,
                evidence_status="observed",
                source=f"scan:{parsed.source}",
                report_id=report.id,
                now=now,
            )
    for c in host.connections:
        upsert_relationship(
            db,
            kind="CONNECTS_TO",
            src=f"asset:{asset.id}",
            dst=f"cidr:{c.dst}",
            port=c.port,
            protocol=c.protocol,
            evidence_status="observed",
            source=f"report:{parsed.source}",
            report_id=report.id,
            now=now,
        )


def ingest_report(db: Session, report: ScanReport, parsed: ReportIn) -> None:
    now, intel = utcnow(), IntelProvider(db)
    max_findings = get_settings().max_findings_per_host
    total = new = updated = 0
    for host in sorted(parsed.hosts, key=lambda h: h.ip_address):
        if len(host.vulnerabilities) > max_findings:
            raise ParseError(f"host {host.ip_address} has more than {max_findings} findings")
        res = resolve_asset(db, host, source=parsed.source, report_id=report.id, now=now)
        services, findings = build_findings(host, parsed.source, intel)
        update_exposure(res.asset, host, report, services)
        upsert_services(db, res.asset, services, now)
        record_network_evidence(db, res.asset, host, services, report, parsed, now)
        n, u = upsert_findings(db, res.asset, findings, report.id, now)
        total, new, updated = total + len(findings), new + n, updated + u
        db.commit()  # per-host transaction: short lock hold, and the whole pipeline is idempotent
    report.hosts_count = len(parsed.hosts)
    report.findings_count, report.new_count, report.updated_count = total, new, updated


def run_report(db: Session, report_id: int) -> ScanReport:
    """Process a stored report. Used inline (sync API) and by the RQ worker."""
    report = db.get(ScanReport, report_id)
    if report is None:
        raise LookupError(f"report {report_id} not found")
    report.status = ReportStatus.processing.value
    report.attempts = (report.attempts or 0) + 1
    report.started_at = utcnow()
    report.error = None
    db.commit()
    try:
        parsed = parse_report(report.format, report.raw_payload or "")
        report.source = parsed.source
        if parsed.vantage and not report.vantage:
            report.vantage = parsed.vantage
        ingest_report(db, report, parsed)
        report.status = ReportStatus.completed.value
        report.completed_at = utcnow()
        bump_data_version(db)
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
    from app.analysis.runner import after_ingest  # local import: the analysis package imports a lot

    after_ingest(db)
    from app.intel.jobs import request_enrichment

    request_enrichment()
    return report


def _fail(db: Session, report_id: int, message: str) -> None:
    report = db.get(ScanReport, report_id)
    report.status = ReportStatus.failed.value
    report.error = message
    report.completed_at = utcnow()
    db.commit()


def process_report_job(report_id: int) -> None:
    """RQ entry point (see app/services/queue.py). Parse errors are final; other errors propagate so RQ retries."""
    with database.SessionLocal() as db:
        try:
            run_report(db, report_id)
        except ParseError:
            pass  # already recorded on the report; retrying cannot help


def recover_stuck_reports(db: Session, now: datetime | None = None) -> list[int]:
    """Reports left in `processing` by a crashed worker are re-queued (idempotent) or failed after N attempts."""
    s = get_settings()
    cutoff = (now or utcnow()) - timedelta(minutes=s.stuck_report_minutes)
    recovered: list[int] = []
    stuck = db.scalars(
        select(ScanReport).where(ScanReport.status == ReportStatus.processing.value, ScanReport.started_at < cutoff)
    ).all()
    for r in stuck:
        if (r.attempts or 0) >= s.max_report_attempts:
            r.status = ReportStatus.failed.value
            r.error = "worker stopped responding (max attempts)"
            r.completed_at = utcnow()
        else:
            r.status = ReportStatus.pending.value
            recovered.append(r.id)
    db.commit()
    return recovered
