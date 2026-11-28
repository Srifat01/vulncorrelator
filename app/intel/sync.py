"""Writes threat intelligence into the database: per-CVE records with per-source timestamps and origin, an
append-only history whenever a value changes, and a sync-run log. Every function degrades gracefully: an upstream
outage is recorded as a failed run and leaves existing data (and its age) untouched."""

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.intel.http import IntelError, ResilientClient, SlidingWindowLimiter
from app.intel.provider import IntelProvider
from app.intel.sources import EpssRow, KevEntry, NvdClient, NvdCve, cve_affects_cpe, fetch_epss, fetch_kev
from app.models import Asset, CpeLookup, CveIntel, IntelHistory, IntelSyncRun, Service, Vulnerability, utcnow
from app.schemas import HostIn, ServiceIn
from app.services.cpe import canonical_cpe23, parse_cpe
from app.services.ingest import upsert_findings
from app.services.normalizer import build_findings
from app.services.risk import severity_from_score

log = logging.getLogger(__name__)
SOURCES = ("kev", "epss", "nvd", "cpe")  # public vocabulary
# Execution order follows the data dependencies: CPE lookups *discover* CVEs, NVD fills in the rest, and EPSS then
# scores every CVE we now track. (EPSS before CPE would miss all newly discovered CVEs.)
RUN_ORDER = ("kev", "cpe", "nvd", "epss")


@dataclass
class Clients:
    http: ResilientClient  # KEV + EPSS
    nvd: NvdClient

    def close(self) -> None:
        self.http.close()
        self.nvd.client.close()


def build_clients(
    settings: Settings | None = None, *, transport=None, sleep=time.sleep, clock=time.monotonic
) -> Clients:
    s = settings or get_settings()
    kw = dict(timeout=s.intel_http_timeout, max_retries=s.intel_max_retries, transport=transport, sleep=sleep)
    # NVD's published public limits: 5 requests / 30 s without a key, 50 / 30 s with one. Stay inside them.
    calls = 50 if s.nvd_api_key else 5
    nvd_http = ResilientClient(limiter=SlidingWindowLimiter(calls, 30, clock=clock, sleep=sleep), **kw)
    return Clients(ResilientClient(**kw), NvdClient(nvd_http, s.nvd_base_url, s.nvd_api_key))


# ------------------------------------------------------------------ bookkeeping
def _start(db: Session, source: str, origin: str = "live") -> IntelSyncRun:
    run = IntelSyncRun(source=source, status="running", origin=origin)
    db.add(run)
    db.commit()
    return run


def _finish(db: Session, run: IntelSyncRun, status: str, seen: int = 0, updated: int = 0, error=None, mark=None):
    run.status, run.records_seen, run.records_updated = status, seen, updated
    run.error = (error or None) and str(error)[:2000]
    run.watermark = mark or {}
    run.finished_at = utcnow()
    db.commit()
    return run


def last_success(db: Session, source: str) -> IntelSyncRun | None:
    return db.scalar(
        select(IntelSyncRun)
        .where(
            IntelSyncRun.source == source,
            IntelSyncRun.status.in_(["success", "partial"]),
            IntelSyncRun.origin == "live",
        )
        .order_by(IntelSyncRun.id.desc())
    )


def _row(db: Session, cve_id: str) -> CveIntel:
    row = db.get(CveIntel, cve_id)
    if row is None:
        row = CveIntel(cve_id=cve_id, tags=[], cwe=[], in_kev=False)
        db.add(row)
    return row


def _history(db: Session, cve_id: str, source: str, value: dict, now: datetime) -> None:
    db.add(IntelHistory(cve_id=cve_id, source=source, value=value, origin="live", observed_at=now))


def _stale(ts: datetime | None, hours: int, now: datetime) -> bool:
    if ts is None:
        return True
    ts = ts if ts.tzinfo else ts.replace(tzinfo=now.tzinfo)
    return now - ts > timedelta(hours=hours)


def tracked_cves(db: Session) -> list[str]:
    return sorted(
        {c for (c,) in db.execute(select(Vulnerability.cve_id).where(Vulnerability.cve_id.is_not(None)).distinct())}
    )


# ------------------------------------------------------------------ CISA KEV
def sync_kev(db: Session, client: ResilientClient, settings: Settings | None = None) -> IntelSyncRun:
    s, now = settings or get_settings(), utcnow()
    run, prev = _start(db, "kev"), last_success(db, "kev")
    etag = (prev.watermark or {}).get("etag") if prev else None
    try:
        cat = fetch_kev(client, s.kev_url, etag)
    except IntelError as exc:
        return _finish(db, run, "failed", error=exc)
    if cat.not_modified:
        return _finish(db, run, "success", mark={"etag": etag, "not_modified": True})
    seen, changed = {e.cve_id for e in cat.entries}, 0
    entry: KevEntry
    for entry in cat.entries:
        row = _row(db, entry.cve_id)
        if not row.in_kev or row.kev_date_added != entry.date_added or row.kev_origin != "live":
            _history(
                db,
                entry.cve_id,
                "kev",
                {"in_kev": True, "date_added": entry.date_added, "due_date": entry.due_date},
                now,
            )
            changed += 1
        row.in_kev, row.kev_date_added, row.kev_due_date = True, entry.date_added, entry.due_date
        row.kev_ransomware, row.kev_synced_at, row.kev_origin = entry.ransomware, now, "live"
    for row in db.scalars(select(CveIntel).where(CveIntel.in_kev.is_(True), CveIntel.kev_origin == "live")):
        if row.cve_id not in seen:  # removed from the catalog upstream
            row.in_kev, row.kev_synced_at = False, now
            _history(db, row.cve_id, "kev", {"in_kev": False}, now)
            changed += 1
    mark = {"etag": cat.etag, "catalog_version": cat.catalog_version, "skipped_invalid": cat.skipped}
    return _finish(db, run, "success", len(seen), changed, mark=mark)


# ------------------------------------------------------------------ FIRST EPSS
def sync_epss(
    db: Session, client: ResilientClient, settings: Settings | None = None, *, force: bool = False
) -> IntelSyncRun:
    s, now = settings or get_settings(), utcnow()
    run = _start(db, "epss")
    wanted = [
        c for c in tracked_cves(db)
        if force or _stale((db.get(CveIntel, c) or CveIntel()).epss_synced_at, s.epss_ttl_hours, now)
    ]  # fmt: skip
    if not wanted:
        return _finish(db, run, "success", mark={"note": "all tracked CVEs are fresh"})
    try:
        rows: dict[str, EpssRow] = fetch_epss(client, s.epss_base_url, wanted)
    except IntelError as exc:
        return _finish(db, run, "failed", seen=len(wanted), error=exc)
    changed = 0
    for cve_id, r in rows.items():
        row = _row(db, cve_id)
        if row.epss != r.epss or row.epss_date != r.date:
            _history(db, cve_id, "epss", {"epss": r.epss, "percentile": r.percentile, "date": r.date}, now)
            changed += 1
        row.epss, row.epss_percentile, row.epss_date = r.epss, r.percentile, r.date
        row.epss_synced_at, row.epss_origin = now, "live"
    missing = sorted(set(wanted) - set(rows))
    return _finish(
        db, run, "success", len(wanted), changed, mark={"unscored": missing[:50], "unscored_count": len(missing)}
    )


# ------------------------------------------------------------------ NVD
def _apply_nvd(db: Session, cve: NvdCve, now: datetime) -> bool:
    row = _row(db, cve.cve_id)
    changed = (row.cvss_score, row.cvss_vector, row.nvd_last_modified) != (
        cve.cvss_score,
        cve.cvss_vector,
        cve.last_modified,
    )
    if changed:
        value = {"cvss_score": cve.cvss_score, "cvss_vector": cve.cvss_vector, "version": cve.cvss_version,
                 "last_modified": cve.last_modified.isoformat() if cve.last_modified else None}  # fmt: skip
        _history(db, cve.cve_id, "nvd", value, now)
    row.description, row.published, row.nvd_last_modified = cve.description, cve.published, cve.last_modified
    row.cvss_score, row.cvss_vector, row.cvss_version = cve.cvss_score, cve.cvss_vector, cve.cvss_version
    row.cwe, row.tags = cve.cwe, cve.tags
    row.nvd_synced_at, row.nvd_origin = now, "live"
    return changed


def sync_nvd(
    db: Session, nvd: NvdClient, settings: Settings | None = None, *, force: bool = False, max_requests: int = 200
) -> IntelSyncRun:
    s, now = settings or get_settings(), utcnow()
    run = _start(db, "nvd")
    todo = [
        c for c in tracked_cves(db)
        if force or _stale((db.get(CveIntel, c) or CveIntel()).nvd_synced_at, s.nvd_ttl_hours, now)
    ]  # fmt: skip
    fetched = changed = 0
    errors: list[str] = []
    status = "success"
    for cve_id in todo:
        if fetched >= max_requests:
            status = "partial"
            errors.append(f"stopped after {max_requests} requests; {len(todo) - fetched} CVE(s) left for the next run")
            break
        try:
            cve = nvd.fetch_cve(cve_id)
        except IntelError as exc:
            errors.append(f"{cve_id}: {exc}")
            if exc.retryable:  # upstream is down/limiting us: stop hammering it
                status = "partial" if fetched else "failed"
                break
            continue
        fetched += 1
        if cve is not None:
            changed += _apply_nvd(db, cve, now)
        else:
            errors.append(f"{cve_id}: not found in NVD")
    if errors and status == "success":
        status = "partial"
    return _finish(db, run, status, len(todo), changed, error="; ".join(errors[:10]) or None)


def lookup_cpes(
    db: Session, nvd: NvdClient, settings: Settings | None = None, *, force: bool = False, max_requests: int = 100
) -> IntelSyncRun:
    """Ask NVD which CVEs apply to each discovered product version, and verify its answer before trusting it."""
    s, now = settings or get_settings(), utcnow()
    run = _start(db, "cpe")
    wanted = sorted(
        {
            k
            for (c,) in db.execute(select(Service.cpe).where(Service.cpe.is_not(None)).distinct())
            if (k := canonical_cpe23(c))
        }
    )
    todo = [
        k
        for k in wanted
        if force or _stale((db.get(CpeLookup, k) or CpeLookup()).looked_up_at, s.cpe_lookup_ttl_hours, now)
    ]
    done = changed = rejected = 0
    errors: list[str] = []
    status = "success"
    for cpe in todo:
        if done >= max_requests:
            status = "partial"
            errors.append(f"stopped after {max_requests} lookups")
            break
        try:
            cves = nvd.fetch_by_cpe(cpe)
        except IntelError as exc:
            errors.append(f"{cpe}: {exc}")
            status = "partial" if done else "failed"
            if exc.retryable:
                break
            continue
        done += 1
        target = parse_cpe(cpe)
        verified = [c for c in cves if cve_affects_cpe(c, target)]
        rejected += len(cves) - len(verified)
        for c in verified:
            changed += _apply_nvd(db, c, now)
        lookup = db.get(CpeLookup, cpe) or CpeLookup(cpe=cpe)
        lookup.cve_ids, lookup.looked_up_at, lookup.origin = sorted(c.cve_id for c in verified), now, "live"
        db.add(lookup)
    if rejected:
        errors.append(f"{rejected} NVD result(s) rejected: their cpeMatch data did not cover the queried version")
    return _finish(db, run, status, len(todo), changed, error="; ".join(errors[:10]) or None)


# ------------------------------------------------------------------ propagate to findings
def refresh_vulnerabilities(db: Session, cve_ids: list[str] | None = None) -> int:
    """Copy current intelligence onto findings (EPSS, KEV, and NVD's authoritative CVSS) with attribution."""
    q = select(Vulnerability).where(Vulnerability.cve_id.is_not(None))
    if cve_ids:
        q = q.where(Vulnerability.cve_id.in_(cve_ids))
    updated = 0
    for v in db.scalars(q):
        row = db.get(CveIntel, v.cve_id)
        if row is None:
            continue
        before = (v.epss, v.in_kev, v.cvss_score, v.cvss_vector)
        if row.epss_origin == "live":
            v.epss = row.epss
        if row.in_kev and row.kev_origin == "live":
            v.in_kev = True
        if row.nvd_origin == "live" and row.cvss_score is not None:
            v.cvss_score, v.cvss_vector, v.cvss_source = row.cvss_score, row.cvss_vector or v.cvss_vector, "nvd"
            v.severity = severity_from_score(v.cvss_score)
        if row.nvd_origin == "live" and row.tags:
            v.tags = sorted(set(v.tags or []) | set(row.tags))
        if before != (v.epss, v.in_kev, v.cvss_score, v.cvss_vector):
            updated += 1
    return updated


def _service_in(x: Service) -> ServiceIn:
    return ServiceIn(port=x.port, protocol=x.protocol, name=x.name, product=x.product, version=x.version, cpe=x.cpe)


def apply_cpe_matches(db: Session) -> int:
    """Create (inferred) findings for CVEs that NVD associates with a discovered product version."""
    now, provider, created = utcnow(), IntelProvider(db), 0
    by_asset: dict[int, list[Service]] = {}
    for svc in db.scalars(select(Service).where(Service.cpe.is_not(None))):
        if canonical_cpe23(svc.cpe) and db.get(CpeLookup, canonical_cpe23(svc.cpe)):
            by_asset.setdefault(svc.asset_id, []).append(svc)
    for asset_id, svcs in by_asset.items():
        asset = db.get(Asset, asset_id)
        host = HostIn(ip_address=asset.ip_address, services=[_service_in(x) for x in svcs])
        _, findings = build_findings(host, "nvd-cpe", provider)
        findings = [f for f in findings if "nvd-cpe" in f.sources]
        new, _ = upsert_findings(db, asset, findings, None, now)
        created += new
    return created


# ------------------------------------------------------------------ orchestration
def sync_all(
    db: Session,
    clients: Clients,
    sources: tuple[str, ...] = SOURCES,
    *,
    force: bool = False,
    settings: Settings | None = None,
) -> list[IntelSyncRun]:
    """Run the requested syncs in dependency order, then push results to findings and refresh the analysis."""
    from app.analysis.runner import after_ingest
    from app.services.cache import get_cache
    from app.services.meta import bump_data_version

    s, runs = settings or get_settings(), []
    for name in RUN_ORDER:
        if name not in sources:
            continue
        try:
            if name == "kev":
                runs.append(sync_kev(db, clients.http, s))
            elif name == "cpe":
                runs.append(lookup_cpes(db, clients.nvd, s, force=force))
                apply_cpe_matches(db)
            elif name == "nvd":
                runs.append(sync_nvd(db, clients.nvd, s, force=force))
            elif name == "epss":
                runs.append(sync_epss(db, clients.http, s, force=force))
        except Exception:  # one broken source must not stop the others
            log.exception("intel sync %s crashed", name)
            db.rollback()
    refresh_vulnerabilities(db)
    bump_data_version(db)
    db.commit()
    get_cache().invalidate()
    after_ingest(db, "intel")
    return runs


def count_rows(db: Session, model) -> int:
    return db.scalar(select(func.count()).select_from(model)) or 0
