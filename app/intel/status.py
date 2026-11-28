"""Freshness and provenance reporting. Every value is classified so a consumer can tell what it is looking at:

  live     fetched from the real source within its freshness window
  cached   last value fetched from the real source, but older than the window (stale)
  demo     bundled demonstration data (only when INTEL_DEMO_DATA=true); never conflated with live data
  missing  nothing is known - and nothing is substituted
Historical values (what a score used to be) are in the history list.
"""

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.intel.provider import _demo
from app.models import CpeLookup, CveIntel, IntelHistory, IntelSyncRun, utcnow
from app.services.cpe import canonical_cpe23


def _age_hours(ts: datetime | None, now: datetime) -> float | None:
    if ts is None:
        return None
    return round((now - (ts if ts.tzinfo else ts.replace(tzinfo=now.tzinfo))).total_seconds() / 3600, 2)


def _cls(synced: datetime | None, origin: str | None, ttl: int, now: datetime) -> str:
    if synced is None:
        return "missing"
    if origin == "demo":
        return "demo"
    age = _age_hours(synced, now)
    return "live" if age is not None and age <= ttl else "cached"


def ttls() -> dict[str, int]:
    s = get_settings()
    return {"kev": s.kev_ttl_hours, "epss": s.epss_ttl_hours, "nvd": s.nvd_ttl_hours, "cpe": s.cpe_lookup_ttl_hours}


def source_status(db: Session, source: str, now: datetime) -> dict:
    ttl = ttls()[source]
    q = select(IntelSyncRun).where(IntelSyncRun.source == source, IntelSyncRun.origin == "live")
    last = db.scalar(q.order_by(IntelSyncRun.id.desc()))
    ok = db.scalar(q.where(IntelSyncRun.status.in_(["success", "partial"])).order_by(IntelSyncRun.id.desc()))
    age = _age_hours(ok.finished_at, now) if ok else None
    if ok is None:
        state = "failing" if last and last.status == "failed" else "never_synced"
    elif last is not None and last.status == "failed" and last.id > ok.id:
        state = "failing"  # we hold older data, and the most recent attempt did not refresh it
    elif age is not None and age > ttl:
        state = "stale"
    else:
        state = "fresh"
    return {
        "status": state,
        "ttl_hours": ttl,
        "last_success_at": ok.finished_at.isoformat() if ok else None,
        "age_hours": age,
        "last_attempt_at": last.finished_at.isoformat() if last and last.finished_at else None,
        "last_attempt_status": last.status if last else None,
        "last_error": last.error if last and last.status in ("failed", "partial") else None,
        "records_updated_last_success": ok.records_updated if ok else None,
        "watermark": ok.watermark if ok else None,
    }


def intel_status(db: Session) -> dict:
    s, now = get_settings(), utcnow()
    n = lambda q: db.scalar(q) or 0  # noqa: E731
    tracked = n(select(func.count(func.distinct(CveIntel.cve_id))))
    t = ttls()
    live = CveIntel.nvd_origin == "live"
    out = {
        "generated_at": now.isoformat(),
        "live_sync_enabled": s.intel_live_sync,
        "nvd_api_key_configured": bool(s.nvd_api_key),
        "sources": {name: source_status(db, name, now) for name in ("kev", "epss", "nvd", "cpe")},
        "coverage": {
            "cves_with_intel": tracked,
            "with_live_nvd": n(select(func.count()).select_from(CveIntel).where(live)),
            "with_live_epss": n(select(func.count()).select_from(CveIntel).where(CveIntel.epss_origin == "live")),
            "on_kev_live": n(
                select(func.count()).select_from(CveIntel).where(CveIntel.in_kev, CveIntel.kev_origin == "live")
            ),
            "stale_nvd_records": sum(
                1
                for (ts,) in db.execute(select(CveIntel.nvd_synced_at).where(live))
                if _cls(ts, "live", t["nvd"], now) == "cached"
            ),
            "stale_epss_records": sum(
                1
                for (ts,) in db.execute(select(CveIntel.epss_synced_at).where(CveIntel.epss_origin == "live"))
                if _cls(ts, "live", t["epss"], now) == "cached"
            ),
            "cpe_lookups_cached": n(select(func.count(CpeLookup.cpe))),
            "history_records": n(select(func.count(IntelHistory.id))),
        },
        "demo_data": {"enabled": s.intel_demo_data},
        "data_classes": {
            "live": "fetched from the real source within its freshness window",
            "cached": "last live value, older than its freshness window (stale)",
            "demo": "bundled demonstration data; labelled, never mixed into live values",
            "missing": "unknown - nothing is substituted",
        },
    }
    if s.intel_demo_data:
        d = _demo(s.intel_dir)
        out["demo_data"].update(
            catalog_entries=len(d._catalog), kev_ids=len(d.kev), epss_values=0,
            warning="demonstration data is enabled: it is illustrative, incomplete and NOT live intelligence",
        )  # fmt: skip
    return out


def cve_view(db: Session, cve_id: str, *, history_limit: int = 50) -> dict | None:
    s, now, t = get_settings(), utcnow(), ttls()
    cve_id = cve_id.upper()
    row = db.get(CveIntel, cve_id)
    demo = _demo(s.intel_dir) if s.intel_demo_data else None
    d_entry = demo.lookup(cve_id) if demo else None
    if row is None and d_entry is None and not (demo and demo.is_kev(cve_id)):
        return None
    out: dict = {"cve_id": cve_id, "sources": {}}
    nvd_live = row is not None and row.nvd_synced_at is not None
    if nvd_live:
        out["sources"]["nvd"] = {
            "data_class": _cls(row.nvd_synced_at, row.nvd_origin, t["nvd"], now),
            "origin": row.nvd_origin,
            "synced_at": row.nvd_synced_at.isoformat(),
            "age_hours": _age_hours(row.nvd_synced_at, now),
            "ttl_hours": t["nvd"],
            "value": {
                "cvss_score": row.cvss_score, "cvss_vector": row.cvss_vector, "cvss_version": row.cvss_version,
                "cwe": row.cwe, "tags": row.tags, "published": row.published.isoformat() if row.published else None,
                "last_modified": row.nvd_last_modified.isoformat() if row.nvd_last_modified else None,
                "description": row.description,
            },
        }  # fmt: skip
    elif d_entry:
        out["sources"]["nvd"] = {
            "data_class": "demo", "origin": "demo", "synced_at": None, "age_hours": None, "ttl_hours": None,
            "value": {"cvss_score": d_entry.cvss_score, "cvss_vector": d_entry.cvss_vector, "tags": list(d_entry.tags),
                      "description": d_entry.description},
        }  # fmt: skip
    else:
        out["sources"]["nvd"] = {"data_class": "missing"}
    has_epss = row is not None and row.epss_origin == "live"
    out["sources"]["epss"] = (
        {
            "data_class": _cls(row.epss_synced_at, row.epss_origin, t["epss"], now),
            "origin": "live",
            "synced_at": row.epss_synced_at.isoformat(),
            "age_hours": _age_hours(row.epss_synced_at, now),
            "ttl_hours": t["epss"],
            "value": {"epss": row.epss, "percentile": row.epss_percentile, "score_date": row.epss_date},
        }
        if has_epss
        else {"data_class": "missing"}
    )
    kev_live = row is not None and row.kev_origin == "live"
    if kev_live:
        out["sources"]["kev"] = {
            "data_class": _cls(row.kev_synced_at, "live", t["kev"], now),
            "origin": "live",
            "synced_at": row.kev_synced_at.isoformat() if row.kev_synced_at else None,
            "age_hours": _age_hours(row.kev_synced_at, now),
            "ttl_hours": t["kev"],
            "value": {"in_kev": row.in_kev, "date_added": row.kev_date_added, "due_date": row.kev_due_date,
                      "ransomware_use": row.kev_ransomware},
        }  # fmt: skip
    elif demo and demo.is_kev(cve_id):
        out["sources"]["kev"] = {"data_class": "demo", "origin": "demo", "value": {"in_kev": True}}
    else:
        out["sources"]["kev"] = {"data_class": "missing"}
    out["history"] = [
        {"source": h.source, "origin": h.origin, "observed_at": h.observed_at.isoformat(), "value": h.value}
        for h in db.scalars(
            select(IntelHistory)
            .where(IntelHistory.cve_id == cve_id)
            .order_by(IntelHistory.id.desc())
            .limit(history_limit)
        )
    ]
    return out


__all__ = ["intel_status", "cve_view", "source_status", "canonical_cpe23"]
