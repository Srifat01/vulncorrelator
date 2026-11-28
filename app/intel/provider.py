"""Where ingestion gets intelligence from. Priority: live data in the database > clearly-labelled demo data
(only when INTEL_DEMO_DATA=true) > nothing. A missing value stays missing: nothing is ever fabricated."""

from functools import lru_cache
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import CpeLookup, CveIntel
from app.services.cpe import canonical_cpe23
from app.services.intel import CatalogEntry, ThreatIntel


@lru_cache
def _demo(directory: Path) -> ThreatIntel:
    return ThreatIntel.from_dir(directory)


def _entry_from_row(row: CveIntel) -> CatalogEntry:
    first = (row.description or "").strip().split(". ")[0][:140]
    return CatalogEntry(
        cve_id=row.cve_id,
        title=f"{row.cve_id}: {first}" if first else row.cve_id,
        description=row.description,
        cvss_score=row.cvss_score,
        cvss_vector=row.cvss_vector,
        tags=tuple(row.tags or []),
        origin="nvd",
    )


class IntelProvider:
    def __init__(self, db: Session | None):
        self._db = db
        s = get_settings()
        self._demo = _demo(s.intel_dir) if s.intel_demo_data else None
        self._rows: dict[str, CveIntel | None] = {}

    def _row(self, cve_id: str | None) -> CveIntel | None:
        if not cve_id or self._db is None:
            return None
        key = cve_id.upper()
        if key not in self._rows:
            self._rows[key] = self._db.get(CveIntel, key)
        return self._rows[key]

    def lookup(self, cve_id: str | None) -> CatalogEntry | None:
        row = self._row(cve_id)
        if row is not None and row.nvd_synced_at is not None and row.nvd_origin == "live":
            return _entry_from_row(row)
        return self._demo.lookup(cve_id) if self._demo else None

    def match_product(self, product: str | None, version: str | None) -> list[CatalogEntry]:
        return self._demo.match_product(product, version) if self._demo else []

    def match_cpe(self, cpe: str | None) -> list[CatalogEntry]:
        """CVEs NVD associates with this exact CPE, from the lookup cache (no network access here)."""
        key = canonical_cpe23(cpe)
        if key is None or self._db is None:
            return []
        lookup = self._db.get(CpeLookup, key)
        if lookup is None:
            return []
        rows = self._db.scalars(select(CveIntel).where(CveIntel.cve_id.in_(lookup.cve_ids or []))).all()
        return [_entry_from_row(r) for r in sorted(rows, key=lambda r: r.cve_id)]

    def is_kev(self, cve_id: str | None) -> bool:
        row = self._row(cve_id)
        if row is not None and row.in_kev and row.kev_origin == "live":
            return True
        return bool(self._demo and self._demo.is_kev(cve_id))

    def epss_score(self, cve_id: str | None) -> float | None:
        row = self._row(cve_id)
        return row.epss if row is not None and row.epss_origin == "live" else None
