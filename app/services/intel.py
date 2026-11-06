"""Threat-intel enrichment: CVE catalog (product/version -> CVE), CISA KEV, EPSS."""

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from app.config import get_settings
from app.services.versions import version_matches

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

# Fallback classifier for CVEs that are not in the catalog.
_TAG_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    ("rce", ("remote code execution", "arbitrary code execution", "command injection", "rce")),
    ("backdoor", ("backdoor",)),
    ("privesc", ("privilege escalation", "elevation of privilege", "local privilege")),
    ("auth-bypass", ("authentication bypass", "auth bypass", "default credentials")),
    ("sqli", ("sql injection",)),
    ("path-traversal", ("path traversal", "directory traversal")),
    ("info-disclosure", ("information disclosure", "information leak")),
    ("dos", ("denial of service",)),
]


def infer_tags(title: str, description: str | None) -> list[str]:
    text = f"{title} {description or ''}".lower()
    return [tag for tag, words in _TAG_KEYWORDS if any(w in text for w in words)]


@dataclass(frozen=True)
class CatalogEntry:
    cve_id: str
    title: str
    description: str | None
    cvss_score: float | None
    cvss_vector: str | None
    tags: tuple[str, ...]
    affects: tuple[dict, ...] = field(default_factory=tuple)

    def matches(self, product: str, version: str) -> bool:
        for rule in self.affects:
            if rule["product"] != product:
                continue
            if version_matches(version, exact=rule.get("versions")) and rule.get("versions"):
                return True
            for rng in rule.get("ranges", []):
                if version_matches(version, **rng):
                    return True
        return False


class ThreatIntel:
    def __init__(
        self,
        catalog: list[CatalogEntry],
        kev: set[str] | None = None,
        epss: dict[str, float] | None = None,
    ):
        self._by_cve = {e.cve_id: e for e in catalog}
        self._catalog = catalog
        self.kev = {c.upper() for c in (kev or set())}
        self.epss = {k.upper(): float(v) for k, v in (epss or {}).items()}

    @classmethod
    def from_dir(cls, directory: Path) -> "ThreatIntel":
        def load(name: str) -> dict:
            path = directory / name
            return json.loads(path.read_text()) if path.exists() else {}

        entries = [
            CatalogEntry(
                cve_id=e["cve_id"].upper(),
                title=e["title"],
                description=e.get("description"),
                cvss_score=e.get("cvss_score"),
                cvss_vector=e.get("cvss_vector"),
                tags=tuple(e.get("tags", [])),
                affects=tuple(e.get("affects", [])),
            )
            for e in load("cve_catalog.json").get("entries", [])
        ]
        return cls(
            entries,
            set(load("kev.json").get("cve_ids", [])),
            load("epss.json").get("scores", {}),
        )

    def lookup(self, cve_id: str | None) -> CatalogEntry | None:
        return self._by_cve.get(cve_id.upper()) if cve_id else None

    def match_product(self, product: str | None, version: str | None) -> list[CatalogEntry]:
        if not product or not version:
            return []
        return [e for e in self._catalog if e.matches(product, version)]

    def is_kev(self, cve_id: str | None) -> bool:
        return bool(cve_id) and cve_id.upper() in self.kev

    def epss_score(self, cve_id: str | None) -> float | None:
        return self.epss.get(cve_id.upper()) if cve_id else None


@lru_cache
def get_intel() -> ThreatIntel:
    return ThreatIntel.from_dir(get_settings().intel_dir)
