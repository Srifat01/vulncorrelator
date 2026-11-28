"""Clients and parsers for the three feeds: CISA KEV, FIRST EPSS, NVD CVE API 2.0.

Parsers validate structure and raise IntelError on anything malformed. Nothing here ever invents a value.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.intel.http import IntelError, ResilientClient
from app.services.cpe import Cpe, parse_cpe
from app.services.intel import CVE_RE, infer_tags
from app.services.versions import version_matches

# CWE -> what exploitation yields. Deliberately small and conservative; free-text inference fills the rest.
CWE_TAGS = {
    "CWE-22": "path-traversal", "CWE-78": "rce", "CWE-77": "rce", "CWE-94": "rce", "CWE-502": "rce",
    "CWE-89": "sqli", "CWE-287": "auth-bypass", "CWE-306": "auth-bypass", "CWE-269": "privesc",
    "CWE-250": "privesc", "CWE-200": "info-disclosure", "CWE-400": "dos",
}  # fmt: skip


# ------------------------------------------------------------------ CISA KEV
@dataclass
class KevEntry:
    cve_id: str
    date_added: str | None
    due_date: str | None
    ransomware: str | None
    name: str | None = None


@dataclass
class KevCatalog:
    entries: list[KevEntry]
    catalog_version: str | None = None
    etag: str | None = None
    not_modified: bool = False
    skipped: int = 0


def parse_kev(data: dict, etag: str | None = None) -> KevCatalog:
    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(vulns, list):
        raise IntelError("KEV feed malformed: no 'vulnerabilities' list")
    entries, skipped = [], 0
    for v in vulns:
        cve = str(v.get("cveID", "")).upper() if isinstance(v, dict) else ""
        if not CVE_RE.fullmatch(cve):
            skipped += 1
            continue
        entries.append(
            KevEntry(
                cve,
                v.get("dateAdded"),
                v.get("dueDate"),
                v.get("knownRansomwareCampaignUse"),
                v.get("vulnerabilityName"),
            )
        )
    if not entries:
        raise IntelError("KEV feed contained no valid entries; refusing to replace existing data")
    return KevCatalog(entries, data.get("catalogVersion"), etag, False, skipped)


def fetch_kev(client: ResilientClient, url: str, etag: str | None = None) -> KevCatalog:
    headers = {"If-None-Match": etag} if etag else None
    resp = client.get(url, headers=headers, ok=(200, 304))
    if resp.status_code == 304:
        return KevCatalog([], etag=etag, not_modified=True)
    try:
        return parse_kev(resp.json(), resp.headers.get("ETag"))
    except ValueError as exc:
        raise IntelError(f"KEV feed is not valid JSON: {exc}") from exc


# ------------------------------------------------------------------ FIRST EPSS
@dataclass
class EpssRow:
    cve_id: str
    epss: float
    percentile: float | None
    date: str | None


def fetch_epss(client: ResilientClient, base_url: str, cve_ids: list[str], batch: int = 100) -> dict[str, EpssRow]:
    out: dict[str, EpssRow] = {}
    ids = sorted({c.upper() for c in cve_ids if CVE_RE.fullmatch(c)})
    for i in range(0, len(ids), batch):
        resp = client.get(base_url, params={"cve": ",".join(ids[i : i + batch])})
        try:
            payload = resp.json()
        except ValueError as exc:
            raise IntelError(f"EPSS response is not valid JSON: {exc}") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise IntelError("EPSS response malformed: no 'data' list")
        for row in payload["data"]:
            try:
                score = float(row["epss"])
                if not 0.0 <= score <= 1.0:
                    continue
                pct = float(row["percentile"]) if row.get("percentile") not in (None, "") else None
                out[row["cve"].upper()] = EpssRow(row["cve"].upper(), score, pct, row.get("date"))
            except (KeyError, ValueError, TypeError):
                continue  # a malformed row is skipped, never defaulted
    return out


# ------------------------------------------------------------------ NVD
@dataclass
class NvdCve:
    cve_id: str
    description: str | None
    published: datetime | None
    last_modified: datetime | None
    cvss_score: float | None
    cvss_vector: str | None
    cvss_version: str | None
    cwe: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    cpe_matches: list[dict] = field(default_factory=list)  # vulnerable cpeMatch entries


def _dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        d = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)  # NVD timestamps are UTC


def _cvss(metrics: dict) -> tuple[float | None, str | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        items = metrics.get(key) or []
        if not items:
            continue
        pick = next((m for m in items if m.get("type") == "Primary"), items[0])
        data = pick.get("cvssData", {})
        if data.get("baseScore") is not None:
            return float(data["baseScore"]), data.get("vectorString"), str(data.get("version", ""))
    return None, None, None


def parse_nvd_cve(raw: dict) -> NvdCve:
    cve = raw.get("cve") if isinstance(raw, dict) else None
    if not isinstance(cve, dict) or not CVE_RE.fullmatch(str(cve.get("id", ""))):
        raise IntelError("NVD record malformed: missing CVE id")
    desc = next((d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"), None)
    score, vector, version = _cvss(cve.get("metrics") or {})
    cwe_values = {d.get("value", "") for w in cve.get("weaknesses", []) for d in w.get("description", [])}
    cwes = sorted(c for c in cwe_values if str(c).startswith("CWE-"))
    tags = sorted({CWE_TAGS[c] for c in cwes if c in CWE_TAGS} | set(infer_tags(cve["id"], desc)))
    matches = [
        m
        for conf in cve.get("configurations", [])
        for node in conf.get("nodes", [])
        for m in node.get("cpeMatch", [])
        if m.get("vulnerable") and m.get("criteria")
    ]
    return NvdCve(cve["id"].upper(), desc, _dt(cve.get("published")), _dt(cve.get("lastModified")),
                  score, vector, version, cwes, tags, matches)  # fmt: skip


def cpe_match_applies(match: dict, target: Cpe) -> bool:
    """Does one NVD cpeMatch entry cover `target`? (Used to verify NVD's answer instead of trusting it blindly.)"""
    crit = parse_cpe(match.get("criteria"))
    if crit is None or crit.vendor != target.vendor or crit.product != target.product or target.version is None:
        return False
    if crit.version is not None:  # criteria names one exact version
        return crit.version == target.version
    bounds = {
        "gte": match.get("versionStartIncluding"),
        "gt": match.get("versionStartExcluding"),
        "lte": match.get("versionEndIncluding"),
        "lt": match.get("versionEndExcluding"),
    }
    if all(v is None for v in bounds.values()):
        return True  # "all versions"
    return version_matches(target.version, **bounds)


def cve_affects_cpe(cve: NvdCve, target: Cpe) -> bool:
    return any(cpe_match_applies(m, target) for m in cve.cpe_matches)


class NvdClient:
    MAX_PAGES = 10

    def __init__(self, client: ResilientClient, base_url: str, api_key: str | None = None):
        self.client, self.base_url = client, base_url
        self.headers = {"apiKey": api_key} if api_key else None

    def _get(self, params: dict) -> dict:
        # NVD signals rate limiting with 403 as well as 429; both are worth backing off on.
        resp = self.client.get(
            self.base_url, params=params, headers=self.headers, retry_on=(403, 429, 500, 502, 503, 504)
        )
        try:
            data = resp.json()
        except ValueError as exc:
            raise IntelError(f"NVD response is not valid JSON: {exc}") from exc
        if not isinstance(data, dict) or "vulnerabilities" not in data:
            raise IntelError("NVD response malformed: no 'vulnerabilities'")
        return data

    def fetch_cve(self, cve_id: str) -> NvdCve | None:
        try:
            data = self._get({"cveId": cve_id})
        except IntelError as exc:
            if exc.status == 404:
                return None
            raise
        return parse_nvd_cve(data["vulnerabilities"][0]) if data["vulnerabilities"] else None

    def fetch_by_cpe(self, cpe23: str) -> list[NvdCve]:
        """CVEs NVD associates with an exact CPE name (NVD evaluates version ranges server-side)."""
        out, start = [], 0
        for _ in range(self.MAX_PAGES):
            try:
                data = self._get({"cpeName": cpe23, "startIndex": start, "resultsPerPage": 2000})
            except IntelError as exc:
                if exc.status in (400, 404):  # name not in the CPE dictionary => no known CVEs, not an outage
                    return out
                raise
            out += [parse_nvd_cve(v) for v in data["vulnerabilities"]]
            start += int(data.get("resultsPerPage") or len(data["vulnerabilities"]) or 1)
            if start >= int(data.get("totalResults") or 0):
                break
        return out
