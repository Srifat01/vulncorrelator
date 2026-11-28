"""Normalization engine: raw per-host data -> unified, enriched, deduplicable findings."""

from dataclasses import dataclass, field

from app.models import EVIDENCE_RANK
from app.schemas import HostIn, ServiceIn
from app.services.cpe import (
    guess_vendor_product,
    normalize_service_name,
    parse_cpe,
)
from app.services.fingerprint import fingerprint
from app.services.intel import CVE_RE, ThreatIntel, infer_tags
from app.services.risk import normalize_cvss

DERIVED_SOURCES = {"catalog", "nvd-cpe"}


@dataclass
class NormalizedFinding:
    fp_parts: dict  # inputs of fingerprint() other than the asset key
    ip_address: str
    cve_id: str | None
    title: str
    description: str | None
    cvss_score: float | None
    cvss_vector: str | None
    severity: str | None
    port: int | None
    protocol: str | None
    service_name: str | None
    product: str | None
    version: str | None
    cpe: str | None
    tags: list[str]
    epss: float | None
    in_kev: bool
    sources: list[str]
    evidence: dict = field(default_factory=dict)
    evidence_status: str = "observed"  # confirmed | observed | inferred
    cvss_source: str | None = None

    def fingerprint_for(self, asset_key: str) -> str:
        return fingerprint(asset_key=asset_key, **self.fp_parts)


@dataclass
class _Resolved:
    """Product identity after combining scanner fields, CPE and alias table."""

    product: str | None  # as displayed
    product_key: str | None  # canonical, e.g. "http_server"
    version: str | None
    cpe: str | None


def _resolve_product(product: str | None, version: str | None, cpe: str | None) -> _Resolved:
    parsed = parse_cpe(cpe)
    key = parsed.product if parsed else None
    vendor = parsed.vendor if parsed else None
    if not key:
        guess = guess_vendor_product(product)
        if guess:
            vendor, key = guess
    version = (version or (parsed.version if parsed else None) or "").strip() or None
    if not cpe and key and vendor:
        cpe = f"cpe:2.3:a:{vendor}:{key}:{version or '*'}:*:*:*:*:*:*:*"
    return _Resolved(product.strip() if product else key, key, version, cpe)


def _clean_cve(raw: str | None, title: str) -> str | None:
    for candidate in (raw, title):
        if candidate:
            m = CVE_RE.search(candidate)
            if m:
                return m.group(0).upper()
    return None


def build_findings(host: HostIn, source: str, intel: ThreatIntel) -> tuple[list[ServiceIn], list[NormalizedFinding]]:
    """Return (merged services, deduplicated findings) for one host."""
    # 1. Merge services; the reported vulnerabilities may also imply services.
    services: dict[tuple[int, str], ServiceIn] = {}
    for svc in host.services:
        services[(svc.port, svc.protocol)] = svc.model_copy(update={"name": normalize_service_name(svc.name)})
    for v in host.vulnerabilities:
        if v.port:
            services.setdefault(
                (v.port, v.protocol or "tcp"),
                ServiceIn(
                    port=v.port,
                    protocol=v.protocol or "tcp",
                    name=normalize_service_name(v.service_name),
                    product=v.product,
                    version=v.version,
                    cpe=v.cpe,
                ),
            )

    # 2. Normalize each service's product identity.
    resolved_svc: dict[tuple[int, str], _Resolved] = {
        k: _resolve_product(s.product, s.version, s.cpe) for k, s in services.items()
    }
    merged_services = [
        s.model_copy(
            update={"product": resolved_svc[k].product, "version": resolved_svc[k].version, "cpe": resolved_svc[k].cpe}
        )
        for k, s in services.items()
    ]

    findings: dict[str, NormalizedFinding] = {}

    def add(f: NormalizedFinding) -> None:
        key = f.fingerprint_for(host.ip_address)  # any stable per-host key works for in-report dedup
        existing = findings.get(key)
        if existing is None:
            findings[key] = f
            return
        # Same finding seen by several sources in one report (e.g. the scanner and the catalog):
        # merge, keeping the higher score and every source's evidence.
        existing.cvss_score = max(filter(None, [existing.cvss_score, f.cvss_score]), default=None)
        existing.tags = sorted(set(existing.tags) | set(f.tags))
        existing.sources = sorted(set(existing.sources) | set(f.sources))
        for key, value in f.evidence.items():
            existing.evidence.setdefault(key, value)
        if EVIDENCE_RANK[f.evidence_status] > EVIDENCE_RANK[existing.evidence_status]:
            existing.evidence_status = f.evidence_status

    def make(
        *,
        entry_cve: str | None,
        title: str,
        description: str | None,
        cvss: float | None,
        vector: str | None,
        severity: str | None,
        port: int | None,
        protocol: str | None,
        res: _Resolved,
        service_name: str | None,
        src: str,
        evidence: dict,
        verified: bool = False,
    ) -> NormalizedFinding:
        cve = _clean_cve(entry_cve, title)
        entry = intel.lookup(cve)
        if entry and title.strip().upper().startswith(entry.cve_id):
            title = entry.title  # scanner only gave a generic "CVE-... on <service>" title
        # CVSS attribution: only a score the scanner itself reported is "scanner"; derived findings carry the origin
        # of the intelligence they came from (nvd | demo).
        cvss_source = "scanner" if cvss is not None and src not in DERIVED_SOURCES else None
        if entry:  # fill gaps from the catalog, never override the scanner
            if entry.cvss_score is not None and (cvss is None or src in DERIVED_SOURCES):
                cvss_source = entry.origin
            cvss = cvss if cvss is not None else entry.cvss_score
            vector = vector or entry.cvss_vector
            description = description or entry.description
        score, sev = normalize_cvss(cvss, severity)
        tags = sorted(set(entry.tags if entry else ()) | set(infer_tags(title, description)))
        in_kev = intel.is_kev(cve)
        epss = intel.epss_score(cve)
        return NormalizedFinding(
            fp_parts=dict(
                port=port,
                protocol=protocol,
                cve_id=cve,
                service_name=service_name or res.product_key,
                version=res.version,
                title=title,
            ),
            ip_address=host.ip_address,
            cve_id=cve,
            title=title.strip(),
            description=description,
            cvss_score=score,
            cvss_vector=vector,
            severity=sev,
            port=port,
            protocol=protocol,
            service_name=service_name,
            product=res.product,
            version=res.version,
            cpe=res.cpe,
            tags=tags,
            epss=epss,
            in_kev=in_kev,
            sources=[src],
            evidence={src: evidence},
            # a finding is "inferred" when it only exists because we matched a version string
            evidence_status="inferred" if src in DERIVED_SOURCES else ("confirmed" if verified else "observed"),
            cvss_source=cvss_source,
        )

    # 3. Findings reported by the scanner.
    for v in host.vulnerabilities:
        port = v.port or None
        protocol = (v.protocol or "tcp") if port else None
        svc_key = (port, protocol) if port else None
        svc = services.get(svc_key) if svc_key else None
        res_svc = resolved_svc.get(svc_key) if svc_key else None
        res_own = _resolve_product(v.product, v.version, v.cpe)
        # Prefer what the finding itself says, fall back to the discovered service.
        res = _Resolved(
            res_own.product or (res_svc.product if res_svc else None),
            res_own.product_key or (res_svc.product_key if res_svc else None),
            res_own.version or (res_svc.version if res_svc else None),
            res_own.cpe or (res_svc.cpe if res_svc else None),
        )
        add(
            make(
                entry_cve=v.cve_id,
                title=v.title,
                description=v.description,
                cvss=v.cvss_score,
                vector=v.cvss_vector,
                severity=v.severity,
                port=port,
                protocol=protocol,
                res=res,
                service_name=normalize_service_name(v.service_name) or (svc.name if svc else None),
                src=source,
                evidence=v.evidence,
                verified=v.verified,
            )
        )

    # 4. Map discovered product versions to known CVEs (the "vendor name -> CVE" step).
    for key, svc in services.items():
        res = resolved_svc[key]
        for entry in intel.match_product(res.product_key, res.version):
            add(
                make(
                    entry_cve=entry.cve_id,
                    title=entry.title,
                    description=entry.description,
                    cvss=entry.cvss_score,
                    vector=entry.cvss_vector,
                    severity=None,
                    port=svc.port,
                    protocol=svc.protocol,
                    res=res,
                    service_name=svc.name,
                    src="catalog",
                    evidence={"matched_product": res.product_key, "matched_version": res.version},
                )
            )

    # 5. CVEs NVD associates with the exact CPE (looked up asynchronously by the intel worker; cached, no network here).
    for key, svc in services.items():
        res = resolved_svc[key]
        for entry in intel.match_cpe(res.cpe):
            add(
                make(
                    entry_cve=entry.cve_id,
                    title=entry.title,
                    description=entry.description,
                    cvss=entry.cvss_score,
                    vector=entry.cvss_vector,
                    severity=None,
                    port=svc.port,
                    protocol=svc.protocol,
                    res=res,
                    service_name=svc.name,
                    src="nvd-cpe",
                    evidence={"matched_cpe": res.cpe, "origin": entry.origin},
                )
            )

    return merged_services, list(findings.values())
