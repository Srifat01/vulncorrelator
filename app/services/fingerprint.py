"""Deterministic dedup key for findings.

Design decision: for a finding that carries a CVE, identity is
(asset, port, protocol, CVE). Service name and version are *attributes* of the finding,
not part of its identity - otherwise Nmap ("Apache httpd 2.4.49") and Nessus ("www",
no version) would report the same flaw twice, and a patched/upgraded service would
fork the record. Findings without a CVE (misconfigurations, default creds, ...) have no
other stable identity, so they fall back to (asset, port, protocol, service, version,
normalized title).
"""

import hashlib
import re


def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:120]


def fingerprint(
    *,
    ip_address: str,
    port: int | None,
    protocol: str | None,
    cve_id: str | None,
    service_name: str | None,
    version: str | None,
    title: str,
) -> str:
    base = [ip_address, str(port or 0), (protocol or "tcp").lower()]
    if cve_id:
        parts = base + ["cve", cve_id.upper()]
    else:
        parts = base + ["finding", service_name or "", version or "", slugify(title)]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()
