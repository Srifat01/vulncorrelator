"""Deterministic dedup key for findings.

The key is anchored on the *internal asset id* (see services/identity.py), never on an IP address:
a host that is renumbered keeps its findings, and an address handed to a different machine does not
inherit the previous machine's findings.

For a finding that carries a CVE, identity is (asset, port, protocol, CVE). Service name and version are
*attributes*, not identity - otherwise Nmap ("Apache httpd 2.4.49") and Nessus ("www", no version) would
each report the same flaw, and upgrading a service would fork the record. Findings without a CVE fall back to
(asset, port, protocol, service, version, normalized title).
"""

import hashlib
import re


def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:120]


def fingerprint(
    *,
    asset_key: str,
    port: int | None,
    protocol: str | None,
    cve_id: str | None,
    service_name: str | None,
    version: str | None,
    title: str,
) -> str:
    base = [asset_key, str(port or 0), (protocol or "tcp").lower()]
    if cve_id:
        parts = base + ["cve", cve_id.upper()]
    else:
        parts = base + ["finding", service_name or "", version or "", slugify(title)]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()
