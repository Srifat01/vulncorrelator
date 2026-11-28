"""A fake upstream for KEV / EPSS / NVD built on httpx.MockTransport. All CVE ids are synthetic (CVE-2099-*)."""

import json
from datetime import datetime, timezone

import httpx

from app.intel.sync import build_clients

NET = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def kev_payload(*cves, version="2026.11.01"):
    return {
        "catalogVersion": version,
        "vulnerabilities": [
            {"cveID": c, "dateAdded": "2026-10-01", "dueDate": "2026-10-22", "knownRansomwareCampaignUse": "Unknown",
             "vulnerabilityName": f"synthetic {c}"} for c in cves
        ],
    }  # fmt: skip


def epss_payload(**scores):
    return {
        "status": "OK",
        "data": [{"cve": c, "epss": str(s), "percentile": "0.9", "date": "2026-11-20"} for c, s in scores.items()],
    }


def nvd_item(cve, *, score=9.8, vector=NET, desc="Allows remote code execution.", cwe="CWE-78", matches=None, v2=None):
    metrics = {
        "cvssMetricV31": [
            {"type": "Primary", "cvssData": {"version": "3.1", "baseScore": score, "vectorString": vector}}
        ]
    }
    if v2:
        metrics["cvssMetricV2"] = [
            {"type": "Primary", "cvssData": {"version": "2.0", "baseScore": v2, "vectorString": "AV:N"}}
        ]
    return {"cve": {
        "id": cve, "published": "2026-01-01T00:00:00.000", "lastModified": "2026-06-01T12:00:00.000",
        "descriptions": [{"lang": "es", "value": "hola"}, {"lang": "en", "value": desc}],
        "metrics": metrics,
        "weaknesses": [{"description": [{"lang": "en", "value": cwe}]}],
        "configurations": [{"nodes": [{"cpeMatch": matches or []}]}],
    }}  # fmt: skip


def nvd_payload(*items, total=None, per_page=None):
    return {
        "resultsPerPage": per_page or len(items),
        "startIndex": 0,
        "totalResults": total if total is not None else len(items),
        "vulnerabilities": list(items),
    }


def cpe_match(crit, **bounds):
    return {"vulnerable": True, "criteria": crit, **bounds}


def widget(version):
    return f"cpe:2.3:a:acme:widget_server:{version}:*:*:*:*:*:*:*"


class Upstream:
    """Route requests by host. A handler may return a dict (200 JSON), an httpx.Response, or raise."""

    def __init__(self):
        self.handlers: dict[str, object] = {}
        self.log: list[httpx.Request] = []
        self.sleeps: list[float] = []

    def _dispatch(self, request: httpx.Request) -> httpx.Response:
        self.log.append(request)
        h = self.handlers[request.url.host]
        out = h(request) if callable(h) else h
        if isinstance(out, httpx.Response):
            return out
        return httpx.Response(200, json=out)

    def clients(self, settings=None):
        return build_clients(settings, transport=httpx.MockTransport(self._dispatch), sleep=self.sleeps.append)

    def hits(self, host):
        return [r for r in self.log if r.url.host == host]


def now():
    return datetime.now(timezone.utc)


def dumps(o):
    return json.dumps(o)
