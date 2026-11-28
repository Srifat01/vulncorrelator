"""Tiny DSL for building graph snapshots with known structure."""

from datetime import datetime, timezone

from app.graph.builder import GraphOptions, build_graph
from app.graph.explain import assemble_path
from app.graph.paths import PathParams, find_attack_paths
from app.graph.schemas import PathOut
from app.graph.snapshot import AssetRec, RelRec, ServiceRec, Snapshot, VulnRec
from app.risk.config import RiskModelConfig

NET = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # remote, no auth, no interaction
LOCAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"  # local, low privileges
NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)


def asset(i, ip, *, crit=3, exposed=False, name=None, **kw):
    return AssetRec(
        i,
        ip,
        hostname=name or f"h{i}",
        criticality=crit,
        internet_facing=exposed,
        exposure_source="declared" if exposed else "unknown",
        first_seen=NOW,
        last_seen=NOW,
        **kw,
    )


def svc(a, port, proto="tcp", **kw):
    return ServiceRec(a, port, proto, kw.pop("name", "svc"), first_seen=NOW, last_seen=NOW, **kw)


def vuln(i, a, port, tags, *, vector=NET, cve=None, status="observed", **kw):
    return VulnRec(i, a, kw.pop("title", f"vuln {i}"), cve or f"CVE-2099-{i:04d}", port, "tcp" if port else None,
                   list(tags), kw.pop("cvss", 9.8), vector, status, kw.pop("sources", ["scanner"]), {},
                   first_seen=NOW, last_seen=NOW, **kw)  # fmt: skip


def rel(i, kind, src, dst, port=0, status="observed", source="operator", proto="any", **attrs):
    return RelRec(i, kind, src, dst, status, source, port, proto, attrs, NOW, NOW)


def flow(i, src, dst, port=0, status="observed"):
    return rel(i, "CONNECTS_TO", src, dst, port, status)


def analyse(snap: Snapshot, *, opts=None, **params):
    """Build -> search -> assemble. Returns (paths as validated dicts, SearchResult, BuildResult)."""
    built = build_graph(snap, opts or GraphOptions())
    p = PathParams(**params)
    res = find_attack_paths(built.graph, p)
    cfg = RiskModelConfig()
    out = [assemble_path(built.graph, f, cfg, p, now=NOW, stale_days=30) for f in res.paths]
    for o in out:
        PathOut.model_validate(o)  # the API contract holds for every path we generate
    return out, res, built


def chain_of(path):
    """('10.0.0.1' -> ...) asset sequence of a path, for readable assertions."""
    return [s["asset_id"] for s in path["steps"]]
