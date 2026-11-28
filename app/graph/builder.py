"""Snapshot -> typed infrastructure graph.

Design rules (these are the correctness-critical decisions):

* Sharing a subnet creates NO connectivity. Reachability edges come only from evidence: an external scan that saw
  the port open, an observed/declared flow, or - at *inferred* confidence - a public-IP / operator flag on the asset.
* Finding a vulnerable version is NOT proof of exploitability. A scanner finding is `observed`, a version match is
  `inferred`, and only active validation by the tool is `confirmed`.
* "Remotely exploitable, and what it grants" is derived from the CVSS vector when there is one; without a vector the
  classification falls back to tags and is capped at `inferred`.
* The old "same /24 means reachable" behaviour exists only as an explicit opt-in (`assume_subnet_reachability`) and
  every edge it creates is `hypothetical`.
"""

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime

from app.graph.model import (
    STATUS_RANK,
    Edge,
    EdgeType,
    InfraGraph,
    Node,
    NodeType,
    edge_id,
    weaker,
)
from app.graph.snapshot import AssetRec, RelRec, ServiceRec, Snapshot, VulnRec
from app.services.cvss import parse_cvss3

INTERNET = "boundary:internet"
DERIVED_SOURCES = {"catalog", "nvd-cpe"}


@dataclass
class GraphOptions:
    assume_subnet_reachability: bool = False


@dataclass(frozen=True)
class VulnClass:
    remote: bool  # exploitable over the network against a service
    gains: str | None  # privilege obtained on the host: user | admin
    privesc: bool  # local escalation user -> admin
    status_cap: str | None  # "inferred" when the classification rests on tags alone
    attack_vector: str
    prerequisites: tuple[str, ...]


def classify(v: VulnRec) -> VulnClass:
    cv = parse_cvss3(v.cvss_vector)
    tags = set(v.tags)
    av = cv.attack_vector if cv else "unknown"
    gains = "admin" if "backdoor" in tags else ("user" if tags & {"rce", "auth-bypass"} else None)
    remote = bool(gains) and v.port is not None and av in ("network", "unknown")
    prereq = list(cv.prerequisites()) if cv else ["CVSS vector unavailable: prerequisites not verified"]
    return VulnClass(
        remote=remote,
        gains=gains,
        privesc="privesc" in tags,
        status_cap="inferred" if cv is None else None,
        attack_vector=av,
        prerequisites=tuple(prereq),
    )


@dataclass
class BuildResult:
    graph: InfraGraph
    stats: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def host_id(a: int) -> str:
    return f"host:{a}"


def svc_id(a: int, port: int, proto: str) -> str:
    return f"svc:{a}:{port}/{proto}"


def priv_id(a: int, level: str) -> str:
    return f"priv:{a}:{level}"


def _label(a: AssetRec) -> str:
    return f"{a.ip} ({a.hostname})" if a.hostname else a.ip


def _evidence_for_vuln(v: VulnRec) -> list[dict]:
    return [
        {
            "source": src,
            "kind": "version_match" if src in DERIVED_SOURCES else "scanner_finding",
            "detail": v.evidence.get(src, {}),
            "observed_at": v.last_seen.isoformat() if v.last_seen else None,
        }
        for src in (v.sources or ["unknown"])
    ]


def _edge(
    g: InfraGraph,
    etype: str,
    src: str,
    dst: str,
    status: str,
    source: str,
    *,
    disc: str = "",
    evidence: list[dict] | None = None,
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
    structural: bool = False,
    **attrs,
) -> Edge:
    return g.add_edge(
        Edge(
            edge_id(etype, src, dst, disc),
            etype,
            src,
            dst,
            status,
            source,
            first_seen=first_seen,
            last_seen=last_seen,
            evidence=evidence or [],
            attrs=attrs,
            structural=structural,
        )
    )


def _add_hosts(g: InfraGraph, snap: Snapshot) -> None:
    for a in snap.assets:
        h = g.add_node(
            Node(
                host_id(a.id),
                NodeType.HOST,
                _label(a),
                {
                    "asset_id": a.id,
                    "ip": a.ip,
                    "hostname": a.hostname,
                    "os": a.os,
                    "criticality": a.criticality,
                    "tags": a.tags,
                    "controls": a.controls,
                    "internet_facing": a.internet_facing,
                    "exposure_source": a.exposure_source,
                },
            )
        )
        for level in ("user", "admin"):
            g.add_node(
                Node(
                    priv_id(a.id, level),
                    NodeType.PRIVILEGE,
                    f"{level} on {_label(a)}",
                    {"asset_id": a.id, "level": level},
                )
            )
        # admin implies user; user implies access to the host. Definitional, hence structural.
        _edge(
            g, EdgeType.CAN_ACCESS, priv_id(a.id, "admin"), priv_id(a.id, "user"), "observed", "definition",
            structural=True,
        )  # fmt: skip
        _edge(g, EdgeType.CAN_ACCESS, priv_id(a.id, "user"), h.id, "observed", "definition", structural=True)
        for ip, first, last in a.interfaces or [(a.ip, a.first_seen, a.last_seen)]:  # at least the current address
            nid = f"if:{a.id}:{ip}"
            g.add_node(Node(nid, NodeType.INTERFACE, ip, {"asset_id": a.id, "ip": ip}))
            _edge(
                g, EdgeType.HOSTS, h.id, nid, "observed", "scan_observation", first_seen=first, last_seen=last,
                evidence=[{"source": "scan_observation", "kind": "address_observation", "detail": {"ip": ip}}],
            )  # fmt: skip


def _add_services(g: InfraGraph, snap: Snapshot, services_by_asset: dict[int, list[ServiceRec]]) -> None:
    for a in snap.assets:
        for s in services_by_asset.get(a.id, []):
            sid = svc_id(a.id, s.port, s.protocol)
            g.add_node(
                Node(
                    sid,
                    NodeType.SERVICE,
                    f"{s.name or s.product or 'service'} {s.port}/{s.protocol} on {a.ip}",
                    {
                        "asset_id": a.id,
                        "port": s.port,
                        "protocol": s.protocol,
                        "name": s.name,
                        "product": s.product,
                        "version": s.version,
                    },
                )
            )
            detail = {"port": s.port, "protocol": s.protocol, "product": s.product, "version": s.version}
            _edge(
                g, EdgeType.RUNS_SERVICE, host_id(a.id), sid, "observed", "scan_observation",
                first_seen=s.first_seen, last_seen=s.last_seen,
                evidence=[{"source": "scan_observation", "kind": "open_port", "detail": detail}],
            )  # fmt: skip


def _add_vulnerabilities(g: InfraGraph, snap: Snapshot, assets: dict[int, AssetRec], stats: dict) -> None:
    for v in snap.vulns:
        a = assets.get(v.asset_id)
        if a is None:
            continue
        vc = classify(v)
        nid = f"vuln:{v.id}"
        g.add_node(
            Node(
                nid,
                NodeType.VULNERABILITY,
                v.cve_id or v.title,
                {
                    "vuln_id": v.id,
                    "asset_id": a.id,
                    "cve_id": v.cve_id,
                    "title": v.title,
                    "cvss_score": v.cvss_score,
                    "tags": v.tags,
                    "in_kev": v.in_kev,
                    "epss": v.epss,
                    "risk_score": v.risk_score,
                    "threat": v.threat,
                    "port": v.port,
                    "evidence_status": v.evidence_status,
                    "remote": vc.remote,
                    "gains": vc.gains,
                    "privesc": vc.privesc,
                    "attack_vector": vc.attack_vector,
                    "prerequisites": list(vc.prerequisites),
                },
            )
        )
        sid = svc_id(a.id, v.port, v.protocol or "tcp") if v.port is not None else None
        anchor = sid if sid and g.node(sid) else host_id(a.id)
        ev = _evidence_for_vuln(v)
        src = ",".join(v.sources) or "unknown"
        common = {"first_seen": v.first_seen, "last_seen": v.last_seen, "evidence": ev}
        _edge(g, EdgeType.AFFECTED_BY, anchor, nid, v.evidence_status, src, vuln_id=v.id, **common)

        classified = weaker(v.evidence_status, vc.status_cap) if vc.status_cap else v.evidence_status
        basis = "tags_only" if vc.status_cap else "cvss_vector"
        if vc.remote and anchor == sid:
            _edge(
                g, EdgeType.CAN_EXPLOIT, nid, priv_id(a.id, vc.gains), classified, src,
                vuln_id=v.id, gains=vc.gains, classification=basis, **common,
            )  # fmt: skip
        if vc.privesc:
            _edge(
                g, EdgeType.CAN_ESCALATE_TO, priv_id(a.id, "user"), priv_id(a.id, "admin"), classified, src,
                disc=str(v.id), vuln_id=v.id, classification=basis, **common,
            )  # fmt: skip
        if not (vc.remote or vc.privesc):
            stats["unclassified_vulnerabilities"] += 1


def _add_boundaries(g: InfraGraph, snap: Snapshot, ip_of: dict) -> None:
    for b in snap.boundaries:
        bid = f"boundary:{b.name}"
        g.add_node(Node(bid, NodeType.BOUNDARY, b.name, {"name": b.name, "kind": "zone", "cidrs": b.cidrs}))
        nets = [ipaddress.ip_network(c, strict=False) for c in b.cidrs]
        for a in snap.assets:
            ip = ip_of[a.id]
            if any(ip in n for n in nets if n.version == ip.version):
                _edge(
                    g, EdgeType.HOSTS, bid, host_id(a.id), "observed", "operator",
                    evidence=[{"source": "operator", "kind": "zone_membership", "detail": {"cidrs": b.cidrs}}],
                )  # fmt: skip


def _add_relationships(
    g: InfraGraph,
    snap: Snapshot,
    assets: dict[int, AssetRec],
    ip_of: dict,
    services_by_asset: dict[int, list[ServiceRec]],
    stats: dict,
) -> set[str]:
    """Flows, credentials and trusts. Returns the services that have an explicit internet flow."""

    def assets_for(ref: str) -> list[int]:
        kind, _, val = ref.partition(":")
        try:
            if kind == "asset":
                return [int(val)] if int(val) in assets else []
            if kind == "ip":
                ip = ipaddress.ip_address(val)
                return [i for i, x in ip_of.items() if x == ip]
            if kind == "cidr":
                net = ipaddress.ip_network(val, strict=False)
                return [i for i, x in ip_of.items() if x.version == net.version and x in net]
        except ValueError:
            pass
        return []

    def target_services(asset_id: int, port: int, proto: str) -> list[ServiceRec]:
        return [
            s
            for s in services_by_asset.get(asset_id, [])
            if (port == 0 or s.port == port) and (proto == "any" or s.protocol == proto)
        ]

    def rel_edge(r: RelRec, etype: str, src: str, dst: str, disc: str, **attrs) -> None:
        _edge(
            g, etype, src, dst, r.evidence_status, r.source, disc=f"{r.id}:{disc}",
            first_seen=r.first_seen, last_seen=r.last_seen,
            evidence=[{"source": r.source, "kind": "relationship", "detail": {"relationship_id": r.id, **r.attrs}}],
            relationship_id=r.id, **attrs,
        )  # fmt: skip

    covered_internet: set[str] = set()
    for r in snap.relationships:
        made = False
        if r.kind == "CONNECTS_TO":
            srcs = [INTERNET] if r.src == "internet" else [priv_id(i, "user") for i in assets_for(r.src)]
            for dst_asset in assets_for(r.dst):
                for s in target_services(dst_asset, r.port, r.protocol):
                    dst = svc_id(dst_asset, s.port, s.protocol)
                    for src in srcs:
                        if src != priv_id(dst_asset, "user"):
                            rel_edge(r, EdgeType.CONNECTS_TO, src, dst, dst, port=s.port, protocol=s.protocol)
                            made = True
                    if r.src == "internet":
                        covered_internet.add(dst)
        elif r.kind == "AUTHENTICATES_TO":
            name = r.src.partition(":")[2]
            ident = f"ident:{name}"
            g.add_node(Node(ident, NodeType.IDENTITY, name, {"name": name}))
            grants = r.attrs.get("grants", "user")
            for dst_asset in assets_for(r.dst):
                for s in target_services(dst_asset, r.port, r.protocol):
                    sid = svc_id(dst_asset, s.port, s.protocol)
                    rel_edge(r, EdgeType.AUTHENTICATES_TO, ident, sid, sid)
                    rel_edge(r, EdgeType.CAN_ACCESS, sid, priv_id(dst_asset, grants), "login", via_identity=ident)
                    made = True
        elif r.kind == "CAN_ACCESS":  # credential material obtainable on an asset
            name = r.dst.partition(":")[2]
            ident = f"ident:{name}"
            g.add_node(Node(ident, NodeType.IDENTITY, name, {"name": name}))
            for a_id in assets_for(r.src):
                rel_edge(r, EdgeType.CAN_ACCESS, priv_id(a_id, r.attrs.get("requires", "admin")), ident, "cred")
                made = True
        elif r.kind == "SHARES_TRUST_WITH":
            for a_id in assets_for(r.src):
                for b_id in assets_for(r.dst):
                    if a_id != b_id:
                        src = priv_id(a_id, r.attrs.get("requires", "admin"))
                        dst = priv_id(b_id, r.attrs.get("grants", "user"))
                        rel_edge(r, EdgeType.SHARES_TRUST_WITH, src, dst, f"{a_id}>{b_id}")
                        made = True
        if not made:
            stats["unresolved_relationships"] += 1
    return covered_internet


def _add_inferred_exposure(
    g: InfraGraph, snap: Snapshot, services_by_asset: dict[int, list[ServiceRec]], covered: set[str]
) -> None:
    """Asset-level 'internet-facing' flag => each of its services gets an *inferred* internet edge."""
    for a in snap.assets:
        if not a.internet_facing:
            continue
        for s in services_by_asset.get(a.id, []):
            sid = svc_id(a.id, s.port, s.protocol)
            if sid in covered:
                continue
            note = (
                "the asset is flagged internet-facing, but no external scan or flow confirmed that this "
                "specific port is reachable"
            )
            _edge(
                g, EdgeType.CONNECTS_TO, INTERNET, sid, "inferred", f"asset_flag:{a.exposure_source}",
                disc="exposure", first_seen=a.first_seen, last_seen=a.last_seen,
                evidence=[
                    {
                        "source": f"asset_flag:{a.exposure_source}",
                        "kind": "asset_level_exposure",
                        "detail": {"note": note, "exposure_source": a.exposure_source},
                    }
                ],
                port=s.port, protocol=s.protocol,
            )  # fmt: skip


def _add_subnet_assumptions(
    g: InfraGraph, snap: Snapshot, ip_of: dict, services_by_asset: dict[int, list[ServiceRec]]
) -> None:
    existing = {(e.src, e.dst) for e in g.edges(EdgeType.CONNECTS_TO)}
    by_net: dict[str, list[AssetRec]] = {}
    for a in snap.assets:
        ip = ip_of[a.id]
        net = ipaddress.ip_network(f"{ip}/{24 if ip.version == 4 else 64}", strict=False)
        by_net.setdefault(str(net), []).append(a)
    note = "hosts share a subnet; connectivity is ASSUMED, not observed"
    for members in by_net.values():
        for a in members:
            for b in members:
                if a.id == b.id:
                    continue
                for s in services_by_asset.get(b.id, []):
                    sid = svc_id(b.id, s.port, s.protocol)
                    if (priv_id(a.id, "user"), sid) in existing:
                        continue
                    _edge(
                        g, EdgeType.CONNECTS_TO, priv_id(a.id, "user"), sid, "hypothetical", "assumption:same_subnet",
                        disc="subnet-assumption",
                        evidence=[{"source": "assumption:same_subnet", "kind": "assumption", "detail": {"note": note}}],
                        port=s.port, protocol=s.protocol,
                    )  # fmt: skip


def build_graph(snap: Snapshot, opts: GraphOptions | None = None) -> BuildResult:
    opts = opts or GraphOptions()
    g, warnings = InfraGraph(), []
    stats: dict = {"unresolved_relationships": 0, "unclassified_vulnerabilities": 0}

    assets = {a.id: a for a in snap.assets}
    ip_of = {a.id: ipaddress.ip_address(a.ip) for a in snap.assets}
    services_by_asset: dict[int, list[ServiceRec]] = {}
    for s in snap.services:
        if s.asset_id in assets:
            services_by_asset.setdefault(s.asset_id, []).append(s)

    g.add_node(Node(INTERNET, NodeType.BOUNDARY, "internet", {"name": "internet", "kind": "internet"}))
    _add_hosts(g, snap)
    _add_services(g, snap, services_by_asset)
    _add_vulnerabilities(g, snap, assets, stats)
    _add_boundaries(g, snap, ip_of)
    covered = _add_relationships(g, snap, assets, ip_of, services_by_asset, stats)
    _add_inferred_exposure(g, snap, services_by_asset, covered)
    if opts.assume_subnet_reachability:
        _add_subnet_assumptions(g, snap, ip_of, services_by_asset)

    stats.update(
        nodes=g.number_of_nodes(),
        edges=g.number_of_edges(),
        nodes_by_type={t: sum(1 for _ in g.nodes(t)) for t in NodeType.ALL},
        edges_by_type={t: sum(1 for _ in g.edges(t)) for t in EdgeType.ALL},
        edges_by_status={
            s: sum(1 for e in g.edges() if e.evidence_status == s and not e.structural) for s in STATUS_RANK
        },
        cyclic_components=[
            [int(h.split(":")[1]) for h in comp]
            for comp in g.strongly_connected_components(
                (EdgeType.CONNECTS_TO, EdgeType.SHARES_TRUST_WITH, EdgeType.AUTHENTICATES_TO), NodeType.HOST
            )
        ][:20],
    )
    if stats["unresolved_relationships"]:
        warnings.append(
            f"{stats['unresolved_relationships']} relationship(s) could not be resolved to known assets/services "
            "and were ignored"
        )
    return BuildResult(g, stats, warnings)
