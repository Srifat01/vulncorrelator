"""Turn a found path into a structured, auditable explanation.

Nothing here invents evidence: every claim traces to an edge, and anything that is NOT known is listed under
`assumptions` / `missing_evidence`. Confidence is the *weakest link* of the evidential edges (not a product, not a
probability), and the path's evidence class can only be as strong as that link.
"""

import hashlib
import math
from datetime import datetime, timedelta, timezone

from app.graph.builder import INTERNET
from app.graph.model import STATUS_RANK, Edge, EdgeType, GraphView, Node
from app.graph.paths import FoundPath, PathParams, Transition, _asset_of, _threat
from app.risk.config import RiskModelConfig

ACTIONS = {"escalate": "privilege_escalation", "credential": "credential_use", "trust": "trust_pivot"}


def _rf(factor: str, value, detail: str) -> dict:
    return {"factor": factor, "value": value, "detail": detail}


def confidence_level(c: float) -> str:
    return "high" if c >= 0.85 else "medium" if c >= 0.6 else "low" if c >= 0.3 else "very_low"


def path_evidence_status(statuses: list[str]) -> str:
    """confirmed: every link verified | observed: every link seen | partially_inferred: some inferred | hypothetical."""
    if "hypothetical" in statuses:
        return "hypothetical"
    if "inferred" in statuses:
        return "partially_inferred"
    if all(s == "confirmed" for s in statuses):
        return "confirmed"
    return "observed"


def host_label(graph: GraphView, asset_id: int | None) -> str:
    n = graph.node(f"host:{asset_id}")
    return n.label if n else f"asset {asset_id}"


def _zones(graph: GraphView, asset_id: int | None) -> list[str]:
    return sorted(
        e.src.removeprefix("boundary:")
        for e in graph.in_edges(f"host:{asset_id}", EdgeType.HOSTS)
        if e.src.startswith("boundary:") and e.src != INTERNET
    )


def _ev(e: Edge, role: str = "evidence") -> dict:
    return {
        "edge_id": e.id,
        "edge_type": e.type,
        "role": role,
        "evidence_status": e.evidence_status,
        "confidence": e.confidence,
        "source": e.source,
        "first_seen": e.first_seen.isoformat() if e.first_seen else None,
        "last_seen": e.last_seen.isoformat() if e.last_seen else None,
        "detail": e.evidence,
    }


def _vuln(v: Node, selected: bool) -> dict:
    return {
        "vulnerability_id": v.attrs.get("vuln_id"),
        "cve_id": v.attrs.get("cve_id"),
        "title": v.attrs.get("title") or v.label,
        "cvss_score": v.attrs.get("cvss_score"),
        "risk_score": v.attrs.get("risk_score"),
        "evidence_status": v.attrs.get("evidence_status"),
        "selected": selected,
    }


def _aware(dt: datetime | None) -> datetime | None:
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _step(graph: GraphView, i: int, t: Transition, entry: str, entry_kind: str, stale: timedelta, now: datetime):
    a = _asset_of(graph, t.dst)
    here = host_label(graph, a)
    src_label = "internet" if t.src == INTERNET else graph.node(t.src).label
    action = ACTIONS.get(t.kind) or ("initial_access" if t.src == INTERNET else "lateral_movement")
    prereq: list[str] = []
    missing: list[str] = []
    svc = t.service.attrs if t.service else None
    svc_txt = f"{svc['port']}/{svc['protocol']} ({svc.get('product') or svc.get('name') or 'service'})" if svc else ""

    if t.kind == "exploit":
        prereq.append(f"network reachability from {src_label} to {svc_txt} on {here}")
        prereq += [f"exploit prerequisite: {x}" for x in t.vuln.attrs.get("prerequisites", [])]
        v = t.vuln
        what = f"{v.attrs.get('cve_id') or v.attrs.get('title')}"
        desc = (
            f"From {src_label}, reach {svc_txt} on {here} and exploit {what} to obtain "
            f"{t.dst.rsplit(':', 1)[1]}-level access."
        )
    elif t.kind == "escalate":
        v = t.vuln
        prereq.append(f"existing unprivileged code execution on {here}")
        prereq += [f"exploit prerequisite: {x}" for x in v.attrs.get("prerequisites", [])]
        desc = f"On {here}, escalate from user to admin using {v.attrs.get('cve_id') or v.attrs.get('title')}."
    elif t.kind == "credential":
        prereq.append(
            f"{t.edges[0].src.rsplit(':', 1)[1]}-level access on {src_label.split(' on ')[-1]} to read the credential"
        )
        prereq.append(f"network reachability to {svc_txt} on {here}")
        cred = t.identity.removeprefix("ident:")
        desc = f"Use credential '{cred}' (obtainable on {src_label}) to log in to {svc_txt} on {here}."
        missing.append(f"credential '{t.identity.removeprefix('ident:')}' reuse is declared, not demonstrated")
    else:  # trust
        prereq.append(f"{t.edges[0].src.rsplit(':', 1)[1]}-level access on {src_label.split(' on ')[-1]}")
        desc = f"{src_label} is trusted by {here}; compromising it grants {t.dst.rsplit(':', 1)[1]}-level access there."
        missing.append("the trust relationship is declared; the network path that carries it is not evaluated")

    for e in t.edges:
        if e.evidence_status == "inferred":
            if e.type == EdgeType.CONNECTS_TO and e.attrs.get("port") is not None and e.source.startswith("asset_flag"):
                missing.append(
                    f"reachability of {e.attrs['port']}/{e.attrs['protocol']} on {here} from the internet is inferred "
                    f"from an asset-level flag ({e.source.split(':', 1)[1]}); no external scan verified it"
                )
            elif e.type in (EdgeType.AFFECTED_BY, EdgeType.CAN_EXPLOIT, EdgeType.CAN_ESCALATE_TO):
                if e.attrs.get("classification") == "tags_only":
                    missing.append(
                        f"impact of {t.vuln.attrs.get('cve_id') or t.vuln.attrs.get('title')} is classified from tags "
                        "only (no CVSS vector), so remote exploitability is assumed"
                    )
                else:
                    missing.append(
                        f"{t.vuln.attrs.get('cve_id') or t.vuln.attrs.get('title')} on {here} is inferred from a "
                        "version match; no scanner validated that it is exploitable"
                    )
        elif e.evidence_status == "hypothetical":
            missing.append(f"hypothetical link ({e.source}): {e.evidence[0]['detail'].get('note', 'assumption')}")
        ls = _aware(e.last_seen)
        if ls and now - ls > stale:
            missing.append(f"evidence '{e.type}' ({e.source}) was last seen {(now - ls).days} days ago")
    sc = [e.confidence for e in t.edges]
    statuses = [e.evidence_status for e in t.edges]
    weakest = min(statuses, key=lambda s: STATUS_RANK[s])
    vulns = []
    if t.vuln:
        vulns = [_vuln(t.vuln, True)] + [_vuln(x, False) for x in t.alternatives]
    return {
        "order": i + 1,
        "action": action,
        "from_position": src_label,
        "to_position": graph.node(t.dst).label,
        "asset_id": a,
        "asset": here,
        "service": {k: svc[k] for k in ("port", "protocol", "name", "product", "version")} if svc else None,
        "vulnerabilities": vulns,
        "identity": t.identity.removeprefix("ident:") if t.identity else None,
        "prerequisites": prereq,
        "confidence": min(sc),
        "evidence_status": weakest,
        "evidence": [_ev(e) for e in t.edges] + [_ev(e, "supporting") for e in t.supporting],
        "description": desc,
    }, missing


def assemble_path(
    graph: GraphView, found: FoundPath, cfg: RiskModelConfig, params: PathParams, now: datetime | None = None,
    stale_days: int = 30,
) -> dict:  # fmt: skip
    now = now or datetime.now(timezone.utc)
    stale = timedelta(days=stale_days)
    steps, missing, assumptions = [], [], []
    for i, t in enumerate(found.transitions):
        s, m = _step(graph, i, t, found.entry, found.entry_kind, stale, now)
        steps.append(s)
        missing += m

    all_edges = [e for t in found.transitions for e in t.edges]
    conf = min(e.confidence for e in all_edges)
    status = path_evidence_status([e.evidence_status for e in all_edges])

    entry_asset = None
    if found.entry_kind == "internet":
        assumptions.append("the attacker starts on the internet with no prior access")
        entry = {"kind": "internet", "label": "internet"}
    else:
        entry_asset = host_label(graph, _asset_of(graph, found.entry))
        entry = {"kind": "assumed_foothold", "label": entry_asset, "asset_id": _asset_of(graph, found.entry)}
        assumptions.append(
            f"ASSUMPTION: the attacker already has user-level control of {entry_asset} (analyst-supplied foothold)"
        )
        status = "hypothetical"  # the starting point itself is an assumption
        conf = min(conf, 0.15)
    if any(t.kind == "credential" for t in found.transitions):
        assumptions.append(
            "credentials found on a compromised host are assumed reusable from any position already held"
        )
    if any(e.evidence_status == "hypothetical" for e in all_edges):
        assumptions.append("hypothetical links (assumed reachability) are included; treat this path as a what-if")

    last = found.transitions[-1]
    target_id = _asset_of(graph, last.dst)
    target_node = graph.node(f"host:{target_id}")
    level = last.dst.rsplit(":", 1)[1]
    crit = int(target_node.attrs.get("criticality") or 3)

    controls = sorted(
        {
            f"{c} on {host_label(graph, s['asset_id'])}"
            for s in steps
            for c in (graph.node(f"host:{s['asset_id']}").attrs.get("controls") or [])
        }
    )
    if controls:
        missing.append(
            "declared security controls (" + ", ".join(controls) + ") may block individual steps; their effect on "
            "path feasibility is not modelled"
        )

    # ---- prioritisation (documented in README "Attack-path scoring")
    factors = []
    for t in found.transitions:
        f = _threat(t.vuln) if t.vuln else cfg.path_nonvuln_step_factor
        factors.append(f if f > 0 else cfg.path_unknown_threat)
    geo = math.exp(sum(math.log(max(f, 1e-6)) for f in factors) / len(factors))
    tv = cfg.criticality_factor(crit)
    length = cfg.path_length_decay ** (len(factors) - 1)
    score = round(10 * tv * geo * length, 2)
    risk_factors = [
        _rf("target_criticality", crit, f"{host_label(graph, target_id)} (business-impact factor {tv})"),
        _rf(
            "step_exploitability",
            round(geo, 3),
            "geometric mean of each step's threat (exploitation likelihood x attackability); "
            "credential/trust steps use a fixed factor",
        ),
        _rf(
            "path_length",
            len(steps),
            f"x{round(length, 3)} for {len(steps)} steps (decay {cfg.path_length_decay} per extra step)",
        ),
        _rf(
            "evidence_class",
            status,
            "reported separately from the score: a high-scoring path can still be weakly evidenced",
        ),
    ]
    kev = []
    for s_ in steps:
        top = s_["vulnerabilities"][:1]
        if top and graph.node(f"vuln:{top[0]['vulnerability_id']}").attrs.get("in_kev"):
            kev.append(top[0]["cve_id"] or top[0]["title"])
    if kev:
        risk_factors.append(
            _rf(
                "known_exploited", ", ".join(kev), "uses vulnerabilities on CISA's Known Exploited Vulnerabilities list"
            )
        )

    cves = [v["cve_id"] for s in steps for v in s["vulnerabilities"][:1] if v["cve_id"]]
    pid = hashlib.sha1((found.entry + "|" + "|".join(e.id for e in all_edges)).encode()).hexdigest()[:16]
    zones, prev = [], ["internet"] if found.entry_kind == "internet" else _zones(graph, _asset_of(graph, found.entry))
    for s in steps:
        cur = _zones(graph, s["asset_id"])
        if cur != prev and (cur or prev):
            zones.append(
                {"step": s["order"], "from": prev or ["(no declared zone)"], "to": cur or ["(no declared zone)"]}
            )
        prev = cur
    label = {
        "confirmed": "confirmed exploit chain",
        "observed": "observed attack path",
        "partially_inferred": "partially inferred attack path",
        "hypothetical": "hypothetical scenario",
    }[status]
    return {
        "path_id": pid,
        "confidence": round(conf, 2),
        "confidence_level": confidence_level(conf),
        "confidence_semantics": "ordinal_uncalibrated",
        "evidence_status": status,
        "is_confirmed_exploit_chain": status == "confirmed",
        "entry": entry,
        "entry_asset": entry_asset,
        "target_asset": host_label(graph, target_id),
        "target_asset_id": target_id,
        "hop_count": len(steps),
        "priority_score": score,
        "steps": steps,
        "assumptions": assumptions,
        "missing_evidence": list(dict.fromkeys(missing)),
        "risk_factors": risk_factors,
        "potential_impact": {
            "target_asset_id": target_id,
            "target_asset": host_label(graph, target_id),
            "target_criticality": crit,
            "privilege_gained": level,
            "summary": f"{level}-level compromise of {host_label(graph, target_id)} (criticality {crit}/5)",
        },
        "boundaries_crossed": zones,
        "cves": list(dict.fromkeys(cves)),
        "summary": f"{label.capitalize()}: {entry['label']} -> {host_label(graph, target_id)} in {len(steps)} step(s)",
    }
