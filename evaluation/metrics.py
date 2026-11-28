"""Scoring: path precision/recall, false-positive/negative rates, evidence-class accuracy, graph accuracy, and a
measured comparison against the legacy rule engine."""

import time
import tracemalloc
from dataclasses import dataclass

from app.graph.builder import GraphOptions, build_graph
from app.graph.explain import assemble_path
from app.graph.paths import PathParams, find_attack_paths
from app.graph.snapshot import Snapshot
from app.risk.config import RiskModelConfig
from app.services.chains import AssetNode, VulnNode, find_chains
from evaluation.scenarios import NOW, PathKey, Scenario

STATUS_RANK = {"hypothetical": 0, "partially_inferred": 1, "observed": 2, "confirmed": 3}


@dataclass
class EngineRun:
    paths: list[dict]
    truncated: bool
    expansions: int
    build_stats: dict
    seconds_build: float
    seconds_search: float
    seconds_explain: float
    peak_bytes: int


def run_engine(
    snap: Snapshot, *, max_steps: int = 5, max_paths: int = 5000, track_memory: bool = False, **params
) -> EngineRun:
    cfg = RiskModelConfig()
    if track_memory:
        tracemalloc.start()
    t0 = time.perf_counter()
    built = build_graph(snap, GraphOptions())
    t1 = time.perf_counter()
    pp = PathParams(max_steps=max_steps, max_paths=max_paths, **params)
    res = find_attack_paths(built.graph, pp)
    t2 = time.perf_counter()
    paths = [assemble_path(built.graph, f, cfg, pp, now=NOW) for f in res.paths]
    t3 = time.perf_counter()
    peak = 0
    if track_memory:
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
    return EngineRun(paths, res.truncated, res.expansions, built.stats, t1 - t0, t2 - t1, t3 - t2, peak)


def path_key(p: dict) -> PathKey:
    out = []
    for s in p["steps"]:
        sel = next((v["vulnerability_id"] for v in s["vulnerabilities"] if v["selected"]), None)
        out.append((s["asset_id"], s["action"], sel if sel is not None else s.get("identity")))
    return tuple(out)


def prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(p, 4), "recall": round(r, 4),
            "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0}  # fmt: skip


def score_paths(sc: Scenario, paths: list[dict]) -> dict:
    internet = {path_key(p): p for p in paths if p["entry"]["kind"] == "internet"}
    truth = set(sc.truth_paths)
    tp, fp, fn = truth & set(internet), set(internet) - truth, truth - set(internet)
    exact = sum(1 for k in tp if internet[k]["evidence_status"] == sc.truth_paths[k])
    overstated = sum(1 for k in tp if STATUS_RANK[internet[k]["evidence_status"]] > STATUS_RANK[sc.truth_paths[k]])
    touched = {s["asset_id"] for p in paths for s in p["steps"]}
    out = prf(len(tp), len(fp), len(fn))
    out.update(
        evidence_class_accuracy=round(exact / len(tp), 4) if tp else 1.0,
        evidence_overstated=overstated,  # safety metric: must be 0
        decoys=len(sc.decoys),
        decoys_flagged=len(sc.decoys & touched),
        decoy_false_positive_rate=round(len(sc.decoys & touched) / len(sc.decoys), 4) if sc.decoys else 0.0,
        false_negative_rate=round(len(fn) / len(truth), 4) if truth else 0.0,
        per_kind_recall={},
    )
    for kind in sorted(set(sc.kinds.values())):
        ks = {k for k, v in sc.kinds.items() if v == kind}
        out["per_kind_recall"][kind] = {"n": len(ks), "found": len(ks & set(internet))}
    return out


# ------------------------------------------------------------------ graph construction accuracy
def expected_edges(snap: Snapshot) -> set[tuple[str, str, str]]:
    """What the graph SHOULD contain, derived directly from the snapshot (independent of app.graph.builder)."""
    E: set[tuple[str, str, str]] = set()
    svc = {(s.asset_id, s.port, s.protocol) for s in snap.services}
    by_asset: dict[int, list[tuple[int, str]]] = {}
    for a, p, pr in svc:
        by_asset.setdefault(a, []).append((p, pr))
        E.add(("RUNS_SERVICE", f"host:{a}", f"svc:{a}:{p}/{pr}"))
    for v in snap.vulns:
        s = (v.asset_id, v.port, v.protocol or "tcp")
        anchor = f"svc:{s[0]}:{s[1]}/{s[2]}" if v.port is not None and s in svc else f"host:{v.asset_id}"
        E.add(("AFFECTED_BY", anchor, f"vuln:{v.id}"))
        tags = set(v.tags)
        gain = "admin" if "backdoor" in tags else "user" if tags & {"rce", "auth-bypass"} else None
        if gain and v.port is not None and v.cvss_vector and "AV:N" in v.cvss_vector and anchor.startswith("svc:"):
            E.add(("CAN_EXPLOIT", f"vuln:{v.id}", f"priv:{v.asset_id}:{gain}"))
        if "privesc" in tags:
            E.add(("CAN_ESCALATE_TO", f"priv:{v.asset_id}:user", f"priv:{v.asset_id}:admin"))
    covered: set[str] = set()
    aid = lambda ref: int(ref.split(":")[1]) if ref.startswith("asset:") else None  # noqa: E731
    for r in snap.relationships:
        if r.kind == "CONNECTS_TO":
            d = aid(r.dst)
            for p, pr in by_asset.get(d, []):
                if r.port in (0, p) and r.protocol in ("any", pr):
                    node = f"svc:{d}:{p}/{pr}"
                    if r.src == "internet":
                        E.add(("CONNECTS_TO", "boundary:internet", node))
                        covered.add(node)
                    elif aid(r.src) is not None and aid(r.src) != d:
                        E.add(("CONNECTS_TO", f"priv:{aid(r.src)}:user", node))
        elif r.kind == "SHARES_TRUST_WITH" and aid(r.src) and aid(r.dst) and aid(r.src) != aid(r.dst):
            E.add(("SHARES_TRUST_WITH", f"priv:{aid(r.src)}:{r.attrs.get('requires', 'admin')}",
                   f"priv:{aid(r.dst)}:{r.attrs.get('grants', 'user')}"))  # fmt: skip
        elif r.kind == "CAN_ACCESS" and aid(r.src):
            E.add(
                ("CAN_ACCESS", f"priv:{aid(r.src)}:{r.attrs.get('requires', 'admin')}", "ident:" + r.dst.split(":")[1])
            )
        elif r.kind == "AUTHENTICATES_TO":
            d, name = aid(r.dst), r.src.split(":")[1]
            for p, pr in by_asset.get(d, []):
                if r.port in (0, p) and r.protocol in ("any", pr):
                    node = f"svc:{d}:{p}/{pr}"
                    E.add(("AUTHENTICATES_TO", f"ident:{name}", node))
                    E.add(("CAN_ACCESS", node, f"priv:{d}:{r.attrs.get('grants', 'user')}"))
    for a in snap.assets:
        if a.internet_facing:
            for p, pr in by_asset.get(a.id, []):
                if f"svc:{a.id}:{p}/{pr}" not in covered:
                    E.add(("CONNECTS_TO", "boundary:internet", f"svc:{a.id}:{p}/{pr}"))
    return E


CHECKED = {"RUNS_SERVICE", "AFFECTED_BY", "CAN_EXPLOIT", "CAN_ESCALATE_TO", "CONNECTS_TO", "SHARES_TRUST_WITH",
           "AUTHENTICATES_TO", "CAN_ACCESS"}  # fmt: skip


def graph_accuracy(snap: Snapshot) -> dict:
    g = build_graph(snap, GraphOptions()).graph
    built = {(e.type, e.src, e.dst) for e in g.edges() if e.type in CHECKED and not e.structural}
    built = {t for t in built if not (t[0] == "CAN_ACCESS" and t[2].startswith("priv:") and t[1].startswith("priv:"))}
    want = expected_edges(snap)
    inter = want & built
    return {
        "expected_edges": len(want),
        "built_edges": len(built),
        "missing": len(want - built),
        "spurious": len(built - want),
        "precision": round(len(inter) / len(built), 4) if built else 1.0,
        "recall": round(len(inter) / len(want), 4) if want else 1.0,
        "jaccard": round(len(inter) / len(want | built), 4) if want | built else 1.0,
    }


# ------------------------------------------------------------------ legacy baseline
def legacy_targets(snap: Snapshot, targets: set[int]) -> set[int]:
    """Which target hosts the legacy rule engine (same-/24 lateral movement + foothold->privesc) reports."""
    nodes = []
    for a in snap.assets:
        vs = [VulnNode(v.id, v.cve_id, v.title, frozenset(v.tags), v.cvss_score or 0.0, v.in_kev, v.port)
              for v in snap.vulns if v.asset_id == a.id]  # fmt: skip
        nodes.append(AssetNode(a.id, a.ip, a.hostname, a.internet_facing, vs))
    hit: set[int] = set()
    for c in find_chains(nodes):
        if c.rule == "lateral-movement":
            hit.add(c.steps[-1].asset.id)
    return hit & targets
