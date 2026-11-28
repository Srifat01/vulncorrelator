"""Run the evaluation:  python -m evaluation.run [--quick] [--out evaluation/results/latest.json]

Everything printed is measured by this script on the machine it runs on. Nothing is hard-coded or estimated.
Suites:
  planted   attack chains built by construction + provably-uncompromisable decoys (ground truth by design)
  oracle    random networks; engine vs an independent reference implementation; every reported path re-validated
  legacy    the old /24 rule engine scored against the same ground truth
  scaling   wall-clock time (median of N) and Python-heap peak vs network size
"""

import argparse
import json
import platform
import resource
import statistics
import sys
import time
from pathlib import Path

from evaluation.metrics import (
    graph_accuracy,
    legacy_targets,
    prf,
    run_engine,
    score_paths,
)
from evaluation.oracle import Model, validate_path
from evaluation.scenarios import planted, random_network


def suite_planted(seeds: range) -> dict:
    agg = {"tp": 0, "fp": 0, "fn": 0, "overstated": 0, "exact": 0, "decoys": 0, "decoys_flagged": 0, "paths_found": 0}
    kinds: dict[str, list[int]] = {}
    graph = []
    for seed in seeds:
        sc = planted(seed, n_chains=6 + seed % 4)
        run = run_engine(sc.snapshot)
        r = score_paths(sc, run.paths)
        for k in ("tp", "fp", "fn"):
            agg[k] += r[k]
        agg["overstated"] += r["evidence_overstated"]
        agg["exact"] += round(r["evidence_class_accuracy"] * r["tp"])
        agg["decoys"] += r["decoys"]
        agg["decoys_flagged"] += r["decoys_flagged"]
        agg["paths_found"] += len(run.paths)
        for kind, d in r["per_kind_recall"].items():
            kinds.setdefault(kind, [0, 0])
            kinds[kind][0] += d["found"]
            kinds[kind][1] += d["n"]
        graph.append(graph_accuracy(sc.snapshot))
    out = prf(agg["tp"], agg["fp"], agg["fn"])
    out.update(
        scenarios=len(seeds),
        true_paths=agg["tp"] + agg["fn"],
        false_negative_rate=round(agg["fn"] / max(1, agg["tp"] + agg["fn"]), 4),
        decoys=agg["decoys"],
        decoys_flagged=agg["decoys_flagged"],
        decoy_false_positive_rate=round(agg["decoys_flagged"] / max(1, agg["decoys"]), 4),
        evidence_class_accuracy=round(agg["exact"] / max(1, agg["tp"]), 4),
        evidence_overstated=agg["overstated"],
        per_kind_recall={k: {"found": f, "total": t} for k, (f, t) in kinds.items()},
        graph_construction={
            "scenarios": len(graph),
            "mean_jaccard": round(statistics.mean(g["jaccard"] for g in graph), 4),
            "min_jaccard": min(g["jaccard"] for g in graph),
            "mean_precision": round(statistics.mean(g["precision"] for g in graph), 4),
            "mean_recall": round(statistics.mean(g["recall"] for g in graph), 4),
            "edges_checked": sum(g["expected_edges"] for g in graph),
        },
    )
    return out


def suite_oracle(seeds: range, sizes: tuple[int, ...], densities: tuple[float, ...]) -> dict:
    tp = fp = fn = paths = invalid = runs = skipped = multi_hop = special = 0
    disagreements: list[dict] = []
    for seed in seeds:
        for n in sizes:
            for dens in densities:
                snap = random_network(seed, n, dens)
                run = run_engine(snap, max_steps=5, max_paths=5000)
                if run.truncated:
                    skipped += 1  # the engine hit its work budget: a deliberate limit, so no recall claim here
                    continue
                runs += 1
                model = Model(snap)
                inet = [p for p in run.paths if p["entry"]["kind"] == "internet"]
                engine = {p["target_asset_id"] for p in inet}
                truth = model.reachable_targets(max_steps=5)
                tp, fp, fn = tp + len(engine & truth), fp + len(engine - truth), fn + len(truth - engine)
                if engine != truth and len(disagreements) < 5:
                    disagreements.append(
                        {"seed": seed, "hosts": n, "density": dens,
                         "engine_only": sorted(engine - truth), "oracle_only": sorted(truth - engine)}
                    )  # fmt: skip
                for p in inet:
                    paths += 1
                    multi_hop += p["hop_count"] >= 3
                    special += any(s["action"] in ("privilege_escalation", "trust_pivot") for s in p["steps"])
                    invalid += bool(validate_path(model, p, 5))
    out = prf(tp, fp, fn)
    out.update(
        networks=runs,
        skipped_truncated=skipped,
        paths_validated=paths,
        paths_with_3plus_hops=multi_hop,
        paths_with_escalation_or_trust=special,
        invalid_paths=invalid,
        path_validity=round(1 - invalid / paths, 4) if paths else 1.0,
        disagreements=disagreements,
    )
    return out


def suite_legacy(seeds: range) -> dict:
    new = [0, 0, 0]
    old = [0, 0, 0]
    for seed in seeds:
        sc = planted(seed, n_chains=6 + seed % 4)
        run = run_engine(sc.snapshot)
        truth = {p[-1][0] for p in sc.truth_paths}
        engine = {p["target_asset_id"] for p in run.paths if p["entry"]["kind"] == "internet"}
        legacy = legacy_targets(sc.snapshot, {a.id for a in sc.snapshot.assets if a.criticality >= 4})
        for acc, found in ((new, engine), (old, legacy)):
            acc[0] += len(found & truth)
            acc[1] += len(found - truth)
            acc[2] += len(truth - found)
    return {"attack_path_engine": prf(*new), "legacy_subnet_rules": prf(*old),
            "unit": "compromisable crown-jewel hosts (host-level, summed over scenarios)"}  # fmt: skip


def suite_scaling(sizes: tuple[int, ...], repeats: int, density: float) -> list[dict]:
    rows = []
    for n in sizes:
        snap = random_network(11, n, density)
        times = []
        for _ in range(repeats):
            r = run_engine(snap, max_steps=4, max_paths=500)
            times.append((r.seconds_build, r.seconds_search, r.seconds_explain))
        mem = run_engine(snap, max_steps=4, max_paths=500, track_memory=True)
        total = [sum(t) for t in times]
        med = lambda i, ts=times: statistics.median(t[i] for t in ts)  # noqa: E731
        rows.append(
            {
                "hosts": n,
                "density": density,
                "services": len(snap.services),
                "findings": len(snap.vulns),
                "relationships": len(snap.relationships),
                "graph_nodes": mem.build_stats["nodes"],
                "graph_edges": mem.build_stats["edges"],
                "paths_found": len(mem.paths),
                "search_truncated": mem.truncated,
                "expansions": mem.expansions,
                "seconds_build_median": round(med(0), 4),
                "seconds_search_median": round(med(1), 4),
                "seconds_explain_median": round(med(2), 4),
                "seconds_total_median": round(statistics.median(total), 4),
                "seconds_total_min": round(min(total), 4),
                "seconds_total_max": round(max(total), 4),
                "peak_python_heap_mb": round(mem.peak_bytes / 1e6, 1),
                "repeats": repeats,
            }
        )
    return rows


def markdown(res: dict) -> str:
    p, o, lg, g = res["planted"], res["oracle"], res["legacy"], res["planted"]["graph_construction"]
    new, old = lg["attack_path_engine"], lg["legacy_subnet_rules"]
    lines = [
        f"planted ({p['scenarios']} scenarios, {p['true_paths']} true paths, {p['decoys']} decoy hosts)",
        f"  path precision {p['precision']}  recall {p['recall']}  f1 {p['f1']}",
        f"  (tp {p['tp']} fp {p['fp']} fn {p['fn']})  false-negative rate {p['false_negative_rate']}",
        f"  decoy false-positive rate {p['decoy_false_positive_rate']} ({p['decoys_flagged']}/{p['decoys']} flagged)",
        f"  evidence-class accuracy {p['evidence_class_accuracy']}  evidence OVERSTATED {p['evidence_overstated']}",
        f"  graph construction: mean jaccard {g['mean_jaccard']} (min {g['min_jaccard']}) over {g['edges_checked']} edges",
        f"oracle ({o['networks']} random networks, {o['skipped_truncated']} skipped as budget-truncated)",
        f"  target-set precision {o['precision']}  recall {o['recall']}  (tp {o['tp']} fp {o['fp']} fn {o['fn']})",
        f"  every reported path re-validated step by step: {o['paths_validated']} paths, {o['invalid_paths']} invalid",
        f"  ({o['paths_with_3plus_hops']} paths with >=3 hops, {o['paths_with_escalation_or_trust']} using escalation/trust)",
        "legacy comparison (same ground truth, compromisable crown-jewel hosts)",
        f"  attack-path engine: precision {new['precision']} recall {new['recall']}",
        f"  legacy /24 rules  : precision {old['precision']} recall {old['recall']}",
    ]
    head = f"  {'hosts':>6} {'nodes':>7} {'edges':>7} {'paths':>6} {'build':>8} {'search':>8} {'explain':>8} {'total':>8} {'MB':>7}"
    for label in ("sparse", "dense"):
        lines += [f"scaling, {label} networks (median wall-clock seconds, Python-heap peak)", head]
        for r in res["scaling"][label]:
            cells = (r["hosts"], r["graph_nodes"], r["graph_edges"], r["paths_found"], r["seconds_build_median"],
                     r["seconds_search_median"], r["seconds_explain_median"], r["seconds_total_median"],
                     r["peak_python_heap_mb"])  # fmt: skip
            widths = (6, 7, 7, 6, 8, 8, 8, 8, 7)
            row = "  " + " ".join(f"{c:>{w}}" for c, w in zip(cells, widths, strict=True))
            lines.append(row + ("  (search hit its work budget)" if r["search_truncated"] else ""))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="fewer seeds/sizes (CI smoke run)")
    ap.add_argument("--out", default="evaluation/results/latest.json")
    args = ap.parse_args(argv)
    seeds_p, seeds_o = (range(1, 6), range(1, 4)) if args.quick else (range(1, 31), range(1, 41))
    sizes_o, dens_o = ((30,), (1.8,)) if args.quick else ((30, 60), (1.0, 1.8, 2.5))
    scales, repeats = ((50, 100), 2) if args.quick else ((50, 100, 200, 400, 800), 3)
    t0 = time.perf_counter()
    res = {
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cpu_count": __import__("os").cpu_count(),
        },  # fmt: skip
        "planted": suite_planted(seeds_p),
        "oracle": suite_oracle(seeds_o, sizes_o, dens_o),
        "legacy": suite_legacy(seeds_p),
        "scaling": {"sparse": suite_scaling(scales, repeats, 1.0), "dense": suite_scaling(scales[:4], repeats, 2.5)},
    }
    res["environment"]["total_seconds"] = round(time.perf_counter() - t0, 1)
    res["environment"]["process_max_rss_mb"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=2))
    print(markdown(res))
    print(f"\nwritten to {out}")
    bad = res["planted"]["evidence_overstated"] or res["oracle"]["invalid_paths"] or res["oracle"]["fp"]
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
