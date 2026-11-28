"""The evaluation harness itself is tested: it must score a correct engine perfectly AND catch a broken one.

A benchmark that cannot fail is worthless, so each "mutation" below deliberately breaks one documented property of
the engine and asserts that the harness notices.
"""

import pytest

import app.graph.builder as builder
import app.graph.explain as explain
import app.graph.paths as paths_mod
from evaluation.metrics import graph_accuracy, run_engine, score_paths
from evaluation.oracle import Model, validate_path
from evaluation.run import main as run_evaluation
from evaluation.run import suite_oracle, suite_planted
from evaluation.scenarios import planted, random_network


def evaluate(seed=3, **kw):
    sc = planted(seed, n_chains=6)
    return sc, score_paths(sc, run_engine(sc.snapshot, **kw).paths)


# ------------------------------------------------------------------ the correct engine scores perfectly
def test_scenarios_are_deterministic_and_have_real_content():
    a, b = planted(5), planted(5)
    assert sorted(a.truth_paths) == sorted(b.truth_paths) and a.decoys == b.decoys
    assert len(a.truth_paths) == 6 and len(a.decoys) == 24
    assert {"exploit", "priv-trust", "credential"} == set(a.kinds.values())
    assert set(a.truth_paths.values()) <= {"partially_inferred", "observed", "confirmed"}


def test_engine_matches_planted_ground_truth():
    out = suite_planted(range(1, 9))
    assert (out["fp"], out["fn"]) == (0, 0) and out["precision"] == out["recall"] == 1.0
    assert out["decoys_flagged"] == 0 and out["evidence_overstated"] == 0 and out["evidence_class_accuracy"] == 1.0
    assert out["graph_construction"]["min_jaccard"] == 1.0
    assert all(d["found"] == d["total"] for d in out["per_kind_recall"].values())


def test_engine_agrees_with_the_independent_oracle_on_random_networks():
    out = suite_oracle(range(1, 6), (30, 60), (1.0, 1.8, 2.5))
    assert out["networks"] >= 25 and out["disagreements"] == []
    assert (out["fp"], out["fn"], out["invalid_paths"]) == (0, 0, 0)
    assert out["paths_with_3plus_hops"] > 20 and out["paths_with_escalation_or_trust"] > 20  # the suite is not trivial


def test_the_oracle_rejects_a_fabricated_path():
    snap = random_network(1, 30, 1.8)
    model = Model(snap)
    real = next(p for p in run_engine(snap).paths if p["entry"]["kind"] == "internet")
    assert validate_path(model, real) == []
    forged = {
        **real,
        "steps": [{**real["steps"][0], "asset_id": real["steps"][0]["asset_id"] + 1000}, *real["steps"][1:]],
    }
    assert validate_path(model, forged)  # unknown service on a non-existent host is flagged


# ------------------------------------------------------------------ mutations: each break must be caught
def test_mutation_trusting_hypothetical_links_is_caught(monkeypatch):
    monkeypatch.setattr(paths_mod, "_usable", lambda e, p: e.confidence >= p.min_edge_confidence)
    _, r = evaluate()
    assert r["decoys_flagged"] > 0 and r["fp"] > 0


def test_mutation_assuming_same_subnet_reachability_is_caught(monkeypatch):
    real_build = builder.build_graph
    monkeypatch.setattr(
        "evaluation.metrics.build_graph", lambda snap, opts=None: real_build(snap, builder.GraphOptions(True))
    )
    sc = planted(3)
    out = score_paths(sc, run_engine(sc.snapshot, include_hypothetical=True).paths)
    assert out["fp"] > 0  # the same-/24 assumption invents paths into hosts nothing connects to
    assert out["decoys_flagged"] > 0


def test_mutation_overstating_evidence_is_caught(monkeypatch):
    monkeypatch.setattr(explain, "path_evidence_status", lambda statuses: "confirmed")
    _, r = evaluate()
    assert r["evidence_overstated"] > 0 and r["evidence_class_accuracy"] < 1.0


def test_mutation_dropping_credential_pivots_is_caught(monkeypatch):
    real = paths_mod.transitions_from
    monkeypatch.setattr(
        paths_mod, "transitions_from", lambda *a, **k: [t for t in real(*a, **k) if t.kind != "credential"]
    )
    _, r = evaluate()
    assert r["fn"] > 0 and r["per_kind_recall"]["credential"]["found"] < r["per_kind_recall"]["credential"]["n"]


def test_mutation_ignoring_remote_exploitability_is_caught(monkeypatch):
    """Treating a local-only flaw as remotely exploitable must show up as false positives."""
    real = builder.classify

    def sloppy(v):
        c = real(v)
        return builder.VulnClass(bool(c.gains) and v.port is not None, c.gains, c.privesc, c.status_cap,
                                 "network", c.prerequisites)  # fmt: skip

    monkeypatch.setattr(builder, "classify", sloppy)
    _, r = evaluate()
    assert r["decoys_flagged"] > 0


def test_mutation_silently_dropping_vulnerability_edges_is_caught(monkeypatch):
    monkeypatch.setattr(builder, "_add_vulnerabilities", lambda *a, **k: None)
    sc = planted(3)
    acc = graph_accuracy(sc.snapshot)
    assert acc["recall"] < 1.0 and acc["missing"] > 0  # graph accuracy notices missing AFFECTED_BY/CAN_EXPLOIT edges
    assert score_paths(sc, run_engine(sc.snapshot).paths)["recall"] == 0.0  # ...and so does path recall


def test_a_structurally_broken_graph_fails_loudly_not_silently(monkeypatch):
    monkeypatch.setattr(builder, "_add_services", lambda *a, **k: None)
    with pytest.raises(KeyError, match="unknown node"):
        run_engine(planted(3).snapshot)


@pytest.mark.parametrize("max_steps,expect_all", [(1, False), (5, True)])
def test_step_limit_is_visible_in_recall(max_steps, expect_all):
    _, r = evaluate(max_steps=max_steps)
    assert (r["fn"] == 0) is expect_all  # chains need up to 4 transitions


def test_quick_run_passes_end_to_end(tmp_path, capsys):
    assert run_evaluation(["--quick", "--out", str(tmp_path / "r.json")]) == 0
    out = capsys.readouterr().out
    assert "legacy /24 rules" in out and (tmp_path / "r.json").exists()
