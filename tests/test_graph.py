"""Graph construction and attack-path discovery on snapshots with known ground truth."""

import pytest

from app.graph.builder import INTERNET, GraphOptions, build_graph
from app.graph.model import EdgeType, NodeType
from app.graph.snapshot import BoundaryRec, Snapshot
from tests.graph_helpers import LOCAL, NOW, analyse, asset, chain_of, flow, rel, svc, vuln


def simple_chain(**over):
    """internet -> web(1) --flow--> db(2, crown jewel).  web: RCE on :80.  db: RCE on :5432."""
    s = Snapshot(
        assets=[asset(1, "10.0.0.1", exposed=True, name="web"), asset(2, "10.0.0.2", crit=5, name="db")],
        services=[svc(1, 80), svc(2, 5432)],
        vulns=[vuln(1, 1, 80, ["rce"]), vuln(2, 2, 5432, ["rce"])],
        relationships=[flow(1, "asset:1", "asset:2", 5432)],
    )
    for k, v in over.items():
        setattr(s, k, v)
    return s


# ------------------------------------------------------------------ construction
def test_every_node_and_edge_type_is_constructed():
    s = simple_chain()
    s.vulns.append(vuln(3, 1, None, ["privesc"], vector=LOCAL))  # host-level local escalation
    s.relationships += [
        rel(2, "CAN_ACCESS", "asset:1", "identity:backup", requires="admin"),
        rel(3, "AUTHENTICATES_TO", "identity:backup", "asset:2", port=5432),
        rel(4, "SHARES_TRUST_WITH", "asset:1", "asset:2"),
    ]
    s.boundaries = [BoundaryRec("dmz", ["10.0.0.0/30"])]
    g = build_graph(s).graph
    assert {n.type for n in g.nodes()} == set(NodeType.ALL)
    assert {e.type for e in g.edges()} == set(EdgeType.ALL)


def test_nodes_and_edges_carry_evidence_source_confidence_and_timestamps():
    g = build_graph(simple_chain()).graph
    for e in g.edges():
        assert e.evidence_status in ("confirmed", "observed", "inferred", "hypothetical")
        assert 0 < e.confidence <= 1 and e.source
        if not e.structural:
            assert e.evidence, f"{e.type} edge has no supporting evidence"
    aff = next(g.edges(EdgeType.AFFECTED_BY))
    assert aff.first_seen == NOW and aff.last_seen == NOW


def test_edge_ids_are_deterministic():
    a = sorted(e.id for e in build_graph(simple_chain()).graph.edges())
    b = sorted(e.id for e in build_graph(simple_chain()).graph.edges())
    assert a == b and len(set(a)) == len(a)


def test_vulnerability_classification_comes_from_the_cvss_vector():
    s = simple_chain()
    s.vulns = [
        vuln(1, 1, 80, ["rce"], vector=LOCAL),  # "rce" tag but local attack vector: not a remote foothold
        vuln(2, 1, None, ["rce"]),  # network vector but host-level (no service): nothing to attack remotely
        vuln(3, 1, 80, ["info-disclosure"]),  # remote but grants no code execution
    ]
    g = build_graph(s).graph
    assert not list(g.edges(EdgeType.CAN_EXPLOIT))


# ------------------------------------------------------------------ the core correctness property
def test_shared_subnet_does_not_create_reachability():
    s = simple_chain(relationships=[])  # no flow between web and db at all
    paths, _, built = analyse(s)
    assert paths == []
    assert built.stats["edges_by_type"][EdgeType.CONNECTS_TO] == 1  # only the (inferred) internet -> web edge


def test_subnet_assumption_is_opt_in_and_always_hypothetical():
    s = simple_chain(relationships=[])
    opts = GraphOptions(assume_subnet_reachability=True)
    # edges exist but are hypothetical, so the default search ignores them...
    assert analyse(s, opts=opts)[0] == []
    # ...and when explicitly asked for, the path is labelled a hypothetical scenario, never a confirmed chain
    paths, _, _ = analyse(s, opts=opts, include_hypothetical=True)
    assert len(paths) == 1
    p = paths[0]
    assert p["evidence_status"] == "hypothetical" and not p["is_confirmed_exploit_chain"]
    assert any("ASSUMED" in m or "assumption" in m for m in p["missing_evidence"])
    assert "hypothetical" in p["summary"].lower()


def test_vulnerable_but_unreachable_host_is_not_on_a_path():
    s = simple_chain(relationships=[flow(1, "asset:1", "asset:2", 22)])  # flow to a port nothing listens on
    paths, _, built = analyse(s)
    assert paths == [] and built.stats["unresolved_relationships"] == 1
    assert built.warnings


# ------------------------------------------------------------------ evidence classification
def test_internet_flag_alone_is_inferred_not_observed():
    paths, _, _ = analyse(simple_chain())
    [p] = paths
    assert p["evidence_status"] == "partially_inferred" and not p["is_confirmed_exploit_chain"]
    assert any("inferred from an asset-level flag" in m for m in p["missing_evidence"])
    assert p["confidence"] == 0.4 and p["confidence_level"] == "low"


def test_external_scan_makes_exposure_observed():
    s = simple_chain()
    s.relationships.append(flow(9, "internet", "asset:1", 80, status="observed"))
    [p] = analyse(s)[0]
    assert p["evidence_status"] == "observed" and p["confidence"] == 0.7
    assert not any("asset-level flag" in m for m in p["missing_evidence"])


def test_only_fully_verified_chains_are_called_confirmed():
    s = simple_chain()
    for v in s.vulns:
        v.evidence_status = "confirmed"
    s.relationships = [
        flow(1, "asset:1", "asset:2", 5432, "confirmed"),
        flow(9, "internet", "asset:1", 80, "confirmed"),
    ]
    [p] = analyse(s)[0]
    assert p["evidence_status"] == "confirmed" and p["is_confirmed_exploit_chain"] and p["confidence"] == 0.9
    # one weaker link and the whole path drops (weakest-link rule)
    s.relationships[0].evidence_status = "observed"
    [p] = analyse(s)[0]
    assert p["evidence_status"] == "observed" and not p["is_confirmed_exploit_chain"] and p["confidence"] == 0.7


def test_version_match_findings_are_inferred():
    s = simple_chain()
    s.vulns[1].evidence_status, s.vulns[1].sources = "inferred", ["catalog"]
    [p] = analyse(s)[0]
    assert p["evidence_status"] == "partially_inferred"
    assert any("inferred from a version match" in m for m in p["missing_evidence"])


def test_missing_cvss_vector_caps_the_step_at_inferred():
    s = simple_chain()
    s.vulns[1].cvss_vector = None
    [p] = analyse(s)[0]
    assert p["evidence_status"] == "partially_inferred"
    assert any("tags only" in m for m in p["missing_evidence"])


# ------------------------------------------------------------------ path discovery
def test_multi_hop_path_with_full_explanation():
    [p] = analyse(simple_chain())[0]
    assert chain_of(p) == [1, 2] and p["hop_count"] == 2
    assert [s["action"] for s in p["steps"]] == ["initial_access", "lateral_movement"]
    assert p["entry"]["kind"] == "internet" and p["target_asset_id"] == 2
    assert p["cves"] == ["CVE-2099-0001", "CVE-2099-0002"]
    assert p["potential_impact"]["target_criticality"] == 5
    step = p["steps"][1]
    assert step["service"]["port"] == 5432 and step["prerequisites"]
    kinds = {(e["edge_type"], e["role"]) for e in step["evidence"]}
    assert {("CONNECTS_TO", "evidence"), ("AFFECTED_BY", "evidence"), ("CAN_EXPLOIT", "evidence"),
            ("RUNS_SERVICE", "supporting")} <= kinds  # fmt: skip
    assert p["confidence_semantics"] == "ordinal_uncalibrated"


def test_privilege_escalation_chain_to_any_admin():
    s = Snapshot(
        assets=[asset(1, "1.2.3.4", exposed=True)],
        services=[svc(1, 80)],
        vulns=[vuln(1, 1, 80, ["rce"]), vuln(2, 1, None, ["privesc"], vector=LOCAL, cvss=7.8)],
    )
    paths, res, _ = analyse(s)
    assert res.target_mode == "any_admin"  # no crown jewels defined => look for privileged states
    [p] = paths
    assert [s["action"] for s in p["steps"]] == ["initial_access", "privilege_escalation"]
    assert p["potential_impact"]["privilege_gained"] == "admin"
    assert p["steps"][1]["prerequisites"][0].startswith("existing unprivileged code execution")


def test_local_only_flaw_cannot_start_a_path():
    s = Snapshot(
        assets=[asset(1, "1.2.3.4", exposed=True, crit=5)],
        services=[svc(1, 80)],
        vulns=[vuln(1, 1, None, ["privesc"], vector=LOCAL)],  # no remote foothold at all
    )
    assert analyse(s)[0] == []


def test_backdoor_grants_admin_directly():
    s = Snapshot(
        assets=[asset(1, "1.2.3.4", exposed=True)],
        services=[svc(1, 21)],
        vulns=[vuln(1, 1, 21, ["rce", "backdoor"])],
    )
    [p] = analyse(s)[0]
    assert p["potential_impact"]["privilege_gained"] == "admin" and p["hop_count"] == 1


def test_max_steps_is_enforced():
    # internet -> 1 -> 2 -> 3 -> 4 (crown jewel): 4 transitions
    s = Snapshot(
        assets=[asset(i, f"10.0.0.{i}", exposed=(i == 1), crit=5 if i == 4 else 3) for i in (1, 2, 3, 4)],
        services=[svc(i, 80) for i in (1, 2, 3, 4)],
        vulns=[vuln(i, i, 80, ["rce"]) for i in (1, 2, 3, 4)],
        relationships=[flow(i, f"asset:{i}", f"asset:{i + 1}", 80) for i in (1, 2, 3)],
    )
    assert analyse(s, max_steps=3)[0] == []
    [p] = analyse(s, max_steps=4)[0]
    assert chain_of(p) == [1, 2, 3, 4]


def test_cycles_terminate_and_never_repeat_a_position():
    s = Snapshot(
        assets=[asset(1, "10.0.0.1", exposed=True), asset(2, "10.0.0.2"), asset(3, "10.0.0.3", crit=5)],
        services=[svc(1, 80), svc(2, 80), svc(3, 80)],
        vulns=[vuln(i, i, 80, ["rce"]) for i in (1, 2, 3)],
        relationships=[  # 1 <-> 2 mutual flows (a cycle), and 2 -> 3
            flow(1, "asset:1", "asset:2", 80), flow(2, "asset:2", "asset:1", 80), flow(3, "asset:2", "asset:3", 80),
        ],
    )  # fmt: skip
    paths, res, built = analyse(s)
    assert not res.truncated and len(paths) == 1 and chain_of(paths[0]) == [1, 2, 3]
    assert built.stats["cyclic_components"] == [[1, 2]]  # the cycle is detected and reported
    for p in paths:
        assert len(chain_of(p)) == len(set(chain_of(p)))


def test_assumed_foothold_is_labelled_hypothetical():
    s = simple_chain()
    paths, _, _ = analyse(s, start_internet=False, start_assets=[1])
    [p] = paths
    assert p["entry"]["kind"] == "assumed_foothold" and p["evidence_status"] == "hypothetical"
    assert any(a.startswith("ASSUMPTION") for a in p["assumptions"])
    assert p["confidence"] <= 0.15


def test_credential_reuse_requires_a_reachable_service():
    s = Snapshot(
        assets=[asset(1, "1.2.3.4", exposed=True), asset(2, "10.0.0.2", crit=5)],
        services=[svc(1, 80), svc(2, 22)],
        vulns=[vuln(1, 1, 80, ["rce"]), vuln(2, 1, None, ["privesc"], vector=LOCAL)],
        relationships=[
            rel(1, "CAN_ACCESS", "asset:1", "identity:backup", requires="admin"),
            rel(2, "AUTHENTICATES_TO", "identity:backup", "asset:2", port=22),
        ],
    )
    assert analyse(s)[0] == []  # a valid credential is useless if 1 cannot reach 2:22
    s.relationships.append(flow(3, "asset:1", "asset:2", 22))
    [p] = analyse(s)[0]
    assert [x["action"] for x in p["steps"]] == ["initial_access", "privilege_escalation", "credential_use"]
    assert p["steps"][2]["identity"] == "backup"
    assert any("credential 'backup'" in a for a in p["missing_evidence"])


def test_trust_pivot_needs_the_declared_privilege():
    s = Snapshot(
        assets=[asset(1, "1.2.3.4", exposed=True), asset(2, "10.0.0.2", crit=5)],
        services=[svc(1, 80)],
        vulns=[vuln(1, 1, 80, ["rce"]), vuln(2, 1, None, ["privesc"], vector=LOCAL)],
        relationships=[rel(1, "SHARES_TRUST_WITH", "asset:1", "asset:2", requires="admin", grants="user")],
    )
    [p] = analyse(s)[0]
    assert [x["action"] for x in p["steps"]] == ["initial_access", "privilege_escalation", "trust_pivot"]
    s.vulns.pop()  # without the escalation the attacker never holds admin on 1, so the trust cannot be used
    assert analyse(s)[0] == []


def test_alternative_exploits_for_one_step_are_collapsed_and_listed():
    s = simple_chain()
    s.vulns.append(vuln(3, 2, 5432, ["rce"], cvss=7.0, cve="CVE-2099-0099"))
    paths, _, _ = analyse(s)
    assert len(paths) == 1  # not one path per CVE
    step = paths[0]["steps"][1]
    assert [(v["cve_id"], v["selected"]) for v in step["vulnerabilities"]] == [
        ("CVE-2099-0002", True), ("CVE-2099-0099", False),
    ]  # fmt: skip


def test_boundary_crossings_are_reported():
    s = simple_chain()
    s.boundaries = [BoundaryRec("dmz", ["10.0.0.1/32"]), BoundaryRec("core", ["10.0.0.2/32"])]
    [p] = analyse(s)[0]
    assert [(b["step"], b["to"]) for b in p["boundaries_crossed"]] == [(1, ["dmz"]), (2, ["core"])]


def test_stale_evidence_is_called_out():
    s = simple_chain()
    for v in s.vulns:
        v.last_seen = NOW.replace(year=2025)
    [p] = analyse(s)[0]
    assert any("days ago" in m for m in p["missing_evidence"])


def test_declared_controls_are_listed_but_not_silently_applied():
    s = simple_chain()
    s.assets[1].controls = ["edr"]
    [p] = analyse(s)[0]
    assert any("edr on" in m and "not modelled" in m for m in p["missing_evidence"])


# ------------------------------------------------------------------ determinism, budgets, prioritisation
def test_results_are_deterministic():
    a, b = analyse(simple_chain())[0], analyse(simple_chain())[0]
    assert [p["path_id"] for p in a] == [p["path_id"] for p in b]


def test_expansion_budget_truncates_instead_of_running_away():
    s = simple_chain()
    _, res, _ = analyse(s, max_expansions=1)
    assert res.truncated


def test_max_paths_cap():
    s = Snapshot(
        assets=[asset(1, "1.2.3.4", exposed=True)] + [asset(i, f"10.0.0.{i}", crit=5) for i in range(2, 12)],
        services=[svc(i, 80) for i in range(1, 12)],
        vulns=[vuln(i, i, 80, ["rce"]) for i in range(1, 12)],
        relationships=[flow(i, "asset:1", f"asset:{i}", 80) for i in range(2, 12)],
    )
    paths, res, _ = analyse(s, max_paths=4)
    assert len(paths) == 4 and res.truncated


def test_target_selection_modes():
    s = simple_chain()
    assert analyse(s)[1].target_mode == "crown_jewels" and analyse(s)[1].target_assets == [2]
    assert analyse(s, target_asset_ids=[1])[1].target_mode == "explicit"
    paths, _, _ = analyse(s, target_asset_ids=[1])
    assert [chain_of(p) for p in paths] == [[1]]


def test_higher_value_targets_score_higher():
    base = analyse(simple_chain())[0][0]["priority_score"]
    s = simple_chain()
    s.assets[1].criticality = 4
    assert analyse(s)[0][0]["priority_score"] < base


def test_internet_boundary_node_exists_even_without_assets():
    g = build_graph(Snapshot()).graph
    assert g.node(INTERNET) is not None
    with pytest.raises(KeyError):
        g.add_edge(__import__("app.graph.model", fromlist=["Edge"]).Edge("x", "HOSTS", "nope", "nada", "observed", "t"))


# ------------------------------------------------------------------ dominated-path pruning
def detour_snapshot():
    """internet -> web(1, rce) -> app(2, rce + local privesc) -> db(3, crown jewel). The flow to db works from user
    level, so escalating on app is a pointless detour."""
    return Snapshot(
        assets=[asset(1, "1.2.3.4", exposed=True), asset(2, "10.0.0.2"), asset(3, "10.0.0.3", crit=5)],
        services=[svc(1, 80), svc(2, 80), svc(3, 80)],
        vulns=[
            vuln(1, 1, 80, ["rce"]),
            vuln(2, 2, 80, ["rce"]),
            vuln(3, 2, None, ["privesc"], vector=LOCAL),
            vuln(4, 3, 80, ["rce"]),
        ],  # fmt: skip
        relationships=[flow(1, "asset:1", "asset:2", 80), flow(2, "asset:2", "asset:3", 80)],
    )


def test_pointless_escalation_detour_is_pruned():
    paths, res, _ = analyse(detour_snapshot())
    assert [chain_of(p) for p in paths] == [[1, 2, 3]] and res.pruned_dominated == 1
    assert [s["action"] for s in paths[0]["steps"]] == ["initial_access", "lateral_movement", "lateral_movement"]
    unpruned, res2, _ = analyse(detour_snapshot(), prune_dominated=False)
    assert len(unpruned) == 2 and res2.pruned_dominated == 0  # the detour exists in the graph; it is just not reported


def test_escalation_that_is_actually_needed_is_kept():
    s = detour_snapshot()
    s.relationships = [
        flow(1, "asset:1", "asset:2", 80),
        rel(2, "SHARES_TRUST_WITH", "asset:2", "asset:3", requires="admin", grants="user"),
    ]
    [p] = analyse(s)[0]
    assert [x["action"] for x in p["steps"]] == [
        "initial_access",
        "lateral_movement",
        "privilege_escalation",
        "trust_pivot",
    ]


def triangle(short_status):
    """A -> T directly, or A -> B -> T. Exposure is observed so only the flow evidence differs."""
    return Snapshot(
        assets=[asset(1, "1.2.3.4", exposed=True), asset(2, "10.0.0.2"), asset(3, "10.0.0.3", crit=5)],
        services=[svc(1, 80), svc(2, 80), svc(3, 80)],
        vulns=[vuln(i, i, 80, ["rce"]) for i in (1, 2, 3)],
        relationships=[
            flow(1, "internet", "asset:1", 80, "observed"),
            flow(2, "asset:1", "asset:3", 80, short_status),  # the shortcut
            flow(3, "asset:1", "asset:2", 80, "observed"),
            flow(4, "asset:2", "asset:3", 80, "observed"),
        ],
    )


def test_longer_path_is_pruned_when_the_shortcut_is_just_as_well_evidenced():
    paths, res, _ = analyse(triangle("observed"))
    assert [chain_of(p) for p in paths] == [[1, 3]] and res.pruned_dominated == 1


def test_longer_path_with_stronger_evidence_is_kept():
    paths, res, _ = analyse(triangle("inferred"))
    assert sorted(chain_of(p) for p in paths) == [[1, 2, 3], [1, 3]] and res.pruned_dominated == 0
    by_len = {len(p["steps"]): p for p in paths}
    assert by_len[3]["confidence"] > by_len[2]["confidence"]  # that is why the longer route survives
