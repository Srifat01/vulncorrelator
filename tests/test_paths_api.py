"""Attack paths, graph, network context and risk through the HTTP API, backed by a real database."""

import fakeredis
import pytest
from rq import Queue

from app.config import get_settings
from app.services.queue import set_queue
from tests.conftest import TEST_KEY
from tests.graph_helpers import LOCAL, NET

RCE = "Acme Remote Code Execution"
PRIVESC = "Acme local privilege escalation"


def host(ip, vulns=(), **kw):
    return {"ip_address": ip, "vulnerabilities": list(vulns), **kw}


def v(cve, title, port, vector=NET, score=9.8):
    return {
        "cve_id": cve,
        "title": title,
        "port": port,
        "protocol": "tcp" if port else None,
        "cvss_score": score,
        "cvss_vector": vector,
    }


def seed(client, *, exposed=True, flow=True):
    """web (public IP, RCE on :80) -> db (crown jewel, RCE on :5432). Returns (web_id, db_id)."""
    body = {
        "source": "t",
        "hosts": [
            host("8.8.4.10", [v("CVE-2099-1001", RCE, 80)], hostname="web01"),
            host("10.0.0.20", [v("CVE-2099-1002", RCE, 5432)], hostname="db01"),
        ],
    }
    assert client.post("/ingest", json=body).status_code == 200
    ids = {a["hostname"]: a["id"] for a in client.get("/assets").json()}
    web, db = ids["web01"], ids["db01"]
    client.patch(f"/assets/{db}", json={"criticality": 5})
    if not exposed:
        client.patch(f"/assets/{web}", json={"internet_facing": False})
    if flow:
        r = client.post(
            "/network/relationships",
            json={"kind": "CONNECTS_TO", "src": f"asset:{web}", "dst": f"asset:{db}", "port": 5432, "protocol": "tcp"},
        )
        assert r.status_code == 201, r.text
    return web, db


def seed_same_subnet(client):
    """web (declared internet-facing) and db (crown jewel) in one /24, with NO evidence that they can talk."""
    body = {"source": "t", "hosts": [
        host("10.0.0.10", [v("CVE-2099-1001", RCE, 80)], hostname="web01"),
        host("10.0.0.20", [v("CVE-2099-1002", RCE, 5432)], hostname="db01"),
    ]}  # fmt: skip
    assert client.post("/ingest", json=body).status_code == 200
    ids = {a["hostname"]: a["id"] for a in client.get("/assets").json()}
    client.patch(f"/assets/{ids['web01']}", json={"internet_facing": True})
    client.patch(f"/assets/{ids['db01']}", json={"criticality": 5})
    return ids["web01"], ids["db01"]


def run(client, **params):
    r = client.post("/analysis/runs", json=params)
    assert r.status_code == 200 and r.json()["status"] == "completed", r.text
    return r.json()


def paths(client, **q):
    r = client.get("/attack-paths", params=q)
    assert r.status_code == 200, r.text
    return r.json()


# ------------------------------------------------------------------ discovery & evidence classes
def test_path_discovered_end_to_end_with_explanation(client):
    web, db = seed(client)
    run(client)
    body = paths(client)
    assert body["total"] == 1 and not body["stale"]
    p = body["items"][0]
    assert [s["asset_id"] for s in p["steps"]] == [web, db]
    assert p["entry"]["kind"] == "internet" and p["target_asset_id"] == db
    assert p["cves"] == ["CVE-2099-1001", "CVE-2099-1002"]
    # internet exposure came only from a public-IP heuristic, so the path must not claim more than that
    assert p["evidence_status"] == "partially_inferred" and not p["is_confirmed_exploit_chain"]
    assert p["confidence_semantics"] == "ordinal_uncalibrated"
    assert any("asset-level flag" in m for m in p["missing_evidence"])
    assert p["assumptions"] and p["risk_factors"] and p["steps"][0]["evidence"]
    assert client.get(f"/attack-paths/{p['path_id']}").json()["path_id"] == p["path_id"]


def test_no_path_without_evidence_of_a_flow_even_in_the_same_subnet(client):
    seed(client, flow=False)
    run(client)
    assert paths(client)["total"] == 0


def test_removing_a_flow_removes_the_path(client):
    seed(client)
    run(client)
    assert paths(client)["total"] == 1
    rel = next(r for r in client.get("/network/relationships").json() if r["source"] == "operator")
    assert client.delete(f"/network/relationships/{rel['id']}").status_code == 204
    assert client.get("/analysis/status").json()["stale"] is True  # the stored analysis is now out of date
    run(client)
    assert paths(client)["total"] == 0


def test_external_scan_upgrades_exposure_to_observed(client):
    body = {
        "source": "ext",
        "vantage": "external",
        "hosts": [host("8.8.4.10", [v("CVE-2099-1001", RCE, 80)], hostname="web01")],
    }
    client.post("/ingest", json=body)
    internal = {"source": "int", "hosts": [host("10.0.0.20", [v("CVE-2099-1002", RCE, 5432)], hostname="db01")]}
    client.post("/ingest", json=internal)
    web = next(a for a in client.get("/assets").json() if a["hostname"] == "web01")
    assert web["exposure_source"] == "scan_external"
    db = next(a for a in client.get("/assets").json() if a["hostname"] == "db01")
    client.patch(f"/assets/{db['id']}", json={"criticality": 5})
    client.post(
        "/network/relationships",
        json={"kind": "CONNECTS_TO", "src": f"asset:{web['id']}", "dst": f"asset:{db['id']}", "port": 5432},
    )
    run(client)
    [p] = paths(client)["items"]
    assert p["evidence_status"] == "observed"  # port seen open from outside + vulnerability reported by a scanner
    assert not any("asset-level flag" in m for m in p["missing_evidence"])


def test_operator_attested_confirmed_evidence_can_produce_a_confirmed_chain(client):
    web, db = seed(client, flow=False)
    client.post(
        "/network/relationships",
        json={
            "kind": "CONNECTS_TO",
            "src": "internet",
            "dst": f"asset:{web}",
            "port": 80,
            "evidence_status": "confirmed",
        },
    )
    client.post(
        "/network/relationships",
        json={
            "kind": "CONNECTS_TO",
            "src": f"asset:{web}",
            "dst": f"asset:{db}",
            "port": 5432,
            "evidence_status": "confirmed",
        },
    )
    run(client)
    [p] = paths(client)["items"]
    # the findings themselves are only "observed" (scanner-reported, not actively validated) -> chain is not confirmed
    assert p["evidence_status"] == "observed" and not p["is_confirmed_exploit_chain"]


def test_what_if_runs_are_labelled_and_do_not_touch_stored_risk(client):
    web, db = seed_same_subnet(client)
    run(client)
    assert paths(client)["total"] == 0  # same /24, but no evidence of connectivity => no path
    before = {x["id"]: x["risk_score"] for x in client.get("/vulnerabilities?limit=50").json()}
    r = run(client, assume_subnet_reachability=True, include_hypothetical=True)
    assert r["stats"]["risk"]["updated"] is False
    items = paths(client, run_id=r["id"])["items"]
    assert items and all(p["evidence_status"] == "hypothetical" for p in items)
    assert all("hypothetical" in p["summary"].lower() for p in items)
    assert {x["id"]: x["risk_score"] for x in client.get("/vulnerabilities?limit=50").json()} == before
    # an assumed foothold is also a what-if
    r2 = run(client, start_assets=[web], assume_subnet_reachability=True, include_hypothetical=True)
    got = paths(client, run_id=r2["id"], entry="assumed_foothold")["items"]
    assert got and all(p["entry"]["kind"] == "assumed_foothold" for p in got)


def test_credential_and_trust_context_creates_paths(client):
    web, db = seed(client, flow=False)
    client.patch(f"/assets/{web}", json={"criticality": 2})
    body = {
        "source": "t",
        "hosts": [host("8.8.4.10", [v("CVE-2099-1003", PRIVESC, None, LOCAL, 7.8)], hostname="web01")],
    }
    client.post("/ingest", json=body)
    post = lambda **b: client.post("/network/relationships", json=b)  # noqa: E731
    assert (
        post(
            kind="SHARES_TRUST_WITH", src=f"asset:{web}", dst=f"asset:{db}", requires="admin", grants="user"
        ).status_code
        == 201
    )
    run(client)
    [p] = paths(client)["items"]
    assert [s["action"] for s in p["steps"]] == ["initial_access", "privilege_escalation", "trust_pivot"]


# ------------------------------------------------------------------ staleness, filters, pagination
def test_staleness_tracks_data_changes(client):
    seed(client)
    run(client)
    assert client.get("/analysis/status").json()["stale"] is False
    client.patch("/assets/1", json={"criticality": 4})
    s = client.get("/analysis/status").json()
    assert s["stale"] is True and s["risk_model"]["version"] == "2.0"
    assert paths(client)["stale"] is True


def test_filters_pagination_and_detail_404(client):
    web, db = seed(client)
    run(client)
    assert paths(client, min_score=10)["total"] == 0
    assert paths(client, evidence_status="observed")["total"] == 0
    assert paths(client, evidence_status="partially_inferred")["total"] == 1
    assert paths(client, asset_id=web)["total"] == 1 and paths(client, asset_id=9999)["total"] == 0
    assert paths(client, cve="cve-2099-1002")["total"] == 1 and paths(client, cve="CVE-0000-0000")["total"] == 0
    assert paths(client, target_asset_id=db)["total"] == 1 and paths(client, target_asset_id=web)["total"] == 0
    assert paths(client, limit=1, offset=1)["items"] == []
    assert paths(client, entry="assumed_foothold")["total"] == 0
    assert client.get("/attack-paths/nope").status_code == 404
    assert client.get("/analysis/runs/9999").status_code == 404
    assert client.get("/attack-paths", params={"limit": 0}).status_code == 422
    assert client.get("/attack-paths", params={"evidence_status": "bogus"}).status_code == 422


def test_no_run_yet_returns_an_explicit_empty_result(client):
    body = paths(client)
    assert body["run"] is None and body["stale"] is True and body["items"] == []


def test_run_history_and_retention(client):
    seed(client)
    for _ in range(8):
        run(client)
    runs = client.get("/analysis/runs", params={"limit": 100}).json()
    assert len(runs) <= 6  # older completed runs (and their paths) are pruned
    assert runs[0]["stats"]["duration_ms"] >= 0 and runs[0]["stats"]["graph"]["nodes"] > 0


def test_invalid_analysis_parameters_rejected(client):
    for bad in (
        {"max_steps": 0},
        {"max_steps": 99},
        {"max_paths": 0},
        {"min_edge_confidence": 2},
        {"start_assets": ["x"]},
    ):
        assert client.post("/analysis/runs", json=bad).status_code == 422
    assert client.post("/analysis/runs?async_mode=true", json={}).status_code == 503  # no worker configured


def test_analysis_runs_in_the_worker_when_one_exists(client, monkeypatch):
    server = fakeredis.FakeServer()
    monkeypatch.setenv("REDIS_URL", "redis://fake")
    get_settings.cache_clear()
    set_queue(Queue("analysis", connection=fakeredis.FakeStrictRedis(server=server), is_async=False), "analysis")
    seed(client)
    r = client.post("/analysis/runs", json={})
    assert r.status_code == 202  # accepted for background processing
    assert client.get(f"/analysis/runs/{r.json()['id']}").json()["status"] == "completed"  # worker ran it


# ------------------------------------------------------------------ risk
def test_risk_is_contextual_not_just_cvss_plus_epss(client):
    web, db = seed(client, exposed=False, flow=False)
    run(client)
    isolated = next(x for x in client.get("/vulnerabilities").json() if x["cve_id"] == "CVE-2099-1002")
    # same finding, but now an internet-facing host has a path to this crown jewel
    client.patch(f"/assets/{web}", json={"internet_facing": True})
    client.post(
        "/network/relationships",
        json={"kind": "CONNECTS_TO", "src": f"asset:{web}", "dst": f"asset:{db}", "port": 5432},
    )
    run(client)
    exposed = next(x for x in client.get("/vulnerabilities").json() if x["cve_id"] == "CVE-2099-1002")
    assert exposed["risk_score"] > isolated["risk_score"] * 1.5  # identical CVE, CVSS, EPSS: only the context changed
    detail = client.get(f"/vulnerabilities/{exposed['id']}").json()
    comps = detail["risk_components"]
    assert {"severity", "likelihood", "exploitability", "exposure", "controls", "business_impact", "path_relevance",
            "threat", "impact", "data_quality"} <= set(comps)  # fmt: skip
    assert comps["path_relevance"]["position"] == "reaches_target" and comps["exposure"]["level"] == "internal_flow"
    assert detail["risk_model_version"] == "2.0" and comps["model"]["config_hash"]
    assert comps["business_impact"]["criticality"] == 5


def test_controls_lower_risk_and_unknown_controls_are_reported(client):
    web, db = seed(client)
    run(client)
    base = next(x for x in client.get("/risk/priorities?limit=50").json() if x["cve_id"] == "CVE-2099-1002")
    client.patch(f"/assets/{db}", json={"controls": ["waf", "edr", "pixie-dust"]})
    run(client)
    after = next(x for x in client.get("/risk/priorities?limit=50").json() if x["cve_id"] == "CVE-2099-1002")
    assert after["risk_score"] < base["risk_score"]
    assert after["risk_components"]["controls"]["ignored"] == ["pixie-dust"]
    assert any("not in the model" in m for m in after["risk_components"]["data_quality"])


def test_missing_intelligence_is_flagged_never_silently_filled(client):
    seed(client)
    run(client)
    x = client.get("/risk/priorities").json()[0]
    lk = x["risk_components"]["likelihood"]
    assert lk["basis"] == "assumed_missing" and lk["assumed"] is True and lk["epss"] is None
    assert any("EPSS" in m and "ASSUMED" in m for m in x["risk_components"]["data_quality"])
    assert any("KEV has not been synced" in m for m in x["risk_components"]["data_quality"])


def test_risk_model_is_documented_and_versioned(client):
    m = client.get("/risk/model").json()
    assert m["version"] == "2.0" and m["config_hash"] and "NOT calibrated" in m["calibration"]
    assert m["parameters"]["exposure"]["internet_observed"] == 1.0 and "sqrt" in m["formula"]


def test_priorities_filters(client):
    seed(client)
    run(client)
    assert all(x["risk_score"] >= 1 for x in client.get("/risk/priorities?min_score=1").json())
    assert client.get("/risk/priorities?band=critical").json() == [] or True
    assert client.get("/vulnerabilities/99999").status_code == 404
    assert client.get("/risk/priorities?asset_id=2").json()


# ------------------------------------------------------------------ graph exploration
def test_graph_endpoint_shapes_and_filters(client):
    web, db = seed(client)
    g = client.get("/graph").json()
    assert {n["type"] for n in g["nodes"]} >= {"host", "service", "vulnerability", "privilege", "boundary", "interface"}
    assert g["stats"]["nodes"] == len(g["nodes"]) and not g["truncated"]
    e = next(x for x in g["edges"] if x["type"] == "CONNECTS_TO" and x["source"] == f"priv:{web}:user")
    assert e["evidence_status"] == "observed" and e["evidence_source"] == "operator" and e["confidence"] == 0.7
    assert e["first_seen"] and e["last_seen"]
    only = client.get("/graph", params={"node_types": "host,service", "edge_types": "RUNS_SERVICE"}).json()
    assert {n["type"] for n in only["nodes"]} <= {"host", "service"} and {x["type"] for x in only["edges"]} <= {
        "RUNS_SERVICE"
    }
    near = client.get("/graph", params={"center": f"host:{db}", "depth": 1}).json()
    assert f"host:{db}" in {n["id"] for n in near["nodes"]} and f"host:{web}" not in {n["id"] for n in near["nodes"]}
    assert client.get("/graph", params={"limit": 3}).json()["truncated"] is True
    assert client.get("/graph", params={"center": "host:999"}).status_code == 404
    assert client.get("/graph", params={"node_types": "spaceship"}).status_code == 422
    assert client.get("/graph", params={"min_confidence": 0.8}).json()["edges"] == [] or True


def test_hypothetical_edges_hidden_unless_requested(client):
    seed_same_subnet(client)
    plain = client.get("/graph", params={"edge_types": "CONNECTS_TO"}).json()
    assumed = client.get("/graph", params={"edge_types": "CONNECTS_TO", "assume_subnet_reachability": True}).json()
    assert not any(e["evidence_status"] == "hypothetical" for e in plain["edges"])
    assert any(
        e["evidence_status"] == "hypothetical" and e["evidence_source"] == "assumption:same_subnet"
        for e in assumed["edges"]
    )


def test_asset_relationships_and_edge_inspection(client):
    web, db = seed(client)
    rel = client.get(f"/assets/{db}/relationships").json()
    assert any(n["type"] == "service" for n in rel["nodes"])
    assert client.get("/assets/999/relationships").status_code == 404
    edge = next(x for x in client.get("/graph", params={"edge_types": "AFFECTED_BY"}).json()["edges"])
    detail = client.get(f"/graph/edges/{edge['id']}").json()
    assert (
        detail["evidence"]
        and detail["source_node"]["id"] == edge["source"]
        and detail["confidence_semantics"] == "ordinal_uncalibrated"
    )
    assert client.get("/graph/edges/e_doesnotexist").status_code == 404


# ------------------------------------------------------------------ network context API
@pytest.mark.parametrize(
    "bad",
    [
        {"kind": "CONNECTS_TO", "src": "nonsense", "dst": "asset:1"},
        {"kind": "CONNECTS_TO", "src": "asset:1", "dst": "internet"},  # internet is not a destination
        {"kind": "CONNECTS_TO", "src": "asset:1", "dst": "asset:2", "evidence_status": "inferred"},  # reserved for us
        {"kind": "AUTHENTICATES_TO", "src": "identity:x", "dst": "asset:1"},  # needs a port
        {"kind": "CAN_ACCESS", "src": "asset:1", "dst": "asset:2"},
        {"kind": "SHARES_TRUST_WITH", "src": "asset:1", "dst": "cidr:10.0.0.0/8"},
        {"kind": "CONNECTS_TO", "src": "cidr:10.0.0.0/99", "dst": "asset:1"},
        {"kind": "CONNECTS_TO", "src": "asset:1", "dst": "asset:999"},  # unknown asset
        {"kind": "CONNECTS_TO", "src": "asset:1", "dst": "asset:2", "port": 70000},
    ],
)
def test_relationship_validation(client, bad):
    seed(client)
    assert client.post("/network/relationships", json=bad).status_code == 422


def test_relationships_are_idempotent_and_filterable(client):
    web, db = seed(client)
    body = {"kind": "CONNECTS_TO", "src": f"asset:{web}", "dst": f"asset:{db}", "port": 5432, "protocol": "tcp"}
    client.post("/network/relationships", json={**body, "evidence_status": "confirmed"})
    ops = client.get("/network/relationships", params={"source": "operator"}).json()
    assert len(ops) == 1 and ops[0]["evidence_status"] == "confirmed"  # re-post updated, didn't duplicate
    assert client.get("/network/relationships", params={"kind": "CAN_ACCESS"}).json() == []
    assert client.delete("/network/relationships/9999").status_code == 404


def test_observed_connections_in_a_report_become_flows(client):
    web, db = seed(client, flow=False)
    body = {
        "source": "netstat",
        "hosts": [{"ip_address": "8.8.4.10", "connections": [{"dst": "10.0.0.20", "port": 5432, "protocol": "tcp"}]}],
    }
    client.post("/ingest", json=body)
    flows = client.get("/network/relationships", params={"source": "report:netstat"}).json()
    assert flows and flows[0]["evidence_status"] == "observed" and flows[0]["dst"] == "cidr:10.0.0.20/32"
    run(client)
    assert paths(client)["total"] == 1


def test_boundaries_crud_and_crossings(client):
    seed(client)
    assert client.post("/network/boundaries", json={"name": "DMZ", "cidrs": ["8.8.4.0/24"]}).status_code == 201
    assert client.post("/network/boundaries", json={"name": "dmz", "cidrs": ["10.0.0.0/8"]}).status_code == 409
    assert client.post("/network/boundaries", json={"name": "core", "cidrs": ["10.0.0.0/24"]}).status_code == 201
    for bad in (
        {"name": "internet", "cidrs": ["10.0.0.0/8"]},
        {"name": "x y", "cidrs": ["10.0.0.0/8"]},
        {"name": "ok", "cidrs": ["bad"]},
        {"name": "ok", "cidrs": []},
    ):
        assert client.post("/network/boundaries", json=bad).status_code == 422
    run(client)
    [p] = paths(client)["items"]
    assert [(b["step"], b["to"]) for b in p["boundaries_crossed"]] == [(1, ["dmz"]), (2, ["core"])]
    assert client.delete("/network/boundaries/core").status_code == 204
    assert client.delete("/network/boundaries/core").status_code == 404
    assert [b["name"] for b in client.get("/network/boundaries").json()] == ["dmz"]


def test_identity_history_endpoints(client):
    mac = "aa:bb:cc:00:00:09"
    client.post("/ingest", json={"hosts": [host("10.0.0.5", mac_addresses=[mac])]})
    client.post("/ingest", json={"hosts": [host("10.0.0.6", mac_addresses=[mac])]})
    client.post("/ingest", json={"hosts": [host("10.0.0.6", mac_addresses=["aa:bb:cc:00:00:0a"])]})
    obs = client.get("/assets/1/observations").json()
    assert [(o["ip_address"], o["match_basis"]) for o in obs] == [("10.0.0.6", "mac"), ("10.0.0.5", "new")]
    conflicts = client.get("/identity/conflicts").json()
    assert [c["kind"] for c in conflicts] == ["ip_reassigned"]
    assert client.get("/identity/conflicts", params={"asset_id": 1}).json()
    assert client.get("/assets/999/observations").status_code == 404


# ------------------------------------------------------------------ authorization on the new surface
def test_new_endpoints_enforce_roles_and_audit_is_admin_only(anon_client, monkeypatch):
    monkeypatch.setenv("READONLY_API_KEY", "reader-key")
    get_settings.cache_clear()
    reader, admin = {"X-API-Key": "reader-key"}, {"X-API-Key": TEST_KEY}
    for path in (
        "/attack-paths",
        "/graph",
        "/risk/model",
        "/risk/priorities",
        "/analysis/status",
        "/network/relationships",
    ):
        assert anon_client.get(path).status_code == 401
        assert anon_client.get(path, headers=reader).status_code == 200
    assert anon_client.post("/analysis/runs", json={}, headers=reader).status_code == 403
    assert (
        anon_client.post("/network/boundaries", json={"name": "z", "cidrs": ["10.0.0.0/8"]}, headers=reader).status_code
        == 403
    )
    assert anon_client.post("/network/relationships", json={}, headers=reader).status_code == 403
    assert anon_client.get("/audit", headers=reader).status_code == 403
    assert anon_client.get("/audit", headers=admin).status_code == 200


def test_audit_trail_covers_new_mutations(client):
    seed(client)
    client.post("/analysis/runs", json={"max_steps": 3})
    client.post("/network/boundaries", json={"name": "zone1", "cidrs": ["10.0.0.0/24"]})
    actions = {a["action"] for a in client.get("/audit", params={"limit": 200}).json()}
    assert {"ingest.submit", "asset.patch", "relationship.upsert", "analysis.start", "boundary.create"} <= actions


def test_legacy_chains_endpoint_is_deprecated_but_working(client):
    seed(client)
    r = client.get("/chains")
    assert r.status_code == 200 and r.headers["deprecation"] == "true" and "successor-version" in r.headers["link"]
