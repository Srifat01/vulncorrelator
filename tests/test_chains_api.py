from app.services.chains import AssetNode, VulnNode, find_chains
from tests.conftest import upload


def V(id, tags, risk=9.8, port=80, kev=False, cve=None):
    return VulnNode(id, cve or f"CVE-X-{id}", f"vuln{id}", frozenset(tags), risk, kev, port)


def A(id, ip, vulns, exposed=False):
    return AssetNode(id, ip, None, exposed, vulns)


# ---- pure rule tests ---------------------------------------------------------
def test_same_host_foothold_plus_privesc():
    chains = find_chains([A(1, "10.0.0.1", [V(1, {"rce"}), V(2, {"privesc"}, 7.8, port=None)])])
    assert [c.rule for c in chains] == ["foothold-to-privesc"]
    c = chains[0]
    assert [s.role for s in c.steps] == ["initial-access", "privilege-escalation"]
    assert c.risk_score == 10.0 and "root" in c.title


def test_no_chain_for_privesc_alone_or_foothold_alone():
    assert find_chains([A(1, "10.0.0.1", [V(1, {"privesc"}, 7.8, port=None)])]) == []
    assert find_chains([A(1, "10.0.0.1", [V(1, {"rce"})])]) == []


def test_local_vuln_with_no_port_is_not_a_remote_foothold():
    assert find_chains([A(1, "10.0.0.1", [V(1, {"rce"}, port=None), V(2, {"privesc"}, port=None)])]) == []


def test_lateral_movement_requires_exposed_entry_same_subnet_and_unexposed_target():
    exposed = A(1, "10.0.0.1", [V(1, {"rce"})], exposed=True)
    inside = A(2, "10.0.0.2", [V(2, {"rce"}, 9.0)])
    other_subnet = A(3, "10.0.9.2", [V(3, {"rce"})])
    also_exposed = A(4, "10.0.0.4", [V(4, {"rce"})], exposed=True)
    lateral = [c for c in find_chains([exposed, inside, other_subnet, also_exposed]) if c.rule == "lateral-movement"]
    # every pivot ends on the one unexposed, same-subnet host; neither other-subnet nor exposed hosts are targets
    assert {s.asset.id for c in lateral for s in c.steps[1:]} == {2}
    from_1 = [c for c in lateral if c.steps[0].asset.id == 1]
    assert len(from_1) == 1 and "Pivot" in from_1[0].title


def test_lateral_targets_are_capped():
    entry = A(1, "10.0.0.1", [V(1, {"rce"})], exposed=True)
    inner = [A(i, f"10.0.0.{i}", [V(i, {"rce"}, 8.0)]) for i in range(2, 10)]
    assert len([c for c in find_chains([entry, *inner]) if c.rule == "lateral-movement"]) == 3


def test_kev_on_exposed_service():
    chains = find_chains([A(1, "1.2.3.4", [V(1, {"info-disclosure"}, 7.5, kev=True)], exposed=True)])
    assert [c.rule for c in chains] == ["exploited-on-exposed-service"]
    assert find_chains([A(1, "10.0.0.1", [V(1, set(), 7.5, kev=True)], exposed=False)]) == []


def test_chain_ids_are_deterministic_and_sorted_by_risk():
    assets = [
        A(1, "10.0.0.1", [V(1, {"rce"}), V(2, {"privesc"}, 7.8, port=None)]),
        A(2, "10.0.0.2", [V(3, {"rce"}, 5.0), V(4, {"privesc"}, 5.0, port=None)]),
    ]
    c1, c2 = find_chains(assets), find_chains(assets)
    assert [c.id for c in c1] == [c.id for c in c2]
    assert [c.risk_score for c in c1] == sorted([c.risk_score for c in c1], reverse=True)


# ---- end to end --------------------------------------------------------------
def _ingest_samples(client, nmap_xml, nessus_xml):
    upload(client, nmap_xml, "nmap")
    upload(client, nessus_xml, "nessus")
    return {a["ip_address"]: a for a in client.get("/assets").json()}


def test_end_to_end_chains(client, nmap_xml, nessus_xml):
    assets = _ingest_samples(client, nmap_xml, nessus_xml)
    web, ftp = assets["10.0.1.10"], assets["10.0.1.20"]

    chains = client.get("/chains").json()
    assert [c["rule"] for c in chains] == ["foothold-to-privesc"]  # nothing is internet-facing yet
    assert chains[0]["risk_score"] == 10.0 and chains[0]["assets"][0]["id"] == web["id"]
    assert [s["cve_id"] for s in chains[0]["steps"]] == ["CVE-2021-41773", "CVE-2021-4034"]
    assert "explanation" in chains[0] and "CVE-2021-4034" in chains[0]["explanation"]

    # Declare the web server internet-facing -> pivot chains appear
    assert client.patch(f"/assets/{web['id']}", json={"internet_facing": True}).json()["internet_facing"] is True
    rules = {c["rule"] for c in client.get("/chains").json()}
    assert rules == {"foothold-to-privesc", "lateral-movement", "exploited-on-exposed-service"}
    lateral = client.get("/chains?rule=lateral-movement").json()[0]
    assert [s["asset_id"] for s in lateral["steps"]] == [web["id"], ftp["id"]]
    assert lateral["steps"][0]["cve_id"] == "CVE-2021-41773"
    assert lateral["steps"][1]["cve_id"] in {"CVE-2011-2523", "CVE-2017-7494"}  # both 10.0 risk on the ftp host

    assert client.get(f"/chains?asset_id={ftp['id']}").json()  # filter by involved asset
    assert client.get("/chains?min_risk=10.1").status_code == 422
    one = client.get(f"/chains/{lateral['id']}")
    assert one.status_code == 200 and one.json()["id"] == lateral["id"]
    assert client.get("/chains/doesnotexist").status_code == 404


def test_stats_and_top_vulns(client, nmap_xml, nessus_xml):
    _ingest_samples(client, nmap_xml, nessus_xml)
    stats = client.get("/stats").json()
    assert stats["assets"] == 2 and stats["known_exploited"] >= 3 and stats["chains"] == 1
    top = client.get("/vulnerabilities?limit=3").json()
    assert len(top) == 3 and [v["risk_score"] for v in top] == sorted((v["risk_score"] for v in top), reverse=True)
    assert all(v["in_kev"] for v in client.get("/vulnerabilities?kev_only=true").json())
    assert client.get("/vulnerabilities?cve_id=cve-2011-2523").json()[0]["tags"] == ["backdoor", "rce"]
