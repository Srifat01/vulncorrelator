"""Asset identity resolution: an asset is not its IP address."""

import threading

import pytest
from sqlalchemy import func, select

from app import database
from app.models import Asset, AssetObservation, IdentityConflict, Vulnerability
from tests.conftest import TEST_DB_URL, TEST_KEY

A_MAC, B_MAC = "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"
VULN = {"cve_id": "CVE-2099-0001", "title": "Demo RCE", "port": 80, "protocol": "tcp", "cvss_score": 9.8}


def ingest(client, ip, *, vulns=(VULN,), **host):
    body = {"source": "t", "hosts": [{"ip_address": ip, "vulnerabilities": list(vulns), **host}]}
    r = client.post("/ingest", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def assets(db):
    return db.scalars(select(Asset).order_by(Asset.id)).all()


def basis(db):
    return [o.match_basis for o in db.scalars(select(AssetObservation).order_by(AssetObservation.id))]


def test_ip_change_with_same_mac_is_the_same_asset(client, db):
    ingest(client, "10.0.0.5", mac_addresses=[A_MAC], hostname="web01")
    ingest(client, "10.0.0.99", mac_addresses=[A_MAC], hostname="web01")  # DHCP renumbering
    [a] = assets(db)
    assert a.ip_address == "10.0.0.99"
    assert basis(db) == ["new", "mac"]
    # findings follow the asset: still exactly one row, re-sighted rather than duplicated
    assert db.scalar(select(func.count(Vulnerability.id))) == 1
    # history of where it has been is preserved
    assert [o.ip_address for o in db.scalars(select(AssetObservation).order_by(AssetObservation.id))] == [
        "10.0.0.5",
        "10.0.0.99",
    ]


def test_ip_reused_by_a_different_machine_is_not_merged(client, db):
    ingest(client, "10.0.0.5", mac_addresses=[A_MAC])
    ingest(client, "10.0.0.5", mac_addresses=[B_MAC])  # same address, different NIC
    assert len(assets(db)) == 2
    c = db.scalars(select(IdentityConflict)).one()
    assert c.kind == "ip_reassigned" and "disjoint" in c.detail["reason"]
    # each machine keeps its own copy of the finding; the new one did not inherit the old one's
    assert db.scalar(select(func.count(Vulnerability.id))) == 2


def test_same_ip_without_strong_ids_merges_unless_hostnames_clash(client, db):
    ingest(client, "10.0.0.5", hostname="web01.corp.local")
    ingest(client, "10.0.0.5", hostname="web01.corp.local")  # same everything -> same asset
    assert len(assets(db)) == 1
    ingest(client, "10.0.0.5", hostname="db07.corp.local")  # same IP, clearly another host
    assert len(assets(db)) == 2
    assert db.scalars(select(IdentityConflict)).one().kind == "hostname_mismatch"


def test_scan_without_hostname_merges_into_known_ip(client, db):
    ingest(client, "10.0.0.5", hostname="web01.corp.local", mac_addresses=[A_MAC])
    ingest(client, "10.0.0.5")  # e.g. a remote scan that saw neither MAC nor name
    assert len(assets(db)) == 1 and basis(db)[-1] == "ip"


def test_renumbered_host_is_matched_by_unique_fqdn(client, db):
    ingest(client, "10.0.0.5", hostname="web01.corp.local")
    ingest(client, "10.0.0.77", hostname="web01.corp.local")
    [a] = assets(db)
    assert a.ip_address == "10.0.0.77" and basis(db)[-1] == "hostname"


def test_ambiguous_fqdn_is_not_merged(client, db):
    ingest(client, "10.0.0.5", hostname="app.corp.local", mac_addresses=[A_MAC])
    ingest(client, "10.0.0.6", hostname="app.corp.local", mac_addresses=[B_MAC])
    ingest(client, "10.0.0.7", hostname="app.corp.local")  # two candidates -> refuse to guess
    assert len(assets(db)) == 3
    kinds = [c.kind for c in db.scalars(select(IdentityConflict))]
    assert "split_identity" in kinds


def test_short_hostnames_are_not_trusted_for_renumbering(client, db):
    ingest(client, "10.0.0.5", hostname="ubuntu")
    ingest(client, "10.0.0.9", hostname="ubuntu")  # "ubuntu" is on a thousand machines
    assert len(assets(db)) == 2


def test_external_id_outranks_mac_and_contradictions_block_merging(client, db):
    ingest(client, "10.0.0.5", mac_addresses=[A_MAC], external_ids={"nessus_uuid": "u-1"})
    # same MAC but a different scanner id: the two facts contradict, so we do not merge
    ingest(client, "10.0.0.6", mac_addresses=[A_MAC], external_ids={"nessus_uuid": "u-2"})
    assert len(assets(db)) == 2
    assert "contradiction" in [c.kind for c in db.scalars(select(IdentityConflict))]
    # same scanner id, new MAC and new IP -> still the first asset
    ingest(client, "10.0.0.50", mac_addresses=[B_MAC], external_ids={"nessus_uuid": "u-1"})
    assert len(assets(db)) == 2 and basis(db)[-1] == "external_id"


def test_identifiers_pointing_at_two_assets_are_flagged_not_merged(client, db):
    ingest(client, "10.0.0.5", mac_addresses=[A_MAC])
    ingest(client, "10.0.0.6", external_ids={"agent": "x"})
    ingest(client, "10.0.0.7", mac_addresses=[A_MAC], external_ids={"agent": "x"})
    assert len(assets(db)) == 2  # no third asset, and the two originals stay separate
    assert "split_identity" in [c.kind for c in db.scalars(select(IdentityConflict))]


def test_shared_virtual_macs_never_identify_a_host(client, db):
    vrrp = "00:00:5e:00:01:0a"
    ingest(client, "10.0.0.5", mac_addresses=[vrrp])
    ingest(client, "10.0.0.6", mac_addresses=[vrrp])
    assert len(assets(db)) == 2


def test_findings_are_keyed_on_asset_not_ip(client, db):
    ingest(client, "10.0.0.5", mac_addresses=[A_MAC])
    r = ingest(client, "10.0.0.5", mac_addresses=[B_MAC])  # a different machine on the same IP
    assert r["new_count"] == 1  # it does not inherit the previous machine's finding


def test_nmap_mac_addresses_feed_identity(client, db, nmap_xml):
    from tests.conftest import upload

    with_mac = nmap_xml.replace(
        '<address addr="10.0.1.10" addrtype="ipv4"/>',
        '<address addr="10.0.1.10" addrtype="ipv4"/><address addr="AA:BB:CC:00:00:01" addrtype="mac"/>',
    )
    assert upload(client, with_mac, "nmap").status_code == 200
    renumbered = with_mac.replace('addr="10.0.1.10"', 'addr="10.0.1.200"')
    assert upload(client, renumbered, "nmap").status_code == 200
    web = [a for a in assets(db) if a.hostname == "web01.corp.local"]
    assert len(web) == 1 and web[0].ip_address == "10.0.1.200"


@pytest.mark.skipif(not TEST_DB_URL.startswith("postgres"), reason="advisory locks only matter on PostgreSQL")
def test_concurrent_first_sighting_creates_one_asset():
    from fastapi.testclient import TestClient

    from app.main import app

    body = {"hosts": [{"ip_address": "10.4.4.4", "mac_addresses": [A_MAC], "vulnerabilities": [VULN]}]}
    errors: list[str] = []

    def worker():
        c = TestClient(app, headers={"X-API-Key": TEST_KEY})
        r = c.post("/ingest", json=body)
        if r.status_code != 200:
            errors.append(r.text)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors
    with database.SessionLocal() as db:
        assert db.scalar(select(func.count(Asset.id))) == 1
        assert db.scalar(select(func.count(Vulnerability.id))) == 1
