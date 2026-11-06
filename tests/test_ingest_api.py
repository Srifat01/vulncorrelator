from sqlalchemy import func, select

from app.config import get_settings
from app.models import Vulnerability
from tests.conftest import upload

PAYLOAD = {
    "source": "custom",
    "hosts": [
        {
            "ip_address": "192.168.1.1",
            "hostname": "test-host",
            "os": "Linux",
            "vulnerabilities": [
                {"cve_id": "CVE-2021-44228", "cvss_score": 10.0, "title": "Log4j", "port": 80, "protocol": "tcp"}
            ],
        }
    ],
}


def vuln_count(db) -> int:
    return db.scalar(select(func.count(Vulnerability.id)))


def test_duplicate_ingest_creates_one_row(client, db):
    r1 = client.post("/ingest", json=PAYLOAD)
    assert r1.status_code == 200 and r1.json()["status"] == "completed"
    assert (r1.json()["new_count"], r1.json()["updated_count"]) == (1, 0)
    r2 = client.post("/ingest", json=PAYLOAD)
    assert (r2.json()["new_count"], r2.json()["updated_count"]) == (0, 1)
    assert vuln_count(db) == 1
    assert len(client.get("/assets").json()) == 1


def test_resighting_updates_last_seen_but_keeps_first_seen(client):
    client.post("/ingest", json=PAYLOAD)
    first = client.get("/vulnerabilities").json()[0]
    client.post("/ingest", json=PAYLOAD)
    second = client.get("/vulnerabilities").json()[0]
    assert second["first_seen"] == first["first_seen"]
    assert second["last_seen"] >= first["last_seen"]


def test_same_cve_from_two_scanners_is_one_finding(client, db, nmap_xml, nessus_xml):
    assert upload(client, nmap_xml, "nmap").status_code == 200
    assert upload(client, nessus_xml, "nessus").status_code == 200
    rows = db.scalars(select(Vulnerability).where(Vulnerability.cve_id == "CVE-2021-41773")).all()
    assert len(rows) == 1
    assert set(rows[0].sources) == {"nmap", "nessus", "catalog"}
    assert rows[0].cvss_score == 9.8  # the higher of 7.5 (nmap/vulners) and 9.8 (nessus)
    assert set(rows[0].evidence) == {"nmap", "nessus", "catalog"}


def test_reingesting_native_scan_is_idempotent(client, db, nmap_xml):
    upload(client, nmap_xml, "nmap")
    before = vuln_count(db)
    r = upload(client, nmap_xml, "nmap").json()
    assert vuln_count(db) == before and r["new_count"] == 0 and r["updated_count"] == before


def test_findings_without_cve_dedupe_on_service_and_title(client, db):
    payload = {
        "hosts": [
            {
                "ip_address": "10.9.9.9",
                "vulnerabilities": [
                    {"title": "Default credentials", "port": 8080, "service_name": "http", "severity": "high"},
                    {"title": "default  credentials!", "port": 8080, "service_name": "http", "severity": "high"},
                    {"title": "Default credentials", "port": 9090, "service_name": "http", "severity": "high"},
                ],
            }
        ]
    }
    client.post("/ingest", json=payload)
    client.post("/ingest", json=payload)
    assert vuln_count(db) == 2


def test_internet_facing_defaults_from_ip_and_can_be_overridden(client):
    pub = {"hosts": [{"ip_address": "8.8.8.8"}, {"ip_address": "10.1.1.1"}]}
    client.post("/ingest", json=pub)
    flags = {a["ip_address"]: a["internet_facing"] for a in client.get("/assets").json()}
    assert flags == {"8.8.8.8": True, "10.1.1.1": False}
    client.post("/ingest?internet_facing=true", json={"hosts": [{"ip_address": "10.1.1.1"}]})
    assert client.get("/assets?internet_facing=true").json().__len__() == 2


def test_validation_errors(client):
    assert client.post("/ingest", json={"hosts": [{"ip_address": "not-an-ip"}]}).status_code == 422
    assert client.post("/ingest", json={"hosts": []}).status_code == 422
    bad_score = {"hosts": [{"ip_address": "1.2.3.4", "vulnerabilities": [{"title": "x", "cvss_score": 11}]}]}
    assert client.post("/ingest", json=bad_score).status_code == 422


def test_bad_upload_returns_422_and_records_failed_report(client):
    r = upload(client, "<html>not a scan</html>", "nmap")
    assert r.status_code == 422
    report = client.get("/reports").json()[0]
    assert report["status"] == "failed" and "nmap" in report["error"].lower()


def test_upload_size_limit(client, monkeypatch):
    monkeypatch.setenv("MAX_UPLOAD_MB", "0")
    get_settings.cache_clear()
    assert upload(client, "<nmaprun/>", "nmap").status_code == 413


def test_unknown_format_rejected(client, nmap_xml):
    assert upload(client, nmap_xml, "csv").status_code == 422


def test_async_without_redis_is_503(client):
    assert client.post("/ingest?async_mode=true", json=PAYLOAD).status_code == 503
