import fakeredis
import pytest
from rq import Queue

from app.config import get_settings
from app.services.cache import RedisCache, set_cache
from app.services.queue import set_queue
from tests.conftest import upload

PAYLOAD = {
    "hosts": [
        {
            "ip_address": "10.0.0.7",
            "vulnerabilities": [
                {"cve_id": "CVE-2021-41773", "title": "Apache", "port": 80, "cvss_score": 9.8},
                {"cve_id": "CVE-2021-4034", "title": "PwnKit", "cvss_score": 7.8},
            ],
        }
    ]
}


def test_assets_endpoints(client, nmap_xml):
    upload(client, nmap_xml, "nmap")
    assets = client.get("/assets").json()
    assert assets[0]["max_risk_score"] >= assets[-1]["max_risk_score"]  # riskiest first
    a = assets[0]
    assert client.get(f"/assets/{a['id']}").json()["vulnerability_count"] == a["vulnerability_count"]
    assert {s["port"] for s in client.get(f"/assets/{a['id']}/services").json()} <= {21, 22, 80, 445}
    vulns = client.get(f"/assets/{a['id']}/vulnerabilities?min_risk=9").json()
    assert vulns and all(v["risk_score"] >= 9 for v in vulns)
    assert all(x["max_risk_score"] >= 9.9 for x in client.get("/assets?min_risk=9.9").json())
    for path in ("/assets/999", "/assets/999/vulnerabilities", "/assets/999/services", "/reports/999"):
        assert client.get(path).status_code == 404
    assert client.patch("/assets/999", json={"hostname": "x"}).status_code == 404


def test_pagination_bounds(client):
    assert client.get("/assets?limit=0").status_code == 422
    assert client.get("/assets?limit=501").status_code == 422
    assert client.get("/vulnerabilities?offset=-1").status_code == 422


def test_api_key_enforced_when_configured(client, monkeypatch):
    monkeypatch.setenv("API_KEY", "s3cret")
    get_settings.cache_clear()
    assert client.get("/assets").status_code == 401
    assert client.get("/assets", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/assets", headers={"X-API-Key": "s3cret"}).status_code == 200
    assert client.post("/ingest", json=PAYLOAD).status_code == 401
    assert client.get("/health").status_code == 200  # probes stay open


def test_health(client):
    assert client.get("/health").json() == {"status": "ok", "database": "ok"}


@pytest.fixture
def redis_stack(monkeypatch):
    """fakeredis-backed queue (jobs run inline) and cache sharing one fake server."""
    server = fakeredis.FakeServer()
    monkeypatch.setenv("REDIS_URL", "redis://fake")
    get_settings.cache_clear()
    set_queue(Queue("ingest", connection=fakeredis.FakeStrictRedis(server=server), is_async=False))
    cache = RedisCache(fakeredis.FakeStrictRedis(server=server, decode_responses=True), ttl=60)
    set_cache(cache)
    return cache


def test_async_ingest_via_queue(client, redis_stack):
    r = client.post("/ingest?async_mode=true", json=PAYLOAD)
    assert r.status_code == 202
    report = client.get(f"/reports/{r.json()['id']}").json()  # worker ran inline
    assert report["status"] == "completed" and report["new_count"] == 2
    assert len(client.get("/vulnerabilities").json()) == 2


def test_async_failure_is_recorded_on_report(client, redis_stack):
    r = upload(client, "<nope/>", "nmap", async_mode=True)
    assert r.status_code == 202
    report = client.get(f"/reports/{r.json()['id']}").json()
    assert report["status"] == "failed" and report["error"]


def test_chain_cache_is_used_and_invalidated_by_ingest(client, redis_stack):
    client.post("/ingest?internet_facing=true", json=PAYLOAD)
    first = client.get("/chains").json()
    assert redis_stack.get("chains") == first  # cached
    client.post(
        "/ingest",
        json={
            "hosts": [
                {
                    "ip_address": "10.0.0.8",
                    "vulnerabilities": [
                        {"cve_id": "CVE-2011-2523", "title": "vsftpd backdoor", "port": 21, "cvss_score": 9.8},
                        {"cve_id": "CVE-2021-4034", "title": "PwnKit", "cvss_score": 7.8},
                    ],
                }
            ]
        },
    )
    assert redis_stack.get("chains") is None  # invalidated
    assert len(client.get("/chains").json()) > len(first)
