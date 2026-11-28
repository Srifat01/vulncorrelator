"""Authentication, authorization, rate limiting, input hardening, audit trail, worker recovery."""

from datetime import timedelta

import fakeredis
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.config import get_settings
from app.models import AuditLog, ReportStatus, ScanReport, utcnow
from app.services.ingest import recover_stuck_reports
from app.services.ratelimit import MemoryLimiter, RedisLimiter, set_limiter
from tests.conftest import TEST_KEY, upload

BODY = {"hosts": [{"ip_address": "10.0.0.1"}]}


def configure(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k.upper(), str(v))
    get_settings.cache_clear()
    set_limiter(None)


# ------------------------------------------------------------------ authn / authz
def test_secure_by_default_without_any_key(anon_client, monkeypatch):
    monkeypatch.delenv("API_KEY")
    get_settings.cache_clear()
    r = anon_client.get("/assets")
    assert r.status_code == 503 and "authentication is not configured" in r.json()["detail"]
    assert anon_client.get("/health").status_code == 200  # probes stay open


def test_explicit_opt_out_for_local_development(anon_client, monkeypatch):
    monkeypatch.delenv("API_KEY")
    configure(monkeypatch, auth_disabled="true")
    assert anon_client.get("/assets").status_code == 200


def test_missing_and_wrong_keys_are_rejected(anon_client):
    assert anon_client.get("/assets").status_code == 401
    assert anon_client.get("/assets", headers={"X-API-Key": "wrong"}).status_code == 401
    assert anon_client.get("/assets", headers={"X-API-Key": TEST_KEY}).status_code == 200
    assert anon_client.post("/ingest", json=BODY).status_code == 401


def test_read_only_key_cannot_mutate(anon_client, monkeypatch):
    configure(monkeypatch, readonly_api_key="reader-key")
    h = {"X-API-Key": "reader-key"}
    assert anon_client.get("/assets", headers=h).status_code == 200
    assert anon_client.post("/ingest", json=BODY, headers=h).status_code == 403
    assert anon_client.patch("/assets/1", json={"criticality": 5}, headers=h).status_code == 403
    # ...and the admin key still can
    assert anon_client.post("/ingest", json=BODY, headers={"X-API-Key": TEST_KEY}).status_code == 200


def test_brute_force_lockout(anon_client, monkeypatch):
    configure(monkeypatch, rate_limit_enabled="true")
    codes = [anon_client.get("/assets", headers={"X-API-Key": f"guess{i}"}).status_code for i in range(25)]
    assert codes[:20] == [401] * 20 and codes[20:] == [429] * 5
    # even the correct key is refused while the lockout lasts - the comparison never runs
    assert anon_client.get("/assets", headers={"X-API-Key": TEST_KEY}).status_code == 429


# ------------------------------------------------------------------ rate limiting
def test_rate_limit_per_category_with_headers(client, monkeypatch):
    configure(monkeypatch, rate_limit_enabled="true", rate_limit_ingest_per_min=3)
    codes = [client.post("/ingest", json=BODY).status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    r = client.post("/ingest", json=BODY)
    assert int(r.headers["retry-after"]) >= 1 and r.headers["x-ratelimit-remaining"] == "0"
    assert client.get("/assets").status_code == 200  # other categories have their own budget


def test_memory_limiter_window_resets():
    now = [0.0]
    lim = MemoryLimiter(clock=lambda: now[0])
    assert [lim.hit("k", 2, 60)[0] for _ in range(3)] == [True, True, False]
    now[0] = 61
    assert lim.hit("k", 2, 60)[0] is True
    assert lim.count("k") == 1


def test_redis_limiter_shares_state_between_instances():
    server = fakeredis.FakeServer()
    a, b = (RedisLimiter(fakeredis.FakeStrictRedis(server=server)) for _ in range(2))
    assert a.hit("k", 2, 60)[0] and b.hit("k", 2, 60)[0]
    assert a.hit("k", 2, 60)[0] is False  # a different API worker sees the same counter


# ------------------------------------------------------------------ input hardening
def test_oversized_json_body_rejected_before_parsing(client, monkeypatch):
    configure(monkeypatch, max_request_body_mb=0)
    r = client.post("/ingest", json=BODY)
    assert r.status_code == 413 and r.json()["detail"] == "request body too large"


def test_oversized_upload_rejected(client, monkeypatch):
    configure(monkeypatch, max_upload_mb=0, max_request_body_mb=50)
    assert upload(client, "<nmaprun/>", "nmap").status_code == 413


@pytest.mark.parametrize(
    "content",
    ["\x00\x01binary", "plain text, not xml", '{"json": "not xml"}'],
    ids=["binary", "text", "json"],
)
def test_non_xml_uploads_rejected(client, content):
    assert upload(client, content, "nmap").status_code == 422


def test_xml_element_bomb_rejected(client, monkeypatch, nmap_xml):
    configure(monkeypatch, max_xml_elements=10)
    r = upload(client, nmap_xml, "nmap")
    assert r.status_code == 422 and "elements" in r.json()["detail"]


@pytest.mark.parametrize(
    "evil",
    [
        '<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///etc/passwd">]><nmaprun>&x;</nmaprun>',
        '<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY a "aa"><!ENTITY b "&a;&a;&a;&a;">]><nmaprun>&b;</nmaprun>',
        "<nmaprun><host>",  # truncated
    ],
    ids=["xxe", "entity-expansion", "malformed"],
)
def test_hostile_xml_rejected_and_recorded_as_failed(client, evil):
    r = upload(client, evil, "nmap")
    assert r.status_code == 422
    assert client.get("/reports").json()[0]["status"] == "failed"


def test_too_many_findings_per_host_rejected(client, monkeypatch):
    configure(monkeypatch, max_findings_per_host=2)
    vulns = [{"title": f"v{i}", "port": 80} for i in range(3)]
    r = client.post("/ingest", json={"hosts": [{"ip_address": "10.0.0.1", "vulnerabilities": vulns}]})
    assert r.status_code == 422 and "more than 2 findings" in r.json()["detail"]


@pytest.mark.parametrize(
    "bad",
    [
        {"hosts": [{"ip_address": "999.1.1.1"}]},
        {"hosts": [{"ip_address": "10.0.0.1", "external_ids": {"BAD KEY": "x"}}]},
        {"hosts": [{"ip_address": "10.0.0.1", "connections": [{"dst": "nonsense"}]}]},
        {"hosts": [{"ip_address": "10.0.0.1", "vulnerabilities": [{"title": "x", "port": 70000}]}]},
        {"hosts": "not-a-list"},
        {"vantage": "mars", "hosts": [{"ip_address": "10.0.0.1"}]},
    ],
)
def test_invalid_structures_return_422(client, bad):
    assert client.post("/ingest", json=bad).status_code == 422


def test_asset_patch_validation(client):
    client.post("/ingest", json=BODY)
    for bad in ({"criticality": 9}, {"criticality": 0}, {"tags": ["has space"]}, {"controls": ["X" * 50]}):
        assert client.patch("/assets/1", json=bad).status_code == 422
    ok = client.patch("/assets/1", json={"criticality": 5, "tags": ["Domain-Controller"], "controls": ["edr"]})
    assert ok.status_code == 200 and ok.json()["tags"] == ["domain-controller"] and ok.json()["criticality"] == 5


def test_errors_do_not_leak_internals_and_carry_a_request_id(monkeypatch):
    from app.main import app

    def boom(*a, **k):
        raise RuntimeError("secret database password is hunter2")

    monkeypatch.setattr("app.api.routes_ingest.run_report", boom)
    c = TestClient(app, headers={"X-API-Key": TEST_KEY}, raise_server_exceptions=False)
    r = c.post("/ingest", json=BODY)
    assert r.status_code == 500 and "hunter2" not in r.text
    assert r.json()["request_id"] == r.headers["x-request-id"]


# ------------------------------------------------------------------ audit trail
def test_audit_log_records_actions_and_denials_without_secrets(client, anon_client, db):
    client.post("/ingest", json=BODY)
    client.patch("/assets/1", json={"criticality": 4})
    anon_client.get("/assets", headers={"X-API-Key": "attacker-guess-123"})
    rows = db.scalars(select(AuditLog).order_by(AuditLog.id)).all()
    assert [(r.action, r.status) for r in rows] == [
        ("ingest.submit", "ok"),
        ("asset.patch", "ok"),
        ("auth", "denied"),
    ]
    dump = " ".join(f"{r.actor} {r.resource} {r.detail}" for r in rows)
    assert TEST_KEY not in dump and "attacker-guess-123" not in dump
    assert rows[0].actor.startswith("key:") and rows[0].request_id and rows[0].client_ip


# ------------------------------------------------------------------ worker failure recovery
def test_stuck_reports_are_requeued_then_failed(db, monkeypatch):
    old = utcnow() - timedelta(hours=2)
    stuck = ScanReport(source="x", format="json", status="processing", started_at=old, attempts=1, raw_payload="{}")
    dead = ScanReport(source="x", format="json", status="processing", started_at=old, attempts=3, raw_payload="{}")
    fresh = ScanReport(
        source="x", format="json", status="processing", started_at=utcnow(), attempts=1, raw_payload="{}"
    )
    db.add_all([stuck, dead, fresh])
    db.commit()
    assert recover_stuck_reports(db) == [stuck.id]
    db.refresh(stuck), db.refresh(dead), db.refresh(fresh)
    assert stuck.status == ReportStatus.pending.value
    assert dead.status == ReportStatus.failed.value and "max attempts" in dead.error
    assert fresh.status == ReportStatus.processing.value  # a live worker is not disturbed
