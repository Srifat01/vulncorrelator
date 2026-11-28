"""Real Redis + real RQ worker (no fakes). Skipped unless TEST_REDIS_URL is set (CI sets it)."""

import os

import pytest
import redis
from rq import SimpleWorker

from app import database
from app.config import get_settings
from app.services.queue import get_queue, set_queue
from app.services.ratelimit import set_limiter

pytestmark = pytest.mark.skipif(not os.getenv("TEST_REDIS_URL"), reason="needs a real Redis (TEST_REDIS_URL)")

BODY = {
    "source": "t",
    "hosts": [
        {
            "ip_address": "8.8.4.10",
            "hostname": "web01",
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2099-1",
                    "title": "Remote Code Execution",
                    "port": 80,
                    "protocol": "tcp",
                    "cvss_score": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                }
            ],  # fmt: skip
        }
    ],
}


@pytest.fixture
def real_redis(monkeypatch):
    url = os.environ["TEST_REDIS_URL"]
    monkeypatch.setenv("REDIS_URL", url)
    get_settings.cache_clear()
    conn = redis.Redis.from_url(url)
    conn.flushdb()
    for name in ("ingest", "analysis", "intel"):
        set_queue(None, name)
    set_limiter(None)
    yield conn
    conn.flushdb()
    for name in ("ingest", "analysis", "intel"):
        set_queue(None, name)


def drain(conn):
    SimpleWorker(["ingest", "analysis", "intel"], connection=conn).work(burst=True, with_scheduler=False)


def test_async_ingest_then_analysis_through_a_real_worker(client, real_redis):
    r = client.post("/ingest?async_mode=true", json=BODY)
    assert r.status_code == 202
    rid = r.json()["id"]
    assert client.get(f"/reports/{rid}").json()["status"] == "pending"  # nothing has run yet: the job is in Redis
    assert get_queue("ingest").count == 1

    drain(real_redis)  # the worker runs ingest, which enqueues analysis, which the same drain then runs

    report = client.get(f"/reports/{rid}").json()
    assert report["status"] == "completed" and report["new_count"] == 1 and report["attempts"] == 1
    status = client.get("/analysis/status").json()
    assert status["latest_completed_run"]["trigger"] == "ingest" and status["stale"] is False
    assert client.get("/vulnerabilities").json()[0]["risk_model_version"] == "2.0"


def test_failed_jobs_are_recorded_and_do_not_wedge_the_queue(client, real_redis):
    bad = client.post(
        "/ingest/upload", files={"file": ("x.xml", b"<nmaprun><host>")}, data={"format": "nmap", "async_mode": "true"}
    )
    good = client.post("/ingest?async_mode=true", json=BODY)
    assert bad.status_code == good.status_code == 202
    drain(real_redis)
    assert client.get(f"/reports/{bad.json()['id']}").json()["status"] == "failed"
    assert client.get(f"/reports/{good.json()['id']}").json()["status"] == "completed"


def test_rate_limits_are_shared_through_redis(client, real_redis, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_INGEST_PER_MIN", "2")
    get_settings.cache_clear()
    set_limiter(None)
    codes = [client.post("/ingest", json={"hosts": [{"ip_address": "10.0.0.1"}]}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    assert any(k.startswith(b"vc:rl:") for k in real_redis.keys("*"))  # counters live in Redis, not process memory


def test_health_reports_redis(client, real_redis):
    assert client.get("/health").json() == {"status": "ok", "database": "ok", "redis": "ok"}
    assert database.engine is not None
