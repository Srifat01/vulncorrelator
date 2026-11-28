"""Threat-intelligence pipeline: clients, retries, rate limits, freshness, provenance, history, scheduling."""

import json
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import func, select

from app import database
from app.config import get_settings
from app.intel import jobs, scheduler
from app.intel.cli import main as cli_main
from app.intel.http import IntelError, ResilientClient, SlidingWindowLimiter
from app.intel.sources import cpe_match_applies, fetch_epss, fetch_kev, parse_kev, parse_nvd_cve
from app.intel.status import cve_view, intel_status
from app.intel.sync import (
    apply_cpe_matches,
    last_success,
    lookup_cpes,
    refresh_vulnerabilities,
    sync_all,
    sync_epss,
    sync_kev,
    sync_nvd,
)
from app.models import CpeLookup, CveIntel, IntelHistory, IntelSyncRun, ScanReport, Vulnerability, utcnow
from app.services.cpe import parse_cpe
from tests.conftest import TEST_KEY
from tests.intel_helpers import NET, Upstream, cpe_match, epss_payload, kev_payload, nvd_item, nvd_payload, widget

CVE_A, CVE_B, CVE_C = "CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"


@pytest.fixture(autouse=True)
def feeds(monkeypatch):
    monkeypatch.setenv("INTEL_LIVE_SYNC", "true")  # these tests use a mock upstream, never the real network
    monkeypatch.setenv("KEV_URL", "https://kev.test/feed.json")
    monkeypatch.setenv("EPSS_BASE_URL", "https://epss.test/v1/epss")
    monkeypatch.setenv("NVD_BASE_URL", "https://nvd.test/cves")
    get_settings.cache_clear()


@pytest.fixture
def up():
    return Upstream()


def track(db, *cves, asset_ip="10.0.0.1"):
    """Give the database some findings so there are CVEs to look up."""
    from app.models import Asset

    a = Asset(ip_address=asset_ip, hostname="h", internet_facing=False)
    db.add(a)
    db.flush()
    for i, c in enumerate(cves):
        db.add(Vulnerability(fingerprint=f"fp-{asset_ip}-{i}", asset_id=a.id, cve_id=c, title=c, tags=[], sources=["t"],
                             evidence={}, cvss_score=5.0, port=80, protocol="tcp"))  # fmt: skip
    db.commit()
    return a


# ================================================================== HTTP resilience
class TestResilientClient:
    def make(self, handler, **kw):
        sleeps = []
        c = ResilientClient(transport=httpx.MockTransport(handler), sleep=sleeps.append, rng=lambda: 0.0, **kw)
        return c, sleeps

    def test_retries_server_errors_with_exponential_backoff_then_succeeds(self):
        codes = iter([503, 502, 200])
        c, sleeps = self.make(lambda r: httpx.Response(next(codes), json={"ok": 1}))
        assert c.get("https://x.test/").json() == {"ok": 1}
        assert sleeps == [1.0, 2.0] and c.requests_made == 3

    def test_honours_retry_after_but_caps_it(self):
        seq = iter(
            [
                httpx.Response(429, headers={"Retry-After": "7"}),
                httpx.Response(429, headers={"Retry-After": "99999"}),
                httpx.Response(200, json={}),
            ]
        )
        c, sleeps = self.make(lambda r: next(seq))
        c.get("https://x.test/")
        assert sleeps == [7.0, 120.0]

    def test_gives_up_after_max_retries_with_a_retryable_error(self):
        c, sleeps = self.make(lambda r: httpx.Response(503), max_retries=2)
        with pytest.raises(IntelError) as e:
            c.get("https://x.test/")
        assert e.value.retryable and c.requests_made == 3 and len(sleeps) == 2

    def test_client_errors_are_not_retried(self):
        c, sleeps = self.make(lambda r: httpx.Response(404))
        with pytest.raises(IntelError) as e:
            c.get("https://x.test/")
        assert e.value.status == 404 and not e.value.retryable and c.requests_made == 1 and sleeps == []

    def test_timeouts_and_connection_errors_are_retried(self):
        calls = []

        def handler(request):
            calls.append(1)
            if len(calls) == 1:
                raise httpx.ConnectTimeout("slow", request=request)
            if len(calls) == 2:
                raise httpx.ConnectError("down", request=request)
            return httpx.Response(200, json={"ok": True})

        c, sleeps = self.make(handler)
        assert c.get("https://x.test/").json() == {"ok": True} and len(sleeps) == 2

    def test_not_modified_is_a_valid_answer_when_allowed(self):
        c, _ = self.make(lambda r: httpx.Response(304))
        assert c.get("https://x.test/", ok=(200, 304)).status_code == 304


def test_rate_limiter_waits_instead_of_exceeding_the_window():
    t, sleeps = [0.0], []

    def sleep(s):
        sleeps.append(s)
        t[0] += s

    lim = SlidingWindowLimiter(5, 30, clock=lambda: t[0], sleep=sleep)
    for _ in range(5):
        lim.acquire()
    assert sleeps == []
    lim.acquire()  # the 6th call inside 30s must wait for the window to roll over
    assert sleeps == [30.0] and t[0] == 30.0


# ================================================================== parsing
class TestParsers:
    def test_kev(self):
        cat = parse_kev(kev_payload(CVE_A, "garbage", CVE_B), etag='"v1"')
        assert [e.cve_id for e in cat.entries] == [CVE_A, CVE_B] and cat.skipped == 1 and cat.etag == '"v1"'

    @pytest.mark.parametrize(
        "bad", [{}, {"vulnerabilities": "x"}, {"vulnerabilities": []}, {"vulnerabilities": [{"cveID": "nope"}]}, []]
    )
    def test_kev_malformed_is_refused(self, bad):
        with pytest.raises(IntelError):
            parse_kev(bad)

    def test_epss_batches_and_skips_bad_rows(self, up):
        ids = [f"CVE-2099-{i:04d}" for i in range(150)]
        junk = [{"cve": "CVE-2099-9999", "epss": "7.0"}, {"cve": "CVE-2099-9998", "epss": "abc"}, {"nope": 1}]
        up.handlers["epss.test"] = lambda r: {
            "data": [
                {"cve": c, "epss": "0.5", "percentile": "0.7", "date": "2026-11-20"}
                for c in r.url.params["cve"].split(",")
            ]
            + junk
        }
        out = fetch_epss(up.clients().http, "https://epss.test/v1/epss", ids + ["not-a-cve"])
        assert len(up.hits("epss.test")) == 2 and len(out) == 150  # 100 + 50; invalid/out-of-range rows dropped
        assert "CVE-2099-9999" not in out and "CVE-2099-9998" not in out

    def test_epss_malformed_payload(self, up):
        up.handlers["epss.test"] = {"status": "OK"}
        with pytest.raises(IntelError, match="malformed"):
            fetch_epss(up.clients().http, "https://epss.test/v1/epss", [CVE_A])

    def test_nvd_prefers_primary_v31_over_v2_and_derives_tags(self):
        m = [cpe_match(widget("1.0"))]
        c = parse_nvd_cve(
            nvd_item(CVE_A, score=9.8, v2=7.5, matches=m, cwe="CWE-22", desc="A privilege escalation bug.")
        )
        assert (c.cvss_score, c.cvss_version, c.cvss_vector) == (9.8, "3.1", NET)
        assert c.cwe == ["CWE-22"] and c.tags == ["path-traversal", "privesc"]
        assert c.description == "A privilege escalation bug." and len(c.cpe_matches) == 1 and c.last_modified.tzinfo

    def test_nvd_falls_back_to_v2_and_tolerates_missing_metrics(self):
        item = nvd_item(CVE_A)
        item["cve"]["metrics"] = {
            "cvssMetricV2": [
                {"type": "Primary", "cvssData": {"version": "2.0", "baseScore": 5.0, "vectorString": "AV:N"}}
            ]
        }
        assert parse_nvd_cve(item).cvss_score == 5.0
        item["cve"]["metrics"] = {}
        c = parse_nvd_cve(item)
        assert c.cvss_score is None and c.cvss_vector is None  # absent stays absent

    @pytest.mark.parametrize("bad", [{}, {"cve": {}}, {"cve": {"id": "nope"}}, []])
    def test_nvd_malformed(self, bad):
        with pytest.raises(IntelError):
            parse_nvd_cve(bad)


class TestCpeMatching:
    t = parse_cpe(widget("2.4.49"))

    @pytest.mark.parametrize(
        "match,expected",
        [
            (cpe_match(widget("2.4.49")), True),  # exact version
            (cpe_match(widget("2.4.50")), False),
            (cpe_match("cpe:2.3:a:acme:widget_server:*:*:*:*:*:*:*:*"), True),  # all versions
            (
                cpe_match(
                    "cpe:2.3:a:acme:widget_server:*:*:*:*:*:*:*:*",
                    versionStartIncluding="2.4.0",
                    versionEndExcluding="2.4.50",
                ),
                True,
            ),
            (cpe_match("cpe:2.3:a:acme:widget_server:*:*:*:*:*:*:*:*", versionEndExcluding="2.4.49"), False),
            (cpe_match("cpe:2.3:a:acme:widget_server:*:*:*:*:*:*:*:*", versionStartExcluding="2.4.49"), False),
            (cpe_match("cpe:2.3:a:acme:widget_server:*:*:*:*:*:*:*:*", versionEndIncluding="2.4.49"), True),
            (cpe_match("cpe:2.3:a:other:widget_server:*:*:*:*:*:*:*:*"), False),  # different vendor
            (cpe_match("cpe:2.3:a:acme:gadget:*:*:*:*:*:*:*:*"), False),  # different product
            ({"vulnerable": True, "criteria": "garbage"}, False),
        ],
    )
    def test_cases(self, match, expected):
        assert cpe_match_applies(match, self.t) is expected

    def test_needs_a_version_on_the_target(self):
        assert (
            cpe_match_applies(cpe_match(widget("1")), parse_cpe("cpe:2.3:a:acme:widget_server:*:*:*:*:*:*:*:*"))
            is False
        )


# ================================================================== KEV sync
class TestKevSync:
    def test_first_sync_creates_live_records_and_history(self, db, up):
        up.handlers["kev.test"] = lambda r: httpx.Response(
            200, json=kev_payload(CVE_A, CVE_B), headers={"ETag": '"e1"'}
        )
        run = sync_kev(db, up.clients().http)
        assert (run.status, run.records_seen, run.records_updated) == ("success", 2, 2)
        row = db.get(CveIntel, CVE_A)
        assert row.in_kev and row.kev_origin == "live" and row.kev_synced_at and row.kev_date_added == "2026-10-01"
        assert run.watermark["etag"] == '"e1"' and run.watermark["catalog_version"] == "2026.11.01"
        assert db.scalar(select(func.count(IntelHistory.id)).where(IntelHistory.source == "kev")) == 2

    def test_conditional_get_uses_the_stored_etag(self, db, up):
        up.handlers["kev.test"] = lambda r: httpx.Response(200, json=kev_payload(CVE_A), headers={"ETag": '"e1"'})
        sync_kev(db, up.clients().http)
        up.handlers["kev.test"] = lambda r: httpx.Response(304)
        run = sync_kev(db, up.clients().http)
        assert up.hits("kev.test")[-1].headers["if-none-match"] == '"e1"'
        assert run.status == "success" and run.watermark["not_modified"] and run.records_updated == 0

    def test_entries_removed_upstream_are_unflagged_with_history(self, db, up):
        up.handlers["kev.test"] = kev_payload(CVE_A, CVE_B)
        sync_kev(db, up.clients().http)
        up.handlers["kev.test"] = kev_payload(CVE_A)
        sync_kev(db, up.clients().http)
        assert db.get(CveIntel, CVE_B).in_kev is False and db.get(CveIntel, CVE_A).in_kev is True
        assert db.scalars(
            select(IntelHistory).where(IntelHistory.cve_id == CVE_B).order_by(IntelHistory.id.desc())
        ).first().value == {"in_kev": False}

    def test_outage_is_recorded_and_leaves_existing_data_untouched(self, db, up):
        up.handlers["kev.test"] = kev_payload(CVE_A)
        sync_kev(db, up.clients().http)
        stamp = db.get(CveIntel, CVE_A).kev_synced_at
        up.handlers["kev.test"] = lambda r: httpx.Response(503)
        run = sync_kev(db, up.clients().http)
        assert run.status == "failed" and "giving up" in run.error
        db.expire_all()
        assert db.get(CveIntel, CVE_A).in_kev is True and db.get(CveIntel, CVE_A).kev_synced_at == stamp
        assert up.sleeps  # it backed off rather than hammering

    def test_malformed_feed_never_wipes_the_catalog(self, db, up):
        up.handlers["kev.test"] = kev_payload(CVE_A)
        sync_kev(db, up.clients().http)
        up.handlers["kev.test"] = {
            "vulnerabilities": []
        }  # an empty feed is treated as corruption, not "everything fixed"
        assert sync_kev(db, up.clients().http).status == "failed"
        assert db.get(CveIntel, CVE_A).in_kev is True


# ================================================================== EPSS sync
class TestEpssSync:
    def test_writes_live_values_and_history_only_on_change(self, db, up):
        track(db, CVE_A)
        up.handlers["epss.test"] = epss_payload(**{CVE_A: 0.25})
        run = sync_epss(db, up.clients().http, force=True)
        assert run.status == "success" and run.records_updated == 1
        row = db.get(CveIntel, CVE_A)
        assert (row.epss, row.epss_percentile, row.epss_date, row.epss_origin) == (0.25, 0.9, "2026-11-20", "live")
        sync_epss(db, up.clients().http, force=True)  # same value again
        assert db.scalar(select(func.count(IntelHistory.id)).where(IntelHistory.source == "epss")) == 1
        up.handlers["epss.test"] = epss_payload(**{CVE_A: 0.6})
        sync_epss(db, up.clients().http, force=True)
        hist = db.scalars(select(IntelHistory).where(IntelHistory.source == "epss").order_by(IntelHistory.id)).all()
        assert [h.value["epss"] for h in hist] == [0.25, 0.6]  # the old score is preserved

    def test_fresh_records_are_not_refetched(self, db, up):
        track(db, CVE_A)
        up.handlers["epss.test"] = epss_payload(**{CVE_A: 0.25})
        sync_epss(db, up.clients().http)
        before = len(up.hits("epss.test"))
        run = sync_epss(db, up.clients().http)
        assert len(up.hits("epss.test")) == before and run.watermark["note"] == "all tracked CVEs are fresh"
        row = db.get(CveIntel, CVE_A)
        row.epss_synced_at = utcnow() - timedelta(days=30)  # now stale
        db.commit()
        sync_epss(db, up.clients().http)
        assert len(up.hits("epss.test")) == before + 1

    def test_unscored_cves_stay_unscored(self, db, up):
        track(db, CVE_A, CVE_B)
        up.handlers["epss.test"] = epss_payload(**{CVE_A: 0.1})
        run = sync_epss(db, up.clients().http)
        assert run.watermark["unscored"] == [CVE_B]
        assert db.get(CveIntel, CVE_B) is None or db.get(CveIntel, CVE_B).epss is None  # no default invented

    def test_failure_is_recorded_not_raised(self, db, up):
        track(db, CVE_A)
        up.handlers["epss.test"] = lambda r: httpx.Response(500)
        run = sync_epss(db, up.clients().http)
        assert run.status == "failed" and db.get(CveIntel, CVE_A) is None


# ================================================================== NVD sync
class TestNvdSync:
    def test_fetches_tracked_cves_and_records_history_on_change(self, db, up):
        track(db, CVE_A)
        up.handlers["nvd.test"] = lambda r: nvd_payload(nvd_item(r.url.params["cveId"], score=7.5))
        run = sync_nvd(db, up.clients().nvd)
        assert run.status == "success" and run.records_updated == 1
        row = db.get(CveIntel, CVE_A)
        assert (row.cvss_score, row.cvss_version, row.nvd_origin) == (7.5, "3.1", "live") and "rce" in row.tags
        up.handlers["nvd.test"] = lambda r: nvd_payload(nvd_item(r.url.params["cveId"], score=9.1))
        sync_nvd(db, up.clients().nvd, force=True)
        hist = db.scalars(select(IntelHistory).where(IntelHistory.source == "nvd").order_by(IntelHistory.id)).all()
        assert [h.value["cvss_score"] for h in hist] == [7.5, 9.1]

    def test_respects_ttl(self, db, up):
        track(db, CVE_A)
        up.handlers["nvd.test"] = lambda r: nvd_payload(nvd_item(r.url.params["cveId"]))
        sync_nvd(db, up.clients().nvd)
        n = len(up.hits("nvd.test"))
        sync_nvd(db, up.clients().nvd)
        assert len(up.hits("nvd.test")) == n

    def test_client_side_rate_limit_without_api_key(self, db, up):
        cves = [f"CVE-2099-{i:04d}" for i in range(7)]
        track(db, *cves)
        up.handlers["nvd.test"] = lambda r: nvd_payload(nvd_item(r.url.params["cveId"]))
        run = sync_nvd(db, up.clients().nvd)
        assert run.status == "success" and len(up.hits("nvd.test")) == 7
        assert any(s > 0 for s in up.sleeps)  # 5 requests per 30 s: calls 6 and 7 had to wait

    def test_api_key_is_sent_and_raises_the_allowance(self, db, up, monkeypatch):
        monkeypatch.setenv("NVD_API_KEY", "k-123")
        get_settings.cache_clear()
        cves = [f"CVE-2099-{i:04d}" for i in range(7)]
        track(db, *cves)
        up.handlers["nvd.test"] = lambda r: nvd_payload(nvd_item(r.url.params["cveId"]))
        sync_nvd(db, up.clients().nvd)
        assert all(r.headers["apikey"] == "k-123" for r in up.hits("nvd.test")) and up.sleeps == []

    def test_403_rate_limiting_is_retried(self, db, up):
        track(db, CVE_A)
        seq = iter([httpx.Response(403), None])
        up.handlers["nvd.test"] = lambda r: next(seq) or nvd_payload(nvd_item(CVE_A))
        assert sync_nvd(db, up.clients().nvd).status == "success" and len(up.hits("nvd.test")) == 2

    def test_outage_stops_the_run_cleanly(self, db, up):
        track(db, CVE_A, CVE_B, CVE_C)
        up.handlers["nvd.test"] = lambda r: httpx.Response(503)
        run = sync_nvd(db, up.clients().nvd)
        assert run.status == "failed" and len(up.hits("nvd.test")) == get_settings().intel_max_retries + 1  # not 3x

    def test_request_budget_yields_a_partial_run(self, db, up):
        track(db, CVE_A, CVE_B, CVE_C)
        up.handlers["nvd.test"] = lambda r: nvd_payload(nvd_item(r.url.params["cveId"]))
        run = sync_nvd(db, up.clients().nvd, max_requests=2)
        assert run.status == "partial" and "left for the next run" in run.error and run.records_updated == 2

    def test_unknown_cve_is_reported_not_invented(self, db, up):
        track(db, CVE_A)
        up.handlers["nvd.test"] = nvd_payload()
        run = sync_nvd(db, up.clients().nvd)
        assert run.status == "partial" and "not found in NVD" in run.error and db.get(CveIntel, CVE_A) is None


# ================================================================== CPE lookups
class TestCpeLookups:
    def service_on(self, db, version="2.4.49"):
        from app.models import Asset, Service

        a = Asset(ip_address="10.0.0.9", hostname="w", internet_facing=False)
        db.add(a)
        db.flush()
        db.add(Service(asset_id=a.id, port=80, protocol="tcp", name="http", product="widget", version=version,
                       cpe=f"cpe:/a:acme:widget_server:{version}"))  # fmt: skip
        db.commit()
        return a

    def test_results_are_verified_before_being_trusted(self, db, up):
        self.service_on(db)
        good = nvd_item(
            CVE_A, matches=[cpe_match("cpe:2.3:a:acme:widget_server:*:*:*:*:*:*:*:*", versionEndExcluding="3.0")]
        )
        bad = nvd_item(CVE_B, matches=[cpe_match(widget("9.9"))])  # NVD "answered" with a CVE that doesn't cover 2.4.49
        up.handlers["nvd.test"] = lambda r: nvd_payload(good, bad)
        run = lookup_cpes(db, up.clients().nvd)
        assert run.status == "success" and "1 NVD result(s) rejected" in run.error
        lookup = db.get(CpeLookup, widget("2.4.49"))
        assert lookup.cve_ids == [CVE_A] and lookup.origin == "live"
        assert db.get(CveIntel, CVE_A) is not None and db.get(CveIntel, CVE_B) is None  # the rejected one is not stored
        assert up.hits("nvd.test")[0].url.params["cpeName"] == widget("2.4.49")  # 2.2 CPE was canonicalised

    def test_pagination(self, db, up):
        self.service_on(db)
        m = [cpe_match(widget("2.4.49"))]
        pages = {"0": nvd_payload(nvd_item(CVE_A, matches=m), nvd_item(CVE_B, matches=m), total=3, per_page=2),
                 "2": nvd_payload(nvd_item(CVE_C, matches=m), total=3, per_page=2)}  # fmt: skip
        up.handlers["nvd.test"] = lambda r: pages[r.url.params["startIndex"]]
        lookup_cpes(db, up.clients().nvd)
        assert len(up.hits("nvd.test")) == 2 and db.get(CpeLookup, widget("2.4.49")).cve_ids == [CVE_A, CVE_B, CVE_C]

    def test_unknown_cpe_is_cached_as_empty(self, db, up):
        self.service_on(db)
        up.handlers["nvd.test"] = lambda r: httpx.Response(404)
        run = lookup_cpes(db, up.clients().nvd)
        assert run.status == "success" and db.get(CpeLookup, widget("2.4.49")).cve_ids == []
        n = len(up.hits("nvd.test"))
        lookup_cpes(db, up.clients().nvd)
        assert len(up.hits("nvd.test")) == n  # cached: no re-query within the TTL

    def test_versionless_cpes_are_not_looked_up(self, db, up):
        from app.models import Asset, Service

        a = Asset(ip_address="10.0.0.9", internet_facing=False)
        db.add(a)
        db.flush()
        db.add(Service(asset_id=a.id, port=80, protocol="tcp", cpe="cpe:/a:acme:widget_server"))
        db.commit()
        up.handlers["nvd.test"] = nvd_payload()
        lookup_cpes(db, up.clients().nvd)
        assert up.hits("nvd.test") == []


# ================================================================== end-to-end propagation
def make_upstream_for_widget(up, *, kev=(), epss=None, score=8.8):
    m = [cpe_match("cpe:2.3:a:acme:widget_server:*:*:*:*:*:*:*:*", versionEndExcluding="3.0")]
    up.handlers["kev.test"] = kev_payload(*kev) if kev else kev_payload("CVE-2099-7777")
    up.handlers["epss.test"] = epss_payload(**(epss or {}))
    up.handlers["nvd.test"] = lambda r: nvd_payload(
        nvd_item(CVE_A, score=score, matches=m, desc="Allows remote code execution.")
    )


WIDGET_SERVICE = {
    "port": 80, "protocol": "tcp", "name": "http", "product": "widget", "version": "2.4.49",
    "cpe": "cpe:/a:acme:widget_server:2.4.49",
}  # fmt: skip
WIDGET_SCAN = {"source": "t", "hosts": [{"ip_address": "10.0.0.9", "hostname": "w1", "services": [WIDGET_SERVICE]}]}


def test_full_pipeline_from_scan_to_attributed_risk(client, db, up, monkeypatch):
    monkeypatch.setenv("INTEL_DEMO_DATA", "false")
    get_settings.cache_clear()
    client.post("/ingest", json=WIDGET_SCAN)
    assert (
        db.scalar(select(func.count(Vulnerability.id))) == 0
    )  # no intel yet => no CVEs invented from a version string
    make_upstream_for_widget(up, kev=[CVE_A], epss={CVE_A: 0.75})
    runs = sync_all(db, up.clients())
    assert {r.source: r.status for r in runs} == {
        "kev": "success",
        "cpe": "success",
        "nvd": "success",
        "epss": "success",
    }
    v = db.scalars(select(Vulnerability)).one()
    assert (
        v.cve_id == CVE_A and v.sources == ["nvd-cpe"] and v.evidence_status == "inferred"
    )  # version match, not a scanner finding
    assert (v.cvss_score, v.cvss_source, v.epss, v.in_kev) == (8.8, "nvd", 0.75, True)
    assert "rce" in v.tags
    detail = client.get(f"/vulnerabilities/{v.id}").json()
    comps = detail["risk_components"]
    assert (
        comps["likelihood"]["basis"] == "kev"
        and comps["likelihood"]["epss"] == 0.75
        and not comps["likelihood"]["assumed"]
    )
    assert not any("KEV has not been synced" in m for m in comps["data_quality"]) or detail["in_kev"]
    assert (
        detail["intel"]["sources"]["nvd"]["data_class"] == "live"
        and detail["intel"]["sources"]["epss"]["data_class"] == "live"
    )
    assert detail["intel"]["history"]


def test_enrichment_applies_to_later_scans_from_the_cache(client, db, up, monkeypatch):
    monkeypatch.setenv("INTEL_DEMO_DATA", "false")
    get_settings.cache_clear()
    client.post("/ingest", json=WIDGET_SCAN)
    make_upstream_for_widget(up)
    sync_all(db, up.clients(), ("cpe", "nvd"))
    other = json.loads(json.dumps(WIDGET_SCAN))
    other["hosts"][0].update(ip_address="10.0.0.77", hostname="w2")
    client.post("/ingest", json=other)  # a brand-new host with the same product version
    assert (
        db.scalar(select(func.count(Vulnerability.id)).where(Vulnerability.cve_id == CVE_A)) == 2
    )  # matched at ingest, offline


def test_scanner_cvss_is_replaced_by_nvd_with_attribution(db, up):
    a = track(db, CVE_A)
    up.handlers["nvd.test"] = lambda r: nvd_payload(nvd_item(CVE_A, score=6.1))
    sync_nvd(db, up.clients().nvd)
    assert refresh_vulnerabilities(db) == 1
    v = db.scalars(select(Vulnerability).where(Vulnerability.asset_id == a.id)).one()
    assert (v.cvss_score, v.cvss_source, v.severity) == (6.1, "nvd", "medium")


def test_sync_all_survives_one_broken_source(db, up):
    track(db, CVE_A)
    up.handlers["kev.test"] = lambda r: httpx.Response(500)
    up.handlers["epss.test"] = epss_payload(**{CVE_A: 0.3})
    up.handlers["nvd.test"] = lambda r: nvd_payload(nvd_item(CVE_A))
    runs = {r.source: r.status for r in sync_all(db, up.clients())}
    assert runs["kev"] == "failed" and runs["epss"] == "success" and runs["nvd"] == "success"


def test_ingestion_never_touches_the_network(client, monkeypatch):
    import socket

    def boom(*a, **k):
        raise AssertionError("ingestion attempted a network call")

    # TestClient is an in-process ASGI client (no sockets), so a socket-level guard only trips on real network use.
    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr("app.intel.http.ResilientClient.get", boom)
    assert client.post("/ingest", json=WIDGET_SCAN).status_code == 200


# ================================================================== demo vs live vs missing
def test_demo_data_is_off_by_default_and_never_invents_epss(client, monkeypatch, nmap_xml):
    from tests.conftest import upload

    monkeypatch.setenv("INTEL_DEMO_DATA", "false")
    get_settings.cache_clear()
    upload(client, nmap_xml, "nmap")
    cves = {v["cve_id"] for v in client.get("/vulnerabilities?limit=50").json()}
    assert cves == {"CVE-2021-41773"}  # only what the scanner itself reported; nothing derived from the bundled catalog
    top = client.get("/risk/priorities").json()[0]
    assert top["epss"] is None and top["cvss_source"] == "scanner"
    assert top["risk_components"]["likelihood"]["basis"] == "assumed_missing"
    st = client.get("/intel/status").json()
    assert st["demo_data"] == {"enabled": False}
    assert all(s["status"] == "never_synced" for s in st["sources"].values())


def test_demo_data_is_labelled_wherever_it_surfaces(client, nmap_xml):
    from tests.conftest import upload

    upload(client, nmap_xml, "nmap")  # conftest enables the demo catalog
    v = next(x for x in client.get("/vulnerabilities?limit=50").json() if x["cve_id"] == "CVE-2021-42013")
    assert v["sources"] == ["catalog"] and v["evidence_status"] == "inferred" and v["cvss_source"] == "demo"
    assert v["epss"] is None  # the demo set contains no EPSS values at all
    view = client.get("/intel/cves/CVE-2021-41773").json()
    assert view["sources"]["nvd"]["data_class"] == "demo" and view["sources"]["kev"]["data_class"] == "demo"
    assert view["sources"]["epss"] == {"data_class": "missing"}
    st = client.get("/intel/status").json()
    assert (
        st["demo_data"]["enabled"] and "NOT live" in st["demo_data"]["warning"] and st["demo_data"]["epss_values"] == 0
    )


def test_live_data_outranks_demo_data(client, db, up, nmap_xml):
    from tests.conftest import upload

    upload(client, nmap_xml, "nmap")
    up.handlers["nvd.test"] = lambda r: nvd_payload(nvd_item(r.url.params["cveId"], score=4.2, vector=NET))
    sync_nvd(db, up.clients().nvd, force=True)
    refresh_vulnerabilities(db)
    view = client.get("/intel/cves/CVE-2021-41773").json()
    assert view["sources"]["nvd"]["data_class"] == "live" and view["sources"]["nvd"]["value"]["cvss_score"] == 4.2


# ================================================================== freshness / staleness
def age(db, source, hours):
    run = last_success(db, source)
    run.finished_at = utcnow() - timedelta(hours=hours)
    db.commit()


def test_status_distinguishes_never_fresh_stale_and_failing(client, db, up):
    track(db, CVE_A)
    s = client.get("/intel/status").json()["sources"]["kev"]
    assert s["status"] == "never_synced" and s["last_success_at"] is None
    up.handlers["kev.test"] = kev_payload(CVE_A)
    sync_kev(db, up.clients().http)
    s = client.get("/intel/status").json()["sources"]["kev"]
    assert s["status"] == "fresh" and s["age_hours"] < 1 and s["ttl_hours"] == 48
    age(db, "kev", 72)
    assert client.get("/intel/status").json()["sources"]["kev"]["status"] == "stale"
    up.handlers["kev.test"] = lambda r: httpx.Response(503)
    sync_kev(db, up.clients().http)  # fails; the old data remains but is no fresher
    s = client.get("/intel/status").json()["sources"]["kev"]
    assert s["status"] == "failing" and s["last_attempt_status"] == "failed" and "giving up" in s["last_error"]


def test_record_level_data_classes_and_stale_detection(client, db, up):
    track(db, CVE_A)
    up.handlers["epss.test"] = epss_payload(**{CVE_A: 0.4})
    sync_epss(db, up.clients().http)
    assert client.get(f"/intel/cves/{CVE_A}").json()["sources"]["epss"]["data_class"] == "live"
    row = db.get(CveIntel, CVE_A)
    row.epss_synced_at = utcnow() - timedelta(days=10)
    db.commit()
    view = client.get(f"/intel/cves/{CVE_A}").json()["sources"]["epss"]
    assert (
        view["data_class"] == "cached" and view["age_hours"] > 200 and view["value"]["epss"] == 0.4
    )  # kept, but flagged
    assert client.get("/intel/status").json()["coverage"]["stale_epss_records"] == 1


def test_history_and_cve_endpoint_validation(client, db, up):
    track(db, CVE_A)
    for score in (0.1, 0.9):
        up.handlers["epss.test"] = epss_payload(**{CVE_A: score})
        sync_epss(db, up.clients().http, force=True)
    hist = client.get(f"/intel/cves/{CVE_A}").json()["history"]
    assert [h["value"]["epss"] for h in hist] == [0.9, 0.1]  # newest first, old score preserved
    assert client.get("/intel/cves/not-a-cve").status_code == 422
    assert client.get("/intel/cves/CVE-2099-5555").status_code == 404
    assert client.get("/intel/sync-runs", params={"source": "epss"}).json()[0]["source"] == "epss"
    assert client.get("/intel/sync-runs", params={"source": "bogus"}).status_code == 422


# ================================================================== triggering & scheduling
def test_sync_endpoint_inline_when_no_worker(client, db, up, monkeypatch):
    track(db, CVE_A)
    up.handlers["epss.test"] = epss_payload(**{CVE_A: 0.2})
    monkeypatch.setattr("app.api.routes_intel.build_clients", lambda: up.clients())
    r = client.post("/intel/sync", json={"sources": ["epss"]})
    assert (
        r.status_code == 200
        and [x["source"] for x in r.json()["runs"]] == ["epss"]
        and r.json()["runs"][0]["status"] == "success"
    )
    assert client.post("/intel/sync?async_mode=true", json={}).status_code == 503
    assert client.post("/intel/sync", json={"sources": ["nope"]}).status_code == 422
    assert "intel.sync" in {a["action"] for a in client.get("/audit").json()}


def test_sync_endpoint_respects_the_air_gap_switch_and_roles(client, anon_client, monkeypatch):
    monkeypatch.setenv("INTEL_LIVE_SYNC", "false")
    monkeypatch.setenv("READONLY_API_KEY", "rk")
    get_settings.cache_clear()
    assert client.post("/intel/sync", json={}).status_code == 409
    assert anon_client.post("/intel/sync", json={}, headers={"X-API-Key": "rk"}).status_code == 403
    assert anon_client.get("/intel/status", headers={"X-API-Key": "rk"}).status_code == 200


def _queue(name="intel"):
    import fakeredis
    from rq import Queue

    from app.services.queue import set_queue

    q = Queue(name, connection=fakeredis.FakeStrictRedis(), is_async=True)  # jobs stay queued: no execution, no network
    set_queue(q, name)
    return q


def test_scheduler_queues_a_sync_only_when_due(db, monkeypatch):
    monkeypatch.setenv("REDIS_URL", "redis://fake")
    get_settings.cache_clear()
    q = _queue()
    _queue("ingest")
    assert scheduler.tick(db) == ["queued intel sync"] and q.count == 1  # never synced => due
    db.add(IntelSyncRun(source="kev", status="success", origin="live", finished_at=utcnow() - timedelta(hours=2)))
    db.commit()
    assert scheduler.tick(db) == []  # synced 2h ago, interval is 24h
    last = last_success(db, "kev")
    last.finished_at = utcnow() - timedelta(hours=25)
    db.commit()
    assert scheduler.tick(db) == ["queued intel sync"]  # overdue
    db.add(IntelSyncRun(source="kev", status="failed", origin="live", finished_at=utcnow() - timedelta(minutes=10)))
    db.commit()
    assert scheduler.tick(db) == []  # failed 10 minutes ago: back off
    newest = db.scalars(select(IntelSyncRun).order_by(IntelSyncRun.id.desc())).first()
    newest.finished_at = utcnow() - timedelta(hours=2)
    db.commit()
    assert scheduler.tick(db) == ["queued intel sync"]  # retry after an hour


def test_scheduler_honours_the_air_gap_switch_and_needs_a_worker(db, monkeypatch):
    assert scheduler.tick(db) == []  # no Redis configured: nothing to enqueue into
    monkeypatch.setenv("REDIS_URL", "redis://fake")
    monkeypatch.setenv("INTEL_LIVE_SYNC", "false")
    get_settings.cache_clear()
    _queue()
    _queue("ingest")
    assert scheduler.tick(db) == []


def test_scheduler_requeues_reports_stranded_by_a_dead_worker(db, monkeypatch):
    monkeypatch.setenv("REDIS_URL", "redis://fake")
    monkeypatch.setenv("INTEL_LIVE_SYNC", "false")
    get_settings.cache_clear()
    q = _queue("ingest")
    r = ScanReport(
        source="x",
        format="json",
        status="processing",
        started_at=utcnow() - timedelta(hours=3),
        attempts=1,
        raw_payload="{}",
    )
    db.add(r)
    db.commit()
    assert scheduler.tick(db) == [f"requeued report {r.id}"] and q.count == 1


def test_enrichment_is_debounced_and_optional(monkeypatch):
    monkeypatch.setenv("REDIS_URL", "redis://fake")
    get_settings.cache_clear()
    q = _queue()
    assert jobs.request_enrichment() is True and jobs.request_enrichment() is False and q.count == 1  # 2-minute lock
    monkeypatch.setenv("INTEL_LIVE_SYNC", "false")
    get_settings.cache_clear()
    assert jobs.request_enrichment() is False


def test_sync_job_runs_against_the_database(up, monkeypatch):
    with database.SessionLocal() as db:
        track(db, CVE_A)
    up.handlers["epss.test"] = epss_payload(**{CVE_A: 0.33})
    monkeypatch.setattr("app.intel.jobs.build_clients", lambda: up.clients())
    assert jobs.sync_job(["epss"]) == [{"source": "epss", "status": "success", "updated": 1}]


def test_cli(db, up, monkeypatch, capsys):
    track(db, CVE_A)
    up.handlers["epss.test"] = epss_payload(**{CVE_A: 0.5})
    monkeypatch.setattr("app.intel.cli.build_clients", lambda: up.clients())
    assert cli_main(["sync", "--sources", "epss"]) == 0
    assert "epss" in capsys.readouterr().out and cli_main(["status"]) == 0
    assert json.loads(capsys.readouterr().out)["sources"]["epss"]["status"] == "fresh"
    up.handlers["epss.test"] = lambda r: httpx.Response(500)
    assert cli_main(["sync", "--sources", "epss", "--force"]) == 1  # non-zero exit lets cron/alerting notice
    with pytest.raises(SystemExit):
        cli_main(["sync", "--sources", "nope"])


def test_cve_view_for_unknown_cve_is_none(db):
    assert cve_view(db, "CVE-2099-0000") is None
    assert intel_status(db)["coverage"]["cves_with_intel"] == 0
    _ = TEST_KEY, fetch_kev, apply_cpe_matches  # exported API stays importable
