import pytest

from app.services.cpe import guess_vendor_product, normalize_service_name, parse_cpe
from app.services.fingerprint import fingerprint
from app.services.risk import normalize_cvss, risk_score, severity_from_score
from app.services.versions import parse_version, version_matches


class TestCpe:
    def test_parses_22_and_23_forms(self):
        a = parse_cpe("cpe:/a:apache:http_server:2.4.49")
        b = parse_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
        assert a == b
        assert (a.vendor, a.product, a.version, a.key) == ("apache", "http_server", "2.4.49", "apache:http_server")

    def test_wildcard_version_is_none(self):
        assert parse_cpe("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*").version is None

    @pytest.mark.parametrize("bad", [None, "", "nonsense", "cpe:/x:a:b", "cpe:/a:onlyvendor"])
    def test_rejects_garbage(self, bad):
        assert parse_cpe(bad) is None

    def test_vendor_aliases(self):
        assert guess_vendor_product("Apache httpd") == ("apache", "http_server")
        assert guess_vendor_product("OpenSSH") == ("openbsd", "openssh")
        assert guess_vendor_product("totally-unknown") is None

    def test_service_name_aliases(self):
        assert normalize_service_name("www") == "http"
        assert normalize_service_name("microsoft-ds") == "smb"
        assert normalize_service_name("http?") == "http"


class TestVersions:
    @pytest.mark.parametrize(
        "v,kw,expected",
        [
            ("2.4.49", {"exact": ["2.4.49"]}, True),
            ("2.4.50", {"exact": ["2.4.49"]}, False),
            ("1.0.1f", {"gte": "1.0.1", "lte": "1.0.1f"}, True),
            ("1.0.1g", {"gte": "1.0.1", "lte": "1.0.1f"}, False),
            ("7.2p2", {"lt": "7.7"}, True),
            ("8.9p1", {"lt": "7.7"}, False),
            ("2.4.100", {"lt": "2.4.9"}, False),  # numeric, not lexicographic
        ],
    )
    def test_matching(self, v, kw, expected):
        assert version_matches(v, **kw) is expected

    def test_parse(self):
        assert parse_version("2.4.49") < parse_version("2.4.50")


class TestRisk:
    def test_severity_bands(self):
        assert [severity_from_score(s) for s in (0, 3.9, 4, 6.9, 7, 8.9, 9, 10)] == [
            "info",
            "low",
            "medium",
            "medium",
            "high",
            "high",
            "critical",
            "critical",
        ]

    def test_normalize_clamps_and_falls_back_to_label(self):
        assert normalize_cvss(14.2, None) == (10.0, "critical")
        assert normalize_cvss(None, "High") == (8.0, "high")
        assert normalize_cvss(None, None) == (None, None)

    def test_kev_and_epss_raise_risk(self):
        assert risk_score(7.5, None, False) == 7.5
        assert risk_score(7.5, 0.5, True) == 9.0
        assert risk_score(9.8, 0.97, True) == 10.0  # capped


class TestFingerprint:
    base = dict(ip_address="10.0.0.1", port=80, protocol="tcp", service_name="http", version="2.4.49", title="x")

    def test_cve_identity_ignores_service_and_version(self):
        a = fingerprint(cve_id="CVE-2021-41773", **self.base)
        b = fingerprint(cve_id="cve-2021-41773", **{**self.base, "service_name": "www", "version": None})
        assert a == b

    def test_cve_identity_depends_on_asset_and_port(self):
        a = fingerprint(cve_id="CVE-2021-41773", **self.base)
        assert a != fingerprint(cve_id="CVE-2021-41773", **{**self.base, "port": 8080})
        assert a != fingerprint(cve_id="CVE-2021-41773", **{**self.base, "ip_address": "10.0.0.2"})

    def test_no_cve_uses_service_version_and_title(self):
        a = fingerprint(cve_id=None, **self.base)
        assert a == fingerprint(cve_id=None, **{**self.base, "title": "X!"})  # slug-normalized
        assert a != fingerprint(cve_id=None, **{**self.base, "version": "2.4.50"})
