import pytest

from app.parsers import ParseError, parse_report
from app.schemas import HostIn, ServiceIn, VulnerabilityIn
from app.services.intel import get_intel
from app.services.normalizer import build_findings


def test_nmap_parser(nmap_xml):
    report = parse_report("nmap", nmap_xml)
    assert [h.ip_address for h in report.hosts] == ["10.0.1.10", "10.0.1.20"]  # down host skipped
    web = report.hosts[0]
    assert web.hostname == "web01.corp.local" and web.os == "Linux 5.4"
    assert {s.port for s in web.services} == {22, 80}  # closed 8080 skipped
    assert [v.cve_id for v in web.vulnerabilities] == ["CVE-2021-41773"]  # PACKETSTORM ignored
    assert web.vulnerabilities[0].cvss_score == 7.5


def test_nessus_parser(nessus_xml):
    host = parse_report("nessus", nessus_xml).hosts[0]
    assert host.ip_address == "10.0.1.10"
    assert {(v.cve_id, v.port) for v in host.vulnerabilities} == {
        ("CVE-2021-41773", 80),
        ("CVE-2021-4034", None),
        (None, 443),
    }  # port 0 -> host-level; info plugin skipped
    assert next(v for v in host.vulnerabilities if v.cve_id == "CVE-2021-41773").cvss_score == 9.8


def test_xml_with_encoding_declaration(nmap_xml):
    parse_report("nmap", nmap_xml.replace('<?xml version="1.0"?>', '<?xml version="1.0" encoding="UTF-8"?>'))


def test_xxe_and_entity_bombs_rejected():
    evil = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><nmaprun>&a;</nmaprun>'
    with pytest.raises(ParseError, match="unsafe XML"):
        parse_report("nmap", evil)


@pytest.mark.parametrize(
    "fmt,raw",
    [("nmap", "<nessus/>"), ("nessus", "<nmaprun/>"), ("nmap", "not xml"), ("json", "{"), ("json", "{}"), ("csv", "")],
)
def test_bad_input_raises_parse_error(fmt, raw):
    with pytest.raises(ParseError):
        parse_report(fmt, raw)


def _host(**kw):
    return HostIn(ip_address="10.0.0.5", **kw)


def test_service_version_maps_to_cves_via_catalog():
    host = _host(services=[ServiceIn(port=80, name="http", product="Apache httpd", version="2.4.49")])
    services, findings = build_findings(host, "nmap", get_intel())
    assert {f.cve_id for f in findings} == {"CVE-2021-41773", "CVE-2021-42013"}
    f = next(f for f in findings if f.cve_id == "CVE-2021-41773")
    assert f.in_kev and f.risk_score == 10.0 and "rce" in f.tags and f.sources == ["catalog"]
    assert services[0].cpe.startswith("cpe:2.3:a:apache:http_server:2.4.49")  # vendor name normalized


def test_scanner_and_catalog_findings_dedupe_within_a_host():
    host = _host(
        services=[ServiceIn(port=80, name="http", product="Apache httpd", version="2.4.49")],
        vulnerabilities=[
            VulnerabilityIn(cve_id="cve-2021-41773", title="Apache bug", port=80, protocol="tcp", cvss_score=7.5)
        ],
    )
    _, findings = build_findings(host, "nmap", get_intel())
    [f] = [f for f in findings if f.cve_id == "CVE-2021-41773"]
    assert f.sources == ["catalog", "nmap"] and set(f.evidence) == {"catalog", "nmap"}


def test_cvss_from_label_cve_from_title_and_tag_inference():
    host = _host(
        vulnerabilities=[VulnerabilityIn(title="Foo allows Remote Code Execution (CVE-2099-0001)", severity="High")]
    )
    _, [f] = build_findings(host, "x", get_intel())
    assert f.cve_id == "CVE-2099-0001" and f.cvss_score == 8.0 and f.severity == "high" and f.tags == ["rce"]


def test_finding_inherits_service_details():
    host = _host(
        services=[ServiceIn(port=22, name="ssh", product="OpenSSH", version="7.2p2")],
        vulnerabilities=[VulnerabilityIn(title="weak kex", port=22)],
    )
    _, findings = build_findings(host, "x", get_intel())
    weak = next(f for f in findings if f.title == "weak kex")
    assert (weak.product, weak.version, weak.service_name) == ("OpenSSH", "7.2p2", "ssh")
    assert any(f.cve_id == "CVE-2018-15473" for f in findings)  # OpenSSH < 7.7


def test_generic_scanner_title_is_replaced_by_catalog_title():
    host = _host(vulnerabilities=[VulnerabilityIn(cve_id="CVE-2021-4034", title="CVE-2021-4034 on polkit", port=None)])
    _, [f] = build_findings(host, "nmap", get_intel())
    assert "PwnKit" in f.title
