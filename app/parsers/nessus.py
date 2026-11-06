"""Nessus (.nessus v2 XML) parser."""

from app.parsers.base import ParseError, parse_xml, to_float, valid_ip
from app.schemas import HostIn, ReportIn, ServiceIn, VulnerabilityIn

_SEVERITY = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}


def _text(item, tag: str) -> str | None:
    el = item.find(tag)
    return el.text.strip() if el is not None and el.text and el.text.strip() else None


def parse_nessus(raw: str | bytes) -> ReportIn:
    root = parse_xml(raw)
    if root.tag != "NessusClientData_v2":
        raise ParseError("not a .nessus v2 report (root element is not <NessusClientData_v2>)")

    hosts: list[HostIn] = []
    for rh in root.findall("Report/ReportHost"):
        props = {t.get("name"): (t.text or "").strip() for t in rh.findall("HostProperties/tag")}
        ip = valid_ip(props.get("host-ip")) or valid_ip(rh.get("name"))
        if not ip:
            continue
        services: dict[tuple[int, str], ServiceIn] = {}
        vulns: list[VulnerabilityIn] = []
        for item in rh.findall("ReportItem"):
            port = int(item.get("port", "0") or 0)
            proto = item.get("protocol", "tcp")
            proto = proto if proto in ("tcp", "udp") else "tcp"
            svc_name = item.get("svc_name")
            if svc_name == "general":
                svc_name = None
            cpe = _text(item, "cpe")
            if port and (port, proto) not in services:
                services[(port, proto)] = ServiceIn(port=port, protocol=proto, name=svc_name)

            severity = _SEVERITY.get(item.get("severity", "0"), "info")
            cves = [c.text.strip() for c in item.findall("cve") if c.text and c.text.strip()]
            if severity == "info" and not cves:
                continue  # informational plugins only contribute services
            score = to_float(_text(item, "cvss3_base_score")) or to_float(_text(item, "cvss_base_score"))
            vector = _text(item, "cvss3_vector") or _text(item, "cvss_vector")
            common = dict(
                title=item.get("pluginName") or "Unnamed Nessus finding",
                description=_text(item, "description") or _text(item, "synopsis"),
                cvss_score=score,
                cvss_vector=vector,
                severity=severity,
                port=port or None,
                protocol=proto if port else None,
                service_name=svc_name,
                cpe=cpe,
                evidence={
                    "plugin_id": item.get("pluginID"),
                    "plugin_output": (_text(item, "plugin_output") or "")[:2000],
                },
            )
            if cves:
                vulns += [VulnerabilityIn(cve_id=c, **common) for c in cves]
            else:
                vulns.append(VulnerabilityIn(**common))

        hosts.append(
            HostIn(
                ip_address=ip,
                hostname=props.get("host-fqdn") or props.get("netbios-name"),
                os=props.get("operating-system"),
                services=list(services.values()),
                vulnerabilities=vulns,
            )
        )
    if not hosts:
        raise ParseError("no hosts found in Nessus report")
    return ReportIn(source="nessus", hosts=hosts)
