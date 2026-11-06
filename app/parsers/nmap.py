"""Nmap XML (-oX) parser. Understands -sV service detection and the `vulners` NSE script."""

from app.parsers.base import ParseError, parse_xml, to_float, valid_ip
from app.schemas import HostIn, ReportIn, ServiceIn, VulnerabilityIn
from app.services.intel import CVE_RE


def _vulners(script, svc_name, product, version, cpe, port, proto) -> list[VulnerabilityIn]:
    out: list[VulnerabilityIn] = []
    for table in script.iter("table"):
        elems = {e.get("key"): (e.text or "").strip() for e in table.findall("elem")}
        cve = elems.get("id", "")
        if not CVE_RE.fullmatch(cve) or elems.get("type", "cve") != "cve":
            continue
        out.append(
            VulnerabilityIn(
                cve_id=cve,
                title=f"{cve} on {product or svc_name or 'service'} {version or ''}".strip(),
                cvss_score=to_float(elems.get("cvss")),
                port=port,
                protocol=proto,
                service_name=svc_name,
                product=product,
                version=version,
                cpe=cpe,
                evidence={"script": "vulners", "is_exploit": elems.get("is_exploit") == "true"},
            )
        )
    return out


def parse_nmap(raw: str | bytes) -> ReportIn:
    root = parse_xml(raw)
    if root.tag != "nmaprun":
        raise ParseError("not an Nmap XML report (root element is not <nmaprun>)")

    hosts: list[HostIn] = []
    for h in root.findall("host"):
        status = h.find("status")
        if status is not None and status.get("state") != "up":
            continue
        ip = next(
            (valid_ip(a.get("addr")) for a in h.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")),
            None,
        )
        if not ip:
            continue
        hostname_el = h.find("hostnames/hostname")
        osmatch = h.find("os/osmatch")

        services: list[ServiceIn] = []
        vulns: list[VulnerabilityIn] = []
        for p in h.findall("ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            port = int(p.get("portid", "0"))
            proto = p.get("protocol", "tcp")
            if proto not in ("tcp", "udp") or not port:
                continue
            svc = p.find("service")
            name = svc.get("name") if svc is not None else None
            product = svc.get("product") if svc is not None else None
            version = svc.get("version") if svc is not None else None
            cpe_el = svc.find("cpe") if svc is not None else None
            cpe = cpe_el.text.strip() if cpe_el is not None and cpe_el.text else None
            services.append(ServiceIn(port=port, protocol=proto, name=name, product=product, version=version, cpe=cpe))
            for script in p.findall("script"):
                if script.get("id") == "vulners":
                    vulns += _vulners(script, name, product, version, cpe, port, proto)

        hosts.append(
            HostIn(
                ip_address=ip,
                hostname=hostname_el.get("name") if hostname_el is not None else None,
                os=osmatch.get("name") if osmatch is not None else None,
                services=services,
                vulnerabilities=vulns,
            )
        )
    if not hosts:
        raise ParseError("no live hosts found in Nmap report")
    return ReportIn(source="nmap", hosts=hosts)
