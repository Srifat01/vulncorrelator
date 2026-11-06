"""Correlation engine: rules that turn individual findings into attack chains.

Rules are pure functions over lightweight in-memory nodes, so they are easy to unit test
and easy to extend - add a function and append it to RULES.

Vocabulary (tags on a finding):
  foothold  = remotely reachable flaw that gives code execution/access: rce, backdoor, auth-bypass, sqli
  privesc   = local privilege escalation (needs a foothold first)
"""

import hashlib
import ipaddress
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset, Vulnerability
from app.services.risk import severity_from_score

FOOTHOLD_TAGS = frozenset({"rce", "backdoor", "auth-bypass", "sqli"})
PRIVESC_TAGS = frozenset({"privesc"})
MAX_PIVOT_TARGETS = 3  # per internet-facing entry point, to keep output readable


@dataclass(frozen=True)
class VulnNode:
    id: int
    cve_id: str | None
    title: str
    tags: frozenset[str]
    risk: float
    in_kev: bool
    port: int | None

    @property
    def label(self) -> str:
        if self.cve_id and self.cve_id.upper() not in self.title.upper():
            return f"{self.title} ({self.cve_id})"
        return self.title

    @property
    def is_remote_foothold(self) -> bool:
        return self.port is not None and bool(self.tags & FOOTHOLD_TAGS)


@dataclass
class AssetNode:
    id: int
    ip: str
    hostname: str | None
    internet_facing: bool
    vulns: list[VulnNode] = field(default_factory=list)

    @property
    def name(self) -> str:
        return f"{self.ip} ({self.hostname})" if self.hostname else self.ip

    @property
    def subnet(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        ip = ipaddress.ip_address(self.ip)
        return ipaddress.ip_network(f"{ip}/{24 if ip.version == 4 else 64}", strict=False)


@dataclass
class Step:
    role: str
    asset: AssetNode
    vuln: VulnNode


@dataclass
class Chain:
    rule: str
    title: str
    steps: list[Step]
    explanation: str
    risk_score: float = 0.0

    def __post_init__(self) -> None:
        self.risk_score = _chain_risk(self.steps)

    @property
    def id(self) -> str:
        key = self.rule + "|" + ",".join(str(s.vuln.id) for s in self.steps)
        return hashlib.sha1(key.encode()).hexdigest()[:12]

    @property
    def severity(self) -> str:
        return severity_from_score(self.risk_score) or "info"


def _chain_risk(steps: list[Step]) -> float:
    """Worst step, +0.5 per extra step, +0.5 if any step is actively exploited (KEV),
    +0.5 if the entry point is internet-facing. Capped at 10."""
    score = max(s.vuln.risk for s in steps)
    score += 0.5 * (len(steps) - 1)
    score += 0.5 if any(s.vuln.in_kev for s in steps) else 0.0
    score += 0.5 if steps[0].asset.internet_facing else 0.0
    return round(min(10.0, score), 1)


def _best(vulns: Iterable[VulnNode], pred: Callable[[VulnNode], bool]) -> VulnNode | None:
    return max((v for v in vulns if pred(v)), key=lambda v: (v.risk, -v.id), default=None)


# ------------------------------------------------------------------ rules
def rule_foothold_to_privesc(assets: list[AssetNode]) -> Iterable[Chain]:
    """Same host: a remote foothold plus a local privilege escalation = full host takeover."""
    for a in assets:
        foothold = _best(a.vulns, lambda v: v.is_remote_foothold)
        privesc = _best(a.vulns, lambda v: bool(v.tags & PRIVESC_TAGS))
        if foothold and privesc:
            yield Chain(
                rule="foothold-to-privesc",
                title=f"Remote foothold to root on {a.name}",
                steps=[Step("initial-access", a, foothold), Step("privilege-escalation", a, privesc)],
                explanation=(
                    f"{a.name} exposes {foothold.label} on port {foothold.port}, which gives an attacker "
                    f"code execution as the service user. The same host also has {privesc.label}, "
                    f"so that foothold can be escalated to full control of the machine."
                ),
            )


def rule_lateral_movement(assets: list[AssetNode]) -> Iterable[Chain]:
    """Internet-facing foothold + a remotely exploitable flaw on a non-exposed neighbour
    in the same subnet = pivot into the internal network."""
    for a in (x for x in assets if x.internet_facing):
        entry = _best(a.vulns, lambda v: v.is_remote_foothold)
        if not entry:
            continue
        targets = []
        for b in assets:
            if b.id == a.id or b.internet_facing or b.subnet != a.subnet:
                continue
            target = _best(b.vulns, lambda v: v.is_remote_foothold)
            if target:
                targets.append((b, target))
        targets.sort(key=lambda t: (-t[1].risk, t[0].id))
        for b, target in targets[:MAX_PIVOT_TARGETS]:
            yield Chain(
                rule="lateral-movement",
                title=f"Pivot from {a.name} to {b.name}",
                steps=[Step("initial-access", a, entry), Step("lateral-movement", b, target)],
                explanation=(
                    f"{a.name} is internet-facing and vulnerable to {entry.label}. Once compromised it "
                    f"sits in the same {a.subnet} network as {b.name}, which runs {target.label} on "
                    f"port {target.port} and is not directly exposed - a classic pivot path."
                ),
            )


def rule_exploited_on_exposed(assets: list[AssetNode]) -> Iterable[Chain]:
    """Internet-facing service with a vulnerability known to be exploited in the wild (CISA KEV)."""
    for a in (x for x in assets if x.internet_facing):
        for v in a.vulns:
            if v.in_kev and v.port is not None:
                yield Chain(
                    rule="exploited-on-exposed-service",
                    title=f"Actively exploited flaw on internet-facing {a.name}",
                    steps=[Step("initial-access", a, v)],
                    explanation=(
                        f"{v.label} is on CISA's Known Exploited Vulnerabilities list and affects port "
                        f"{v.port} on internet-facing {a.name}. Attackers are using it in the wild."
                    ),
                )


RULES: list[Callable[[list[AssetNode]], Iterable[Chain]]] = [
    rule_foothold_to_privesc,
    rule_lateral_movement,
    rule_exploited_on_exposed,
]


def find_chains(assets: list[AssetNode]) -> list[Chain]:
    chains = [c for rule in RULES for c in rule(assets)]
    return sorted(chains, key=lambda c: (-c.risk_score, c.id))


# ------------------------------------------------------------------ DB bridge
def load_nodes(db: Session) -> list[AssetNode]:
    nodes = {
        a.id: AssetNode(a.id, a.ip_address, a.hostname, a.internet_facing)
        for a in db.scalars(select(Asset).order_by(Asset.id))
    }
    rows = db.execute(
        select(
            Vulnerability.id,
            Vulnerability.asset_id,
            Vulnerability.cve_id,
            Vulnerability.title,
            Vulnerability.tags,
            Vulnerability.risk_score,
            Vulnerability.in_kev,
            Vulnerability.port,
        )
    )
    for vid, asset_id, cve, title, tags, risk, kev, port in rows:
        nodes[asset_id].vulns.append(VulnNode(vid, cve, title, frozenset(tags or []), risk, bool(kev), port))
    return list(nodes.values())


def chain_to_dict(c: Chain) -> dict:
    seen: dict[int, dict] = {}
    for s in c.steps:
        seen.setdefault(s.asset.id, {"id": s.asset.id, "ip_address": s.asset.ip})
    return {
        "id": c.id,
        "rule": c.rule,
        "title": c.title,
        "risk_score": c.risk_score,
        "severity": c.severity,
        "explanation": c.explanation,
        "assets": list(seen.values()),
        "steps": [
            {
                "order": i + 1,
                "role": s.role,
                "asset_id": s.asset.id,
                "ip_address": s.asset.ip,
                "vulnerability_id": s.vuln.id,
                "cve_id": s.vuln.cve_id,
                "title": s.vuln.title,
                "risk_score": s.vuln.risk,
            }
            for i, s in enumerate(c.steps)
        ],
    }


def compute_chains(db: Session) -> list[dict]:
    return [chain_to_dict(c) for c in find_chains(load_nodes(db))]
