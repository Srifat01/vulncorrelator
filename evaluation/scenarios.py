"""Synthetic networks with *known* attack paths.

Planted scenarios: attack chains are built by construction, then surrounded by decoys that, by construction,
cannot be compromised. Ground truth is therefore known exactly and does not depend on the engine under test.
All identifiers are synthetic; nothing here is real vulnerability data.
"""

import random
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.graph.snapshot import AssetRec, RelRec, ServiceRec, Snapshot, VulnRec

NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)
NET = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
LOCAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"

PathKey = tuple  # ((asset_id, action, vuln_id | identity | None), ...)


@dataclass
class Scenario:
    name: str
    snapshot: Snapshot
    truth_paths: dict[PathKey, str]  # key -> expected evidence class
    decoys: set[int]  # hosts that must never appear on any path
    targets: set[int]
    kinds: dict[PathKey, str] = field(default_factory=dict)  # chain kind per path, for reporting


class _Builder:
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.snap = Snapshot()
        self.next_asset = self.next_vuln = self.next_rel = 1
        self.port = 8000

    def asset(self, subnet: int, *, crit: int = 2, exposed: bool = False) -> int:
        i = self.next_asset
        self.next_asset += 1
        ip = f"10.{subnet}.{i // 250}.{i % 250 + 1}"
        self.snap.assets.append(
            AssetRec(
                i, ip, f"h{i}", None, exposed, "declared" if exposed else "unknown", crit, first_seen=NOW, last_seen=NOW
            )  # fmt: skip
        )
        return i

    def service(self, a: int) -> int:
        self.port += 1
        self.snap.services.append(ServiceRec(a, self.port, "tcp", "svc", first_seen=NOW, last_seen=NOW))
        return self.port

    def vuln(self, a: int, port: int | None, tags: list[str], *, vector=NET, status="observed") -> int:
        v = self.next_vuln
        self.next_vuln += 1
        self.snap.vulns.append(
            VulnRec(
                v,
                a,
                f"synthetic {v}",
                f"CVE-2099-{v:05d}",
                port,
                "tcp" if port else None,
                tags,
                9.8,
                vector,
                status,
                ["synthetic"],
                {},
                first_seen=NOW,
                last_seen=NOW,
            )  # fmt: skip
        )
        return v

    def rel(self, kind, src, dst, port=0, status="observed", **attrs) -> None:
        r = self.next_rel
        self.next_rel += 1
        self.snap.relationships.append(RelRec(r, kind, src, dst, status, "synthetic", port, "any", attrs, NOW, NOW))


def _expected(statuses: list[str]) -> str:
    # Written independently of app.graph.explain: weakest link decides.
    if "hypothetical" in statuses:
        return "hypothetical"
    if "inferred" in statuses:
        return "partially_inferred"
    return "confirmed" if all(s == "confirmed" for s in statuses) else "observed"


def planted(seed: int = 1, n_chains: int = 6, n_decoy_groups: int = 4, n_subnets: int = 3) -> Scenario:
    """`n_chains` attack chains of three kinds, plus decoys in the same subnets (a flat network)."""
    b = _Builder(seed)
    truth: dict[PathKey, str] = {}
    kinds: dict[PathKey, str] = {}
    targets: set[int] = set()
    chain_hosts: list[int] = []

    for c in range(n_chains):
        kind = ("exploit", "priv-trust", "credential")[c % 3]
        exposure = b.rng.choice(["inferred", "observed", "confirmed"])
        vstat = b.rng.choice(["observed", "inferred", "confirmed"])
        fstat = b.rng.choice(["observed", "confirmed"])
        sub = lambda: b.rng.randrange(n_subnets)  # noqa: E731

        if kind == "exploit":
            length = b.rng.randint(2, 4)
            hosts = [b.asset(sub(), exposed=(i == 0)) for i in range(length)]
            b.snap.assets[hosts[-1] - 1].criticality = 5
            ports = [b.service(h) for h in hosts]
            vulns = [b.vuln(h, p, ["rce"], status=vstat) for h, p in zip(hosts, ports, strict=True)]
            statuses = []
            if exposure != "inferred":
                b.rel("CONNECTS_TO", "internet", f"asset:{hosts[0]}", ports[0], exposure)
            steps = []
            for i, h in enumerate(hosts):
                conn = exposure if i == 0 else fstat
                if i > 0:
                    b.rel("CONNECTS_TO", f"asset:{hosts[i - 1]}", f"asset:{h}", ports[i], fstat)
                statuses += [conn if (i or exposure != "inferred") else "inferred", vstat, vstat]
                steps.append((h, "initial_access" if i == 0 else "lateral_movement", vulns[i]))
            key = tuple(steps)
            truth[key], kinds[key] = _expected(statuses), kind
            chain_hosts += hosts
            targets.add(hosts[-1])

        else:  # priv-trust / credential: a foothold on h0, local escalation, then a pivot to the target h1
            h0, h1 = b.asset(sub(), exposed=True), b.asset(sub(), crit=5)
            p0 = b.service(h0)
            p1 = b.service(h1)
            v_rce = b.vuln(h0, p0, ["rce"], status=vstat)
            v_esc = b.vuln(h0, None, ["privesc"], vector=LOCAL, status=vstat)
            if exposure != "inferred":
                b.rel("CONNECTS_TO", "internet", f"asset:{h0}", p0, exposure)
            first = exposure if exposure != "inferred" else "inferred"
            statuses = [first, vstat, vstat, vstat]  # reach, AFFECTED_BY, CAN_EXPLOIT, escalation
            steps = [(h0, "initial_access", v_rce), (h0, "privilege_escalation", v_esc)]
            if kind == "priv-trust":
                b.rel("SHARES_TRUST_WITH", f"asset:{h0}", f"asset:{h1}", 0, fstat, requires="admin", grants="user")
                statuses += [fstat]
                steps.append((h1, "trust_pivot", None))
            else:
                name = f"svc-key-{c}"
                b.rel("CAN_ACCESS", f"asset:{h0}", f"identity:{name}", 0, fstat, requires="admin")
                b.rel("AUTHENTICATES_TO", f"identity:{name}", f"asset:{h1}", p1, fstat)
                b.rel("CONNECTS_TO", f"asset:{h0}", f"asset:{h1}", p1, fstat)
                statuses += [fstat] * 4
                steps.append((h1, "credential_use", name))
            key = tuple(steps)
            truth[key], kinds[key] = _expected(statuses), kind
            chain_hosts += [h0, h1]
            targets.add(h1)

    # ---- decoys: each is provably not compromisable
    decoys: set[int] = set()
    for _ in range(n_decoy_groups):
        sub = b.rng.randrange(n_subnets)
        src = b.rng.choice(chain_hosts)  # a host an attacker legitimately controls along some chain

        unreachable = b.asset(sub, crit=5)  # vulnerable crown jewel in the same subnet, no flow at all
        b.vuln(unreachable, b.service(unreachable), ["rce"])

        dead_end = b.asset(sub, crit=5)  # reachable, but its only flaw grants no code execution
        p = b.service(dead_end)
        b.vuln(dead_end, p, ["info-disclosure"])
        b.rel("CONNECTS_TO", f"asset:{src}", f"asset:{dead_end}", p)

        local_only = b.asset(sub, crit=5)  # reachable, flaw needs local access
        p = b.service(local_only)
        b.vuln(local_only, p, ["rce"], vector=LOCAL)
        b.rel("CONNECTS_TO", f"asset:{src}", f"asset:{local_only}", p)

        assumed = b.asset(sub, crit=5)  # vulnerable, but the only flow into it is an assumption
        p = b.service(assumed)
        b.vuln(assumed, p, ["rce"])
        b.rel("CONNECTS_TO", f"asset:{src}", f"asset:{assumed}", p, "hypothetical")

        closed = b.asset(sub, crit=5)  # flow targets a port nothing listens on
        p = b.service(closed)
        b.vuln(closed, p, ["rce"])
        b.rel("CONNECTS_TO", f"asset:{src}", f"asset:{closed}", p + 500)

        exposed_clean = b.asset(sub, crit=5, exposed=True)  # internet-facing, but nothing exploitable
        b.service(exposed_clean)
        decoys |= {unreachable, dead_end, local_only, assumed, closed, exposed_clean}

    return Scenario(f"planted(seed={seed},chains={n_chains})", b.snap, truth, decoys, targets, kinds)


def random_network(seed: int, n_hosts: int, density: float = 1.0) -> Snapshot:
    """A random topology for oracle comparison. No ground truth is baked in: the independent oracle supplies it.

    `density` scales how many exploitable flaws and flows there are (1.0 = sparse, 2.5 = richly connected)."""
    b = _Builder(seed)
    r = b.rng
    ids = [
        b.asset(r.randrange(4), crit=5 if r.random() < 0.12 else 2, exposed=r.random() < 0.2) for _ in range(n_hosts)
    ]
    ports: dict[int, list[int]] = {}
    for a in ids:
        ports[a] = [b.service(a) for _ in range(r.randint(1, 3))]
        for p in ports[a]:
            roll = r.random()
            if roll < 0.35 * density:
                b.vuln(a, p, ["rce"], status=r.choice(["observed", "inferred", "confirmed"]))
            elif roll < 0.35 * density + 0.03:
                b.vuln(a, p, ["rce", "backdoor"])
            elif roll < 0.35 * density + 0.15:
                b.vuln(a, p, ["info-disclosure"])
            elif roll < 0.35 * density + 0.2:
                b.vuln(a, p, ["rce"], vector=LOCAL)
        if r.random() < min(0.6, 0.25 * density):
            b.vuln(a, None, ["privesc"], vector=LOCAL)
    for a in ids:
        for _ in range(r.randint(0, round(2 * density))):
            dst = r.choice(ids)
            if dst != a:
                b.rel("CONNECTS_TO", f"asset:{a}", f"asset:{dst}", r.choice(ports[dst]),
                      r.choice(["observed", "observed", "confirmed", "hypothetical"]))  # fmt: skip
    for _ in range(max(2, n_hosts // 5)):  # trusts exercise the admin-only pivots that make escalation necessary
        a, c = r.sample(ids, 2)
        b.rel("SHARES_TRUST_WITH", f"asset:{a}", f"asset:{c}", 0, "observed",
              requires=r.choice(["admin", "admin", "user"]), grants=r.choice(["user", "admin"]))  # fmt: skip
    return b.snap
