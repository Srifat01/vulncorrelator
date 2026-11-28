"""An independent reference implementation, written from the raw snapshot.

It shares NO code with app.graph (not the classifier, not the builder, not the search). If the engine and this
oracle agree on randomized networks, that is evidence the engine implements the documented model; if they
disagree, one of them is wrong - which is exactly what an evaluation is for.

Model (the same documented semantics, restated in the simplest possible form):
  * a position is (host, level) with level 1 = user, 2 = admin; the internet is the start
  * the internet reaches every service of a host flagged internet-facing, plus services named by an
    explicit internet flow; hosts reach services named by their (non-hypothetical) flows
  * a service flaw is usable remotely iff its CVSS vector says AV:N, it grants code execution (rce / backdoor /
    auth-bypass), and the service exists; backdoor => admin, otherwise user
  * a local escalation flaw (tag privesc) lifts user -> admin on the same host
  * a declared trust a -> b lets (a, level >= requires) become (b, grants)
  * a path ends the moment it reaches a target (criticality >= threshold)
"""

import re
from collections import defaultdict, deque

from app.graph.snapshot import Snapshot

LVL = {"user": 1, "admin": 2}


def _gain(v) -> int | None:
    tags = set(v.tags)
    if v.port is None or not v.cvss_vector or "AV:N" not in v.cvss_vector:
        return None
    if "backdoor" in tags:
        return 2
    return 1 if tags & {"rce", "auth-bypass"} else None


class Model:
    def __init__(self, snap: Snapshot, *, include_hypothetical: bool = False, min_crit: int = 4):
        self.crit = {a.id: a.criticality for a in snap.assets}
        self.min_crit = min_crit
        self.services: dict[int, set[tuple[int, str]]] = defaultdict(set)
        for s in snap.services:
            self.services[s.asset_id].add((s.port, s.protocol))
        self.gains: dict[tuple[int, int, str], set[int]] = defaultdict(set)
        self.priv_esc = {v.asset_id for v in snap.vulns if "privesc" in v.tags}
        for v in snap.vulns:
            g = _gain(v)
            if g and (v.port, v.protocol or "tcp") in self.services[v.asset_id]:
                self.gains[(v.asset_id, v.port, v.protocol or "tcp")].add(g)
        ok = lambda r: include_hypothetical or r.evidence_status != "hypothetical"  # noqa: E731
        self.inet: set[tuple[int, int, str]] = set()
        for a in snap.assets:
            if a.internet_facing:
                self.inet |= {(a.id, p, pr) for p, pr in self.services[a.id]}
        self.flows: dict[int, set[tuple[int, int, str]]] = defaultdict(set)
        self.trust: dict[int, list[tuple[int, int, int]]] = defaultdict(list)  # a -> (b, requires, grants)
        for r in snap.relationships:
            if not ok(r):
                continue
            dst = self._asset(r.dst)
            if r.kind == "CONNECTS_TO" and dst is not None:
                svcs = [(p, pr) for p, pr in self.services[dst] if (r.port in (0, p)) and (r.protocol in ("any", pr))]
                if r.src == "internet":
                    self.inet |= {(dst, p, pr) for p, pr in svcs}
                elif self._asset(r.src) is not None and self._asset(r.src) != dst:
                    self.flows[self._asset(r.src)] |= {(dst, p, pr) for p, pr in svcs}
            elif r.kind == "SHARES_TRUST_WITH" and dst is not None and self._asset(r.src) is not None:
                self.trust[self._asset(r.src)].append(
                    (dst, LVL[r.attrs.get("requires", "admin")], LVL[r.attrs.get("grants", "user")])
                )

    @staticmethod
    def _asset(ref: str) -> int | None:
        m = re.fullmatch(r"asset:(\d+)", ref)
        return int(m.group(1)) if m else None

    def is_target(self, a: int) -> bool:
        return self.crit.get(a, 0) >= self.min_crit

    def reachable_targets(self, max_steps: int = 5) -> set[int]:
        """Targets an attacker starting on the internet can reach within `max_steps` transitions."""
        seen: dict[tuple[int, int], int] = {}
        found: set[int] = set()
        q: deque[tuple[int, int, int]] = deque()

        def visit(a: int, lvl: int, depth: int) -> None:
            if (a, lvl) in seen and seen[(a, lvl)] <= depth:
                return
            seen[(a, lvl)] = depth
            if self.is_target(a):
                found.add(a)  # a path ends at its first target; do not expand through it
                return
            q.append((a, lvl, depth))

        for a, p, pr in self.inet:
            for g in self.gains.get((a, p, pr), ()):
                visit(a, g, 1)
        while q:
            a, lvl, d = q.popleft()
            if d >= max_steps or seen.get((a, lvl), 99) < d:
                continue
            for b, p, pr in self.flows.get(a, ()):
                for g in self.gains.get((b, p, pr), ()):
                    visit(b, g, d + 1)
            if lvl == 1 and a in self.priv_esc:
                visit(a, 2, d + 1)
            for b, req, grant in self.trust.get(a, ()):
                if lvl >= req:
                    visit(b, grant, d + 1)
        return found


def validate_path(model: Model, path: dict, max_steps: int = 5) -> list[str]:
    """Check every step of an engine-reported path against the raw model. Returns the list of violations."""
    bad: list[str] = []
    held: dict[int, int] = {}
    prev: int | None = None
    if len(path["steps"]) > max_steps:
        bad.append("too many steps")
    for s in path["steps"]:
        a, action = s["asset_id"], s["action"]
        svc = s.get("service") or {}
        sv = (svc.get("port"), svc.get("protocol"))
        lvl = LVL[s["to_position"].split(" on ")[0]]
        if action in ("initial_access", "lateral_movement"):
            if sv not in model.services[a]:
                bad.append(f"step {s['order']}: no such service")
            if lvl not in model.gains.get((a, *sv), set()):
                bad.append(f"step {s['order']}: no remote flaw granting level {lvl}")
            if action == "initial_access" and path["entry"]["kind"] == "internet":
                if (a, *sv) not in model.inet:
                    bad.append(f"step {s['order']}: service is not internet-reachable")
            elif prev is None or (a, *sv) not in model.flows.get(prev, set()):
                bad.append(f"step {s['order']}: no flow from {prev}")
        elif action == "privilege_escalation":
            if a != prev or held.get(a) != 1 or a not in model.priv_esc:
                bad.append(f"step {s['order']}: escalation not possible")
        elif action == "trust_pivot":
            if not any(
                b == a and held.get(prev, 0) >= req and grant == lvl for b, req, grant in model.trust.get(prev, ())
            ):
                bad.append(f"step {s['order']}: no usable trust")
        if lvl <= held.get(a, 0) and action != "privilege_escalation":
            bad.append(f"step {s['order']}: re-gains privilege already held")
        held[a] = max(held.get(a, 0), lvl)
        prev = a
    last = path["steps"][-1]["asset_id"]
    if not model.is_target(last):
        bad.append("path does not end at a target")
    return bad
