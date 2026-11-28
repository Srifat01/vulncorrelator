"""Constrained attack-path search over an `InfraGraph`.

The attacker is modelled as occupying a *position*: the internet, or a privilege level (user / admin) on a host.
A path is a sequence of *transitions* between positions. Four transition kinds exist, each requiring specific edges:

  exploit     position --CONNECTS_TO--> service --AFFECTED_BY--> vulnerability --CAN_EXPLOIT--> privilege
  escalate    user on host --CAN_ESCALATE_TO--> admin on the same host          (needs an existing foothold)
  credential  privilege --CAN_ACCESS--> identity --AUTHENTICATES_TO--> service --CAN_ACCESS--> privilege
              (the service must be reachable from a position the attacker already holds)
  trust       privilege --SHARES_TRUST_WITH--> privilege

Constraints: no position is visited twice (cycle-safe), at most `max_steps` transitions, hypothetical edges are
ignored unless `include_hypothetical`, a hard expansion budget bounds worst-case work, and a path ends the moment it
reaches a target. Nothing here assumes two hosts can talk to each other: every CONNECTS_TO edge is evidence.
"""

from dataclasses import dataclass, field

from app.graph.builder import INTERNET, priv_id
from app.graph.model import Edge, EdgeType, GraphView, Node, NodeType

LEVEL = {"user": 1, "admin": 2}


@dataclass
class PathParams:
    max_steps: int = 5
    max_paths: int = 500
    max_expansions: int = 200_000
    include_hypothetical: bool = False
    min_edge_confidence: float = 0.0
    start_internet: bool = True
    start_assets: list[int] = field(default_factory=list)  # analyst-supplied "assume this host is compromised"
    target_asset_ids: list[int] | None = None
    target_min_criticality: int = 4
    prune_dominated: bool = True  # drop a path when a shorter, at-least-as-well-evidenced path covers it


@dataclass
class Transition:
    kind: str  # exploit | escalate | credential | trust
    src: str  # position before
    dst: str  # position after (a privilege node)
    edges: list[Edge]  # evidential edges, in order; their statuses decide the path's evidence class
    supporting: list[Edge] = field(default_factory=list)  # context edges (e.g. RUNS_SERVICE) - listed, not scored
    vuln: Node | None = None
    service: Node | None = None
    identity: str | None = None
    alternatives: list[Node] = field(default_factory=list)  # other vulns that would achieve the same step


@dataclass
class FoundPath:
    entry: str  # INTERNET or a privilege node id
    entry_kind: str  # internet | assumed_foothold
    transitions: list[Transition]


@dataclass
class SearchResult:
    paths: list[FoundPath]
    truncated: bool
    expansions: int
    target_mode: str  # explicit | crown_jewels | any_admin
    target_assets: list[int]
    pruned_dominated: int = 0


def _threat(v: Node) -> float:
    t = v.attrs.get("threat")
    if t is not None:
        return float(t)
    return float(v.attrs.get("cvss_score") or 0) / 10


def _usable(e: Edge, p: PathParams) -> bool:
    if e.evidence_status == "hypothetical" and not p.include_hypothetical:
        return False
    return e.confidence >= p.min_edge_confidence


def _stronger(a: Edge, b: Edge) -> bool:
    return (a.confidence, b.id) > (b.confidence, a.id)  # higher confidence wins; ties broken by id for determinism


def _asset_of(graph: GraphView, pos: str) -> int | None:
    n = graph.node(pos)
    return n.attrs.get("asset_id") if n else None


def _sources(graph: GraphView, pos: str) -> list[str]:
    """Nodes whose outgoing edges the attacker can use from `pos` (admin implies user)."""
    if pos == INTERNET:
        return [INTERNET]
    a = _asset_of(graph, pos)
    return [pos, priv_id(a, "user")] if pos.endswith(":admin") else [pos]


def _best_vuln(cands: list[tuple[Edge, Node, Edge]]) -> tuple[tuple[Edge, Node, Edge], list[Node]]:
    ranked = sorted(cands, key=lambda c: (-_threat(c[1]), -(c[1].attrs.get("cvss_score") or 0), c[1].id))
    return ranked[0], [c[1] for c in ranked[1:]]


def transitions_from(
    graph: GraphView, pos: str, held_hosts: set[int], has_internet: bool, held_idents: frozenset[str], p: PathParams
) -> list[Transition]:
    out: list[Transition] = []
    srcs = _sources(graph, pos)

    # ---- exploit: reach a service, then use a remotely exploitable flaw on it
    reach: dict[str, Edge] = {}
    for s in srcs:
        for e in graph.out_edges(s, EdgeType.CONNECTS_TO):
            if _usable(e, p) and (e.dst not in reach or _stronger(e, reach[e.dst])):
                reach[e.dst] = e
    for svc_id, conn in sorted(reach.items()):
        groups: dict[str, list[tuple[Edge, Node, Edge]]] = {}
        for aff in graph.out_edges(svc_id, EdgeType.AFFECTED_BY):
            v = graph.node(aff.dst)
            if v is None or not v.attrs.get("remote") or not _usable(aff, p):
                continue
            for ex in graph.out_edges(v.id, EdgeType.CAN_EXPLOIT):
                if _usable(ex, p):
                    groups.setdefault(ex.dst, []).append((aff, v, ex))
        for dst, cands in sorted(groups.items()):
            (aff, v, ex), alts = _best_vuln(cands)
            support = [e for e in graph.in_edges(svc_id, EdgeType.RUNS_SERVICE)]
            out.append(Transition("exploit", pos, dst, [conn, aff, ex], support, v, graph.node(svc_id), None, alts))

    # ---- escalate: user -> admin on the same host via a local flaw
    if pos != INTERNET and pos.endswith(":user"):
        groups2: dict[str, list[tuple[Edge, Node]]] = {}
        for e in graph.out_edges(pos, EdgeType.CAN_ESCALATE_TO):
            v = graph.node(f"vuln:{e.attrs.get('vuln_id')}")
            if v is not None and _usable(e, p):
                groups2.setdefault(e.dst, []).append((e, v))
        for dst, cands in sorted(groups2.items()):
            cands.sort(key=lambda c: (-_threat(c[1]), c[1].id))
            e, v = cands[0]
            out.append(Transition("escalate", pos, dst, [e], [], v, None, None, [c[1] for c in cands[1:]]))

    # ---- credential: obtain an identity on a held host, then log in to a reachable service
    for s in srcs:
        if s == INTERNET:
            continue
        for cred in graph.out_edges(s, EdgeType.CAN_ACCESS):
            if cred.structural or not cred.dst.startswith("ident:") or not _usable(cred, p):
                continue
            for auth in graph.out_edges(cred.dst, EdgeType.AUTHENTICATES_TO):
                if not _usable(auth, p):
                    continue
                # the login service must be reachable from some position already held (credentials are portable)
                reach_edge = None
                for ce in graph.in_edges(auth.dst, EdgeType.CONNECTS_TO):
                    ok = (ce.src == INTERNET and has_internet) or any(
                        ce.src == priv_id(h, "user") for h in held_hosts | {_asset_of(graph, pos)}
                    )
                    if ok and _usable(ce, p) and (reach_edge is None or _stronger(ce, reach_edge)):
                        reach_edge = ce
                if reach_edge is None:
                    continue
                for login in graph.out_edges(auth.dst, EdgeType.CAN_ACCESS):
                    if login.attrs.get("via_identity") == cred.dst and _usable(login, p):
                        svc = graph.node(auth.dst)
                        out.append(Transition("credential", pos, login.dst, [cred, auth, reach_edge, login], [],
                                              None, svc, cred.dst))  # fmt: skip

    # ---- trust
    for s in srcs:
        if s == INTERNET:
            continue
        for e in graph.out_edges(s, EdgeType.SHARES_TRUST_WITH):
            if _usable(e, p):
                out.append(Transition("trust", pos, e.dst, [e]))
    return out


def resolve_targets(graph: GraphView, p: PathParams) -> tuple[str, set[int]]:
    if p.target_asset_ids:
        return "explicit", set(p.target_asset_ids)
    crown = {
        n.attrs["asset_id"]
        for n in graph.nodes(NodeType.HOST)
        if (n.attrs.get("criticality") or 0) >= p.target_min_criticality
    }
    return ("crown_jewels", crown) if crown else ("any_admin", set())


def _signature(f: FoundPath) -> list[tuple[int | None, str]]:
    return [(_asset_of_pos(t.dst), t.kind) for t in f.transitions]


def _asset_of_pos(pos: str) -> int | None:
    return int(pos.split(":")[1]) if pos.startswith("priv:") else None


def _confidence(f: FoundPath) -> float:
    return min(e.confidence for t in f.transitions for e in t.edges)


def _is_subsequence(short: list, long: list) -> bool:
    it = iter(long)
    return all(x in it for x in short)


def _prune_dominated(found: list[FoundPath]) -> tuple[list[FoundPath], int]:
    """Path Q dominates P (same entry, same target) when Q's steps are a strict subsequence of P's and Q is at
    least as well evidenced: P then only adds detours. A longer path with *stronger* evidence is kept."""
    groups: dict[tuple, list[FoundPath]] = {}
    for f in found:
        groups.setdefault((f.entry, f.transitions[-1].dst), []).append(f)
    keep: list[FoundPath] = []
    for members in groups.values():
        sigs = [(m, _signature(m), _confidence(m)) for m in members]
        for m, sig, conf in sigs:
            dominated = any(
                len(o_sig) < len(sig) and o_conf >= conf and _is_subsequence(o_sig, sig)
                for o, o_sig, o_conf in sigs
                if o is not m
            )
            if not dominated:
                keep.append(m)
    order = {id(f): i for i, f in enumerate(found)}  # preserve the search's deterministic order
    keep.sort(key=lambda f: order[id(f)])
    return keep, len(found) - len(keep)


def find_attack_paths(graph: GraphView, p: PathParams | None = None) -> SearchResult:
    p = p or PathParams()
    mode, targets = resolve_targets(graph, p)
    found: list[FoundPath] = []
    state = {"expansions": 0, "truncated": False}

    def is_target(pos: str) -> bool:
        a = _asset_of(graph, pos)
        return pos.endswith(":admin") if mode == "any_admin" else a in targets

    def dfs(entry: str, entry_kind: str, pos: str, visited: set[str], trail: list[Transition], held: dict[int, int],
            has_internet: bool, idents: frozenset[str]) -> None:  # fmt: skip
        if len(trail) >= p.max_steps or state["truncated"]:
            return
        for t in transitions_from(graph, pos, set(held), has_internet, idents, p):
            state["expansions"] += 1
            if state["expansions"] > p.max_expansions or len(found) >= p.max_paths:
                state["truncated"] = True
                return
            a, level = _asset_of(graph, t.dst), LEVEL[graph.node(t.dst).attrs["level"]]
            if t.dst in visited or held.get(a, 0) >= level:  # never loop, never "re-gain" what we hold
                continue
            new_trail = [*trail, t]
            if is_target(t.dst):
                found.append(FoundPath(entry, entry_kind, new_trail))
                continue
            dfs(entry, entry_kind, t.dst, visited | {t.dst}, new_trail, {**held, a: max(held.get(a, 0), level)},
                has_internet, idents | ({t.identity} if t.identity else frozenset()))  # fmt: skip

    if p.start_internet and graph.node(INTERNET):
        dfs(INTERNET, "internet", INTERNET, {INTERNET}, [], {}, True, frozenset())
    for a in p.start_assets:
        pos = priv_id(a, "user")
        if graph.node(pos):
            dfs(pos, "assumed_foothold", pos, {pos}, [], {a: 1}, False, frozenset())
    pruned = 0
    if p.prune_dominated:
        found, pruned = _prune_dominated(found)
    return SearchResult(found, state["truncated"], state["expansions"], mode, sorted(targets), pruned)
