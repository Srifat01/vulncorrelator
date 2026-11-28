"""Typed infrastructure graph.

`InfraGraph` is the only module that touches NetworkX. Everything else (builder, path search, API) talks to
the `GraphView` protocol, so a persistent backend (e.g. Neo4j) can be added later by implementing the same
small interface.
"""

import hashlib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

import networkx as nx


class NodeType:
    HOST = "host"
    INTERFACE = "interface"
    SERVICE = "service"
    VULNERABILITY = "vulnerability"
    IDENTITY = "identity"  # credential / identity
    PRIVILEGE = "privilege"
    BOUNDARY = "boundary"  # security boundary / zone / the internet

    ALL = (HOST, INTERFACE, SERVICE, VULNERABILITY, IDENTITY, PRIVILEGE, BOUNDARY)


class EdgeType:
    HOSTS = "HOSTS"
    RUNS_SERVICE = "RUNS_SERVICE"
    AFFECTED_BY = "AFFECTED_BY"
    CONNECTS_TO = "CONNECTS_TO"
    AUTHENTICATES_TO = "AUTHENTICATES_TO"
    CAN_EXPLOIT = "CAN_EXPLOIT"
    CAN_ACCESS = "CAN_ACCESS"
    CAN_ESCALATE_TO = "CAN_ESCALATE_TO"
    SHARES_TRUST_WITH = "SHARES_TRUST_WITH"

    ALL = (
        HOSTS, RUNS_SERVICE, AFFECTED_BY, CONNECTS_TO, AUTHENTICATES_TO,
        CAN_EXPLOIT, CAN_ACCESS, CAN_ESCALATE_TO, SHARES_TRUST_WITH,
    )  # fmt: skip


# Evidence classes (weakest -> strongest) and the *ordinal, uncalibrated* confidence each one maps to.
# These are NOT probabilities: they rank how well-supported a relationship is, nothing more.
STATUS_CONFIDENCE = {"hypothetical": 0.15, "inferred": 0.4, "observed": 0.7, "confirmed": 0.9}
STATUS_RANK = {"hypothetical": 0, "inferred": 1, "observed": 2, "confirmed": 3}


def weaker(a: str, b: str) -> str:
    return a if STATUS_RANK[a] <= STATUS_RANK[b] else b


def edge_id(etype: str, src: str, dst: str, disc: str = "") -> str:
    return "e_" + hashlib.sha1(f"{etype}|{src}|{dst}|{disc}".encode()).hexdigest()[:12]


@dataclass
class Node:
    id: str
    type: str
    label: str
    attrs: dict = field(default_factory=dict)


@dataclass
class Edge:
    id: str
    type: str
    src: str
    dst: str
    evidence_status: str
    source: str
    confidence: float = 0.0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    evidence: list[dict] = field(default_factory=list)  # [{source, kind, detail, observed_at}]
    attrs: dict = field(default_factory=dict)
    structural: bool = False  # definitional (privilege implies host access); carries no evidence of its own

    def __post_init__(self) -> None:
        if not self.confidence:
            self.confidence = STATUS_CONFIDENCE[self.evidence_status]


class GraphView(Protocol):
    """What the algorithms need from a graph backend."""

    def node(self, node_id: str) -> Node | None: ...
    def nodes(self, node_type: str | None = None) -> Iterator[Node]: ...
    def edges(self, edge_type: str | None = None) -> Iterator[Edge]: ...
    def out_edges(self, node_id: str, edge_type: str | None = None) -> list[Edge]: ...
    def in_edges(self, node_id: str, edge_type: str | None = None) -> list[Edge]: ...
    def edge(self, edge_id: str) -> Edge | None: ...
    def number_of_nodes(self) -> int: ...
    def number_of_edges(self) -> int: ...


class InfraGraph:
    """NetworkX-backed implementation of `GraphView`."""

    def __init__(self) -> None:
        self._g = nx.MultiDiGraph()
        self._edges: dict[str, Edge] = {}

    # -- construction
    def add_node(self, node: Node) -> Node:
        if node.id not in self._g:
            self._g.add_node(node.id, data=node)
        return self._g.nodes[node.id]["data"]

    def add_edge(self, edge: Edge) -> Edge:
        if edge.src not in self._g or edge.dst not in self._g:
            raise KeyError(f"edge {edge.type} references unknown node ({edge.src} -> {edge.dst})")
        if edge.id in self._edges:  # idempotent: keep the stronger evidence
            old = self._edges[edge.id]
            if STATUS_RANK[edge.evidence_status] <= STATUS_RANK[old.evidence_status]:
                return old
            self._g.remove_edge(old.src, old.dst, key=old.id)
        self._g.add_edge(edge.src, edge.dst, key=edge.id, data=edge)
        self._edges[edge.id] = edge
        return edge

    # -- queries
    def node(self, node_id: str) -> Node | None:
        return self._g.nodes[node_id]["data"] if node_id in self._g else None

    def nodes(self, node_type: str | None = None) -> Iterator[Node]:
        for _, d in self._g.nodes(data="data"):
            if node_type is None or d.type == node_type:
                yield d

    def edges(self, edge_type: str | None = None) -> Iterator[Edge]:
        for e in self._edges.values():
            if edge_type is None or e.type == edge_type:
                yield e

    def out_edges(self, node_id: str, edge_type: str | None = None) -> list[Edge]:
        if node_id not in self._g:
            return []
        out = [d for _, _, d in self._g.out_edges(node_id, data="data")]
        return [e for e in out if edge_type is None or e.type == edge_type]

    def in_edges(self, node_id: str, edge_type: str | None = None) -> list[Edge]:
        if node_id not in self._g:
            return []
        inc = [d for _, _, d in self._g.in_edges(node_id, data="data")]
        return [e for e in inc if edge_type is None or e.type == edge_type]

    def edge(self, edge_id: str) -> Edge | None:
        return self._edges.get(edge_id)

    def number_of_nodes(self) -> int:
        return self._g.number_of_nodes()

    def number_of_edges(self) -> int:
        return len(self._edges)

    # -- analysis helpers
    def strongly_connected_components(self, edge_types: Iterable[str], node_type: str) -> list[list[str]]:
        """Cycles among nodes of `node_type` linked by `edge_types` (size > 1 only), via host-level projection."""
        # Project privilege/service nodes onto their host so "A can reach B and B can reach A" shows up.
        proj = nx.DiGraph()
        wanted = set(edge_types)
        for e in self._edges.values():
            if e.type not in wanted:
                continue
            a, b = self._host_of(e.src), self._host_of(e.dst)
            if a and b and a != b:
                proj.add_edge(a, b)
        comps = [sorted(c) for c in nx.strongly_connected_components(proj) if len(c) > 1]
        return sorted(comps)

    def _host_of(self, node_id: str) -> str | None:
        n = self.node(node_id)
        if n is None:
            return None
        if n.type == NodeType.HOST:
            return n.id
        asset_id = n.attrs.get("asset_id")
        return f"host:{asset_id}" if asset_id is not None else None

    def neighborhood(self, center: str, depth: int, max_nodes: int) -> tuple[set[str], bool]:
        """Node ids within `depth` undirected hops of `center`, capped at `max_nodes`. Returns (ids, truncated)."""
        seen, frontier, truncated = {center}, [center], False
        for _ in range(depth):
            nxt: list[str] = []
            for n in frontier:
                for m in set(self._g.successors(n)) | set(self._g.predecessors(n)):
                    if m in seen:
                        continue
                    if len(seen) >= max_nodes:
                        return seen, True
                    seen.add(m)
                    nxt.append(m)
            frontier = nxt
        return seen, truncated
