from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.graph.builder import GraphOptions, build_graph
from app.graph.model import STATUS_RANK, Edge, EdgeType, InfraGraph, Node, NodeType
from app.graph.schemas import GraphEdgeOut, GraphNodeOut, GraphOut
from app.graph.snapshot import load_snapshot
from app.models import Asset
from app.security import authorize

router = APIRouter(tags=["graph"], dependencies=[Depends(authorize)])

TYPE_ORDER = {
    t: i for i, t in enumerate(["host", "service", "vulnerability", "privilege", "identity", "boundary", "interface"])
}


def _node_out(n: Node) -> GraphNodeOut:
    return GraphNodeOut(id=n.id, type=n.type, label=n.label, attrs=n.attrs)


def _edge_out(e: Edge) -> GraphEdgeOut:
    return GraphEdgeOut(
        id=e.id, type=e.type, source=e.src, target=e.dst, evidence_status=e.evidence_status,
        confidence=e.confidence, evidence_source=e.source,
        first_seen=e.first_seen.isoformat() if e.first_seen else None,
        last_seen=e.last_seen.isoformat() if e.last_seen else None,
        structural=e.structural, attrs=e.attrs,
    )  # fmt: skip


def _csv(value: str | None, allowed: tuple[str, ...], what: str) -> set[str] | None:
    if not value:
        return None
    items = {x.strip() for x in value.split(",") if x.strip()}
    if items - set(allowed):
        raise HTTPException(422, f"unknown {what}: {sorted(items - set(allowed))}; allowed: {list(allowed)}")
    return items


def _subgraph(
    g: InfraGraph, *, center: str | None, depth: int, node_types: set[str] | None, edge_types: set[str] | None,
    min_confidence: float, include_hypothetical: bool, include_structural: bool, limit: int,
) -> tuple[list[Node], list[Edge], bool]:  # fmt: skip
    truncated = False
    if center:
        ids, truncated = g.neighborhood(center, depth, limit)
        nodes = [n for n in g.nodes() if n.id in ids]
    else:
        nodes = sorted(g.nodes(), key=lambda n: (TYPE_ORDER.get(n.type, 9), n.id))
    if node_types:
        nodes = [n for n in nodes if n.type in node_types or n.id == center]
    if len(nodes) > limit:
        nodes, truncated = nodes[:limit], True
    keep = {n.id for n in nodes}
    edges = [
        e for e in g.edges()
        if e.src in keep and e.dst in keep
        and (edge_types is None or e.type in edge_types)
        and e.confidence >= min_confidence
        and (include_hypothetical or e.evidence_status != "hypothetical")
        and (include_structural or not e.structural)
    ]  # fmt: skip
    return nodes, sorted(edges, key=lambda e: e.id), truncated


def graph_response(
    db: Session, *, center: str | None, depth: int, node_types: str | None, edge_types: str | None,
    min_confidence: float, include_hypothetical: bool, assume_subnet_reachability: bool,
    include_structural: bool, limit: int,
) -> GraphOut:  # fmt: skip
    built = build_graph(load_snapshot(db), GraphOptions(assume_subnet_reachability=assume_subnet_reachability))
    if center and built.graph.node(center) is None:
        raise HTTPException(404, f"node {center!r} not found")
    nodes, edges, truncated = _subgraph(
        built.graph, center=center, depth=depth, node_types=_csv(node_types, NodeType.ALL, "node type"),
        edge_types=_csv(edge_types, EdgeType.ALL, "edge type"), min_confidence=min_confidence,
        include_hypothetical=include_hypothetical or assume_subnet_reachability,
        include_structural=include_structural, limit=limit,
    )  # fmt: skip
    return GraphOut(
        nodes=[_node_out(n) for n in nodes], edges=[_edge_out(e) for e in edges], truncated=truncated,
        stats=built.stats, warnings=built.warnings,
    )  # fmt: skip


Limit = Annotated[int, Query(ge=1, le=get_settings().path_max_expansions // 40, description="max nodes returned")]


@router.get("/graph", response_model=GraphOut)
def get_graph(
    db: Annotated[Session, Depends(get_db)],
    center: Annotated[str | None, Query(description="node id, e.g. host:3, svc:3:80/tcp, vuln:12")] = None,
    depth: Annotated[int, Query(ge=1, le=4)] = 2,
    node_types: Annotated[str | None, Query(description="comma list: host,service,vulnerability,...")] = None,
    edge_types: Annotated[str | None, Query(description="comma list: CONNECTS_TO,AFFECTED_BY,...")] = None,
    min_confidence: Annotated[float, Query(ge=0, le=1)] = 0,
    include_hypothetical: bool = False,
    assume_subnet_reachability: Annotated[bool, Query(description="add HYPOTHETICAL same-subnet links")] = False,
    include_structural: bool = False,
    limit: Limit = 500,
):
    """Typed infrastructure graph for visualisation. Every edge carries evidence status, confidence, source, times."""
    return graph_response(
        db, center=center, depth=depth, node_types=node_types, edge_types=edge_types, min_confidence=min_confidence,
        include_hypothetical=include_hypothetical, assume_subnet_reachability=assume_subnet_reachability,
        include_structural=include_structural, limit=limit,
    )  # fmt: skip


@router.get("/assets/{asset_id}/relationships", response_model=GraphOut)
def asset_relationships(
    asset_id: int,
    db: Annotated[Session, Depends(get_db)],
    depth: Annotated[int, Query(ge=1, le=3)] = 1,
    min_confidence: Annotated[float, Query(ge=0, le=1)] = 0,
    include_hypothetical: bool = False,
    limit: Limit = 300,
):
    """Everything directly (or within `depth` hops) connected to one asset: services, findings, flows, trusts."""
    if db.get(Asset, asset_id) is None:
        raise HTTPException(404, "asset not found")
    return graph_response(
        db, center=f"host:{asset_id}", depth=depth, node_types=None, edge_types=None, min_confidence=min_confidence,
        include_hypothetical=include_hypothetical, assume_subnet_reachability=False, include_structural=False,
        limit=limit,
    )  # fmt: skip


@router.get("/graph/edges/{edge_id}")
def inspect_edge(
    edge_id: str,
    db: Annotated[Session, Depends(get_db)],
    assume_subnet_reachability: bool = False,
):
    """Evidence inspection: the full evidence behind one relationship, with both endpoints."""
    g = build_graph(load_snapshot(db), GraphOptions(assume_subnet_reachability=assume_subnet_reachability)).graph
    e = g.edge(edge_id)
    if e is None:
        raise HTTPException(404, "edge not found (edge ids change when the underlying evidence changes)")
    return {
        **_edge_out(e).model_dump(),
        "source_node": _node_out(g.node(e.src)).model_dump(),
        "target_node": _node_out(g.node(e.dst)).model_dump(),
        "evidence": e.evidence,
        "confidence_semantics": "ordinal_uncalibrated",
        "status_rank": STATUS_RANK[e.evidence_status],
    }
