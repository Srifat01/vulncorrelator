"""Service exposure analysis: how reachable is a service, according to the *evidence* in the graph?"""

from app.graph.builder import INTERNET
from app.graph.model import EdgeType, GraphView

LEVELS = ("internet_observed", "internet_inferred", "internal_flow", "unknown")


def service_exposure(graph: GraphView, service_node: str) -> tuple[str, list[str]]:
    """Strongest reachability evidence into a service. Hypothetical (assumed) edges never count."""
    best, ids = "unknown", []
    for e in graph.in_edges(service_node, EdgeType.CONNECTS_TO):
        if e.evidence_status == "hypothetical":
            continue
        if e.src == INTERNET:
            level = "internet_observed" if e.evidence_status in ("observed", "confirmed") else "internet_inferred"
        else:
            level = "internal_flow"
        if LEVELS.index(level) < LEVELS.index(best):
            best, ids = level, [e.id]
        elif level == best:
            ids.append(e.id)
    return best, ids


def vulnerability_exposure(graph: GraphView, vuln_node: str) -> tuple[str, list[str]]:
    """Host-level findings have no service to reach: they are exploitable only after a foothold ('local_only')."""
    for e in graph.in_edges(vuln_node, EdgeType.AFFECTED_BY):
        src = graph.node(e.src)
        if src is not None and src.type == "service":
            return service_exposure(graph, src.id)
    return "local_only", []
