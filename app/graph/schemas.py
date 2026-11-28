"""API schemas for attack paths and graph data (validated on the way out, so the contract is enforced)."""

from typing import Literal

from pydantic import BaseModel, Field

EvidenceStatus = Literal["confirmed", "observed", "partially_inferred", "hypothetical"]


class EdgeEvidence(BaseModel):
    edge_id: str
    edge_type: str
    role: Literal["evidence", "supporting"] = "evidence"  # supporting edges give context but don't set the class
    evidence_status: Literal["confirmed", "observed", "inferred", "hypothetical"]
    confidence: float
    source: str
    first_seen: str | None = None
    last_seen: str | None = None
    detail: list[dict] = Field(default_factory=list)


class PathVuln(BaseModel):
    vulnerability_id: int | None
    cve_id: str | None
    title: str
    cvss_score: float | None = None
    risk_score: float | None = None
    evidence_status: str | None = None
    selected: bool = True  # False = an alternative that would achieve the same step


class PathStep(BaseModel):
    order: int
    action: Literal["initial_access", "lateral_movement", "privilege_escalation", "credential_use", "trust_pivot"]
    from_position: str
    to_position: str
    asset_id: int
    asset: str
    service: dict | None = None
    vulnerabilities: list[PathVuln] = Field(default_factory=list)
    identity: str | None = None
    prerequisites: list[str] = Field(default_factory=list)
    confidence: float
    evidence_status: Literal["confirmed", "observed", "inferred", "hypothetical"]
    evidence: list[EdgeEvidence] = Field(default_factory=list)
    description: str


class RiskFactor(BaseModel):
    factor: str
    value: float | str
    detail: str


class PotentialImpact(BaseModel):
    target_asset_id: int
    target_asset: str
    target_criticality: int
    privilege_gained: Literal["user", "admin"]
    summary: str


class PathOut(BaseModel):
    path_id: str
    run_id: int | None = None
    rank: int | None = None
    confidence: float
    confidence_level: Literal["high", "medium", "low", "very_low"]
    confidence_semantics: str = "ordinal_uncalibrated"  # NOT a probability
    evidence_status: EvidenceStatus
    is_confirmed_exploit_chain: bool
    entry: dict
    entry_asset: str | None
    target_asset: str
    target_asset_id: int
    hop_count: int
    priority_score: float
    steps: list[PathStep]
    assumptions: list[str]
    missing_evidence: list[str]
    risk_factors: list[RiskFactor]
    potential_impact: PotentialImpact
    boundaries_crossed: list[dict] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)
    summary: str


class PathList(BaseModel):
    run: dict | None
    stale: bool
    total: int
    limit: int
    offset: int
    items: list[PathOut]


class GraphNodeOut(BaseModel):
    id: str
    type: str
    label: str
    attrs: dict = Field(default_factory=dict)


class GraphEdgeOut(BaseModel):
    id: str
    type: str
    source: str  # node id (D3/Cytoscape convention)
    target: str
    evidence_status: str
    confidence: float
    evidence_source: str
    first_seen: str | None = None
    last_seen: str | None = None
    structural: bool = False
    attrs: dict = Field(default_factory=dict)


class GraphOut(BaseModel):
    nodes: list[GraphNodeOut]
    edges: list[GraphEdgeOut]
    truncated: bool
    stats: dict = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
