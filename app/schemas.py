"""Pydantic schemas: ingest payloads (also the parsers' common output) and API responses."""

import ipaddress
import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.services.netutil import normalize_mac


class VulnerabilityIn(BaseModel):
    cve_id: str | None = Field(default=None, max_length=32)
    title: str = Field(min_length=1, max_length=512)
    description: str | None = Field(default=None, max_length=20_000)
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str | None = Field(default=None, max_length=128)
    severity: str | None = Field(default=None, max_length=16)
    port: int | None = Field(default=None, ge=0, le=65535)  # 0/None = host-level
    protocol: Literal["tcp", "udp"] | None = None
    service_name: str | None = Field(default=None, max_length=64)
    product: str | None = Field(default=None, max_length=128)
    version: str | None = Field(default=None, max_length=64)
    cpe: str | None = Field(default=None, max_length=255)
    evidence: dict = Field(default_factory=dict)
    # True only when the tool actively validated exploitability (e.g. Nessus "exploited_by_nessus").
    verified: bool = False


class ServiceIn(BaseModel):
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    name: str | None = Field(default=None, max_length=64)
    product: str | None = Field(default=None, max_length=128)
    version: str | None = Field(default=None, max_length=64)
    cpe: str | None = Field(default=None, max_length=255)


class ConnectionIn(BaseModel):
    """An *observed* outbound connection from this host (netstat, flow log, scan run from the host)."""

    dst: str = Field(max_length=64)  # IP address or CIDR
    port: int = Field(default=0, ge=0, le=65535)  # 0 = unspecified
    protocol: Literal["tcp", "udp", "any"] = "any"

    @field_validator("dst")
    @classmethod
    def _valid_dst(cls, v: str) -> str:
        try:
            return str(ipaddress.ip_network(v.strip(), strict=False))
        except ValueError as exc:
            raise ValueError(f"invalid address/CIDR: {v!r}") from exc


class HostIn(BaseModel):
    ip_address: str
    hostname: str | None = Field(default=None, max_length=255)
    os: str | None = Field(default=None, max_length=255)
    internet_facing: bool | None = None
    # Strong identity hints. Invalid / shared (VRRP) MACs are dropped rather than trusted.
    mac_addresses: list[str] = Field(default_factory=list, max_length=32)
    external_ids: dict[str, str] = Field(default_factory=dict, max_length=8)  # scanner-assigned asset ids
    services: list[ServiceIn] = Field(default_factory=list, max_length=5000)
    vulnerabilities: list[VulnerabilityIn] = Field(default_factory=list, max_length=20000)
    connections: list[ConnectionIn] = Field(default_factory=list, max_length=2000)

    @field_validator("mac_addresses")
    @classmethod
    def _macs(cls, v: list[str]) -> list[str]:
        return sorted({m for m in (normalize_mac(x) for x in v) if m})

    @field_validator("external_ids")
    @classmethod
    def _ext_ids(cls, v: dict[str, str]) -> dict[str, str]:
        for k, val in v.items():
            if not re.fullmatch(r"[a-z0-9_.-]{1,32}", k) or not (1 <= len(val) <= 128):
                raise ValueError("external_ids keys must match [a-z0-9_.-]{1,32}, values 1-128 chars")
        return v

    @field_validator("ip_address")
    @classmethod
    def _valid_ip(cls, v: str) -> str:
        try:
            return str(ipaddress.ip_address(v.strip()))
        except ValueError as exc:
            raise ValueError(f"invalid IP address: {v!r}") from exc


class ReportIn(BaseModel):
    source: str = Field(default="generic", min_length=1, max_length=64)
    # Where the scan ran from. "external" = from the internet, so open services are *observed* to be exposed.
    vantage: Literal["external", "internal"] | None = None
    hosts: list[HostIn] = Field(min_length=1, max_length=5000)


# ---------------------------------------------------------------- responses
class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class ReportOut(ORMModel):
    id: int
    source: str
    format: str
    status: str
    vantage: str | None = None
    attempts: int = 0
    hosts_count: int
    findings_count: int
    new_count: int
    updated_count: int
    error: str | None
    created_at: datetime
    completed_at: datetime | None


class AssetOut(ORMModel):
    id: int
    ip_address: str
    hostname: str | None
    os: str | None
    internet_facing: bool
    exposure_source: str = "unknown"
    criticality: int = 3
    tags: list[str] = Field(default_factory=list)
    controls: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    vulnerability_count: int = 0
    max_risk_score: float | None = None


_LABEL = r"^[a-z0-9][a-z0-9_.:-]{0,39}$"


class AssetPatch(BaseModel):
    hostname: str | None = Field(default=None, max_length=255)
    internet_facing: bool | None = None
    criticality: int | None = Field(default=None, ge=1, le=5)
    tags: list[str] | None = Field(default=None, max_length=20)
    controls: list[str] | None = Field(default=None, max_length=20)

    @field_validator("tags", "controls")
    @classmethod
    def _labels(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        out = sorted({x.strip().lower() for x in v})
        if any(not re.fullmatch(_LABEL, x) for x in out):
            raise ValueError("labels must match [a-z0-9][a-z0-9_.:-]{0,39}")
        return out


class ServiceOut(ORMModel):
    id: int
    port: int
    protocol: str
    name: str | None
    product: str | None
    version: str | None
    cpe: str | None
    last_seen: datetime


class VulnerabilityOut(ORMModel):
    id: int
    asset_id: int
    cve_id: str | None
    title: str
    description: str | None
    cvss_score: float | None
    cvss_vector: str | None
    severity: str | None
    port: int | None
    protocol: str | None
    service_name: str | None
    product: str | None
    version: str | None
    tags: list[str]
    sources: list[str]
    evidence_status: str = "observed"
    cvss_source: str | None = None
    epss: float | None
    in_kev: bool
    risk_score: float
    risk_band: str | None = None
    risk_model_version: str | None = None
    first_seen: datetime
    last_seen: datetime


class ChainAsset(BaseModel):
    id: int
    ip_address: str


class ChainStep(BaseModel):
    order: int
    role: str
    asset_id: int
    ip_address: str
    vulnerability_id: int
    cve_id: str | None
    title: str
    risk_score: float


class ChainOut(BaseModel):
    id: str
    evidence_status: str = "inferred"  # lateral-movement is "hypothetical": it assumes same-subnet connectivity
    deprecated: bool = True
    successor: str = "/attack-paths"
    rule: str
    title: str
    risk_score: float
    severity: str
    explanation: str
    assets: list[ChainAsset]
    steps: list[ChainStep]


class StatsOut(BaseModel):
    assets: int
    vulnerabilities: int
    by_severity: dict[str, int]
    known_exploited: int
    chains: int
    critical_chains: int
