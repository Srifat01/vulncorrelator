"""Pydantic schemas: ingest payloads (also the parsers' common output) and API responses."""

import ipaddress
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


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


class ServiceIn(BaseModel):
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    name: str | None = Field(default=None, max_length=64)
    product: str | None = Field(default=None, max_length=128)
    version: str | None = Field(default=None, max_length=64)
    cpe: str | None = Field(default=None, max_length=255)


class HostIn(BaseModel):
    ip_address: str
    hostname: str | None = Field(default=None, max_length=255)
    os: str | None = Field(default=None, max_length=255)
    internet_facing: bool | None = None
    services: list[ServiceIn] = Field(default_factory=list)
    vulnerabilities: list[VulnerabilityIn] = Field(default_factory=list)

    @field_validator("ip_address")
    @classmethod
    def _valid_ip(cls, v: str) -> str:
        try:
            return str(ipaddress.ip_address(v.strip()))
        except ValueError as exc:
            raise ValueError(f"invalid IP address: {v!r}") from exc


class ReportIn(BaseModel):
    source: str = Field(default="generic", min_length=1, max_length=64)
    hosts: list[HostIn] = Field(min_length=1, max_length=5000)


# ---------------------------------------------------------------- responses
class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class ReportOut(ORMModel):
    id: int
    source: str
    format: str
    status: str
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
    first_seen: datetime
    last_seen: datetime
    vulnerability_count: int = 0
    max_risk_score: float | None = None


class AssetPatch(BaseModel):
    hostname: str | None = Field(default=None, max_length=255)
    internet_facing: bool | None = None


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
    epss: float | None
    in_kev: bool
    risk_score: float
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
