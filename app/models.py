"""ORM models.

Groups: assets & identity | scans & findings | network relationships | analysis | threat intel | audit.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, deferred, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class ReportStatus(str, enum.Enum):
    pending = "pending"
    processing = "processing"
    completed = "completed"
    failed = "failed"


# Evidence classes, weakest -> strongest. See README "Evidence classification".
EVIDENCE_RANK = {"hypothetical": 0, "inferred": 1, "observed": 2, "confirmed": 3}


# ------------------------------------------------------------------ assets & identity
class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    # The *last observed* address. NOT unique and NOT the asset's identity: addresses are re-assigned.
    ip_address: Mapped[str] = mapped_column(String(45), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255))
    os: Mapped[str | None] = mapped_column(String(255))
    internet_facing: Mapped[bool] = mapped_column(Boolean, default=False)
    # declared (operator) | scan_external (seen from an external vantage) | public_ip (heuristic) | unknown
    exposure_source: Mapped[str] = mapped_column(String(24), default="unknown", server_default="unknown")
    criticality: Mapped[int] = mapped_column(Integer, default=3, server_default="3")  # 1 (low) .. 5 (crown jewel)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    controls: Mapped[list] = mapped_column(JSON, default=list)  # e.g. ["waf", "edr", "network_segmentation"]
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    services: Mapped[list[Service]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    vulnerabilities: Mapped[list[Vulnerability]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    identifiers: Mapped[list[AssetIdentifier]] = relationship(cascade="all, delete-orphan")


class AssetIdentifier(Base):
    """Strong identifiers (MAC address, scanner-assigned ids). Globally unique per (kind, value)."""

    __tablename__ = "asset_identifiers"
    __table_args__ = (UniqueConstraint("kind", "value", name="uq_identifier"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(40))  # "mac" | "ext:<name>"
    value: Mapped[str] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(64))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AssetObservation(Base):
    """One row per host per report: what the scanner saw. Preserves history across IP/hostname changes."""

    __tablename__ = "asset_observations"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    report_id: Mapped[int | None] = mapped_column(ForeignKey("scan_reports.id", ondelete="SET NULL"))
    source: Mapped[str] = mapped_column(String(64))
    ip_address: Mapped[str] = mapped_column(String(45), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255))
    os: Mapped[str | None] = mapped_column(String(255))
    macs: Mapped[list] = mapped_column(JSON, default=list)
    match_basis: Mapped[str] = mapped_column(String(16))  # external_id | mac | ip | hostname | new
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class IdentityConflict(Base):
    """Recorded whenever the resolver *declined* to merge hosts (or could not decide)."""

    __tablename__ = "identity_conflicts"

    id: Mapped[int] = mapped_column(primary_key=True)
    report_id: Mapped[int | None] = mapped_column(ForeignKey("scan_reports.id", ondelete="SET NULL"))
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), index=True)
    other_asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    kind: Mapped[str] = mapped_column(String(32))  # ip_reassigned | hostname_mismatch | split_identity | contradiction
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Service(Base):
    """An open port on an asset, as reported by scanners."""

    __tablename__ = "services"
    __table_args__ = (UniqueConstraint("asset_id", "port", "protocol", name="uq_service_endpoint"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    name: Mapped[str | None] = mapped_column(String(64))
    product: Mapped[str | None] = mapped_column(String(128))
    version: Mapped[str | None] = mapped_column(String(64))
    cpe: Mapped[str | None] = mapped_column(String(255))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    asset: Mapped[Asset] = relationship(back_populates="services")


# ------------------------------------------------------------------ scans & findings
class ScanReport(Base):
    __tablename__ = "scan_reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(64))
    format: Mapped[str] = mapped_column(String(16))  # json | nmap | nessus
    status: Mapped[str] = mapped_column(String(16), default=ReportStatus.pending.value, index=True)
    internet_facing: Mapped[bool | None] = mapped_column(Boolean)  # operator override for hosts
    vantage: Mapped[str | None] = mapped_column(String(16))  # external | internal | None (unknown)
    hosts_count: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    new_count: Mapped[int] = mapped_column(Integer, default=0)
    updated_count: Mapped[int] = mapped_column(Integer, default=0)
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    raw_payload: Mapped[str | None] = deferred(mapped_column(Text))


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Deterministic dedup key, see app/services/fingerprint.py. Keyed on the internal asset id.
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    cve_id: Mapped[str | None] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(128))
    cvss_source: Mapped[str | None] = mapped_column(String(32))  # nvd | scanner | demo
    severity: Mapped[str | None] = mapped_column(String(16), index=True)
    port: Mapped[int | None] = mapped_column(Integer)  # None = host-level finding
    protocol: Mapped[str | None] = mapped_column(String(8))
    service_name: Mapped[str | None] = mapped_column(String(64))
    product: Mapped[str | None] = mapped_column(String(128))
    version: Mapped[str | None] = mapped_column(String(64))
    cpe: Mapped[str | None] = mapped_column(String(255))
    tags: Mapped[list] = mapped_column(JSON, default=list)  # rce, privesc, ...
    sources: Mapped[list] = mapped_column(JSON, default=list)  # scanners / derivations that reported it
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)  # keyed by source
    # confirmed: scanner actively validated | observed: scanner reported | inferred: derived from version matching
    evidence_status: Mapped[str] = mapped_column(String(16), default="observed", server_default="observed")
    epss: Mapped[float | None] = mapped_column(Float)  # denormalised from cve_intel (None = unknown)
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    risk_band: Mapped[str | None] = mapped_column(String(16))
    risk_model_version: Mapped[str | None] = mapped_column(String(16))
    risk_components: Mapped[dict | None] = mapped_column(JSON)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_report_id: Mapped[int | None] = mapped_column(ForeignKey("scan_reports.id", ondelete="SET NULL"))

    asset: Mapped[Asset] = relationship(back_populates="vulnerabilities")


# ------------------------------------------------------------------ network relationships
class Relationship(Base):
    """Evidence-bearing facts about how things connect: flows, credentials, trusts.

    Endpoint refs: internet | asset:<id> | ip:<addr> | cidr:<net> | identity:<name> | boundary:<name>
    """

    __tablename__ = "relationships"
    __table_args__ = (UniqueConstraint("kind", "src", "dst", "port", "protocol", "source", name="uq_relationship"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    # CONNECTS_TO | AUTHENTICATES_TO | CAN_ACCESS | SHARES_TRUST_WITH
    kind: Mapped[str] = mapped_column(String(24), index=True)
    src: Mapped[str] = mapped_column(String(80))
    dst: Mapped[str] = mapped_column(String(80))
    port: Mapped[int] = mapped_column(Integer, default=0, server_default="0")  # 0 = any
    protocol: Mapped[str] = mapped_column(String(8), default="any", server_default="any")
    evidence_status: Mapped[str] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(String(64))  # operator | scan:<tool> | report:<source>
    attrs: Mapped[dict] = mapped_column(JSON, default=dict)  # requires / grants / note
    report_id: Mapped[int | None] = mapped_column(ForeignKey("scan_reports.id", ondelete="SET NULL"))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SecurityBoundary(Base):
    __tablename__ = "security_boundaries"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    cidrs: Mapped[list] = mapped_column(JSON, default=list)
    description: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ------------------------------------------------------------------ analysis
class AnalysisRun(Base):
    __tablename__ = "analysis_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)  # pending|running|completed|failed
    trigger: Mapped[str] = mapped_column(String(16), default="api")  # api | ingest | intel | scheduler
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    data_version: Mapped[int | None] = mapped_column(Integer)  # app_meta.data_version the run analysed
    paths_count: Mapped[int] = mapped_column(Integer, default=0)
    stats: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AttackPath(Base):
    __tablename__ = "attack_paths"
    __table_args__ = (UniqueConstraint("run_id", "path_id", name="uq_path_per_run"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("analysis_runs.id", ondelete="CASCADE"), index=True)
    path_id: Mapped[str] = mapped_column(String(40), index=True)  # stable across runs for the same path
    score: Mapped[float] = mapped_column(Float, index=True)
    confidence: Mapped[float] = mapped_column(Float)
    evidence_status: Mapped[str] = mapped_column(String(24), index=True)
    entry_label: Mapped[str] = mapped_column(String(120))
    target_asset_id: Mapped[int | None] = mapped_column(Integer, index=True)
    data: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AppMeta(Base):
    """Tiny key/int store. `data_version` is bumped on every mutation that can change analysis results."""

    __tablename__ = "app_meta"

    key: Mapped[str] = mapped_column(String(40), primary_key=True)
    value: Mapped[int] = mapped_column(Integer, default=0)


# ------------------------------------------------------------------ threat intelligence
class CveIntel(Base):
    """Current intelligence per CVE with per-source timestamps and origin (live | demo)."""

    __tablename__ = "cve_intel"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    description: Mapped[str | None] = mapped_column(Text)
    published: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    nvd_last_modified: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(128))
    cvss_version: Mapped[str | None] = mapped_column(String(8))
    cwe: Mapped[list] = mapped_column(JSON, default=list)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    nvd_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    nvd_origin: Mapped[str | None] = mapped_column(String(8))  # live | demo
    epss: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    epss_date: Mapped[str | None] = mapped_column(String(10))
    epss_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    epss_origin: Mapped[str | None] = mapped_column(String(8))
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_date_added: Mapped[str | None] = mapped_column(String(10))
    kev_due_date: Mapped[str | None] = mapped_column(String(10))
    kev_ransomware: Mapped[str | None] = mapped_column(String(16))
    kev_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    kev_origin: Mapped[str | None] = mapped_column(String(8))


class IntelHistory(Base):
    """Append-only: a row is written only when a source's value for a CVE changes."""

    __tablename__ = "intel_history"

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    source: Mapped[str] = mapped_column(String(8))  # nvd | epss | kev
    value: Mapped[dict] = mapped_column(JSON)
    origin: Mapped[str] = mapped_column(String(8))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IntelSyncRun(Base):
    __tablename__ = "intel_sync_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(8), index=True)  # nvd | epss | kev | demo
    status: Mapped[str] = mapped_column(String(16))  # running | success | failed | partial
    origin: Mapped[str] = mapped_column(String(8), default="live")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    records_seen: Mapped[int] = mapped_column(Integer, default=0)
    records_updated: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    watermark: Mapped[dict] = mapped_column(JSON, default=dict)  # etag / catalog version


class CpeLookup(Base):
    """Cache of "which CVEs does NVD associate with this exact CPE?" so we don't re-query every ingest."""

    __tablename__ = "cpe_lookups"

    cpe: Mapped[str] = mapped_column(String(255), primary_key=True)
    cve_ids: Mapped[list] = mapped_column(JSON, default=list)
    looked_up_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    origin: Mapped[str] = mapped_column(String(8), default="live")


# ------------------------------------------------------------------ audit
class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(24))  # "key:<first 8 of sha256>" - never the key itself
    role: Mapped[str] = mapped_column(String(16))
    action: Mapped[str] = mapped_column(String(48), index=True)
    resource: Mapped[str | None] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(16))  # ok | denied | error
    client_ip: Mapped[str | None] = mapped_column(String(45))
    request_id: Mapped[str | None] = mapped_column(String(36))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
