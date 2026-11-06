"""ORM models: Asset, Service, ScanReport, Vulnerability."""

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


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255))
    os: Mapped[str | None] = mapped_column(String(255))
    # Defaults to "is this a public IP?" at creation; can be overridden via the
    # API because NAT/port-forwarding makes the heuristic imperfect.
    internet_facing: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    services: Mapped[list[Service]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    vulnerabilities: Mapped[list[Vulnerability]] = relationship(back_populates="asset", cascade="all, delete-orphan")


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


class ScanReport(Base):
    __tablename__ = "scan_reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(64))
    format: Mapped[str] = mapped_column(String(16))  # json | nmap | nessus
    status: Mapped[str] = mapped_column(String(16), default=ReportStatus.pending.value, index=True)
    internet_facing: Mapped[bool | None] = mapped_column(Boolean)  # optional override for hosts
    hosts_count: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    new_count: Mapped[int] = mapped_column(Integer, default=0)
    updated_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Kept so a report can be re-processed and so the async worker only needs the id.
    raw_payload: Mapped[str | None] = deferred(mapped_column(Text))


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Deterministic dedup key, see app/services/fingerprint.py.
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    cve_id: Mapped[str | None] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(128))
    severity: Mapped[str | None] = mapped_column(String(16), index=True)
    port: Mapped[int | None] = mapped_column(Integer)  # None = host-level finding
    protocol: Mapped[str | None] = mapped_column(String(8))
    service_name: Mapped[str | None] = mapped_column(String(64))
    product: Mapped[str | None] = mapped_column(String(128))
    version: Mapped[str | None] = mapped_column(String(64))
    cpe: Mapped[str | None] = mapped_column(String(255))
    tags: Mapped[list] = mapped_column(JSON, default=list)  # rce, privesc, ...
    sources: Mapped[list] = mapped_column(JSON, default=list)  # scanners that reported it
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)  # keyed by source
    epss: Mapped[float | None] = mapped_column(Float)
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_report_id: Mapped[int | None] = mapped_column(ForeignKey("scan_reports.id", ondelete="SET NULL"))

    asset: Mapped[Asset] = relationship(back_populates="vulnerabilities")
