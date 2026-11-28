"""Operator-supplied network context: flows, credentials, trusts, security zones. Plus identity history."""

import ipaddress
import re
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Asset, AssetObservation, IdentityConflict, Relationship, SecurityBoundary
from app.schemas import ORMModel
from app.security import audit_action, authorize
from app.services.cache import get_cache
from app.services.meta import bump_data_version
from app.services.relationships import upsert_relationship

router = APIRouter(tags=["network"], dependencies=[Depends(authorize)])

_NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,47}$")
# kind -> (allowed src ref kinds, allowed dst ref kinds)
RULES = {
    "CONNECTS_TO": ({"internet", "asset", "ip", "cidr"}, {"asset", "ip", "cidr"}),
    "AUTHENTICATES_TO": ({"identity"}, {"asset", "ip"}),
    "CAN_ACCESS": ({"asset"}, {"identity"}),
    "SHARES_TRUST_WITH": ({"asset"}, {"asset"}),
}


def parse_ref(ref: str) -> tuple[str, str]:
    """Validate a relationship endpoint reference; returns (kind, value)."""
    if ref == "internet":
        return "internet", ""
    kind, _, val = ref.partition(":")
    try:
        if kind == "asset" and int(val) > 0:
            return kind, val
        if kind == "ip":
            return kind, str(ipaddress.ip_address(val))
        if kind == "cidr":
            return kind, str(ipaddress.ip_network(val, strict=False))
        if kind == "identity" and _NAME.match(val):
            return kind, val
    except ValueError:
        pass
    raise ValueError(f"invalid reference {ref!r}: use internet | asset:<id> | ip:<addr> | cidr:<net> | identity:<name>")


class RelationshipIn(BaseModel):
    kind: Literal["CONNECTS_TO", "AUTHENTICATES_TO", "CAN_ACCESS", "SHARES_TRUST_WITH"]
    src: str = Field(max_length=80)
    dst: str = Field(max_length=80)
    port: int = Field(default=0, ge=0, le=65535, description="0 = any port")
    protocol: Literal["tcp", "udp", "any"] = "any"
    # What the operator attests. "inferred" is reserved for conclusions the system draws itself.
    evidence_status: Literal["observed", "confirmed", "hypothetical"] = "observed"
    note: str | None = Field(default=None, max_length=300)
    requires: Literal["user", "admin"] | None = Field(default=None, description="privilege needed on the source")
    grants: Literal["user", "admin"] | None = Field(default=None, description="privilege obtained on the target")

    @model_validator(mode="after")
    def _check(self):
        src_kind, _ = parse_ref(self.src)
        dst_kind, _ = parse_ref(self.dst)
        allowed_src, allowed_dst = RULES[self.kind]
        if src_kind not in allowed_src or dst_kind not in allowed_dst:
            raise ValueError(f"{self.kind} needs src in {sorted(allowed_src)} and dst in {sorted(allowed_dst)}")
        if self.kind == "AUTHENTICATES_TO" and self.port < 1:
            raise ValueError("AUTHENTICATES_TO needs the port of the service the credential logs in to")
        return self


class RelationshipOut(ORMModel):
    id: int
    kind: str
    src: str
    dst: str
    port: int
    protocol: str
    evidence_status: str
    source: str
    attrs: dict
    first_seen: datetime
    last_seen: datetime


class BoundaryIn(BaseModel):
    name: str = Field(max_length=48)
    cidrs: list[str] = Field(min_length=1, max_length=50)
    description: str | None = Field(default=None, max_length=255)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip().lower()
        if not _NAME.match(v) or v == "internet":
            raise ValueError("name must match [a-z0-9][a-z0-9_.-]{0,47} and not be 'internet'")
        return v

    @field_validator("cidrs")
    @classmethod
    def _cidrs(cls, v: list[str]) -> list[str]:
        try:
            return [str(ipaddress.ip_network(c.strip(), strict=False)) for c in v]
        except ValueError as exc:
            raise ValueError(f"invalid CIDR: {exc}") from exc


class BoundaryOut(ORMModel):
    id: int
    name: str
    cidrs: list[str]
    description: str | None
    created_at: datetime


class ObservationOut(ORMModel):
    id: int
    report_id: int | None
    source: str
    ip_address: str
    hostname: str | None
    os: str | None
    macs: list[str]
    match_basis: str
    observed_at: datetime


class ConflictOut(ORMModel):
    id: int
    report_id: int | None
    asset_id: int | None
    other_asset_id: int | None
    kind: str
    detail: dict
    created_at: datetime


def _changed(db: Session, request: Request, action: str, resource: str, detail: dict) -> None:
    bump_data_version(db)
    db.commit()
    get_cache().invalidate()
    audit_action(request, request.state.principal, action, resource, detail=detail)


# ------------------------------------------------------------------ relationships
@router.post("/network/relationships", response_model=RelationshipOut, status_code=201)
def add_relationship(body: RelationshipIn, request: Request, db: Annotated[Session, Depends(get_db)]):
    """Declare a flow, credential, or trust. Idempotent: re-posting the same relationship updates it."""
    for ref in (body.src, body.dst):
        kind, val = parse_ref(ref)
        if kind == "asset" and db.get(Asset, int(val)) is None:
            raise HTTPException(422, f"unknown asset in {ref!r}")
    attrs = {k: v for k, v in {"note": body.note, "requires": body.requires, "grants": body.grants}.items() if v}
    upsert_relationship(
        db, kind=body.kind, src=body.src, dst=body.dst, port=body.port, protocol=body.protocol,
        evidence_status=body.evidence_status, source="operator", attrs=attrs, replace=True,
    )  # fmt: skip
    row = db.scalars(
        select(Relationship).where(
            Relationship.kind == body.kind, Relationship.src == body.src, Relationship.dst == body.dst,
            Relationship.port == body.port, Relationship.protocol == body.protocol, Relationship.source == "operator",
        )
    ).one()  # fmt: skip
    _changed(db, request, "relationship.upsert", f"relationship:{row.id}", body.model_dump(exclude_none=True))
    return row


@router.get("/network/relationships", response_model=list[RelationshipOut])
def list_relationships(
    db: Annotated[Session, Depends(get_db)],
    kind: str | None = None,
    evidence_status: str | None = None,
    source: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    q = select(Relationship)
    for col, val in (
        (Relationship.kind, kind),
        (Relationship.evidence_status, evidence_status),
        (Relationship.source, source),
    ):
        if val:
            q = q.where(col == val)
    return db.scalars(q.order_by(Relationship.id).limit(limit).offset(offset)).all()


@router.delete("/network/relationships/{rel_id}", status_code=204)
def delete_relationship(rel_id: int, request: Request, db: Annotated[Session, Depends(get_db)]):
    row = db.get(Relationship, rel_id)
    if row is None:
        raise HTTPException(404, "relationship not found")
    db.delete(row)
    _changed(
        db, request, "relationship.delete", f"relationship:{rel_id}", {"kind": row.kind, "src": row.src, "dst": row.dst}
    )
    return Response(status_code=204)


# ------------------------------------------------------------------ security boundaries
@router.post("/network/boundaries", response_model=BoundaryOut, status_code=201)
def add_boundary(body: BoundaryIn, request: Request, db: Annotated[Session, Depends(get_db)]):
    """Declare a security zone (e.g. dmz, prod-db) by CIDR. Used to report boundary crossings on attack paths."""
    b = SecurityBoundary(name=body.name, cidrs=body.cidrs, description=body.description)
    db.add(b)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, f"boundary {body.name!r} already exists") from None
    _changed(db, request, "boundary.create", f"boundary:{body.name}", body.model_dump())
    return b


@router.get("/network/boundaries", response_model=list[BoundaryOut])
def list_boundaries(db: Annotated[Session, Depends(get_db)]):
    return db.scalars(select(SecurityBoundary).order_by(SecurityBoundary.name)).all()


@router.delete("/network/boundaries/{name}", status_code=204)
def delete_boundary(name: str, request: Request, db: Annotated[Session, Depends(get_db)]):
    b = db.scalars(select(SecurityBoundary).where(SecurityBoundary.name == name)).first()
    if b is None:
        raise HTTPException(404, "boundary not found")
    db.delete(b)
    _changed(db, request, "boundary.delete", f"boundary:{name}", {})
    return Response(status_code=204)


# ------------------------------------------------------------------ identity history
@router.get("/assets/{asset_id}/observations", response_model=list[ObservationOut])
def asset_observations(
    asset_id: int,
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    """Where and how this asset has been seen: addresses, names, and how each sighting was matched to it."""
    if db.get(Asset, asset_id) is None:
        raise HTTPException(404, "asset not found")
    q = select(AssetObservation).where(AssetObservation.asset_id == asset_id)
    return db.scalars(q.order_by(AssetObservation.id.desc()).limit(limit).offset(offset)).all()


@router.get("/identity/conflicts", response_model=list[ConflictOut])
def identity_conflicts(
    db: Annotated[Session, Depends(get_db)],
    kind: str | None = None,
    asset_id: int | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    """Every time the resolver refused to merge two hosts (or could not decide), with the reason."""
    q = select(IdentityConflict)
    if kind:
        q = q.where(IdentityConflict.kind == kind)
    if asset_id is not None:
        q = q.where((IdentityConflict.asset_id == asset_id) | (IdentityConflict.other_asset_id == asset_id))
    return db.scalars(q.order_by(IdentityConflict.id.desc()).limit(limit).offset(offset)).all()
