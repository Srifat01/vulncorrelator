"""Writing evidence-bearing relationships (flows, credentials, trusts)."""

from datetime import datetime

from sqlalchemy.orm import Session

from app.models import Relationship, utcnow
from app.services.dbutil import dialect_insert


def upsert_relationship(
    db: Session,
    *,
    kind: str,
    src: str,
    dst: str,
    evidence_status: str,
    source: str,
    port: int = 0,
    protocol: str = "any",
    attrs: dict | None = None,
    report_id: int | None = None,
    now: datetime | None = None,
    replace: bool = False,
) -> None:
    """Idempotent. A re-sighting refreshes last_seen; `replace=True` (operator edits) also rewrites status/attrs."""
    now = now or utcnow()
    stmt = dialect_insert(db, Relationship).values(
        kind=kind,
        src=src,
        dst=dst,
        port=port,
        protocol=protocol,
        evidence_status=evidence_status,
        source=source,
        attrs=attrs or {},
        report_id=report_id,
        first_seen=now,
        last_seen=now,
    )
    update = {"last_seen": now, "report_id": report_id}
    if replace:
        update.update(evidence_status=evidence_status, attrs=attrs or {})
    db.execute(
        stmt.on_conflict_do_update(index_elements=["kind", "src", "dst", "port", "protocol", "source"], set_=update)
    )
