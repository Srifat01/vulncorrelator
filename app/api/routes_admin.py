from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AuditLog
from app.schemas import ORMModel
from app.security import authorize, require_admin

router = APIRouter(tags=["admin"], dependencies=[Depends(authorize), Depends(require_admin)])


class AuditOut(ORMModel):
    id: int
    ts: datetime
    actor: str
    role: str
    action: str
    resource: str | None
    status: str
    client_ip: str | None
    request_id: str | None
    detail: dict


@router.get("/audit", response_model=list[AuditOut])
def audit_log(
    db: Annotated[Session, Depends(get_db)],
    action: str | None = None,
    status: str | None = None,
    actor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    """Security audit trail (admin only). Actors are key fingerprints; secrets are never stored."""
    q = select(AuditLog)
    for col, val in ((AuditLog.action, action), (AuditLog.status, status), (AuditLog.actor, actor)):
        if val:
            q = q.where(col == val)
    return db.scalars(q.order_by(AuditLog.id.desc()).limit(limit).offset(offset)).all()
