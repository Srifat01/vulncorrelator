"""Audit trail for security-relevant actions. Written in its own short transaction so a denied or failed
request is still recorded. Secrets are never stored: actors are a short hash of the API key."""

import logging

from app import database
from app.models import AuditLog

log = logging.getLogger("vulncorrelator.audit")


def audit(
    *,
    actor: str,
    role: str,
    action: str,
    status: str = "ok",
    resource: str | None = None,
    client_ip: str | None = None,
    request_id: str | None = None,
    detail: dict | None = None,
) -> None:
    try:
        with database.SessionLocal() as db:
            db.add(
                AuditLog(
                    actor=actor,
                    role=role,
                    action=action,
                    status=status,
                    resource=(resource or "")[:120] or None,
                    client_ip=client_ip,
                    request_id=request_id,
                    detail=detail or {},
                )
            )
            db.commit()
    except Exception:  # an audit-store outage must not take the API down, but it must be loud
        log.exception("AUDIT WRITE FAILED action=%s actor=%s status=%s", action, actor, status)
    else:
        log.info("audit action=%s actor=%s status=%s resource=%s", action, actor, status, resource)
