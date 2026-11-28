"""Dialect helpers shared by services (Postgres in production, SQLite in tests/dev)."""

import hashlib

from sqlalchemy import text
from sqlalchemy.orm import Session


def dialect(db: Session) -> str:
    return db.get_bind().dialect.name


def dialect_insert(db: Session, model):
    """INSERT construct that supports ON CONFLICT on both supported databases."""
    if dialect(db) == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:
        from sqlalchemy.dialects.sqlite import insert
    return insert(model)


def advisory_lock(db: Session, keys: list[str]) -> None:
    """Transaction-scoped advisory locks (Postgres). Keys are taken in sorted order to avoid deadlocks.

    Used where no unique constraint can serialise a "look up, else create" decision (asset identity).
    SQLite serialises writers itself, so this is a no-op there.
    """
    if dialect(db) != "postgresql":
        return
    for k in sorted(set(keys)):
        n = int.from_bytes(hashlib.sha256(k.encode()).digest()[:8], "big", signed=True)
        db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": n})
