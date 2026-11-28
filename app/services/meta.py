"""`data_version`: bumped by every mutation that can change analysis results, so we can tell when
a stored analysis run is stale."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AppMeta
from app.services.dbutil import dialect_insert

KEY = "data_version"


def bump_data_version(db: Session) -> None:
    stmt = dialect_insert(db, AppMeta).values(key=KEY, value=1)
    db.execute(stmt.on_conflict_do_update(index_elements=["key"], set_={"value": AppMeta.value + 1}))


def get_data_version(db: Session) -> int:
    return db.scalar(select(AppMeta.value).where(AppMeta.key == KEY)) or 0
