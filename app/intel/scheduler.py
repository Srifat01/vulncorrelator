"""Periodic jobs without an extra dependency: a small loop that enqueues work when it is due.

  * threat-intel sync every INTEL_SYNC_INTERVAL_HOURS (retried hourly after a failed attempt)
  * recovery of ingest reports stranded in `processing` by a crashed worker

`tick()` holds all the logic and is unit-tested; `main()` just calls it once a minute. A Redis lock keeps several
scheduler containers from acting at once. No Redis? Use `python -m app.intel.cli sync` from cron instead.
"""

import logging
import time
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import database
from app.config import get_settings
from app.intel.jobs import enqueue_sync
from app.intel.sync import last_success
from app.models import IntelSyncRun, utcnow
from app.services.ingest import recover_stuck_reports
from app.services.queue import INTEL_QUEUE, enqueue_report, get_queue

log = logging.getLogger(__name__)
RETRY_AFTER_FAILURE = timedelta(hours=1)
LOCK_KEY, LOCK_TTL = "vc:scheduler:lock", 90


def intel_sync_due(db: Session, now: datetime) -> bool:
    s = get_settings()
    last = last_success(db, "kev")  # KEV is attempted on every scheduled sync, so it anchors the schedule
    newest = db.scalar(select(IntelSyncRun).where(IntelSyncRun.source == "kev").order_by(IntelSyncRun.id.desc()))
    if newest is not None and newest.status == "failed" and newest.finished_at:
        fin = newest.finished_at if newest.finished_at.tzinfo else newest.finished_at.replace(tzinfo=now.tzinfo)
        if now - fin < RETRY_AFTER_FAILURE:
            return False  # don't hammer an upstream that just failed
    if last is None or last.finished_at is None:
        return True
    fin = last.finished_at if last.finished_at.tzinfo else last.finished_at.replace(tzinfo=now.tzinfo)
    return now - fin >= timedelta(hours=s.intel_sync_interval_hours)


def tick(db: Session, now: datetime | None = None) -> list[str]:
    now, actions = now or utcnow(), []
    queue = get_queue()
    for report_id in recover_stuck_reports(db, now):
        if queue is not None:
            enqueue_report(queue, report_id)
            actions.append(f"requeued report {report_id}")
    if get_settings().intel_live_sync and get_queue(INTEL_QUEUE) is not None and intel_sync_due(db, now):
        if enqueue_sync():
            actions.append("queued intel sync")
    return actions


def main() -> None:  # pragma: no cover - thin loop around tick()
    logging.basicConfig(level=logging.INFO)
    queue = get_queue()
    if queue is None:
        raise SystemExit("the scheduler needs REDIS_URL (use `python -m app.intel.cli sync` from cron otherwise)")
    while True:
        if queue.connection.set(LOCK_KEY, "1", nx=True, ex=LOCK_TTL) or queue.connection.expire(LOCK_KEY, LOCK_TTL):
            try:
                with database.SessionLocal() as db:
                    for action in tick(db):
                        log.info("scheduler: %s", action)
            except Exception:
                log.exception("scheduler tick failed")
        time.sleep(60)


if __name__ == "__main__":  # pragma: no cover
    main()
