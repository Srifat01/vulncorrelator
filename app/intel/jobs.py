"""Worker entry points and enqueue helpers for the intel queue."""

import logging

from rq import Retry

from app import database
from app.config import get_settings
from app.intel.sync import SOURCES, build_clients, sync_all
from app.services.queue import INTEL_QUEUE, get_queue

log = logging.getLogger(__name__)
LOCK_KEY = "vc:intel:enrich-lock"


def sync_job(sources: list[str] | None = None, force: bool = False) -> list[dict]:
    """RQ entry point: sync the given feeds (default all), update findings, refresh the analysis."""
    clients = build_clients()
    try:
        with database.SessionLocal() as db:
            runs = sync_all(db, clients, tuple(sources or SOURCES), force=force)
            return [{"source": r.source, "status": r.status, "updated": r.records_updated} for r in runs]
    finally:
        clients.close()


def enqueue_sync(sources: list[str] | None = None, force: bool = False) -> bool:
    queue = get_queue(INTEL_QUEUE)
    if queue is None:
        return False
    queue.enqueue(
        "app.intel.jobs.sync_job", sources, force, job_timeout=3600, result_ttl=3600, failure_ttl=86400,
        retry=Retry(max=2, interval=[300, 1800]),
    )  # fmt: skip
    return True


def request_enrichment() -> bool:
    """After an ingest: ask the worker to fetch intel for new CVEs/CPEs. Debounced; never raises; never blocks."""
    try:
        if not get_settings().intel_live_sync:
            return False
        queue = get_queue(INTEL_QUEUE)
        if queue is None:
            return False
        if not queue.connection.set(LOCK_KEY, "1", nx=True, ex=120):  # a sync was requested in the last 2 minutes
            return False
        return enqueue_sync()
    except Exception:
        log.exception("could not schedule intel enrichment")
        return False
