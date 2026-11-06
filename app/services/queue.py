"""Redis Queue (RQ) integration for background ingestion."""

import redis
from rq import Queue

from app.config import get_settings

QUEUE_NAME = "ingest"
JOB_PATH = "app.services.ingest.process_report_job"

_queue: Queue | None = None


def get_queue() -> Queue | None:
    """None when Redis isn't configured."""
    global _queue
    if _queue is None:
        url = get_settings().redis_url
        if not url:
            return None
        _queue = Queue(QUEUE_NAME, connection=redis.Redis.from_url(url))
    return _queue


def set_queue(queue: Queue | None) -> None:
    global _queue
    _queue = queue


def enqueue_report(queue: Queue, report_id: int) -> None:
    queue.enqueue(JOB_PATH, report_id, job_timeout=900, result_ttl=3600, failure_ttl=86400)
