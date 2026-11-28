"""Redis Queue (RQ) integration for background ingestion."""

import redis
from rq import Queue, Retry

from app.config import get_settings

QUEUE_NAME = "ingest"
ANALYSIS_QUEUE = "analysis"
INTEL_QUEUE = "intel"
JOB_PATH = "app.services.ingest.process_report_job"

_queues: dict[str, Queue] = {}


def get_queue(name: str = QUEUE_NAME) -> Queue | None:
    """None when Redis isn't configured. One queue per job class so long analysis runs never block ingestion."""
    if name not in _queues:
        url = get_settings().redis_url
        if not url:
            return None
        _queues[name] = Queue(name, connection=redis.Redis.from_url(url))
    return _queues[name]


def set_queue(queue: Queue | None, name: str = QUEUE_NAME) -> None:
    if queue is None:
        _queues.pop(name, None)
    else:
        _queues[name] = queue


def enqueue_report(queue: Queue, report_id: int) -> None:
    # Transient failures (DB blip, deadlock victim) are retried with back-off; ingestion is idempotent.
    queue.enqueue(
        JOB_PATH,
        report_id,
        job_timeout=900,
        result_ttl=3600,
        failure_ttl=86400,
        retry=Retry(max=3, interval=[10, 60, 300]),
    )


def enqueue_analysis(queue: Queue, run_id: int) -> None:
    queue.enqueue(
        "app.analysis.runner.execute_run_job",
        run_id,
        job_timeout=1800,
        result_ttl=3600,
        failure_ttl=86400,
        retry=Retry(max=2, interval=[30, 120]),
    )
