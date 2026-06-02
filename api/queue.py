"""
rq queue wiring for crash-durable job execution.

make_queue() returns an rq Queue when REDIS_URL is set and rq/redis are importable,
else None. When it returns None the API runs jobs in-process via BackgroundTasks
(fine for a single dev replica); when it returns a Queue the API only enqueues and a
separate worker process (api/worker.py) executes the swarm — so an API crash cannot
orphan an in-flight job.
"""
from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger("ens.queue")

RCA_QUEUE_NAME = "rca"
# rq job timeout must exceed the swarm timeout so rq does not kill a job that is
# still legitimately running.
RCA_JOB_TIMEOUT = 180


def make_queue(redis_url: str = "") -> Any | None:
    """Return an rq Queue if Redis + rq are available, else None."""
    if not redis_url:
        return None
    try:
        from redis import Redis
        from rq import Queue
    except ImportError:
        log.warning("REDIS_URL set but rq/redis not installed — using in-process BackgroundTasks.")
        return None
    conn = Redis.from_url(redis_url)
    log.info("rq queue %r connected at %s", RCA_QUEUE_NAME, redis_url)
    return Queue(RCA_QUEUE_NAME, connection=conn, default_timeout=RCA_JOB_TIMEOUT)
