"""
rq worker process — executes RCA jobs enqueued by the API.

Run:
    uv run python -m api.worker          # needs REDIS_URL set

In Docker this is a separate service (see docker-compose.yml) so an API crash never
orphans an in-flight job: the worker owns execution, the API only enqueues.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from api.queue import RCA_QUEUE_NAME
from config.settings import REDIS_URL

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("ens.worker")


def main() -> None:
    if not REDIS_URL:
        log.error("REDIS_URL not set — the worker requires Redis. Set REDIS_URL and retry.")
        raise SystemExit(1)

    import sys

    from redis import Redis
    from rq import Queue, SimpleWorker, Worker

    conn = Redis.from_url(REDIS_URL)
    queue = Queue(RCA_QUEUE_NAME, connection=conn)

    # rq's default Worker forks a work-horse per job. On macOS, fork() after the
    # Objective-C runtime / threads have initialised aborts with SIGABRT
    # ("may have been in progress in another thread when fork() was called").
    # Our swarm pulls in such libraries, so on darwin we run SimpleWorker, which
    # executes jobs in-process (no fork). On Linux the forking Worker is safe and
    # gives per-job crash isolation, so we keep it there.
    worker_cls = SimpleWorker if sys.platform == "darwin" else Worker
    log.info(
        "ENS worker (%s) listening on queue %r at %s",
        worker_cls.__name__, RCA_QUEUE_NAME, REDIS_URL,
    )
    worker_cls([queue], connection=conn).work(with_scheduler=False)


if __name__ == "__main__":
    main()
