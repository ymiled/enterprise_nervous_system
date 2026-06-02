"""Live-infra integration tests for the Redis-backed job path.

Runs the real RedisJobStore and a real rq Worker against a live Redis. Skipped
cleanly when no Redis is reachable, so the default test run stays hermetic.

Start infra with:  docker compose up -d redis
Override URL with: TEST_REDIS_URL=redis://host:6379/15
"""
import asyncio
import os
import types
import uuid

import pytest

from api.jobstore import RedisJobStore
from api.tasks import run_rca_job

TEST_REDIS_URL = os.getenv("TEST_REDIS_URL", "redis://localhost:6379/15")

PAYLOAD = {"service": "payment-svc", "incident_time": "2021-12-10T06:15:00Z", "severity": "P0"}

pytestmark = pytest.mark.integration


def _redis_or_skip():
    redis = pytest.importorskip("redis")
    client = redis.Redis.from_url(TEST_REDIS_URL)
    try:
        client.ping()
    except Exception as exc:  # redis.exceptions.ConnectionError and friends
        pytest.skip(f"Redis not reachable at {TEST_REDIS_URL}: {exc}")
    return client


@pytest.fixture
def redis_client():
    client = _redis_or_skip()
    # Isolate: db 15 is the test db; flush before and after.
    client.flushdb()
    yield client
    client.flushdb()


async def test_redis_jobstore_roundtrip_live(redis_client):
    import redis.asyncio as aioredis

    aclient = aioredis.from_url(TEST_REDIS_URL)
    store = RedisJobStore(aclient, ttl_seconds=60)
    job_id = str(uuid.uuid4())

    await store.set(job_id, {"status": "done", "result": {"confidence_score": 0.9}})
    got = await store.get(job_id)
    assert got["status"] == "done"
    assert got["result"]["confidence_score"] == 0.9

    # TTL is actually set on the key (durable-with-expiry behaviour).
    ttl = redis_client.ttl("ens:job:" + job_id)
    assert 0 < ttl <= 60
    await aclient.aclose()


async def test_redis_jobstore_missing_key_live(redis_client):
    import redis.asyncio as aioredis

    aclient = aioredis.from_url(TEST_REDIS_URL)
    store = RedisJobStore(aclient, ttl_seconds=60)
    assert await store.get("does-not-exist") is None
    await aclient.aclose()


def _fake_pm(dump):
    return types.SimpleNamespace(model_dump=lambda: dict(dump))


def test_rq_worker_end_to_end_live(redis_client, monkeypatch):
    """Real enqueue → real rq Worker → result in real Redis.

    Uses SimpleWorker (in-process, no fork) so the monkeypatched orchestrator
    applies. Against real Redis the CLIENT INFO 'addr' field exists, so the
    SimpleWorker construction that failed under fakeredis succeeds here.
    """
    from rq import Queue, SimpleWorker

    # Point the worker's JobStore at the same live Redis (async client),
    # and stub the swarm so we exercise the queue path, not a real LLM call.
    monkeypatch.setenv("REDIS_URL", TEST_REDIS_URL)
    monkeypatch.setattr("api.tasks.REDIS_URL", TEST_REDIS_URL)
    monkeypatch.setattr("api.tasks._should_use_swarm", lambda *a, **k: False)

    async def run_impl(**kwargs):
        return _fake_pm({"confidence_score": 0.77, "inconclusive": False}), {"estimated_tokens": 42}

    monkeypatch.setattr("api.tasks.run_incident_analysis", run_impl)

    queue = Queue("rca", connection=redis_client)
    job_id = "itest-" + str(uuid.uuid4())[:8]
    queue.enqueue(run_rca_job, job_id, PAYLOAD, job_id=job_id)
    assert queue.count == 1

    SimpleWorker([queue], connection=redis_client).work(burst=True)

    # The worker wrote the result to RedisJobStore under ens:job:{job_id}.
    # Read + close on a single loop (the async client binds to its creating loop).
    async def _read():
        import redis.asyncio as aioredis

        aclient = aioredis.from_url(TEST_REDIS_URL)
        try:
            return await RedisJobStore(aclient, ttl_seconds=3600).get(job_id)
        finally:
            await aclient.aclose()

    state = asyncio.run(_read())

    assert state is not None, "worker did not persist job result"
    assert state["status"] == "done"
    assert state["result"]["confidence_score"] == 0.77
    assert state["result"]["_mode"] == "single"
