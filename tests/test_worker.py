"""Tests for the RCA job execution path (execute_rca) and queue/transport wiring.

execute_rca is the shared implementation behind both BackgroundTasks and the rq
worker, so testing it covers job-lifecycle correctness for both transports. A
fakeredis-backed rq round-trip confirms enqueue → worker → store actually wires up.
"""
import asyncio
import types

import pytest

from api.jobstore import InMemoryJobStore
from api.queue import make_queue
from api.tasks import execute_rca, run_rca_job

PAYLOAD = {"service": "payment-svc", "incident_time": "2021-12-10T06:15:00Z", "severity": "P0"}


def _fake_pm(dump: dict):
    return types.SimpleNamespace(model_dump=lambda: dict(dump))


async def _run_with(monkeypatch, run_impl):
    store = InMemoryJobStore(ttl_seconds=60)
    monkeypatch.setattr("api.tasks._should_use_swarm", lambda *a, **k: False)
    monkeypatch.setattr("api.tasks.run_incident_analysis", run_impl)
    await execute_rca("job1", PAYLOAD, store)
    return await store.get("job1")


async def test_execute_success(monkeypatch):
    async def run_impl(**kwargs):
        return _fake_pm({"confidence_score": 0.9, "inconclusive": False}), {"estimated_tokens": 100}

    state = await _run_with(monkeypatch, run_impl)
    assert state["status"] == "done"
    assert state["result"]["confidence_score"] == 0.9
    assert state["result"]["_usage"]["estimated_tokens"] == 100
    assert state["result"]["_mode"] == "single"


async def test_execute_none_postmortem(monkeypatch):
    async def run_impl(**kwargs):
        return None, {}

    state = await _run_with(monkeypatch, run_impl)
    assert state["status"] == "failed"
    assert "no PostMortem" in state["error"]


async def test_execute_exception(monkeypatch):
    async def run_impl(**kwargs):
        raise ValueError("boom")

    state = await _run_with(monkeypatch, run_impl)
    assert state["status"] == "failed"
    assert "boom" in state["error"]


async def test_execute_timeout(monkeypatch):
    async def run_impl(**kwargs):
        raise asyncio.TimeoutError()

    state = await _run_with(monkeypatch, run_impl)
    assert state["status"] == "failed"
    assert "timed out" in state["error"]


def test_make_queue_none_without_redis():
    assert make_queue("") is None


def test_make_queue_returns_queue_with_url():
    # redis.Redis.from_url is lazy (no connection); rq.Queue construction does not ping.
    q = make_queue("redis://localhost:6379/0")
    assert q is not None
    assert hasattr(q, "enqueue")


def test_enqueue_registers_job_with_fakeredis():
    """The API's enqueue call registers run_rca_job with the right id and args."""
    fakeredis = pytest.importorskip("fakeredis")
    from rq import Queue

    conn = fakeredis.FakeStrictRedis()
    queue = Queue("rca", connection=conn)
    job = queue.enqueue(run_rca_job, "jobX", PAYLOAD, job_id="jobX")

    assert job.id == "jobX"
    assert queue.count == 1
    assert job.func_name.endswith("run_rca_job")
    assert job.args == ("jobX", PAYLOAD)


def test_run_rca_job_executes_and_writes_store(monkeypatch):
    """run_rca_job is the sync entrypoint rq invokes in the worker process.

    Patch its store + orchestrator so we observe the result without a real LLM.
    This is the worker-side execution rq drives once it dequeues the job above.
    """
    shared = InMemoryJobStore(ttl_seconds=60)
    monkeypatch.setattr("api.tasks.make_job_store", lambda *a, **k: shared)
    monkeypatch.setattr("api.tasks._should_use_swarm", lambda *a, **k: False)

    async def run_impl(**kwargs):
        return _fake_pm({"confidence_score": 0.85}), {"estimated_tokens": 50}

    monkeypatch.setattr("api.tasks.run_incident_analysis", run_impl)

    run_rca_job("jobX", PAYLOAD)  # sync; runs execute_rca via asyncio.run internally

    state = asyncio.run(shared.get("jobX"))
    assert state["status"] == "done"
    assert state["result"]["confidence_score"] == 0.85
