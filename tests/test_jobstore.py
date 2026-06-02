"""Tests for the in-memory JobStore backend (TTL eviction, size cap, missing keys).

asyncio_mode=auto (see pyproject) runs async test functions directly.
"""
import asyncio

import pytest

from api.jobstore import InMemoryJobStore, RedisJobStore, make_job_store


async def test_set_and_get():
    store = InMemoryJobStore(ttl_seconds=60)
    await store.set("job1", {"status": "queued"})
    assert await store.get("job1") == {"status": "queued"}


async def test_get_missing_returns_none():
    store = InMemoryJobStore(ttl_seconds=60)
    assert await store.get("nope") is None


async def test_overwrite_status():
    store = InMemoryJobStore(ttl_seconds=60)
    await store.set("job1", {"status": "queued"})
    await store.set("job1", {"status": "done", "result": {"x": 1}})
    assert (await store.get("job1"))["status"] == "done"


async def test_ttl_expiry():
    store = InMemoryJobStore(ttl_seconds=0)  # expires immediately
    await store.set("job1", {"status": "done"})
    await asyncio.sleep(0.01)
    assert await store.get("job1") is None


async def test_size_cap_evicts_oldest():
    store = InMemoryJobStore(ttl_seconds=60, max_entries=3)
    for i in range(5):
        await store.set(f"job{i}", {"status": "queued", "n": i})
    # Only the cap's worth should remain; the newest must survive.
    remaining = [await store.get(f"job{i}") for i in range(5)]
    survivors = [r for r in remaining if r is not None]
    assert len(survivors) <= 3
    assert await store.get("job4") is not None


async def test_concurrent_writes_are_safe():
    store = InMemoryJobStore(ttl_seconds=60)
    await asyncio.gather(*(store.set(f"job{i}", {"n": i}) for i in range(100)))
    assert (await store.get("job42"))["n"] == 42


def test_make_job_store_defaults_in_memory():
    # No REDIS_URL → in-memory backend
    store = make_job_store(redis_url="", ttl_seconds=60)
    assert isinstance(store, InMemoryJobStore)


class _FakeRedis:
    """Minimal async fake covering the get/set surface RedisJobStore uses."""

    def __init__(self):
        self.kv: dict[str, str] = {}

    async def set(self, key, value, ex=None):
        self.kv[key] = value

    async def get(self, key):
        return self.kv.get(key)


async def test_redis_store_roundtrip():
    store = RedisJobStore(_FakeRedis(), ttl_seconds=60)
    await store.set("job1", {"status": "done", "result": {"confidence_score": 0.9}})
    got = await store.get("job1")
    assert got["status"] == "done"
    assert got["result"]["confidence_score"] == 0.9


async def test_redis_store_missing_returns_none():
    store = RedisJobStore(_FakeRedis(), ttl_seconds=60)
    assert await store.get("nope") is None
