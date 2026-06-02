"""
Job store for async RCA jobs.

Two backends, selected by make_job_store():
  RedisJobStore     — used when REDIS_URL is set and redis is importable.
                      Jobs persist across API restarts; TTL via SETEX.
  InMemoryJobStore  — fallback. TTL eviction + size cap. Lost on restart.

The store holds the lifecycle of a single /analyze request:
  {"status": "queued"|"running"|"done"|"failed", "result": {...}, "error": "..."}

Production note: InMemoryJobStore is fine for a single API replica. For multiple
replicas or durability across restarts, set REDIS_URL so all replicas share state
and a separate worker can be added later (rq) without changing this interface.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Protocol

log = logging.getLogger("ens.jobstore")


class JobStore(Protocol):
    async def set(self, job_id: str, data: dict[str, Any]) -> None: ...
    async def get(self, job_id: str) -> dict[str, Any] | None: ...


class InMemoryJobStore:
    """Async-safe in-memory store with lazy TTL eviction and a hard size cap.

    Eviction runs on every write: expired entries are dropped, and if the store
    still exceeds max_entries the oldest entries are removed. This bounds memory
    without a background sweeper task.
    """

    def __init__(self, ttl_seconds: int = 3600, max_entries: int = 10_000) -> None:
        self._ttl = ttl_seconds
        self._max = max_entries
        self._data: dict[str, tuple[float, dict[str, Any]]] = {}
        self._lock = asyncio.Lock()

    def _evict_locked(self) -> None:
        now = time.monotonic()
        expired = [k for k, (exp, _) in self._data.items() if exp <= now]
        for k in expired:
            del self._data[k]
        if len(self._data) > self._max:
            # Drop oldest by expiry timestamp until back under cap.
            overflow = len(self._data) - self._max
            oldest = sorted(self._data.items(), key=lambda kv: kv[1][0])[:overflow]
            for k, _ in oldest:
                del self._data[k]

    async def set(self, job_id: str, data: dict[str, Any]) -> None:
        async with self._lock:
            self._data[job_id] = (time.monotonic() + self._ttl, data)
            self._evict_locked()

    async def get(self, job_id: str) -> dict[str, Any] | None:
        async with self._lock:
            entry = self._data.get(job_id)
            if entry is None:
                return None
            exp, data = entry
            if exp <= time.monotonic():
                del self._data[job_id]
                return None
            return data


class RedisJobStore:
    """Redis-backed store. Jobs persist across restarts; TTL via SETEX.

    Uses redis.asyncio. Values are JSON-serialised under key 'ens:job:{job_id}'.
    """

    _PREFIX = "ens:job:"

    def __init__(self, client: Any, ttl_seconds: int = 3600) -> None:
        self._redis = client
        self._ttl = ttl_seconds

    async def set(self, job_id: str, data: dict[str, Any]) -> None:
        await self._redis.set(
            self._PREFIX + job_id, json.dumps(data), ex=self._ttl
        )

    async def get(self, job_id: str) -> dict[str, Any] | None:
        raw = await self._redis.get(self._PREFIX + job_id)
        if raw is None:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode()
        return json.loads(raw)


def make_job_store(redis_url: str = "", ttl_seconds: int = 3600) -> JobStore:
    """Return RedisJobStore if redis_url is set and redis is importable, else InMemoryJobStore."""
    if redis_url:
        try:
            import redis.asyncio as aioredis  # type: ignore

            client = aioredis.from_url(redis_url)
            log.info("JobStore: Redis backend at %s (TTL %ss)", redis_url, ttl_seconds)
            return RedisJobStore(client, ttl_seconds)
        except ImportError:
            log.warning(
                "REDIS_URL set but redis package not installed — "
                "falling back to in-memory store. Run `uv add redis`."
            )
    log.info("JobStore: in-memory backend (TTL %ss, not durable across restarts)", ttl_seconds)
    return InMemoryJobStore(ttl_seconds)
