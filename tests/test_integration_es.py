"""Live-infra integration tests for the Elasticsearch logs backend.

Ingests the real log4shell seed logs into a throwaway index and exercises the
live MCP functions (_live_query_logs / _live_error_spike / _live_get_trace)
against a live Elasticsearch. Skipped cleanly when ES is unreachable.

Start infra with:  docker compose up -d elasticsearch
Override URL with: TEST_ES_URL=http://host:9200
"""
import json
import os
from pathlib import Path

import httpx
import pytest

import mcp_servers.logs_mcp as logs

TEST_ES_URL = os.getenv("TEST_ES_URL", "http://localhost:9200")
TEST_INDEX = "ens-logs-test"
SEED = Path(__file__).parent.parent / "data" / "seeds" / "log4shell_logs.json"

pytestmark = pytest.mark.integration

# Explicit mapping so timestamp sorts as a date and keyword fields filter exactly.
_MAPPING = {
    "mappings": {
        "properties": {
            "timestamp": {"type": "date"},
            "service": {"type": "keyword"},
            "level": {"type": "keyword"},
            "trace_id": {"type": "keyword"},
            "logger": {"type": "keyword"},
            "message": {"type": "text"},
        }
    }
}


def _es_or_skip():
    try:
        r = httpx.get(f"{TEST_ES_URL}/_cluster/health", timeout=3)
        r.raise_for_status()
    except Exception as exc:
        pytest.skip(f"Elasticsearch not reachable at {TEST_ES_URL}: {exc}")


@pytest.fixture
def es_index(monkeypatch):
    _es_or_skip()
    with httpx.Client(timeout=15) as c:
        c.delete(f"{TEST_ES_URL}/{TEST_INDEX}")  # ignore 404
        c.put(f"{TEST_ES_URL}/{TEST_INDEX}", json=_MAPPING).raise_for_status()
        docs = json.loads(SEED.read_text())
        bulk = "".join(
            json.dumps({"index": {}}) + "\n" + json.dumps(d) + "\n" for d in docs
        )
        c.post(
            f"{TEST_ES_URL}/{TEST_INDEX}/_bulk",
            content=bulk,
            headers={"Content-Type": "application/x-ndjson"},
        ).raise_for_status()
        c.post(f"{TEST_ES_URL}/{TEST_INDEX}/_refresh").raise_for_status()

    # Point the live functions at the test index / URL.
    monkeypatch.setattr(logs, "ES_URL", TEST_ES_URL)
    monkeypatch.setattr(logs, "ES_INDEX", TEST_INDEX)
    yield
    with httpx.Client(timeout=15) as c:
        c.delete(f"{TEST_ES_URL}/{TEST_INDEX}")


def test_live_query_logs(es_index):
    results = logs._live_query_logs("payment-svc", "WARN", time_range_hours=24 * 365 * 10)
    assert len(results) > 0
    # host field is scrubbed; message is truncated to 300 chars.
    assert all("host" not in r for r in results)
    assert all(len(r.get("message", "")) <= 300 for r in results)


def test_live_error_spike(es_index):
    spike = logs._live_error_spike("payment-svc", window_minutes=60 * 24 * 365 * 10)
    assert spike["service"] == "payment-svc"
    assert spike["error_count"] > 0
    assert spike["spike_detected"] is True  # seed is 100% WARN/ERROR
    # JNDI is the dominant logger in the Log4Shell seed.
    assert any("Jndi" in lg for lg in spike["implicated_loggers"])
    assert spike["earliest_error_ts"] is not None


def test_live_get_trace(es_index):
    # Pull a real trace_id from the seed, then resolve it via live ES.
    docs = json.loads(SEED.read_text())
    trace_id = docs[0]["trace_id"]
    trace = logs._live_get_trace(trace_id)
    assert trace["trace_id"] == trace_id
    assert len(trace["spans"]) > 0
    assert "payment-svc" in trace["services_involved"]
