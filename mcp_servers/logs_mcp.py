"""
Logs MCP Server
---------------
Exposes structured log query tools for incident analysis.

Modes (set LOGS_MODE in .env):
  mock — reads local seed JSON file. Default.
  live — queries local Elasticsearch (docker compose up -d, then ingest once).
         Set ES_URL and ES_INDEX in .env if non-default.

Run standalone:
    python mcp_servers/logs_mcp.py

Tools exposed:
    - query_logs(service, severity, time_range_hours)
    - get_error_spike(service, window_minutes)
    - get_trace(trace_id)
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
from fastmcp import FastMCP

# Allow running from project root or mcp_servers/
sys.path.insert(0, str(Path(__file__).parent.parent))
from config.settings import ES_INDEX, ES_URL, LOGS_MODE, LOGS_SEED_FILE

mcp = FastMCP(
    "logs-server",
    instructions=(
        "Query enterprise application logs for incident analysis. "
        "Use these tools to find error spikes, retrieve traces, and filter logs by service/severity."
    ),
)

_LEVEL_RANK = {"INFO": 0, "WARN": 1, "ERROR": 2, "FATAL": 3}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _safe(entry: dict) -> dict:
    """Strip host field and truncate long messages."""
    e = {k: v for k, v in entry.items() if k != "host"}
    if "message" in e:
        e["message"] = e["message"][:300]
    return e


# ── Mock implementations ──────────────────────────────────────────────────────

def _load_logs() -> list[dict[str, Any]]:
    with open(LOGS_SEED_FILE, encoding="utf-8") as f:
        return json.load(f)


def _mock_query_logs(service: str, severity: str, time_range_hours: int) -> list[dict]:
    min_rank = _LEVEL_RANK.get(severity, 2)
    all_logs = _load_logs()
    ref_time = max(_parse_ts(e["timestamp"]) for e in all_logs).replace(tzinfo=timezone.utc)
    cutoff   = ref_time - timedelta(hours=time_range_hours)

    results = []
    for entry in all_logs:
        if _parse_ts(entry["timestamp"]) < cutoff:
            continue
        if _LEVEL_RANK.get(entry.get("level", "INFO"), 0) < min_rank:
            continue
        results.append(_safe(entry))
    return sorted(results, key=lambda e: e["timestamp"])[:15]


def _mock_error_spike(service: str, window_minutes: int) -> dict:
    all_logs = _load_logs()
    ref_time = max(_parse_ts(e["timestamp"]) for e in all_logs).replace(tzinfo=timezone.utc)
    cutoff   = ref_time - timedelta(minutes=window_minutes)
    window   = [e for e in all_logs if _parse_ts(e["timestamp"]) >= cutoff]

    errors = [e for e in window if e.get("level") in ("ERROR", "FATAL", "WARN")]
    error_rate = (len(errors) / len(window) * 100) if window else 0.0
    most_common = Counter(e.get("message", "") for e in errors).most_common(1)

    return {
        "service": service,
        "window_minutes": window_minutes,
        "error_count": len(errors),
        "total_count": len(window),
        "error_rate_pct": round(error_rate, 1),
        "spike_detected": error_rate > 20.0,
        "most_common_error": (most_common[0][0] if most_common else "")[:300],
        "earliest_error_ts": min(e["timestamp"] for e in errors) if errors else None,
        "implicated_loggers": list({e.get("logger", "") for e in errors if e.get("logger")}),
    }


def _mock_get_trace(trace_id: str) -> dict:
    all_logs = _load_logs()
    spans  = sorted(
        [_safe(e) for e in all_logs if e.get("trace_id") == trace_id],
        key=lambda e: e["timestamp"],
    )
    errors = [s for s in spans if s.get("level") in ("ERROR", "FATAL")]
    return {
        "trace_id": trace_id,
        "spans": spans,
        "services_involved": list({s.get("service", "") for s in spans}),
        "has_errors": bool(errors),
        "error_summary": " | ".join(e.get("message", "") for e in errors) or None,
    }


# ── Live implementations (Elasticsearch) ─────────────────────────────────────

def _es_ref_time(client: httpx.Client) -> datetime:
    """Return the timestamp of the most recent document in the index."""
    resp = client.post(
        f"{ES_URL}/{ES_INDEX}/_search",
        json={"size": 1, "sort": [{"timestamp": "desc"}], "_source": ["timestamp"]},
    )
    resp.raise_for_status()
    hits = resp.json()["hits"]["hits"]
    if not hits:
        return datetime.now(timezone.utc)
    return _parse_ts(hits[0]["_source"]["timestamp"])


def _es_query(client: httpx.Client, query: dict, size: int = 100) -> list[dict]:
    resp = client.post(
        f"{ES_URL}/{ES_INDEX}/_search",
        json={"query": query, "sort": [{"timestamp": "asc"}], "size": size},
    )
    resp.raise_for_status()
    return [hit["_source"] for hit in resp.json()["hits"]["hits"]]


def _live_query_logs(service: str, severity: str, time_range_hours: int) -> list[dict]:
    min_rank = _LEVEL_RANK.get(severity, 2)
    levels   = [l for l, r in _LEVEL_RANK.items() if r >= min_rank]

    with httpx.Client(timeout=15) as client:
        cutoff = (_es_ref_time(client) - timedelta(hours=time_range_hours)).isoformat()
        query  = {
            "bool": {
                "filter": [
                    {"term":  {"service": service}},
                    {"terms": {"level": levels}},
                    {"range": {"timestamp": {"gte": cutoff}}},
                ]
            }
        }
        docs = _es_query(client, query, size=15)

    return [_safe(d) for d in docs]


def _live_error_spike(service: str, window_minutes: int) -> dict:
    with httpx.Client(timeout=15) as client:
        cutoff = (_es_ref_time(client) - timedelta(minutes=window_minutes)).isoformat()
        query  = {
            "bool": {
                "filter": [
                    {"term":  {"service": service}},
                    {"range": {"timestamp": {"gte": cutoff}}},
                ]
            }
        }
        window = _es_query(client, query, size=1000)

    errors     = [e for e in window if e.get("level") in ("ERROR", "FATAL", "WARN")]
    error_rate = (len(errors) / len(window) * 100) if window else 0.0
    most_common = Counter(e.get("message", "") for e in errors).most_common(1)

    return {
        "service": service,
        "window_minutes": window_minutes,
        "error_count": len(errors),
        "total_count": len(window),
        "error_rate_pct": round(error_rate, 1),
        "spike_detected": error_rate > 20.0,
        "most_common_error": (most_common[0][0] if most_common else "")[:300],
        "earliest_error_ts": min(e["timestamp"] for e in errors) if errors else None,
        "implicated_loggers": list({e.get("logger", "") for e in errors if e.get("logger")}),
    }


def _live_get_trace(trace_id: str) -> dict:
    with httpx.Client(timeout=15) as client:
        docs = _es_query(client, {"term": {"trace_id": trace_id}}, size=100)

    errors = [d for d in docs if d.get("level") in ("ERROR", "FATAL")]
    return {
        "trace_id": trace_id,
        "spans": [_safe(d) for d in docs],
        "services_involved": list({d.get("service", "") for d in docs}),
        "has_errors": bool(errors),
        "error_summary": " | ".join(e.get("message", "") for e in errors) or None,
    }


# ── Tools ─────────────────────────────────────────────────────────────────────

@mcp.tool()
def query_logs(
    service: str,
    severity: str = "ERROR",
    time_range_hours: int = 24,
) -> list[dict[str, Any]]:
    """
    Return log entries for a specific service, filtered by severity and recency.

    Args:
        service:          Service name to filter on (e.g. "payment-svc").
        severity:         Minimum log level — ERROR, WARN, INFO, FATAL. Case-insensitive.
        time_range_hours: How many hours back from the latest log entry to include.

    Returns:
        List of matching log entries, sorted oldest-first. Each entry includes
        timestamp, level, trace_id, logger, message, and optional stack_trace.
    """
    if LOGS_MODE == "live":
        return _live_query_logs(service, severity.upper(), time_range_hours)
    return _mock_query_logs(service, severity.upper(), time_range_hours)


@mcp.tool()
def get_error_spike(
    service: str,
    window_minutes: int = 60,
) -> dict[str, Any]:
    """
    Detect whether a service had an abnormal error rate in the most recent window.

    Args:
        service:         Service name to analyse (e.g. "payment-svc").
        window_minutes:  How many minutes to look back for the spike window.

    Returns:
        Dict with keys:
          - service: str
          - window_minutes: int
          - error_count: int        — ERROR + FATAL entries in window
          - total_count: int        — all entries in window
          - error_rate_pct: float
          - spike_detected: bool    — True if error_rate > 20%
          - most_common_error: str  — most frequent error message in window
          - earliest_error_ts: str  — ISO timestamp of first error
          - implicated_loggers: list[str]
    """
    if LOGS_MODE == "live":
        return _live_error_spike(service, window_minutes)
    return _mock_error_spike(service, window_minutes)


@mcp.tool()
def get_trace(trace_id: str) -> dict[str, Any]:
    """
    Retrieve all log entries belonging to a distributed trace.

    Args:
        trace_id: The trace ID to look up (e.g. "t-9f2a1c3b").

    Returns:
        Dict with:
          - trace_id: str
          - spans: list of log entries for this trace, sorted by timestamp
          - services_involved: list of distinct services seen in the trace
          - has_errors: bool
          - error_summary: str — concatenated error messages if any
    """
    if LOGS_MODE == "live":
        return _live_get_trace(trace_id)
    return _mock_get_trace(trace_id)


if __name__ == "__main__":
    mcp.run()
