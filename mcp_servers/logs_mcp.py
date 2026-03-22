"""
Logs MCP Server
---------------
Exposes structured log query tools backed by mock seed data (Log4Shell incident).
Swap LOGS_MODE=live and wire to your ELK/Datadog endpoint for production use.

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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

# Allow running from project root or mcp_servers/
sys.path.insert(0, str(Path(__file__).parent.parent))
from config.settings import LOGS_SEED_FILE

mcp = FastMCP(
    "logs-server",
    instructions=(
        "Query enterprise application logs for incident analysis. "
        "Use these tools to find error spikes, retrieve traces, and filter logs by service/severity."
    ),
)

# Seed data loader and helpers

def _load_logs() -> list[dict[str, Any]]:
    with open(LOGS_SEED_FILE, encoding="utf-8") as f:
        return json.load(f)


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


# Tools 

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
    severity = severity.upper()
    level_rank = {"INFO": 0, "WARN": 1, "ERROR": 2, "FATAL": 3}
    min_rank = level_rank.get(severity, 2)

    all_logs = _load_logs()

    # Determine reference time from the latest log entry (seed-safe)
    timestamps = [_parse_ts(e["timestamp"]) for e in all_logs]
    ref_time = max(timestamps)
    cutoff = ref_time.replace(tzinfo=timezone.utc) - __import__("datetime").timedelta(hours=time_range_hours)
    ref_time_tz = ref_time.replace(tzinfo=timezone.utc)

    results = []
    for entry in all_logs:
        if entry.get("service") != service:
            continue
        entry_ts = _parse_ts(entry["timestamp"])
        if entry_ts < cutoff:
            continue
        entry_rank = level_rank.get(entry.get("level", "INFO"), 0)
        if entry_rank < min_rank:
            continue
        # Strip host and truncate long messages to keep context manageable
        safe_entry = {k: v for k, v in entry.items() if k != "host"}
        if "message" in safe_entry:
            safe_entry["message"] = safe_entry["message"][:300]
        results.append(safe_entry)

    return sorted(results, key=lambda e: e["timestamp"])[:15]


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
    all_logs = _load_logs()
    timestamps = [_parse_ts(e["timestamp"]) for e in all_logs]
    ref_time = max(timestamps).replace(tzinfo=timezone.utc)
    cutoff = ref_time - __import__("datetime").timedelta(minutes=window_minutes)

    window_logs = [
        e for e in all_logs
        if e.get("service") == service and _parse_ts(e["timestamp"]) >= cutoff
    ]

    errors = [e for e in window_logs if e.get("level") in ("ERROR", "FATAL", "WARN")]
    error_rate = (len(errors) / len(window_logs) * 100) if window_logs else 0.0

    messages = [e.get("message", "") for e in errors]
    most_common = Counter(messages).most_common(1)[0][0] if messages else ""

    loggers = list({e.get("logger", "") for e in errors if e.get("logger")})

    earliest_error_ts = (
        min(e["timestamp"] for e in errors) if errors else None
    )

    return {
        "service": service,
        "window_minutes": window_minutes,
        "error_count": len(errors),
        "total_count": len(window_logs),
        "error_rate_pct": round(error_rate, 1),
        "spike_detected": error_rate > 20.0,
        "most_common_error": most_common[:300],
        "earliest_error_ts": earliest_error_ts,
        "implicated_loggers": loggers,
    }


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
    all_logs = _load_logs()
    spans = [
        {k: v for k, v in e.items() if k != "host"}
        for e in all_logs
        if e.get("trace_id") == trace_id
    ]
    spans.sort(key=lambda e: e["timestamp"])

    services = list({s.get("service", "") for s in spans})
    errors = [s for s in spans if s.get("level") in ("ERROR", "FATAL")]
    error_summary = " | ".join(e.get("message", "") for e in errors)

    return {
        "trace_id": trace_id,
        "spans": spans,
        "services_involved": services,
        "has_errors": bool(errors),
        "error_summary": error_summary or None,
    }



if __name__ == "__main__":
    mcp.run()
