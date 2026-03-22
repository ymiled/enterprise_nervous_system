"""
Jira MCP Server
---------------
Exposes ticket query tools for incident root-cause analysis.

Modes (set JIRA_MODE in .env):
  mock — uses local seed data (log4shell_tickets.json). No API calls. Default.
  live — queries Apache public Jira REST API (no auth needed for read-only).
         For internal Jira: set JIRA_URL, JIRA_TOKEN, JIRA_EMAIL.

Run standalone:
    python mcp_servers/jira_mcp.py

Tools exposed:
    - get_recent_tickets(project, hours_back)
    - get_ticket(ticket_id)
    - search_tickets(query, project)
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
from fastmcp import FastMCP

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.settings import (
    JIRA_EMAIL,
    JIRA_MODE,
    JIRA_TOKEN,
    JIRA_URL,
    TICKETS_SEED_FILE,
)

mcp = FastMCP(
    "jira-server",
    instructions=(
        "Query Jira tickets to find known issues, recent changes, and flagged components "
        "related to an incident. Focus on Critical/High priority tickets around the incident window."
    ),
)

# Helper functions

def _load_seed_tickets() -> list[dict[str, Any]]:
    with open(TICKETS_SEED_FILE, encoding="utf-8") as f:
        raw = json.load(f)
    return [_normalize_seed_ticket(t) for t in raw]


def _normalize_seed_ticket(t: dict) -> dict:
    """Normalize seed ticket to a consistent internal schema.

    The log4shell_fetcher.py writes tickets with 'id'/'created' fields while
    the live Jira API (and older seeds) use 'ticket_id'/'updated'/'project'.
    This normalises both formats so mock functions work with either.
    """
    ticket_id = t.get("ticket_id") or t.get("id", "")
    # Infer project from ticket key prefix: "LOG4J2-3198" -> "LOG4J2"
    project = t.get("project") or (ticket_id.rsplit("-", 1)[0] if "-" in ticket_id else "")
    # Prefer 'updated'; fall back to 'created', converting bare dates to ISO datetimes
    created = t.get("created", "")
    updated = t.get("updated") or (
        created + "T00:00:00Z" if created and "T" not in created else created or "2000-01-01T00:00:00Z"
    )
    url = t.get("url") or f"https://issues.apache.org/jira/browse/{ticket_id}"
    return {**t, "ticket_id": ticket_id, "project": project, "updated": updated, "url": url}


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _scrub_ticket(ticket: dict) -> dict:
    """Remove individual identity fields — only team names allowed."""
    return {k: v for k, v in ticket.items() if k not in ("reporter", "assignee")}


def _jira_auth() -> httpx.Auth | None:
    if JIRA_TOKEN and JIRA_EMAIL:
        return httpx.BasicAuth(JIRA_EMAIL, JIRA_TOKEN)
    return None


def _normalize_priority(p: str) -> int:
    """Return sortable priority rank (lower = higher priority)."""
    return {"critical": 0, "blocker": 0, "high": 1, "medium": 2, "low": 3}.get(p.lower(), 4)


# Mock implementations

def _mock_recent_tickets(project: str, hours_back: int) -> list[dict[str, Any]]:
    tickets = _load_seed_tickets()
    all_ts = [_parse_ts(t["updated"]) for t in tickets]
    ref_time = max(all_ts)
    cutoff = ref_time - timedelta(hours=hours_back)

    results = [
        _scrub_ticket(t) for t in tickets
        if t.get("project") == project and _parse_ts(t["updated"]) >= cutoff
    ]
    return sorted(results, key=lambda t: _normalize_priority(t.get("priority", "low")))


def _mock_get_ticket(ticket_id: str) -> dict[str, Any]:
    tickets = _load_seed_tickets()
    for t in tickets:
        if t.get("ticket_id") == ticket_id:
            return _scrub_ticket(t)
    return {"error": f"Ticket {ticket_id!r} not found in mock data."}


def _mock_search_tickets(query: str, project: str | None) -> list[dict[str, Any]]:
    tickets = _load_seed_tickets()
    kw = query.lower()
    results = []
    for t in tickets:
        if project and t.get("project") != project:
            continue
        searchable = " ".join([
            t.get("title", ""),
            t.get("description", ""),
            " ".join(t.get("labels", [])),
            t.get("component", ""),
        ]).lower()
        if kw in searchable:
            results.append(_scrub_ticket(t))
    return sorted(results, key=lambda t: _normalize_priority(t.get("priority", "low")))


# Live implementations (Apache public Jira)

def _live_recent_tickets(project: str, hours_back: int) -> list[dict[str, Any]]:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).strftime("%Y-%m-%d %H:%M")
    jql = f'project = "{project}" AND updated >= "{since}" ORDER BY priority ASC'
    url = f"{JIRA_URL}/rest/api/2/search"
    with httpx.Client(timeout=15, auth=_jira_auth()) as client:
        resp = client.get(url, params={"jql": jql, "maxResults": 20,
                                       "fields": "summary,status,priority,updated,labels,components"})
        resp.raise_for_status()
    results = []
    for item in resp.json().get("issues", []):
        f = item.get("fields", {})
        results.append({
            "ticket_id": item["key"],
            "project": project,
            "title": f.get("summary", ""),
            "status": f.get("status", {}).get("name", ""),
            "priority": f.get("priority", {}).get("name", ""),
            "updated": f.get("updated", ""),
            "labels": f.get("labels", []),
            "url": f"{JIRA_URL}/browse/{item['key']}",
        })
    return results


def _live_get_ticket(ticket_id: str) -> dict[str, Any]:
    url = f"{JIRA_URL}/rest/api/2/issue/{ticket_id}"
    with httpx.Client(timeout=15, auth=_jira_auth()) as client:
        resp = client.get(url, params={"fields": "summary,description,status,priority,labels,comment,components"})
        resp.raise_for_status()
    data = resp.json()
    f = data.get("fields", {})
    return {
        "ticket_id": data["key"],
        "title": f.get("summary", ""),
        "description": (f.get("description") or "")[:1000],
        "status": f.get("status", {}).get("name", ""),
        "priority": f.get("priority", {}).get("name", ""),
        "labels": f.get("labels", []),
        "url": f"{JIRA_URL}/browse/{data['key']}",
    }


def _live_search_tickets(query: str, project: str | None) -> list[dict[str, Any]]:
    project_clause = f'project = "{project}" AND ' if project else ""
    jql = f'{project_clause}text ~ "{query}" ORDER BY priority ASC'
    url = f"{JIRA_URL}/rest/api/2/search"
    with httpx.Client(timeout=15, auth=_jira_auth()) as client:
        resp = client.get(url, params={"jql": jql, "maxResults": 20,
                                       "fields": "summary,status,priority,updated,labels"})
        resp.raise_for_status()
    results = []
    for item in resp.json().get("issues", []):
        f = item.get("fields", {})
        results.append({
            "ticket_id": item["key"],
            "title": f.get("summary", ""),
            "status": f.get("status", {}).get("name", ""),
            "priority": f.get("priority", {}).get("name", ""),
            "updated": f.get("updated", ""),
            "labels": f.get("labels", []),
            "url": f"{JIRA_URL}/browse/{item['key']}",
        })
    return results


# Tools

@mcp.tool()
def get_recent_tickets(
    project: str,
    hours_back: int = 72,
) -> list[dict[str, Any]]:
    """
    Return recently updated Jira tickets for a project, sorted by priority.

    Args:
        project:    Jira project key (e.g. "PAY", "INFRA").
        hours_back: How many hours back to search for updated tickets.

    Returns:
        List of ticket summaries sorted Critical → High → Medium → Low.
        Each entry includes ticket_id, title, status, priority, component,
        labels, and linked_tickets.
    """
    if JIRA_MODE == "live":
        return _live_recent_tickets(project, hours_back)
    return _mock_recent_tickets(project, hours_back)


@mcp.tool()
def get_ticket(ticket_id: str) -> dict[str, Any]:
    """
    Retrieve the full detail of a single Jira ticket.

    Args:
        ticket_id: Jira ticket key (e.g. "PAY-441").

    Returns:
        Full ticket including description, status, labels, linked tickets, and URL.
        Reporter/assignee identity is stripped; only team names are returned.
    """
    if JIRA_MODE == "live":
        return _live_get_ticket(ticket_id)
    return _mock_get_ticket(ticket_id)


@mcp.tool()
def search_tickets(
    query: str,
    project: str | None = None,
) -> list[dict[str, Any]]:
    """
    Full-text search across Jira tickets by keyword.

    Args:
        query:   Search term (e.g. "log4j", "JNDI", "payment timeout").
        project: Optional project key to narrow the search (e.g. "PAY").

    Returns:
        Matching tickets sorted by priority, with ticket_id, title, status,
        priority, labels, and URL.
    """
    if JIRA_MODE == "live":
        return _live_search_tickets(query, project)
    return _mock_search_tickets(query, project)


if __name__ == "__main__":
    mcp.run()
