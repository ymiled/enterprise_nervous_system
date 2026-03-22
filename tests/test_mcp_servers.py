"""
Smoke tests for the three MCP servers in mock mode.

These tests import the server modules directly and call the tool
functions as plain Python — no subprocess, no MCP protocol overhead.
All assertions are against the Log4Shell seed data.

Run:
    pytest tests/test_mcp_servers.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

# Import tools directly from server modules (mock mode is the default)
from mcp_servers.logs_mcp import get_error_spike, get_trace, query_logs
from mcp_servers.github_mcp import get_commit_diff, get_recent_commits, search_commits_by_keyword
from mcp_servers.jira_mcp import get_recent_tickets, get_ticket, search_tickets


# Logs MCP

class TestLogsMCP:
    def test_query_logs_returns_errors_for_payment_svc(self):
        logs = query_logs(service="payment-svc", severity="ERROR", time_range_hours=24)
        assert len(logs) > 0, "Expected ERROR logs for payment-svc"
        assert all(e["level"] in ("ERROR", "FATAL") for e in logs)
        assert all(e["service"] == "payment-svc" for e in logs)

    def test_query_logs_no_host_field(self):
        """Host field must be scrubbed (infra PII)."""
        logs = query_logs(service="payment-svc", severity="ERROR", time_range_hours=24)
        assert all("host" not in e for e in logs), "host field must be stripped from output"

    def test_query_logs_sorted_oldest_first(self):
        logs = query_logs(service="payment-svc", severity="ERROR", time_range_hours=24)
        timestamps = [e["timestamp"] for e in logs]
        assert timestamps == sorted(timestamps)

    def test_query_logs_info_filter_excluded(self):
        """INFO-level entries should not appear when filtering for ERROR."""
        logs = query_logs(service="payment-svc", severity="ERROR", time_range_hours=24)
        assert all(e["level"] != "INFO" for e in logs)

    def test_get_error_spike_detects_spike(self):
        result = get_error_spike(service="payment-svc", window_minutes=60)
        assert result["spike_detected"] is True
        assert result["error_count"] > 0
        assert result["error_rate_pct"] > 20.0

    def test_get_error_spike_structure(self):
        result = get_error_spike(service="payment-svc", window_minutes=60)
        required = {"service", "window_minutes", "error_count", "total_count",
                    "error_rate_pct", "spike_detected", "most_common_error",
                    "earliest_error_ts", "implicated_loggers"}
        assert required.issubset(result.keys())

    def test_get_error_spike_implicates_jndi_logger(self):
        result = get_error_spike(service="payment-svc", window_minutes=60)
        loggers = " ".join(result["implicated_loggers"]).lower()
        assert "jndi" in loggers or "log4j" in loggers, (
            f"Expected log4j/JNDI logger implicated, got: {result['implicated_loggers']}"
        )

    def test_get_trace_returns_spans(self):
        result = get_trace(trace_id="t-9f2a1c3b")
        assert result["trace_id"] == "t-9f2a1c3b"
        assert len(result["spans"]) > 0
        assert result["has_errors"] is True
        assert result["error_summary"] is not None

    def test_get_trace_no_host_in_spans(self):
        result = get_trace(trace_id="t-9f2a1c3b")
        assert all("host" not in span for span in result["spans"])

    def test_get_trace_unknown_id_returns_empty(self):
        result = get_trace(trace_id="t-nonexistent")
        assert result["spans"] == []
        assert result["has_errors"] is False


# GitHub MCP 

class TestGitHubMCP:
    def test_get_recent_commits_returns_results(self):
        commits = get_recent_commits(repo="company/payment-svc", hours_back=500)
        assert len(commits) > 0

    def test_get_recent_commits_no_author_identity(self):
        """Author name/email must be scrubbed."""
        commits = get_recent_commits(repo="company/payment-svc", hours_back=500)
        for c in commits:
            assert "author_name" not in c
            assert "author_email" not in c

    def test_get_recent_commits_sorted_newest_first(self):
        commits = get_recent_commits(repo="company/payment-svc", hours_back=500)
        timestamps = [c["timestamp"] for c in commits]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_get_commit_diff_finds_log4j_upgrade(self):
        result = get_commit_diff(commit_sha="a3b4c5d6", repo="company/payment-svc")
        assert "error" not in result, f"Commit not found: {result}"
        assert "pom.xml" in result["files_changed"]
        assert "log4j" in result["message"].lower() or "log4j" in str(result["diff_summary"]).lower()

    def test_get_commit_diff_full_sha_present(self):
        result = get_commit_diff(commit_sha="a3b4c5d6", repo="company/payment-svc")
        assert len(result["sha"]) == 40, "Full 40-char SHA must be returned"

    def test_search_commits_by_keyword_log4j(self):
        results = search_commits_by_keyword(
            repo="company/payment-svc", keyword="log4j", hours_back=500
        )
        assert len(results) > 0
        assert any("log4j" in c.get("message", "").lower() for c in results)

    def test_search_commits_finds_hotfix(self):
        results = search_commits_by_keyword(
            repo="company/payment-svc", keyword="CVE-2021-44228", hours_back=500
        )
        assert len(results) > 0
        assert any("hotfix" in c.get("message", "").lower() for c in results)


# Jira MCP 

class TestJiraMCP:
    def test_get_recent_tickets_returns_results(self):
        tickets = get_recent_tickets(project="PAY", hours_back=500)
        assert len(tickets) > 0

    def test_get_recent_tickets_sorted_by_priority(self):
        tickets = get_recent_tickets(project="PAY", hours_back=500)
        priorities = [t.get("priority", "").lower() for t in tickets]
        rank = {"critical": 0, "blocker": 0, "high": 1, "medium": 2, "low": 3}
        ranked = [rank.get(p, 4) for p in priorities]
        assert ranked == sorted(ranked), "Tickets must be sorted Critical → High → Low"

    def test_get_recent_tickets_no_personal_identity(self):
        tickets = get_recent_tickets(project="PAY", hours_back=500)
        for t in tickets:
            assert "reporter" not in t
            assert "assignee" not in t

    def test_get_ticket_pay441(self):
        ticket = get_ticket(ticket_id="PAY-441")
        assert ticket["ticket_id"] == "PAY-441"
        assert "jndi" in ticket["title"].lower() or "jndi" in ticket["description"].lower()
        assert ticket["priority"].lower() == "critical"

    def test_get_ticket_unknown_returns_error(self):
        result = get_ticket(ticket_id="PAY-9999")
        assert "error" in result

    def test_search_tickets_log4j(self):
        results = search_tickets(query="log4j", project="PAY")
        assert len(results) > 0
        assert any("log4j" in t.get("title", "").lower()
                   or "log4j" in " ".join(t.get("labels", [])).lower()
                   for t in results)

    def test_search_tickets_cve(self):
        results = search_tickets(query="CVE-2021-44228")
        assert len(results) > 0

    def test_search_tickets_prior_warning_exists(self):
        """PAY-441 must be findable — it's the key prior-warning ticket."""
        results = search_tickets(query="JNDI", project="PAY")
        ticket_ids = [t["ticket_id"] for t in results]
        assert "PAY-441" in ticket_ids, "Prior warning ticket PAY-441 must be discoverable"
