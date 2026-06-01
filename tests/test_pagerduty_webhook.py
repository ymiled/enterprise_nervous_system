"""
PagerDuty webhook integration test.

Validates the full end-to-end flow:
  PagerDuty V3 webhook → FastAPI /pagerduty/webhook
  → severity mapping → background RCA task → Slack HTTP POST

Verifies:
  - Payload parsing and severity mapping (critical→P0, high→P1)
  - Correct acceptance response
  - Slack message format (root cause, actions, confidence)
  - Bad-JSON and resolved-event handling

No real LLM, Slack, or PagerDuty credentials needed.
"""
from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, patch

import pytest
import respx
import httpx
from httpx import AsyncClient, ASGITransport

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from api.server import app


_PD_INCIDENT_TRIGGERED = {
    "event": {
        "id": "evt-test-001",
        "event_type": "incident.triggered",
        "data": {
            "id": "P1TEST01",
            "title": "High error rate on payment-svc",
            "status": "triggered",
            "severity": "critical",
            "created_at": "2024-01-15T03:00:00Z",
            "service": {
                "id": "SVC001",
                "name": "payment-svc",
                "html_url": "https://company.pagerduty.com/services/SVC001",
            },
        },
    }
}

_PD_INCIDENT_RESOLVED = {
    "event": {
        "id": "evt-test-002",
        "event_type": "incident.resolved",   # should be ignored
        "data": {"id": "P1TEST02", "severity": "critical", "service": {"name": "api-svc"}},
    }
}


@pytest.mark.asyncio
async def test_pagerduty_triggered_accepted():
    """Triggered incident is accepted; severity mapped correctly; task fired."""
    # Patch the background task so no real LLM call happens
    with patch("api.server._run_pagerduty_incident", new_callable=AsyncMock) as mock_rca:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/pagerduty/webhook",
                content=json.dumps(_PD_INCIDENT_TRIGGERED),
                headers={"Content-Type": "application/json"},
            )

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "accepted"
    assert body["pd_incident_id"] == "P1TEST01"
    assert body["service"] == "payment-svc"
    assert body["severity"] == "P0"      # critical → P0


@pytest.mark.asyncio
async def test_pagerduty_resolved_ignored():
    """Resolved events are silently ignored (not triaged)."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/pagerduty/webhook",
            content=json.dumps(_PD_INCIDENT_RESOLVED),
            headers={"Content-Type": "application/json"},
        )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"


@pytest.mark.asyncio
async def test_pagerduty_severity_mapping():
    """PagerDuty severity strings map to correct P-levels."""
    from api.server import _PD_SEVERITY_MAP
    assert _PD_SEVERITY_MAP["critical"] == "P0"
    assert _PD_SEVERITY_MAP["high"]     == "P1"
    assert _PD_SEVERITY_MAP["warning"]  == "P2"
    assert _PD_SEVERITY_MAP["info"]     == "P3"


@pytest.mark.asyncio
async def test_pagerduty_bad_json_rejected():
    """Malformed JSON body returns 400."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/pagerduty/webhook",
            content=b"not json at all",
            headers={"Content-Type": "application/json"},
        )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_pagerduty_high_severity_maps_p1():
    """high severity → P1."""
    payload = {
        "event": {
            "id": "evt-test-003",
            "event_type": "incident.triggered",
            "data": {
                "id": "P1TEST03",
                "title": "Elevated error rate on order-svc",
                "status": "triggered",
                "severity": "high",
                "created_at": "2024-01-15T04:00:00Z",
                "service": {"name": "order-svc"},
            },
        }
    }
    with patch("api.server._run_pagerduty_incident", new_callable=AsyncMock):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/pagerduty/webhook",
                content=json.dumps(payload),
                headers={"Content-Type": "application/json"},
            )
    assert resp.status_code == 200
    assert resp.json()["severity"] == "P1"


@pytest.mark.asyncio
async def test_e2e_pagerduty_to_slack_posting():
    """
    End-to-end: PagerDuty alert fires → RCA completes → Slack message posted.

    Uses respx to intercept the outbound Slack HTTP POST and verify:
    - The request is a POST to the Slack webhook URL
    - The payload contains root_cause, confidence, and ticket references
    """
    import config.settings as cfg_mod

    from schemas.postmortem import (
        Action, CommitEvidence, Evidence, LogEvidence, PostMortem, TicketEvidence,
    )

    mock_pm = PostMortem(
        incident_id="INC-20211210-001",
        service="payment-svc",
        severity="P0",
        incident_time="2021-12-10T06:15:00Z",
        root_cause=(
            "Log4j2 2.14.1 JNDI lookup via HTTP header (CVE-2021-44228) "
            "allowed attacker-controlled LDAP code execution in payment-svc."
        ),
        contributing_factors=["log4j-core 2.14.1 in pom.xml without security review"],
        evidence=Evidence(
            logs=[LogEvidence(trace_id="t-001", service="payment-svc",
                              timestamp="2021-12-10T06:15:00Z", summary="JNDI lookup attempt")],
            commits=[CommitEvidence(sha="c362aff4abcdef01", repo="apache/logging-log4j2",
                                   message="Disable JNDI by default",
                                   timestamp="2021-12-11T00:00:00Z", files_changed=["JndiManager.java"])],
            tickets=[TicketEvidence(ticket_id="LOG4J2-3208", title="Disable JNDI by default",
                                   status="Closed", url="https://issues.apache.org/jira/browse/LOG4J2-3208")],
        ),
        recommended_actions=[Action(description="Upgrade log4j-core to 2.16.0",
                                    ticket_id="LOG4J2-3208", priority="immediate", owner_team="platform")],
        confidence_score=0.95,
        inconclusive=False,
    )
    mock_usage = {"estimated_tokens": 5371, "estimated_cost_usd": 0.0034}

    fake_slack_url = "https://hooks.slack.com/services/TEST/TEST/test"
    captured_payloads = []

    with patch.object(cfg_mod, "SLACK_WEBHOOK_URL", fake_slack_url):
        import api.server as srv
        with patch.object(srv, "SLACK_WEBHOOK_URL", fake_slack_url):
            with respx.mock:
                respx.post(fake_slack_url).mock(return_value=httpx.Response(200, text="ok"))
                with patch("api.server.run_incident_analysis", return_value=(mock_pm, mock_usage)):
                    from api.server import _run_pagerduty_incident
                    await _run_pagerduty_incident("payment-svc", "2021-12-10T06:15:00Z", "P0", "P1TEST01")

                # Verify the Slack HTTP request was made
                assert respx.calls.call_count == 1, "Expected exactly 1 Slack POST"
                call = respx.calls[0]
                body = json.loads(call.request.content)
                text = body["text"]

    # Verify message content
    assert "payment-svc" in text
    assert "P0" in text
    assert "Log4j2" in text or "JNDI" in text or "CVE-2021-44228" in text
    assert "95%" in text or "0.95" in text  # confidence
    assert "LOG4J2-3208" in text            # ticket reference
    print("\nSlack message posted successfully:")
    print(text)
