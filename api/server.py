"""
FastAPI server for Enterprise Nervous System.

Endpoints:
  POST /analyze        — trigger RCA, return PostMortem JSON
  POST /slack/analyze  — Slack slash command webhook (async, posts back to response_url)

Run:
  uv run uvicorn api.server:app --reload --port 8000
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import sys
import time
from pathlib import Path
from typing import Literal

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent.parent))

from config.settings import SLACK_SIGNING_SECRET
from swarm.orchestrator import run_incident_analysis

app = FastAPI(title="Enterprise Nervous System", version="0.1.0")


# ── /analyze ─────────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    service: str
    incident_time: str
    severity: Literal["P0", "P1", "P2", "P3"]
    jira_project: str = "PAY"


@app.post("/analyze")
async def analyze(req: AnalyzeRequest):
    pm, usage = await run_incident_analysis(
        service=req.service,
        incident_time=req.incident_time,
        severity=req.severity,
        jira_project=req.jira_project,
    )
    if pm is None:
        raise HTTPException(status_code=500, detail={"error": "Swarm did not produce a valid PostMortem"})
    result = pm.model_dump()
    result["_usage"] = usage
    return result


# ── /slack/analyze ────────────────────────────────────────────────────────────

def _verify_slack_signature(secret: str, body: bytes, timestamp: str, signature: str) -> bool:
    basestring = f"v0:{timestamp}:{body.decode()}"
    computed = "v0=" + hmac.new(secret.encode(), basestring.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, signature)


async def _run_and_notify(service: str, incident_time: str, severity: str, response_url: str) -> None:
    try:
        pm, _usage = await run_incident_analysis(
            service=service,
            incident_time=incident_time,
            severity=severity,
        )
    except Exception as exc:
        msg = f":x: RCA failed: {exc}"
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(response_url, json={"response_type": "in_channel", "text": msg})
        return

    if pm is None:
        msg = ":warning: Swarm completed but produced no PostMortem. Check logs."
    else:
        actions = "\n".join(
            f"  • [{a.priority}] {a.description} (`{a.ticket_id}`)"
            for a in pm.recommended_actions[:2]
        )
        msg = (
            f":rotating_light: *RCA complete — {service} {severity}*\n"
            f"*Root cause:* {pm.root_cause}\n"
            f"*Actions:*\n{actions}\n"
            f"*Confidence:* {pm.confidence_score:.0%}"
        )

    async with httpx.AsyncClient(timeout=10) as client:
        await client.post(response_url, json={"response_type": "in_channel", "text": msg})


@app.post("/slack/analyze")
async def slack_analyze(request: Request):
    body = await request.body()
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    signature = request.headers.get("X-Slack-Signature", "")

    if SLACK_SIGNING_SECRET:
        # Reject replayed requests older than 5 minutes
        if abs(time.time() - int(timestamp or 0)) > 300:
            raise HTTPException(status_code=401, detail="Request timestamp too old")
        if not _verify_slack_signature(SLACK_SIGNING_SECRET, body, timestamp, signature):
            raise HTTPException(status_code=401, detail="Invalid Slack signature")

    form = await request.form()
    text = (form.get("text") or "").strip()
    response_url = form.get("response_url", "")

    parts = text.split()
    if len(parts) < 3:
        return {
            "response_type": "ephemeral",
            "text": "Usage: `/analyze <service> <ISO-timestamp> <severity>`\nExample: `/analyze payment-svc 2024-01-15T03:00:00Z P0`",
        }

    service, incident_time, severity = parts[0], parts[1], parts[2].upper()
    if severity not in ("P0", "P1", "P2", "P3"):
        return {"response_type": "ephemeral", "text": f"Invalid severity `{severity}`. Use P0/P1/P2/P3."}

    asyncio.create_task(_run_and_notify(service, incident_time, severity, response_url))

    return {"response_type": "in_channel", "text": f":hourglass: Analyzing `{service}` ({severity})..."}
