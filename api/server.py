"""
FastAPI server for Enterprise Nervous System.

Endpoints:
  GET  /health         — liveness check
  POST /analyze        — trigger RCA, return PostMortem JSON (requires X-API-Key if API_KEY set)
  POST /slack/analyze  — Slack slash command webhook (async, posts back to response_url)

Run:
  uv run uvicorn api.server:app --reload --port 8000
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import sys
import time
from pathlib import Path
from typing import Literal

import httpx
from fastapi import FastAPI, HTTPException, Request, Security
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent.parent))

from config.settings import API_KEY, SLACK_SIGNING_SECRET
from swarm.orchestrator import run_incident_analysis

log = logging.getLogger("ens.api")

app = FastAPI(title="Enterprise Nervous System", version="0.1.0")

_SWARM_TIMEOUT = 120.0  # seconds before a stuck swarm is killed

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# ── Auth dependency ───────────────────────────────────────────────────────────

async def _require_api_key(key: str | None = Security(_api_key_header)) -> None:
    if not API_KEY:
        return  # auth disabled in dev mode — log once at startup
    if key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key header")


# ── GET /health ───────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "model": "llama-3.3-70b-versatile",
        "swarm_timeout_s": _SWARM_TIMEOUT,
        "auth_enabled": bool(API_KEY),
        "version": "0.1.0",
    }


# ── POST /analyze ─────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    service: str
    incident_time: str
    severity: Literal["P0", "P1", "P2", "P3"]
    jira_project: str = "PAY"


@app.post("/analyze")
async def analyze(req: AnalyzeRequest, _: None = Security(_require_api_key)):
    try:
        pm, usage = await asyncio.wait_for(
            run_incident_analysis(
                service=req.service,
                incident_time=req.incident_time,
                severity=req.severity,
                jira_project=req.jira_project,
            ),
            timeout=_SWARM_TIMEOUT,
        )
    except asyncio.TimeoutError:
        log.error("Swarm timed out after %ss for %s", _SWARM_TIMEOUT, req.service)
        raise HTTPException(
            status_code=504,
            detail={"error": f"Swarm did not complete within {_SWARM_TIMEOUT}s timeout"},
        )

    if pm is None:
        raise HTTPException(status_code=500, detail={"error": "Swarm did not produce a valid PostMortem"})

    result = pm.model_dump()
    result["_usage"] = usage
    return result


# ── POST /slack/analyze ───────────────────────────────────────────────────────

def _verify_slack_signature(secret: str, body: bytes, timestamp: str, signature: str) -> bool:
    basestring = f"v0:{timestamp}:{body.decode()}"
    computed = "v0=" + hmac.new(secret.encode(), basestring.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, signature)


async def _run_and_notify(service: str, incident_time: str, severity: str, response_url: str) -> None:
    try:
        pm, _usage = await asyncio.wait_for(
            run_incident_analysis(service=service, incident_time=incident_time, severity=severity),
            timeout=_SWARM_TIMEOUT,
        )
    except asyncio.TimeoutError:
        msg = f":x: RCA timed out after {_SWARM_TIMEOUT:.0f}s for `{service}`."
    except Exception as exc:
        msg = f":x: RCA failed: {exc}"
    else:
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


# ── Startup log ───────────────────────────────────────────────────────────────

@app.on_event("startup")
async def _startup():
    if not API_KEY:
        log.warning("API_KEY not set — /analyze is unauthenticated. Set API_KEY in .env for production.")
    else:
        log.info("API key auth enabled on /analyze.")
    if not SLACK_SIGNING_SECRET:
        log.warning("SLACK_SIGNING_SECRET not set — /slack/analyze accepts unsigned requests.")
