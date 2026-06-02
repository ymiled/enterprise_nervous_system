"""
FastAPI server for Enterprise Nervous System.

Endpoints:
  GET  /health         — liveness check
  POST /analyze        — enqueue RCA job, returns {job_id, status} immediately (202)
  GET  /analyze/{job_id} — poll job status; result included when status == "done"
  POST /slack/analyze  — Slack slash command webhook (async, posts back to response_url)

Run:
  uv run uvicorn api.server:app --reload --port 8000
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator, Literal
from uuid import uuid4

import httpx
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, Security
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent.parent))

from api.jobstore import make_job_store
from api.queue import make_queue
from api.tasks import execute_rca, run_rca_job
from config.settings import (
    API_KEY,
    JOB_TTL_SECONDS,
    PAGERDUTY_WEBHOOK_SECRET,
    REDIS_URL,
    SLACK_SIGNING_SECRET,
    SLACK_WEBHOOK_URL,
)
from swarm.orchestrator import run_incident_analysis

log = logging.getLogger("ens.api")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    if not API_KEY:
        log.warning("API_KEY not set — /analyze is unauthenticated. Set API_KEY in .env for production.")
    else:
        log.info("API key auth enabled on /analyze.")
    if not SLACK_SIGNING_SECRET:
        log.warning("SLACK_SIGNING_SECRET not set — /slack/analyze accepts unsigned requests.")
    yield


app = FastAPI(title="Enterprise Nervous System", version="0.1.0", lifespan=lifespan)

_SWARM_TIMEOUT = 300.0  # seconds before a stuck swarm is killed (all-live gpt-4o needs headroom)

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# Auth dependency

async def _require_api_key(key: str | None = Security(_api_key_header)) -> None:
    if not API_KEY:
        return  # auth disabled in dev mode — log once at startup
    if key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key header")


# GET /health

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "model": "gpt-4o",
        "swarm_timeout_s": _SWARM_TIMEOUT,
        "auth_enabled": bool(API_KEY),
        "version": "0.1.0",
    }


# POST /analyze  (async job queue)
# JobStore holds job lifecycle: Redis-backed when REDIS_URL set, else in-memory+TTL.
# Execution transport:
#   - rq queue + separate worker when Redis+rq available (crash-durable: an API
#     crash cannot orphan an in-flight job — the worker process owns execution).
#   - in-process BackgroundTasks otherwise (single-replica dev mode).

_jobs = make_job_store(REDIS_URL, JOB_TTL_SECONDS)
_queue = make_queue(REDIS_URL)


class AnalyzeRequest(BaseModel):
    service: str
    incident_time: str
    severity: Literal["P0", "P1", "P2", "P3"]
    jira_project: str = "LOG4J2"
    mode: Literal["auto", "swarm", "single"] = "auto"


@app.post("/analyze", status_code=202)
async def analyze(
    req: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    _: None = Security(_require_api_key),
):
    job_id = str(uuid4())
    await _jobs.set(job_id, {"status": "queued"})
    payload = req.model_dump()

    if _queue is not None:
        _queue.enqueue(run_rca_job, job_id, payload, job_id=job_id)
        transport = "rq"
    else:
        background_tasks.add_task(execute_rca, job_id, payload, _jobs)
        transport = "background"

    return {"job_id": job_id, "status": "queued", "transport": transport}


@app.get("/analyze/{job_id}")
async def get_job(job_id: str, _: None = Security(_require_api_key)):
    job = await _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail={"error": f"Job {job_id!r} not found"})
    return job


# POST /slack/analyze

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


# POST /pagerduty/webhook

_PD_SEVERITY_MAP = {
    "critical": "P0",
    "high":     "P1",
    "warning":  "P2",
    "error":    "P2",
    "info":     "P3",
}

_TRIGGER_EVENTS = {"incident.triggered", "incident.acknowledged"}


async def _post_to_slack(text: str) -> None:
    if not SLACK_WEBHOOK_URL:
        log.warning("SLACK_WEBHOOK_URL not set — skipping Slack notification")
        return
    async with httpx.AsyncClient(timeout=10) as client:
        await client.post(SLACK_WEBHOOK_URL, json={"text": text})


async def _run_pagerduty_incident(service: str, incident_time: str, severity: str, pd_id: str, jira_project: str = "LOG4J2") -> None:
    try:
        pm, usage = await asyncio.wait_for(
            run_incident_analysis(service=service, incident_time=incident_time, severity=severity, jira_project=jira_project),
            timeout=_SWARM_TIMEOUT,
        )
    except asyncio.TimeoutError:
        await _post_to_slack(f":x: *[ENS]* RCA timed out after {_SWARM_TIMEOUT:.0f}s for `{service}` (PD: {pd_id})")
        return
    except Exception as exc:
        await _post_to_slack(f":x: *[ENS]* RCA failed for `{service}` (PD: {pd_id}): {exc}")
        return

    if pm is None:
        await _post_to_slack(f":warning: *[ENS]* Swarm produced no PostMortem for `{service}` (PD: {pd_id})")
        return

    if pm.inconclusive:
        msg = (
            f":mag: *[ENS] Inconclusive RCA — {service} {severity}* (PD: {pd_id})\n"
            f"*Root cause:* {pm.root_cause}\n"
            f"*Confidence:* {pm.confidence_score:.0%} — insufficient evidence for a definitive diagnosis"
        )
    else:
        actions = "\n".join(
            f"  • [{a.priority}] {a.description} (`{a.ticket_id}`)"
            for a in pm.recommended_actions[:3]
        )
        tok = usage.get("estimated_tokens", 0)
        msg = (
            f":rotating_light: *[ENS] RCA complete — {service} {severity}* (PD: {pd_id})\n"
            f"*Root cause:* {pm.root_cause}\n"
            f"*Actions ({len(pm.recommended_actions)}):*\n{actions}\n"
            f"*Confidence:* {pm.confidence_score:.0%}  |  Tokens: {tok:,}"
        )

    await _post_to_slack(msg)


@app.post("/pagerduty/webhook", status_code=200)
async def pagerduty_webhook(request: Request):
    """
    Receives PagerDuty V3 webhooks (incident.triggered / incident.acknowledged).
    Triggers the RCA swarm asynchronously and posts the PostMortem to Slack.

    Signature verification: set PAGERDUTY_WEBHOOK_SECRET in .env.
    PagerDuty docs: https://developer.pagerduty.com/docs/ZG9jOjExMDI5NTkz-v3-overview
    """
    body = await request.body()

    if PAGERDUTY_WEBHOOK_SECRET:
        sig = request.headers.get("X-PagerDuty-Signature", "")
        expected = "v1=" + hmac.new(
            PAGERDUTY_WEBHOOK_SECRET.encode(), body, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, sig.split(",")[0] if sig else ""):
            raise HTTPException(status_code=401, detail="Invalid PagerDuty signature")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    event = payload.get("event", {})
    event_type = event.get("event_type", "")

    if event_type not in _TRIGGER_EVENTS:
        return {"status": "ignored", "event_type": event_type}

    data         = event.get("data", {})
    pd_id        = data.get("id", "unknown")
    title        = data.get("title", "")
    created      = data.get("created_at", "")
    severity     = _PD_SEVERITY_MAP.get(data.get("severity", "").lower(), "P2")
    service      = (data.get("service") or {}).get("name") or title.split()[0] or "unknown-svc"
    incident_time = created or "now"
    # Accept optional jira_project in payload details or custom field; default LOG4J2 for Apache projects
    details      = data.get("details") or {}
    jira_project = details.get("jira_project") or payload.get("jira_project") or "LOG4J2"

    log.info("PagerDuty %s: %s (%s) sev=%s jira=%s", event_type, service, pd_id, severity, jira_project)
    asyncio.create_task(_run_pagerduty_incident(service, incident_time, severity, pd_id, jira_project))

    return {"status": "accepted", "pd_incident_id": pd_id, "service": service, "severity": severity}


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

