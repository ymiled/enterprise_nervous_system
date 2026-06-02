"""
RCA job execution — shared by the in-process BackgroundTasks path and the rq worker.

`execute_rca` is the single async implementation: it runs the swarm and writes the
job lifecycle (running → done/failed) into a JobStore. Both transports call it:

  - BackgroundTasks (no Redis): api/server.py awaits execute_rca directly.
  - rq worker (Redis):          run_rca_job() is the sync entrypoint rq invokes in
                                the worker process; it builds its own JobStore and
                                asyncio.run()s execute_rca. Because the worker is a
                                separate process, an API crash cannot orphan the job.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from api.jobstore import JobStore, make_job_store
from config.settings import JOB_TTL_SECONDS, REDIS_URL
from swarm.orchestrator import _should_use_swarm, run_incident_analysis

log = logging.getLogger("ens.tasks")

# Kept in sync with api.server._SWARM_TIMEOUT; duplicated so the worker process
# does not import the FastAPI app module. The all-live path (gpt-4o + real ES/
# GitHub/Jira calls + up to 45 GroupChat rounds) routinely exceeds 120s, so the
# worker allows more headroom than the synchronous API default.
SWARM_TIMEOUT = 300.0


async def execute_rca(job_id: str, payload: dict[str, Any], store: JobStore) -> None:
    """Run one RCA and record its lifecycle in the store. Never raises."""
    service = payload["service"]
    incident_time = payload["incident_time"]
    severity = payload["severity"]
    jira_project = payload.get("jira_project", "LOG4J2")
    mode = payload.get("mode", "auto")

    use_swarm = mode == "swarm" or (mode == "auto" and _should_use_swarm(service, incident_time, severity))
    log.info("RCA job %s: mode=%s for %s", job_id, "swarm" if use_swarm else "single", service)
    await store.set(job_id, {"status": "running"})

    try:
        pm, usage = await asyncio.wait_for(
            run_incident_analysis(
                service=service,
                incident_time=incident_time,
                severity=severity,
                jira_project=jira_project,
            ),
            timeout=SWARM_TIMEOUT,
        )
    except asyncio.TimeoutError:
        log.error("Job %s timed out after %ss", job_id, SWARM_TIMEOUT)
        await store.set(job_id, {"status": "failed", "error": f"timed out after {SWARM_TIMEOUT:.0f}s"})
        return
    except Exception as exc:
        log.error("Job %s failed: %s", job_id, exc)
        await store.set(job_id, {"status": "failed", "error": str(exc)})
        return

    if pm is None:
        await store.set(job_id, {"status": "failed", "error": "swarm produced no PostMortem"})
        return

    result = pm.model_dump()
    result["_usage"] = usage
    result["_mode"] = "swarm" if use_swarm else "single"
    await store.set(job_id, {"status": "done", "result": result})


def run_rca_job(job_id: str, payload: dict[str, Any]) -> None:
    """Synchronous rq entrypoint. Runs in the worker process, not the API process."""
    store = make_job_store(REDIS_URL, JOB_TTL_SECONDS)
    asyncio.run(execute_rca(job_id, payload, store))
