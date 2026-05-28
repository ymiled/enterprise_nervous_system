"""
Single-Agent Baseline
---------------------
Replaces the 4-agent swarm with one LLM call that receives all seed data
(logs + commits + tickets) in a single prompt and is asked to produce the
same PostMortem JSON schema.

Used by ablation_runner.py to measure how much the multi-agent architecture
adds over a naive single-prompt approach.

Usage:
    from benchmarks.baseline import run_baseline
    pm, usage = await run_baseline(scenario)
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from openai import AsyncOpenAI

from benchmarks.scenarios import Scenario
from config.settings import GROQ_API_KEY
from schemas.postmortem import PostMortem

_CLIENT = AsyncOpenAI(
    api_key=GROQ_API_KEY,
    base_url="https://api.groq.com/openai/v1",
)

_MODEL = "llama-3.3-70b-versatile"

_SYSTEM = """\
You are an expert SRE performing root-cause analysis on a production incident.
You will be given all available data: logs, recent commits, and Jira tickets.
Analyse the data and produce a PostMortem JSON matching this schema exactly:

{
  "incident_id": "INC-<YYYYMMDD>-001",
  "service": "<service>",
  "severity": "<P0|P1|P2|P3>",
  "incident_time": "<ISO timestamp>",
  "root_cause": "<one sentence citing evidence>",
  "contributing_factors": ["<factor>"],
  "timeline": ["<timestamp>: <event>"],
  "evidence": {
    "logs":    [{"trace_id": "", "service": "", "timestamp": "", "summary": ""}],
    "commits": [{"sha": "", "repo": "", "message": "", "timestamp": "", "files_changed": []}],
    "tickets": [{"ticket_id": "", "title": "", "status": "", "url": ""}]
  },
  "recommended_actions": [{"description": "", "ticket_id": "", "priority": "immediate|short-term|long-term", "owner_team": ""}],
  "confidence_score": 0.0,
  "inconclusive": false,
  "inconclusive_reason": null
}

Rules:
- Only cite evidence that appears in the data provided.
- If commits array is empty, set evidence.commits = [] and consider inconclusive.
- No PII (no emails, no usernames).
- Output exactly one ```json block, nothing else.
"""


def _load_json(path: Path) -> list | dict:
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []


def _build_prompt(scenario: Scenario) -> str:
    logs    = _load_json(scenario.logs_seed)
    commits = _load_json(scenario.commits_seed)
    tickets = _load_json(scenario.tickets_seed)

    def _trim(obj: list | dict, max_items: int = 8) -> str:
        if isinstance(obj, list):
            return json.dumps(obj[:max_items], indent=2)
        return json.dumps(obj, indent=2)

    return (
        f"INCIDENT: service={scenario.service} severity={scenario.severity} "
        f"time={scenario.incident_time} jira_project={scenario.jira_project}\n\n"
        f"=== LOGS (up to 8) ===\n{_trim(logs)}\n\n"
        f"=== COMMITS (up to 8) ===\n{_trim(commits)}\n\n"
        f"=== TICKETS (up to 8) ===\n{_trim(tickets)}\n\n"
        "Produce the PostMortem JSON now."
    )


def _parse_postmortem(content: str) -> PostMortem | None:
    if "```json" not in content:
        return None
    start = content.find("```json") + 7
    end   = content.find("```", start)
    raw   = content[start:end].strip()
    try:
        return PostMortem(**json.loads(raw))
    except Exception:
        return None


async def run_baseline(scenario: Scenario) -> tuple[PostMortem | None, dict]:
    """Single LLM call baseline. Returns (PostMortem|None, usage_dict)."""
    prompt = _build_prompt(scenario)

    try:
        resp = await _CLIENT.chat.completions.create(
            model=_MODEL,
            temperature=0.0,
            messages=[
                {"role": "system", "content": _SYSTEM},
                {"role": "user",   "content": prompt},
            ],
        )
    except Exception as exc:
        return None, {"error": str(exc), "estimated_tokens": 0, "estimated_cost_usd": 0.0}

    content = resp.choices[0].message.content or ""
    usage   = resp.usage

    prompt_tokens     = usage.prompt_tokens     if usage else 0
    completion_tokens = usage.completion_tokens if usage else 0
    total_tokens      = usage.total_tokens      if usage else 0

    # Groq Llama-3.3-70B: $0.59/1M input, $0.79/1M output
    cost = round(
        (prompt_tokens * 0.59 + completion_tokens * 0.79) / 1_000_000, 6
    )

    usage_dict = {
        "total_messages":    2,
        "total_chars":       len(prompt) + len(content),
        "estimated_tokens":  total_tokens,
        "prompt_tokens":     prompt_tokens,
        "completion_tokens": completion_tokens,
        "estimated_cost_usd": cost,
    }

    return _parse_postmortem(content), usage_dict
