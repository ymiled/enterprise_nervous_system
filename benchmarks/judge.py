"""
LLM-as-Judge
------------
Evaluates postmortem quality beyond keyword matching.
Scores reasoning correctness, evidence relevance, and causal chain quality.

The judge is called once per postmortem and returns three scores used by
the evaluator to replace/augment the old deterministic keyword checks.

Falls back to zeros on any error so the benchmark never crashes.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import anthropic

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.settings import ANTHROPIC_API_KEY
from schemas.postmortem import PostMortem
from benchmarks.scenarios import Scenario

_MODEL  = "claude-opus-4-6"
_CLIENT = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

_PROMPT = """\
You are evaluating an AI-generated incident post-mortem for correctness and quality.
Respond with ONLY valid JSON — no markdown fences, no explanation outside the JSON.

INCIDENT CONTEXT:
  Service:        {service}
  Incident time:  {incident_time}
  Severity:       {severity}

ORACLE (known correct answers for this incident):
  Primary fix commit SHA prefix : {sha_prefix}
  Related ticket IDs            : {ticket_ids}
  Root-cause keywords           : {root_cause_keywords}
  Logger keywords               : {logger_keywords}
  Expected inconclusive         : {expected_inconclusive}

POSTMORTEM TO EVALUATE (truncated to 3000 chars):
{postmortem_json}

Score each dimension 0.0–1.0:

rca_correctness
  Does the root cause correctly identify the actual cause with sound reasoning?
  For expected_inconclusive=true: 1.0 if postmortem.inconclusive is true, 0.0 if it
  fabricates a confident root cause despite having no supporting evidence.
  - 1.0  correct root cause identified with clear causal chain
  - 0.5  partially correct or vague
  - 0.0  wrong root cause, no reasoning, or hallucinated evidence

evidence_relevance
  Is the cited evidence actually traceable and relevant to the stated root cause?
  - 1.0  all cited commits/tickets/logs directly support the root cause
  - 0.5  some evidence is relevant, some tangential or missing
  - 0.0  evidence is irrelevant, fabricated, or absent

reasoning_quality
  Is the causal chain from symptoms → evidence → root cause → actions logically sound?
  - 1.0  clear, coherent progression with no leaps or contradictions
  - 0.5  reasoning present but with gaps or minor contradictions
  - 0.0  no coherent reasoning, circular logic, or contradictions

Respond with exactly this JSON shape:
{{"rca_correctness": 0.0, "evidence_relevance": 0.0, "reasoning_quality": 0.0, "explanation": "one sentence"}}\
"""


def judge_postmortem(pm: PostMortem, scenario: Scenario) -> dict[str, float | str]:
    """
    Call the LLM judge and return a dict with keys:
      rca_correctness, evidence_relevance, reasoning_quality  (floats 0–1)
      explanation  (str)

    On any failure returns zeros so the benchmark continues.
    """
    expected_inconclusive = getattr(scenario, "expected_inconclusive", False)

    prompt = _PROMPT.format(
        service=scenario.service,
        incident_time=scenario.incident_time,
        severity=scenario.severity,
        sha_prefix=scenario.expected_commit_sha_prefix or "(none)",
        ticket_ids=scenario.expected_ticket_ids or [],
        root_cause_keywords=scenario.expected_root_cause_keyword or "(none)",
        logger_keywords=scenario.expected_logger_keyword or "(none)",
        expected_inconclusive=expected_inconclusive,
        postmortem_json=pm.model_dump_json(indent=2)[:3000],
    )

    try:
        message = _CLIENT.messages.create(
            model=_MODEL,
            max_tokens=256,
            temperature=0.0,
            messages=[{"role": "user", "content": prompt}],
        )
        content = message.content[0].text.strip()
        result = json.loads(content)
        return {
            "rca_correctness":   float(result.get("rca_correctness", 0.0)),
            "evidence_relevance": float(result.get("evidence_relevance", 0.0)),
            "reasoning_quality":  float(result.get("reasoning_quality", 0.0)),
            "explanation":        str(result.get("explanation", "")),
        }
    except Exception as exc:
        print(f"[WARN] Judge failed for {scenario.id}: {exc}", file=sys.stderr)
        return {
            "rca_correctness":   0.0,
            "evidence_relevance": 0.0,
            "reasoning_quality":  0.0,
            "explanation":        f"judge error: {str(exc)[:120]}",
        }
