"""
LLM-as-Judge
------------
Evaluates postmortem quality using OpenAI gpt-4o-mini as the primary
independent judge. Falls back to Claude then Groq if OPENAI_API_KEY is absent.

Priority: OpenAI → Claude → Groq (last resort; same model as swarm — avoid for
production benchmarks due to circular evaluation risk).

Falls back to zeros on any error so the benchmark never crashes.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.settings import ANTHROPIC_API_KEY, GROQ_API_KEY, OPENAI_API_KEY
from schemas.postmortem import PostMortem
from benchmarks.scenarios import Scenario

# ---------------------------------------------------------------------------
# Judge prompt
# ---------------------------------------------------------------------------

_PROMPT = """\
You are an expert evaluator of AI-generated incident post-mortems.

IMPORTANT: Your scores MUST be DISCRIMINATING. Do NOT default to 0.5.
Use the full range: 0.0, 0.25, 0.5, 0.75, 1.0.

INCIDENT CONTEXT:
  Service:        {service}
  Incident time:  {incident_time}
  Severity:       {severity}

ORACLE (ground truth for this incident):
  Primary fix commit SHA prefix : {sha_prefix}
  Related ticket IDs            : {ticket_ids}
  Root-cause keywords           : {root_cause_keywords}
  Logger/component keywords     : {logger_keywords}
  Expected inconclusive         : {expected_inconclusive}

HOW TO USE THE ORACLE:
- root_cause_keywords: the key technical terms that MUST appear if the RCA is correct.
  If none appear → score rca_correctness ≤ 0.25.
- logger_keywords: the specific class/component implicated. If root_cause and
  contributing_factors don't mention any of these → deduct from rca_correctness.
- sha_prefix: if the postmortem cites a commit but its SHA doesn't start with
  this prefix → evidence is wrong (deduct from evidence_relevance, not rca_correctness).
- expected_inconclusive=true: the CORRECT answer is to report inconclusive.
  Score rca_correctness=1.0 only if postmortem.inconclusive=true AND root_cause
  explains (a) what was checked and (b) why a confident cause can't be established.
  Score rca_correctness=0.0 if it fabricates a confident root cause.

POSTMORTEM TO EVALUATE (truncated to 3000 chars):
{postmortem_json}

SCORING RUBRIC — assign one of: 0.0 / 0.25 / 0.5 / 0.75 / 1.0

rca_correctness — Does root_cause correctly identify the underlying cause?
  1.00  Exact: names vulnerability/defect type + correct component + correct mechanism.
        For CVE incidents: must name the CVE pattern (e.g. JNDI lookup, OGNL injection)
        AND the affected class (e.g. JndiManager). Clear causal chain.
  0.75  Mostly correct: right vulnerability type and component, but mechanism is
        slightly incomplete (missing one causal link).
  0.50  Partial: right technology area or symptoms but either (a) wrong component,
        (b) symptom described as cause, or (c) correct but too vague to be actionable.
  0.25  Minimal: oracle keywords appear but reasoning is backwards or incoherent.
  0.00  Wrong: incorrect root cause, fabricated evidence, or confident conclusion
        when expected_inconclusive=true.

evidence_relevance — Is cited evidence traceable and relevant to the root cause?
  1.00  All commits/tickets/logs directly trace to stated root cause; no fabrication.
  0.75  Most evidence directly supports root cause; one piece is tangential.
  0.50  Mix of relevant and irrelevant/missing evidence; or evidence present but
        not connected to cause in the narrative.
  0.25  Mostly irrelevant, very sparse, or only loosely connected.
  0.00  Evidence is fabricated, entirely irrelevant, or absent when required.

reasoning_quality — Is the causal chain symptoms → evidence → root cause → actions sound?
  1.00  Explicit chain, every link justified, no leaps, no contradictions.
  0.75  Chain mostly present; one minor gap or unstated assumption.
  0.50  Chain attempted but has a significant gap, circular reference, or one
        contradiction.
  0.25  Chain mostly missing; conclusions don't follow from cited evidence.
  0.00  No coherent chain, circular logic, or conclusion contradicts evidence.

Respond with ONLY this JSON — no markdown, no extra text:
{{"rca_correctness": 0.0, "evidence_relevance": 0.0, "reasoning_quality": 0.0, "explanation": "one sentence"}}\
"""


def _build_prompt(pm: PostMortem, scenario: Scenario) -> str:
    expected_inconclusive = getattr(scenario, "expected_inconclusive", False)
    return _PROMPT.format(
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


def _parse_response(content: str) -> dict:
    result = json.loads(content.strip())
    return {
        "rca_correctness":    float(result.get("rca_correctness", 0.0)),
        "evidence_relevance": float(result.get("evidence_relevance", 0.0)),
        "reasoning_quality":  float(result.get("reasoning_quality", 0.0)),
        "explanation":        str(result.get("explanation", "")),
    }


def _judge_with_claude(prompt: str) -> dict:
    from anthropic import Anthropic
    client = Anthropic(api_key=ANTHROPIC_API_KEY)
    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=256,
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}],
    )
    return _parse_response(message.content[0].text)


def _judge_with_openai(prompt: str) -> dict:
    from openai import OpenAI
    client = OpenAI(api_key=OPENAI_API_KEY)
    message = client.chat.completions.create(
        model="gpt-4o-mini",
        max_tokens=256,
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}],
    )
    return _parse_response(message.choices[0].message.content.strip())


def _judge_with_groq(prompt: str) -> dict:
    from openai import OpenAI
    client = OpenAI(api_key=GROQ_API_KEY, base_url="https://api.groq.com/openai/v1")
    message = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        max_tokens=256,
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}],
    )
    return _parse_response(message.choices[0].message.content.strip())


def judge_postmortem(pm: PostMortem, scenario: Scenario) -> dict[str, float | str]:
    """
    Priority: OpenAI (gpt-4o-mini) → Claude (claude-sonnet-4-6) → Groq (fallback).

    OpenAI is the primary judge: independent of the swarm model (Groq Llama-3.3-70B),
    preventing circular self-evaluation. Set OPENAI_API_KEY for production benchmarks.
    Groq fallback is not recommended — same model as the swarm.

    On any failure returns zeros so the benchmark continues.
    """
    prompt = _build_prompt(pm, scenario)
    if OPENAI_API_KEY:
        backend = "openai"
    elif ANTHROPIC_API_KEY:
        backend = "claude"
    else:
        backend = "groq"

    try:
        if backend == "claude":
            return _judge_with_claude(prompt)
        if backend == "openai":
            return _judge_with_openai(prompt)
        return _judge_with_groq(prompt)
    except Exception as exc:
        print(f"[WARN] Judge ({backend}) failed for {scenario.id}: {exc}", file=sys.stderr)
        return {
            "rca_correctness":    0.0,
            "evidence_relevance": 0.0,
            "reasoning_quality":  0.0,
            "explanation": f"judge error ({backend}): {str(exc)[:120]}",
        }
