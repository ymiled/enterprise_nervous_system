"""
Benchmark Evaluator
-------------------
7 metrics scored [0, 1] for each scenario run.

Metrics:
  rca_accuracy       — LLM judge: does the root cause reasoning correctly identify the cause?
  evidence_quality   — right commit SHA cited + logs + tickets all present
  actionability      — recommended actions link to expected ticket IDs
  reliability        — swarm completed; handles expected_inconclusive correctly
  pii_compliance     — no emails or @usernames in output
  citation_integrity — expected SHA in commits, logger keyword in text, logs present
  reasoning_quality  — LLM judge: is the causal chain logically sound?
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from schemas.postmortem import PostMortem
from benchmarks.scenarios import Scenario


@dataclass
class EvalResult:
    scenario_id:           str
    scenario_name:         str
    rca_accuracy:          float   # judge: rca_correctness
    evidence_quality:      float   # right commit + logs + tickets
    actionability:         float
    reliability:           float
    pii_compliance:        float
    citation_integrity:    float
    reasoning_quality:     float   # judge: reasoning_quality
    elapsed_seconds:       float
    postmortem_confidence: float = 0.0
    notes:                 str   = ""

    @property
    def overall_score(self) -> float:
        return round(
            (self.rca_accuracy + self.evidence_quality + self.actionability
             + self.reliability + self.pii_compliance + self.citation_integrity
             + self.reasoning_quality) / 7,
            3,
        )


# Metric functions

def rca_accuracy(judge_scores: dict) -> float:
    """LLM judge score for root-cause correctness (replaces keyword substring match)."""
    return round(float(judge_scores.get("rca_correctness", 0.0)), 3)


def evidence_quality(pm: PostMortem, scenario: Scenario) -> float:
    """
    Three checks (each worth 1/3):
      1. Logs cited
      2. The *expected* commit SHA is cited (not just any commit)
      3. Tickets cited
    For negative scenarios (expected_commit_sha_prefix=""), check 2 becomes
    'no commits cited' — because fabricating commits is wrong.
    """
    has_logs    = len(pm.evidence.logs) > 0
    has_tickets = len(pm.evidence.tickets) > 0

    sha_prefix = scenario.expected_commit_sha_prefix.lower()
    if sha_prefix:
        # Positive scenario: the right commit must be present
        has_right_commit = any(
            c.sha.lower().startswith(sha_prefix)
            for c in pm.evidence.commits
        )
    else:
        # Negative scenario: no commit should be fabricated as root cause
        has_right_commit = len(pm.evidence.commits) == 0

    return round(sum([has_logs, has_right_commit, has_tickets]) / 3.0, 3)


def actionability(pm: PostMortem, scenario: Scenario) -> float:
    if not pm.recommended_actions:
        return 0.0
    action_ids = {a.ticket_id for a in pm.recommended_actions}
    if scenario.expected_ticket_ids and (action_ids & set(scenario.expected_ticket_ids)):
        return 1.0
    # Actions present but none match oracle tickets: partial credit
    return 0.3 if pm.recommended_actions else 0.0


def reliability(pm: PostMortem, scenario: Scenario) -> float:
    """
    Positive scenarios: completed (not inconclusive) with confidence >= 0.5.
    Negative scenarios: must report inconclusive to score 1.0.
    """
    expected_inconclusive = getattr(scenario, "expected_inconclusive", False)

    if expected_inconclusive:
        return 1.0 if pm.inconclusive else 0.0

    if pm.inconclusive:
        return 0.0
    # Penalise false confidence: completed but suspiciously low confidence
    if pm.confidence_score < 0.5:
        return 0.3
    return 1.0


def pii_compliance(pm: PostMortem) -> float:
    text        = pm.model_dump_json()
    email_re    = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
    username_re = re.compile(r'(?<!\w)@[A-Za-z0-9_]{3,}(?!\w)')
    return 0.0 if (email_re.search(text) or username_re.search(text)) else 1.0


def citation_integrity(pm: PostMortem, scenario: Scenario) -> float:
    """
    Three checks (each worth 1/3):
      1. Expected commit SHA prefix appears in evidence.commits
      2. Expected logger keyword appears in root_cause or contributing_factors
      3. At least one log entry cited

    For negative scenarios both sha_prefix and logger_keyword are empty,
    so checks 1 and 2 are skipped and only log presence is checked.
    """
    sha_prefix = scenario.expected_commit_sha_prefix.lower()
    logger_kw  = scenario.expected_logger_keyword.lower()

    if sha_prefix:
        commit_shas = [c.sha.lower() for c in pm.evidence.commits]
        has_sha = any(sha.startswith(sha_prefix) for sha in commit_shas)
    else:
        has_sha = True  # not applicable for negative scenarios

    if logger_kw:
        full_text  = (pm.root_cause + " ".join(pm.contributing_factors)).lower()
        has_logger = logger_kw in full_text
    else:
        has_logger = True  # not applicable for negative scenarios

    has_logs = len(pm.evidence.logs) > 0

    return round(sum([has_sha, has_logger, has_logs]) / 3.0, 3)


def reasoning_quality(judge_scores: dict) -> float:
    """LLM judge score for causal-chain coherence."""
    return round(float(judge_scores.get("reasoning_quality", 0.0)), 3)


# Entry points

def evaluate(pm: PostMortem, scenario: Scenario, elapsed_seconds: float) -> EvalResult:
    from benchmarks.judge import judge_postmortem
    judge = judge_postmortem(pm, scenario)

    return EvalResult(
        scenario_id=scenario.id,
        scenario_name=scenario.name,
        rca_accuracy=rca_accuracy(judge),
        evidence_quality=evidence_quality(pm, scenario),
        actionability=actionability(pm, scenario),
        reliability=reliability(pm, scenario),
        pii_compliance=pii_compliance(pm),
        citation_integrity=citation_integrity(pm, scenario),
        reasoning_quality=reasoning_quality(judge),
        elapsed_seconds=round(elapsed_seconds, 1),
        postmortem_confidence=pm.confidence_score,
        notes=judge.get("explanation", ""),
    )


def failed_run(scenario: Scenario, elapsed_seconds: float, reason: str) -> EvalResult:
    return EvalResult(
        scenario_id=scenario.id,
        scenario_name=scenario.name,
        rca_accuracy=0.0,
        evidence_quality=0.0,
        actionability=0.0,
        reliability=0.0,
        pii_compliance=1.0,
        citation_integrity=0.0,
        reasoning_quality=0.0,
        elapsed_seconds=round(elapsed_seconds, 1),
        notes=reason,
    )
