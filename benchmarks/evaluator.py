"""
Evaluator
---------
Six deterministic metric functions. Each takes a PostMortem + Scenario and
returns a float in [0.0, 1.0]. No LLM calls.

Metrics:
  1. rca_accuracy        — did the swarm cite the correct root-cause commit?
  2. evidence_quality    — are all 3 evidence types (commit, log, ticket) present?
  3. actionability       — does at least one action reference an expected ticket?
  4. reliability         — did the run complete without error? (set by runner)
  5. pii_compliance      — does the output contain no email / username patterns?
  6. citation_integrity  — every root_cause claim has ≥1 cited SHA + logger/trace
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from schemas.postmortem import PostMortem
from benchmarks.scenarios import Scenario


# ── Result container ──────────────────────────────────────────────────────────

@dataclass
class EvalResult:
    scenario_id: str
    scenario_name: str
    rca_accuracy: float
    evidence_quality: float
    actionability: float
    reliability: float          # 1.0 = completed, 0.0 = swarm error / timeout
    pii_compliance: float
    citation_integrity: float
    elapsed_seconds: float
    postmortem_confidence: float | None = None
    notes: str = ""

    @property
    def overall_score(self) -> float:
        """Unweighted mean of all 6 metrics."""
        return round(sum([
            self.rca_accuracy,
            self.evidence_quality,
            self.actionability,
            self.reliability,
            self.pii_compliance,
            self.citation_integrity,
        ]) / 6, 3)


# ── Individual metrics ────────────────────────────────────────────────────────

def rca_accuracy(pm: PostMortem, scenario: Scenario) -> float:
    """
    1.0 if a cited commit SHA starts with the expected prefix.
    0.5 if the expected keyword appears in root_cause text but no SHA matched.
    0.0 otherwise.
    """
    prefix = scenario.expected_commit_sha_prefix.lower()
    for commit in pm.evidence.commits:
        if commit.sha.lower().startswith(prefix):
            return 1.0
    # partial credit: keyword in root cause narrative
    if scenario.expected_root_cause_keyword.lower() in pm.root_cause.lower():
        return 0.5
    return 0.0


def evidence_quality(pm: PostMortem) -> float:
    """
    Score = (types present) / 3.
    Full score requires at least one log, one commit, and one ticket cited.
    """
    has_log    = len(pm.evidence.logs) > 0
    has_commit = len(pm.evidence.commits) > 0
    has_ticket = len(pm.evidence.tickets) > 0
    return round(sum([has_log, has_commit, has_ticket]) / 3.0, 3)


def actionability(pm: PostMortem, scenario: Scenario) -> float:
    """
    1.0 if at least one recommended action references an expected ticket.
    0.5 if actions exist but none match expected ticket IDs.
    0.0 if no recommended actions at all.
    """
    if not pm.recommended_actions:
        return 0.0
    action_ticket_ids = {a.ticket_id for a in pm.recommended_actions}
    if action_ticket_ids & set(scenario.expected_ticket_ids):
        return 1.0
    return 0.5  # has actions but wrong tickets


def pii_compliance(pm: PostMortem) -> float:
    """
    1.0 if no PII patterns detected in the full serialised PostMortem.
    0.0 if an email address or @username is found anywhere in the output.
    """
    text = pm.model_dump_json()
    email_re = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
    username_re = re.compile(r'(?<!\w)@[A-Za-z0-9_]{3,}(?!\w)')
    if email_re.search(text) or username_re.search(text):
        return 0.0
    return 1.0


def citation_integrity(pm: PostMortem, scenario: Scenario) -> float:
    """
    Score = (checks passed) / 3:
      1. root_cause contains a 7+ char hex string (commit SHA citation)
      2. root_cause or contributing_factors mention the expected logger/exception keyword
      3. at least one evidence.tickets entry exists
    """
    sha_re = re.compile(r'\b[0-9a-f]{7,40}\b', re.IGNORECASE)
    full_text = pm.root_cause + " ".join(pm.contributing_factors)

    has_sha_citation  = bool(sha_re.search(full_text))
    has_logger_cite   = scenario.expected_logger_keyword.lower() in full_text.lower()
    has_ticket_in_ev  = len(pm.evidence.tickets) > 0

    return round(sum([has_sha_citation, has_logger_cite, has_ticket_in_ev]) / 3.0, 3)


# ── Aggregate evaluator ───────────────────────────────────────────────────────

def evaluate(
    pm: PostMortem,
    scenario: Scenario,
    elapsed_seconds: float,
) -> EvalResult:
    """Run all 6 metrics and return a populated EvalResult."""
    return EvalResult(
        scenario_id=scenario.id,
        scenario_name=scenario.name,
        rca_accuracy=rca_accuracy(pm, scenario),
        evidence_quality=evidence_quality(pm),
        actionability=actionability(pm, scenario),
        reliability=1.0,                          # run completed — set to 0 on error
        pii_compliance=pii_compliance(pm),
        citation_integrity=citation_integrity(pm, scenario),
        elapsed_seconds=round(elapsed_seconds, 1),
        postmortem_confidence=pm.confidence_score,
    )


def failed_run(scenario: Scenario, elapsed_seconds: float, reason: str) -> EvalResult:
    """Return a zero-score result for a run that did not produce a PostMortem."""
    return EvalResult(
        scenario_id=scenario.id,
        scenario_name=scenario.name,
        rca_accuracy=0.0,
        evidence_quality=0.0,
        actionability=0.0,
        reliability=0.0,
        pii_compliance=1.0,   # no output = no PII leak
        citation_integrity=0.0,
        elapsed_seconds=round(elapsed_seconds, 1),
        notes=reason,
    )
