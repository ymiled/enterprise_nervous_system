"""
Benchmark Evaluator
-------------------
6 deterministic metrics scored [0, 1] for each scenario run.
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
    rca_accuracy:          float
    evidence_quality:      float
    actionability:         float
    reliability:           float
    pii_compliance:        float
    citation_integrity:    float
    elapsed_seconds:       float
    postmortem_confidence: float = 0.0
    notes:                 str   = ""

    @property
    def overall_score(self) -> float:
        return round(
            (self.rca_accuracy + self.evidence_quality + self.actionability
             + self.reliability + self.pii_compliance + self.citation_integrity) / 6,
            3,
        )


# ── Metric functions ──────────────────────────────────────────────────────────

def rca_accuracy(pm: PostMortem, scenario: Scenario) -> float:
    kw = scenario.expected_root_cause_keyword.lower()
    return 1.0 if kw in pm.root_cause.lower() else 0.0


def evidence_quality(pm: PostMortem) -> float:
    return round(sum([
        len(pm.evidence.logs) > 0,
        len(pm.evidence.commits) > 0,
        len(pm.evidence.tickets) > 0,
    ]) / 3.0, 3)


def actionability(pm: PostMortem, scenario: Scenario) -> float:
    if not pm.recommended_actions:
        return 0.0
    action_ids = {a.ticket_id for a in pm.recommended_actions}
    if action_ids & set(scenario.expected_ticket_ids):
        return 1.0
    return 0.5


def reliability(pm: PostMortem) -> float:
    return 0.0 if pm.inconclusive else 1.0


def pii_compliance(pm: PostMortem) -> float:
    text        = pm.model_dump_json()
    email_re    = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
    username_re = re.compile(r'(?<!\w)@[A-Za-z0-9_]{3,}(?!\w)')
    return 0.0 if (email_re.search(text) or username_re.search(text)) else 1.0


def citation_integrity(pm: PostMortem, scenario: Scenario) -> float:
    """
    Three checks (each worth 1/3):
      1. A commit SHA prefix matching expected_commit_sha_prefix appears in evidence
      2. expected_logger_keyword appears in root_cause or contributing_factors
      3. At least one log entry in evidence
    """
    sha_prefix = scenario.expected_commit_sha_prefix.lower()
    commit_shas = [c.sha.lower() for c in pm.evidence.commits]
    has_sha = any(sha.startswith(sha_prefix) for sha in commit_shas)

    full_text = (pm.root_cause + " ".join(pm.contributing_factors)).lower()
    has_logger = scenario.expected_logger_keyword.lower() in full_text

    has_logs = len(pm.evidence.logs) > 0

    return round(sum([has_sha, has_logger, has_logs]) / 3.0, 3)


# ── Entry points ──────────────────────────────────────────────────────────────

def evaluate(pm: PostMortem, scenario: Scenario, elapsed_seconds: float) -> EvalResult:
    return EvalResult(
        scenario_id=scenario.id,
        scenario_name=scenario.name,
        rca_accuracy=rca_accuracy(pm, scenario),
        evidence_quality=evidence_quality(pm),
        actionability=actionability(pm, scenario),
        reliability=reliability(pm),
        pii_compliance=pii_compliance(pm),
        citation_integrity=citation_integrity(pm, scenario),
        elapsed_seconds=round(elapsed_seconds, 1),
        postmortem_confidence=pm.confidence_score,
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
        elapsed_seconds=round(elapsed_seconds, 1),
        notes=reason,
    )
