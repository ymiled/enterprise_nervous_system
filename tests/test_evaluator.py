"""
Smoke test: evaluator metric functions produce correct scores.
No LLM calls. No external I/O.
"""
import pytest
from schemas.postmortem import PostMortem
from benchmarks.evaluator import (
    evidence_quality,
    actionability,
    reliability,
    pii_compliance,
    citation_integrity,
    rca_keyword_match,
)
from benchmarks.scenarios import SCENARIO_MAP

# Minimal valid PostMortem factory
def _pm(**overrides) -> PostMortem:
    base = {
        "incident_id": "INC-20211210-001",
        "service": "payment-svc",
        "severity": "P0",
        "incident_time": "2021-12-10T06:15:00Z",
        "root_cause": "Log4j jndi lookup exploited via commit c362aff4.",
        "contributing_factors": ["log4j 2.14.1 without security review"],
        "evidence": {
            "logs":    [{"trace_id": "t-001", "service": "payment-svc", "timestamp": "2021-12-10T06:15:00Z", "summary": "JNDI attempt"}],
            "commits": [{"sha": "c362aff4abcdef01", "repo": "apache/logging-log4j2", "message": "Disable JNDI", "timestamp": "2021-12-11T00:00:00Z", "files_changed": ["JndiManager.java"]}],
            "tickets": [{"ticket_id": "LOG4J2-3208", "title": "Disable JNDI", "status": "Closed", "url": "https://issues.apache.org/jira/browse/LOG4J2-3208"}],
        },
        "recommended_actions": [{"description": "Upgrade log4j", "ticket_id": "LOG4J2-3208", "priority": "immediate", "owner_team": "platform"}],
        "confidence_score": 0.95,
        "inconclusive": False,
    }
    base.update(overrides)
    return PostMortem(**base)


_LS01 = SCENARIO_MAP["ls-01"]
_OOM01 = SCENARIO_MAP["oom-01"]
_NEG01 = SCENARIO_MAP["neg-01"]


def test_evidence_quality_full_credit():
    pm = _pm()
    assert evidence_quality(pm, _LS01) == 1.0


def test_evidence_quality_wrong_sha():
    pm = _pm()
    pm.evidence.commits[0].sha = "deadbeef00000000"
    score = evidence_quality(pm, _LS01)
    assert score < 1.0


def test_rca_keyword_match_hit():
    pm = _pm()
    assert rca_keyword_match(pm, _LS01) == 1.0  # "jndi" in root_cause


def test_rca_keyword_match_miss():
    pm = _pm(root_cause="Payment service is slow.")
    assert rca_keyword_match(pm, _LS01) == 0.0


def test_rca_keyword_match_negative_inconclusive():
    pm = _pm(inconclusive=True, confidence_score=0.3)
    assert rca_keyword_match(pm, _NEG01) == 1.0  # neg expects inconclusive=True


def test_rca_keyword_match_negative_fabricated():
    pm = _pm(inconclusive=False)
    assert rca_keyword_match(pm, _NEG01) == 0.0  # neg expects inconclusive but got False


def test_reliability_completed():
    pm = _pm()
    assert reliability(pm, _LS01) == 1.0


def test_reliability_inconclusive_for_positive():
    pm = _pm(inconclusive=True, confidence_score=0.3)
    assert reliability(pm, _LS01) == 0.0


def test_reliability_correctly_inconclusive():
    pm = _pm(inconclusive=True, confidence_score=0.3)
    assert reliability(pm, _OOM01) == 1.0  # oom expects inconclusive


def test_pii_compliance_clean():
    pm = _pm()
    assert pii_compliance(pm) == 1.0


def test_pii_compliance_email_detected():
    pm = _pm(root_cause="Deployed by john.doe@company.com who forgot to upgrade.")
    assert pii_compliance(pm) == 0.0


def test_actionability_ticket_match():
    pm = _pm()
    assert actionability(pm, _LS01) == 1.0


def test_actionability_no_actions():
    pm = _pm()
    pm.recommended_actions = []
    # Pydantic min_length=1 prevents empty list — test partial credit path
    from schemas.postmortem import Action
    pm2 = _pm()
    pm2.recommended_actions = [Action(description="do something", ticket_id="UNKNOWN-99", priority="immediate", owner_team="sre")]
    score = actionability(pm2, _LS01)
    assert score == 0.3  # actions present but no ticket match
