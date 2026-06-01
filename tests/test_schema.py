"""
Smoke test: PostMortem Pydantic schema accepts valid data and rejects invalid.
No LLM calls. No external I/O.
"""
import copy

import pytest
from pydantic import ValidationError

from schemas.postmortem import PostMortem, Evidence, LogEvidence, CommitEvidence, TicketEvidence, Action

_VALID = {
    "incident_id": "INC-20211210-001",
    "service": "payment-svc",
    "severity": "P0",
    "incident_time": "2021-12-10T06:15:00Z",
    "root_cause": "Log4j JNDI lookup via HTTP header (commit c362aff4).",
    "contributing_factors": ["log4j 2.14.1 in pom.xml without security review"],
    "evidence": {
        "logs":    [{"trace_id": "t-001", "service": "payment-svc", "timestamp": "2021-12-10T06:15:00Z", "summary": "JNDI lookup attempt"}],
        "commits": [{"sha": "c362aff4abcdef01", "repo": "apache/logging-log4j2", "message": "Disable JNDI", "timestamp": "2021-12-11T00:00:00Z", "files_changed": ["JndiManager.java"]}],
        "tickets": [{"ticket_id": "LOG4J2-3208", "title": "Disable JNDI by default", "status": "Closed", "url": "https://issues.apache.org/jira/browse/LOG4J2-3208"}],
    },
    "recommended_actions": [{"description": "Upgrade log4j to 2.16.0", "ticket_id": "LOG4J2-3208", "priority": "immediate", "owner_team": "platform"}],
    "confidence_score": 0.95,
    "inconclusive": False,
}


def test_valid_postmortem_parses():
    pm = PostMortem(**_VALID)
    assert pm.service == "payment-svc"
    assert pm.severity == "P0"
    assert pm.confidence_score == 0.95
    assert len(pm.evidence.commits) == 1
    assert pm.evidence.commits[0].sha == "c362aff4abcdef01"


def test_inconclusive_postmortem():
    data = {**_VALID, "inconclusive": True, "inconclusive_reason": "No commit found", "confidence_score": 0.3}
    pm = PostMortem(**data)
    assert pm.inconclusive is True
    assert pm.inconclusive_reason == "No commit found"


def test_invalid_severity_rejected():
    with pytest.raises(ValidationError):
        PostMortem(**{**_VALID, "severity": "P5"})


def test_confidence_out_of_range_rejected():
    with pytest.raises(ValidationError):
        PostMortem(**{**_VALID, "confidence_score": 1.5})


def test_short_sha_rejected():
    bad_commit = copy.deepcopy(_VALID)  # deep copy so we don't mutate shared nested dicts
    bad_commit["evidence"]["commits"][0]["sha"] = "abc"  # too short (< 7 chars)
    with pytest.raises(ValidationError):
        PostMortem(**bad_commit)


def test_empty_contributing_factors_rejected_when_conclusive():
    # _VALID is conclusive (inconclusive=False) → empty factors must be rejected.
    with pytest.raises(ValidationError):
        PostMortem(**{**_VALID, "contributing_factors": []})


def test_empty_lists_allowed_when_inconclusive():
    # An inconclusive verdict may legitimately list no factors or actions.
    pm = PostMortem(**{
        **_VALID,
        "inconclusive": True,
        "inconclusive_reason": "No related commits or tickets found",
        "confidence_score": 0.2,
        "contributing_factors": [],
        "recommended_actions": [],
    })
    assert pm.inconclusive is True
    assert pm.contributing_factors == []
    assert pm.recommended_actions == []


def test_empty_recommended_actions_rejected_when_conclusive():
    with pytest.raises(ValidationError):
        PostMortem(**{**_VALID, "recommended_actions": []})
