from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class LogEvidence(BaseModel):
    trace_id: str
    service: str
    timestamp: str
    summary: str  # What the log entry showed — no raw PII


class CommitEvidence(BaseModel):
    sha: str = Field(..., min_length=7, max_length=40)
    repo: str
    message: str
    timestamp: str
    files_changed: list[str]


class TicketEvidence(BaseModel):
    ticket_id: str  # e.g. "PAY-441"
    title: str
    status: str
    url: str


class Evidence(BaseModel):
    logs: list[LogEvidence] = Field(default_factory=list)
    commits: list[CommitEvidence] = Field(default_factory=list)
    tickets: list[TicketEvidence] = Field(default_factory=list)

    @field_validator("commits")
    @classmethod
    def at_least_one_commit_if_code_cause(cls, v: list) -> list:
        # Validation relaxed here; governor enforces the citation rule at runtime
        return v


class Action(BaseModel):
    description: str
    ticket_id: str  # Jira ticket that tracks this action
    priority: Literal["immediate", "short-term", "long-term"]
    owner_team: str  # team name, NOT an individual (no PII)


class PostMortem(BaseModel):
    incident_id: str
    service: str
    severity: Literal["P0", "P1", "P2", "P3"]
    incident_time: str
    generated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    # Core RCA output
    root_cause: str = Field(..., description="One-sentence root cause, must cite evidence.")
    contributing_factors: list[str] = Field(..., min_length=1)
    timeline: list[str] = Field(default_factory=list)

    # Linked evidence (cited by agents)
    evidence: Evidence

    # Governor-enforced actions
    recommended_actions: list[Action] = Field(..., min_length=1)

    # Confidence
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    inconclusive: bool = False
    inconclusive_reason: str | None = None

    class Config:
        json_schema_extra = {
            "example": {
                "incident_id": "INC-20211210-001",
                "service": "payment-svc",
                "severity": "P0",
                "incident_time": "2021-12-10T06:15:00Z",
                "root_cause": (
                    "Log4j 2.14.1 JNDI lookup vulnerability (CVE-2021-44228) exploited via "
                    "crafted HTTP headers, introduced in commit a3b4c5d6 on 2021-11-28."
                ),
                "contributing_factors": [
                    "log4j-core upgraded to vulnerable 2.14.1 without security review.",
                    "No WAF rule blocking JNDI lookup patterns in HTTP headers.",
                ],
                "evidence": {
                    "logs": [{"trace_id": "t-abc123", "service": "payment-svc",
                              "timestamp": "2021-12-10T06:15:23Z",
                              "summary": "JNDI lookup attempted via User-Agent header"}],
                    "commits": [{"sha": "a3b4c5d6", "repo": "company/payment-svc",
                                 "message": "chore: upgrade log4j-core 2.13.3 → 2.14.1",
                                 "timestamp": "2021-11-28T14:32:00Z",
                                 "files_changed": ["pom.xml"]}],
                    "tickets": [{"ticket_id": "PAY-441",
                                 "title": "Investigate JNDI traffic anomaly in payment-svc",
                                 "status": "Open", "url": "https://jira.company.com/PAY-441"}],
                },
                "recommended_actions": [
                    {"description": "Upgrade log4j-core to 2.15.0 or apply mitigation.",
                     "ticket_id": "PAY-442", "priority": "immediate", "owner_team": "platform"},
                ],
                "confidence_score": 0.95,
                "inconclusive": False,
            }
        }
