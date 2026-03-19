"""
Benchmark Scenarios
-------------------
20 seeded incident scenarios across 3 failure classes:
  - Log4Shell / JNDI injection    (12 variants: service × severity × time)
  - OOM / unbounded cache         ( 4 variants: service × severity)
  - Config error / wrong endpoint ( 4 variants: service × severity)

Each scenario defines:
  - inputs:  what the swarm receives
  - oracles: what a correct PostMortem must contain (used by evaluator)
  - baseline_manual_minutes: real-world median triage time for this class
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

SEEDS = Path(__file__).parent.parent / "data" / "seeds"


@dataclass
class Scenario:
    id: str
    name: str
    # Swarm inputs
    service: str
    incident_time: str
    severity: str
    jira_project: str
    # Seed files to load (passed as env vars to MCP subprocesses)
    logs_seed: Path
    commits_seed: Path
    tickets_seed: Path
    # Evaluation oracles
    expected_commit_sha_prefix: str        # root-cause commit must start with this
    expected_ticket_ids: list[str]         # at least one must appear in actions
    expected_logger_keyword: str           # must appear in cited log evidence
    expected_root_cause_keyword: str       # must appear in root_cause string
    # Baseline for before/after comparison
    baseline_manual_minutes: int


# Log4Shell variants
# Same seed data, different service/severity/time framing.
# Tests swarm robustness to surface-level input variation.

_LS_LOGS    = SEEDS / "log4shell_logs.json"
_LS_COMMITS = SEEDS / "log4shell_commits.json"
_LS_TICKETS = SEEDS / "log4shell_tickets.json"

_LOG4SHELL = dict(
    logs_seed=_LS_LOGS,
    commits_seed=_LS_COMMITS,
    tickets_seed=_LS_TICKETS,
    expected_commit_sha_prefix="a3b4c5d6",
    expected_ticket_ids=["PAY-441", "PAY-442", "INFRA-1150"],
    expected_logger_keyword="JndiLookup",
    expected_root_cause_keyword="log4j",
    baseline_manual_minutes=45,
)

LOG4SHELL_SCENARIOS: list[Scenario] = [
    Scenario(id="ls-01", name="Log4Shell · payment-svc · P0 · full window",
             service="payment-svc", incident_time="2021-12-10T06:15:00Z",
             severity="P0", jira_project="PAY", **_LOG4SHELL),

    Scenario(id="ls-02", name="Log4Shell · payment-svc · P0 · narrow window (1 h)",
             service="payment-svc", incident_time="2021-12-10T06:20:00Z",
             severity="P0", jira_project="PAY", **_LOG4SHELL),

    Scenario(id="ls-03", name="Log4Shell · payment-svc · P1 · declared lower severity",
             service="payment-svc", incident_time="2021-12-10T06:15:00Z",
             severity="P1", jira_project="PAY", **_LOG4SHELL),

    Scenario(id="ls-04", name="Log4Shell · order-svc · P0 · same vuln different service",
             service="order-svc", incident_time="2021-12-10T06:15:00Z",
             severity="P0", jira_project="PAY", **_LOG4SHELL),

    Scenario(id="ls-05", name="Log4Shell · auth-svc · P0",
             service="auth-svc", incident_time="2021-12-10T06:30:00Z",
             severity="P0", jira_project="PAY", **_LOG4SHELL),

    Scenario(id="ls-06", name="Log4Shell · notification-svc · P1",
             service="notification-svc", incident_time="2021-12-10T07:00:00Z",
             severity="P1", jira_project="PAY", **_LOG4SHELL),

    Scenario(id="ls-07", name="Log4Shell · reporting-svc · P1",
             service="reporting-svc", incident_time="2021-12-10T07:30:00Z",
             severity="P1", jira_project="PAY", **_LOG4SHELL),

    Scenario(id="ls-08", name="Log4Shell · api-gateway · P2 · downstream effects",
             service="api-gateway", incident_time="2021-12-10T06:17:00Z",
             severity="P2", jira_project="PAY", **_LOG4SHELL),

    Scenario(id="ls-09", name="Log4Shell · payment-svc · P0 · 6-hour blast radius",
             service="payment-svc", incident_time="2021-12-10T12:00:00Z",
             severity="P0", jira_project="PAY", **_LOG4SHELL),

    Scenario(id="ls-10", name="Log4Shell · payment-svc · P0 · day-after retrospective",
             service="payment-svc", incident_time="2021-12-11T08:00:00Z",
             severity="P0", jira_project="PAY", **_LOG4SHELL),

    Scenario(id="ls-11", name="Log4Shell · payment-svc · P0 · ask for INFRA blast radius",
             service="payment-svc", incident_time="2021-12-10T06:15:00Z",
             severity="P0", jira_project="INFRA", **_LOG4SHELL),

    Scenario(id="ls-12", name="Log4Shell · payment-svc · P0 · minimal log window (15 min)",
             service="payment-svc", incident_time="2021-12-10T06:17:00Z",
             severity="P0", jira_project="PAY", **_LOG4SHELL),
]


# OOM / unbounded cache variants

_OOM_LOGS    = SEEDS / "oom_logs.json"
_OOM_COMMITS = SEEDS / "oom_commits.json"
_OOM_TICKETS = SEEDS / "oom_tickets.json"

_OOM = dict(
    logs_seed=_OOM_LOGS,
    commits_seed=_OOM_COMMITS,
    tickets_seed=_OOM_TICKETS,
    expected_commit_sha_prefix="f1e2d3c4",
    expected_ticket_ids=["ORD-311", "ORD-312"],
    expected_logger_keyword="SessionCache",
    expected_root_cause_keyword="cache",
    baseline_manual_minutes=30,
)

OOM_SCENARIOS: list[Scenario] = [
    Scenario(id="oom-01", name="OOM · order-svc · P0 · heap exhausted",
             service="order-svc", incident_time="2022-03-15T14:52:00Z",
             severity="P0", jira_project="ORD", **_OOM),

    Scenario(id="oom-02", name="OOM · order-svc · P1 · early warning (78% heap)",
             service="order-svc", incident_time="2022-03-15T14:30:00Z",
             severity="P1", jira_project="ORD", **_OOM),

    Scenario(id="oom-03", name="OOM · order-svc · P0 · downstream gateway impact",
             service="api-gateway", incident_time="2022-03-15T14:52:00Z",
             severity="P0", jira_project="ORD", **_OOM),

    Scenario(id="oom-04", name="OOM · order-svc · P2 · post-incident retrospective",
             service="order-svc", incident_time="2022-03-16T09:00:00Z",
             severity="P2", jira_project="ORD", **_OOM),
]


# ── Config error / wrong endpoint variants ────────────────────────────────────

_CFG_LOGS    = SEEDS / "config_error_logs.json"
_CFG_COMMITS = SEEDS / "config_error_commits.json"
_CFG_TICKETS = SEEDS / "config_error_tickets.json"

_CFG = dict(
    logs_seed=_CFG_LOGS,
    commits_seed=_CFG_COMMITS,
    tickets_seed=_CFG_TICKETS,
    expected_commit_sha_prefix="c9d8e7f6",
    expected_ticket_ids=["AUTH-101", "AUTH-102"],
    expected_logger_keyword="RedisConnectionException",
    expected_root_cause_keyword="redis",
    baseline_manual_minutes=20,
)

CONFIG_SCENARIOS: list[Scenario] = [
    Scenario(id="cfg-01", name="Config error · auth-svc · P0 · Redis unreachable",
             service="auth-svc", incident_time="2022-07-04T10:31:00Z",
             severity="P0", jira_project="AUTH", **_CFG),

    Scenario(id="cfg-02", name="Config error · auth-svc · P1 · partial auth failures",
             service="auth-svc", incident_time="2022-07-04T10:32:00Z",
             severity="P1", jira_project="AUTH", **_CFG),

    Scenario(id="cfg-03", name="Config error · api-gateway · P0 · downstream auth block",
             service="api-gateway", incident_time="2022-07-04T10:31:00Z",
             severity="P0", jira_project="AUTH", **_CFG),

    Scenario(id="cfg-04", name="Config error · auth-svc · P2 · post-rollback retrospective",
             service="auth-svc", incident_time="2022-07-04T12:00:00Z",
             severity="P2", jira_project="AUTH", **_CFG),
]


# ── Full scenario bank ────────────────────────────────────────────────────────

ALL_SCENARIOS: list[Scenario] = LOG4SHELL_SCENARIOS + OOM_SCENARIOS + CONFIG_SCENARIOS

SCENARIO_MAP: dict[str, Scenario] = {s.id: s for s in ALL_SCENARIOS}
