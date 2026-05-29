"""
Smoke test: all seed files load without errors for every scenario group.
Tests the MCP mock implementations against new non-CVE seed data.
No LLM calls. No external I/O beyond reading local JSON.
"""
import os
import pytest

# Point at mock mode so no real API calls are made
os.environ.setdefault("LOGS_MODE",   "mock")
os.environ.setdefault("GITHUB_MODE", "mock")
os.environ.setdefault("JIRA_MODE",   "mock")

from benchmarks.scenarios import (
    OOM_SCENARIOS, DEP_SCENARIOS, DBL_SCENARIOS, SVC_SCENARIOS, RLT_SCENARIOS,
    LOG4SHELL_SCENARIOS, TEXT4SHELL_SCENARIOS, NEGATIVE_SCENARIOS,
)


@pytest.mark.parametrize("scenario", [
    *OOM_SCENARIOS, *DEP_SCENARIOS, *DBL_SCENARIOS, *SVC_SCENARIOS, *RLT_SCENARIOS,
    LOG4SHELL_SCENARIOS[0], TEXT4SHELL_SCENARIOS[0], NEGATIVE_SCENARIOS[0],
])
def test_seed_files_exist(scenario):
    assert scenario.logs_seed.exists(),    f"{scenario.id}: logs seed missing"
    assert scenario.commits_seed.exists(), f"{scenario.id}: commits seed missing"
    assert scenario.tickets_seed.exists(), f"{scenario.id}: tickets seed missing"


@pytest.mark.parametrize("scenario", [
    *OOM_SCENARIOS, *DEP_SCENARIOS, *DBL_SCENARIOS, *SVC_SCENARIOS, *RLT_SCENARIOS,
])
def test_logs_mcp_mock_returns_data(scenario):
    import json, sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    os.environ["LOGS_SEED_FILE"] = str(scenario.logs_seed)
    # Re-import to pick up new env
    import importlib
    import config.settings as s
    importlib.reload(s)
    import mcp_servers.logs_mcp as lm
    importlib.reload(lm)

    logs = lm._mock_query_logs(scenario.service, "ERROR", 48)
    # Should return a list (may be empty for non-matching service, but must not crash)
    assert isinstance(logs, list)


@pytest.mark.parametrize("scenario", [*DEP_SCENARIOS])
def test_commits_seed_has_sha(scenario):
    import json
    commits = json.loads(scenario.commits_seed.read_text())
    assert len(commits) > 0
    sha = commits[0]["sha"]
    assert sha.startswith(scenario.expected_commit_sha_prefix), \
        f"SHA {sha} doesn't start with {scenario.expected_commit_sha_prefix}"


@pytest.mark.parametrize("scenario", [*OOM_SCENARIOS, *DBL_SCENARIOS, *SVC_SCENARIOS, *RLT_SCENARIOS])
def test_infra_scenarios_have_empty_commits(scenario):
    import json
    commits = json.loads(scenario.commits_seed.read_text())
    assert commits == [], f"{scenario.id} should have empty commits seed for infra incident"


@pytest.mark.parametrize("scenario", [
    *OOM_SCENARIOS, *DEP_SCENARIOS, *DBL_SCENARIOS, *SVC_SCENARIOS, *RLT_SCENARIOS,
])
def test_tickets_seed_has_correct_project(scenario):
    import json
    tickets = json.loads(scenario.tickets_seed.read_text())
    assert len(tickets) >= 1
    # Ticket IDs should start with the jira_project prefix
    for t in tickets:
        tid = t.get("id") or t.get("ticket_id", "")
        assert tid.startswith(scenario.jira_project), \
            f"{scenario.id}: ticket {tid!r} doesn't match project {scenario.jira_project}"
