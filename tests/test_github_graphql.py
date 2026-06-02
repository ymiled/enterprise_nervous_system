import sys
sys.path.insert(0, ".")
from unittest.mock import patch

from mcp_servers.github_mcp import _live_recent_commits, _live_commit_diff, _live_search_commits

FAKE_NODE = {
    "oid": "abc1234def5678",
    "committedDate": "2021-12-10T06:00:00Z",
    "message": "LOG4J2-3208 - Disable JNDI by default\n\nbody text",
    "changedFilesIfAvailable": 3,
    "associatedPullRequests": {"nodes": [{"number": 42, "title": "fix jndi"}]},
}

FAKE_HISTORY = {
    "repository": {
        "defaultBranchRef": {
            "target": {"history": {"nodes": [FAKE_NODE]}}
        }
    }
}

FAKE_DETAIL = {
    "repository": {
        "object": {
            "oid": "abc1234def5678",
            "committedDate": "2021-12-10T06:00:00Z",
            "message": "LOG4J2-3208 - Disable JNDI by default\n\nbody",
            "additions": 5,
            "deletions": 2,
            "changedFilesIfAvailable": 1,
            "associatedPullRequests": {"nodes": [{"number": 42, "title": "fix jndi", "state": "MERGED"}]},
        }
    }
}


def test_recent_commits():
    with patch("mcp_servers.github_mcp._gql", return_value=FAKE_HISTORY) as mock:
        result = _live_recent_commits("apache/logging-log4j2", 48)
    assert len(result) == 1
    assert result[0]["sha"] == "abc1234def5678"
    assert result[0]["short_sha"] == "abc1234d"
    assert result[0]["message"] == "LOG4J2-3208 - Disable JNDI by default"
    vars_ = mock.call_args[0][1]
    assert vars_["owner"] == "apache"
    assert vars_["name"] == "logging-log4j2"
    assert "2021" in vars_["since"] or "2025" in vars_["since"] or vars_["since"]  # non-empty ISO ts
    print("PASS  test_recent_commits")


def test_commit_diff():
    with patch("mcp_servers.github_mcp._gql", return_value=FAKE_DETAIL) as mock:
        result = _live_commit_diff("abc1234def5678", "apache/logging-log4j2")
    assert result["sha"] == "abc1234def5678"
    assert result["pr_number"] == 42
    assert result["diff_summary"]["additions"] == 5
    assert result["diff_summary"]["deletions"] == 2
    assert result["diff_summary"]["changed_files_count"] == 1
    vars_ = mock.call_args[0][1]
    assert vars_["oid"] == "abc1234def5678"
    print("PASS  test_commit_diff")


def test_commit_diff_not_found():
    with patch("mcp_servers.github_mcp._gql", return_value={"repository": {"object": None}}):
        result = _live_commit_diff("deadbeef", "apache/logging-log4j2")
    assert "error" in result
    print("PASS  test_commit_diff_not_found")


def test_search_commits():
    with patch("mcp_servers.github_mcp._gql", return_value=FAKE_HISTORY):
        result = _live_search_commits("apache/logging-log4j2", "jndi", 8760)
    assert len(result) == 1
    assert result[0]["sha"] == "abc1234def5678"
    print("PASS  test_search_commits")


def test_search_commits_no_match():
    with patch("mcp_servers.github_mcp._gql", return_value=FAKE_HISTORY):
        result = _live_search_commits("apache/logging-log4j2", "struts", 8760)
    assert result == []
    print("PASS  test_search_commits_no_match")


if __name__ == "__main__":
    test_recent_commits()
    test_commit_diff()
    test_commit_diff_not_found()
    test_search_commits()
    test_search_commits_no_match()
    print("\nAll tests passed.")
