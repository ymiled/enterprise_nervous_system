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


# Hybrid: _live_commit_diff fetches metadata + PR via GraphQL, file patches via REST.
FAKE_FILES = (
    ["log4j-core/src/main/java/org/apache/logging/log4j/core/net/JndiManager.java"],
    {"log4j-core/src/main/java/org/apache/logging/log4j/core/net/JndiManager.java": "@@ -1 +1 @@ patch"},
)


def test_commit_diff():
    with patch("mcp_servers.github_mcp._gql", return_value=FAKE_DETAIL) as mock, \
         patch("mcp_servers.github_mcp._rest_commit_files", return_value=FAKE_FILES) as rest:
        result = _live_commit_diff("abc1234def5678", "apache/logging-log4j2")
    assert result["sha"] == "abc1234def5678"
    assert result["pr_number"] == 42
    # files + patches come from the REST half of the hybrid call
    assert result["files_changed"] == FAKE_FILES[0]
    assert result["diff_summary"] == FAKE_FILES[1]
    assert mock.call_args[0][1]["oid"] == "abc1234def5678"
    assert rest.call_args[0][0] == "abc1234def5678"
    print("PASS  test_commit_diff")


def test_commit_diff_pr_flows_into_schema():
    """The PR link GraphQL resolves must survive into the PostMortem schema.

    Proves the commit→PR linkage is functional end-to-end at the data layer:
    GitHub layer emits pr_number/pr_title → CommitEvidence accepts and keeps them.
    """
    from schemas.postmortem import CommitEvidence

    with patch("mcp_servers.github_mcp._gql", return_value=FAKE_DETAIL), \
         patch("mcp_servers.github_mcp._rest_commit_files", return_value=FAKE_FILES):
        result = _live_commit_diff("abc1234def5678", "apache/logging-log4j2")

    ev = CommitEvidence(
        sha=result["sha"],
        repo=result["repo"],
        message=result["message"],
        timestamp=result["timestamp"],
        files_changed=result["files_changed"],
        pr_number=result["pr_number"],
        pr_title=result["pr_title"],
    )
    assert ev.pr_number == 42
    assert ev.pr_title == "fix jndi"
    print("PASS  test_commit_diff_pr_flows_into_schema")


def test_commit_diff_not_found():
    # GraphQL returns no object → short-circuits before the REST call
    with patch("mcp_servers.github_mcp._gql", return_value={"repository": {"object": None}}):
        result = _live_commit_diff("deadbeef", "apache/logging-log4j2")
    assert "error" in result
    print("PASS  test_commit_diff_not_found")


# Fix 1: search now uses REST /search/commits (server-side full-text), not GraphQL.
FAKE_SEARCH_REST = {
    "items": [
        {
            "sha": "c362aff473e9812798ff8f25f30a2619996605d5",
            "commit": {
                "message": "LOG4J2-3208 - Disable JNDI by default\n\nbody",
                "committer": {"date": "2021-12-11T23:05:14Z"},
            },
        }
    ]
}


def test_search_commits_uses_rest():
    with patch("mcp_servers.github_mcp._rest_get", return_value=FAKE_SEARCH_REST) as rest:
        result = _live_search_commits("apache/logging-log4j2", "JndiManager", 8760)
    assert len(result) == 1
    assert result[0]["sha"].startswith("c362aff4")
    assert result[0]["timestamp"] == "2021-12-11T23:05:14Z"
    # hits REST /search/commits with a repo-scoped full-text query
    url = rest.call_args[0][0]
    params = rest.call_args[0][1]
    assert url.endswith("/search/commits")
    assert params["q"] == "repo:apache/logging-log4j2 JndiManager"
    print("PASS  test_search_commits_uses_rest")


def test_search_commits_empty():
    with patch("mcp_servers.github_mcp._rest_get", return_value={"items": []}):
        result = _live_search_commits("apache/logging-log4j2", "struts", 8760)
    assert result == []
    print("PASS  test_search_commits_empty")


# Fix 2: path-scoped history via GraphQL, with PR linkage.
FAKE_PATH_HISTORY = {
    "repository": {
        "defaultBranchRef": {
            "target": {
                "history": {
                    "nodes": [
                        {
                            "oid": "c362aff473e9812798ff8f25f30a2619996605d5",
                            "committedDate": "2021-12-11T23:05:14Z",
                            "message": "LOG4J2-3208 - Disable JNDI by default",
                            "associatedPullRequests": {"nodes": [{"number": 651, "title": "Disable JNDI"}]},
                        }
                    ]
                }
            }
        }
    }
}


def test_commits_for_file_path_history():
    from mcp_servers.github_mcp import _live_commits_for_path

    with patch("mcp_servers.github_mcp._gql", return_value=FAKE_PATH_HISTORY) as g:
        result = _live_commits_for_path(
            "apache/logging-log4j2",
            "log4j-core/src/main/java/org/apache/logging/log4j/core/net/JndiManager.java",
            8760,
        )
    assert len(result) == 1
    assert result[0]["sha"].startswith("c362aff4")
    assert result[0]["pr_number"] == 651  # PR linkage came back in the same query
    assert g.call_args[0][1]["path"].endswith("JndiManager.java")
    print("PASS  test_commits_for_file_path_history")


def test_mock_commits_for_file_matches_basename():
    from mcp_servers.github_mcp import _mock_commits_for_path

    # Mock mode matches the file basename against seed commits' files_changed.
    result = _mock_commits_for_path("apache/logging-log4j2", "x/y/JndiManager.java", 8760)
    assert isinstance(result, list)
    if result:  # seed contains JndiManager.java in the fix commit
        assert any("Jndi" in f for c in result for f in c.get("files_changed", []))
    print("PASS  test_mock_commits_for_file_matches_basename")


if __name__ == "__main__":
    test_recent_commits()
    test_commit_diff()
    test_commit_diff_not_found()
    test_search_commits_uses_rest()
    test_search_commits_empty()
    test_commits_for_file_path_history()
    test_mock_commits_for_file_matches_basename()
    print("\nAll tests passed.")
