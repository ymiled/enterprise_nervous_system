"""
GitHub MCP Server
-----------------
Exposes Git/code analysis tools for incident root-cause analysis.

Modes (set GITHUB_MODE in .env):
  mock: uses local seed data (log4shell_commits.json). No API calls. Default.
  live: queries the GitHub GraphQL API v4 (api.github.com/graphql). Requires GITHUB_TOKEN.
        Note: file-level patches are not exposed by GraphQL v4; diff_summary returns
        aggregate additions/deletions counts instead of per-file patches.
        Commit search uses history + client-side filtering (GraphQL search type
        does not index commits).

Run standalone:
    python mcp_servers/github_mcp.py

Tools exposed:
    - get_recent_commits(repo, hours_back)
    - get_commit_diff(commit_sha, repo)
    - search_commits_by_keyword(repo, keyword, hours_back)
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
from fastmcp import FastMCP

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.settings import (
    COMMITS_SEED_FILE,
    GITHUB_MODE,
    GITHUB_ORG,
    GITHUB_TOKEN,
)

_GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"

mcp = FastMCP(
    "github-server",
    instructions=(
        "Query Git commit history and code diffs to identify changes that may have caused an incident. "
        "Focus on changes made in the blast-radius window before the incident timestamp."
    ),
)

# Helper functions 

def _load_seed_commits() -> list[dict[str, Any]]:
    with open(COMMITS_SEED_FILE, encoding="utf-8") as f:
        return json.load(f)


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _scrub_author(commit: dict) -> dict:
    """Remove author identity fields. Only team names are allowed in output."""
    return {k: v for k, v in commit.items() if k not in ("author_email", "author_name")}


def _github_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return headers


# Mock implementations

def _commit_ts(c: dict) -> datetime:
    """Seed uses 'date'; live code uses 'timestamp'. Handle both."""
    return _parse_ts(c.get("timestamp") or c["date"])


def _slim(c: dict) -> dict:
    """Return a lightweight commit summary — no raw diff to keep context small."""
    return {
        "sha": c["sha"],
        "short_sha": c.get("sha_short", c["sha"][:8]),
        "repo": c.get("repo", "apache/logging-log4j2"),
        "timestamp": c.get("timestamp") or c["date"],
        "message": c["message"],
        "files_changed": c.get("files_changed", []),
    }


def _mock_recent_commits(repo: str, hours_back: int) -> list[dict[str, Any]]:
    commits = _load_seed_commits()
    if not commits:
        return []
    ref_time = max(_commit_ts(c) for c in commits)
    cutoff = ref_time - timedelta(hours=hours_back)
    filtered = [
        _slim(_scrub_author(c)) for c in commits
        if _commit_ts(c) >= cutoff
    ]
    return sorted(filtered, key=lambda c: c["timestamp"], reverse=True)[:20]


def _mock_commit_diff(commit_sha: str, repo: str) -> dict[str, Any]:
    commits = _load_seed_commits()
    for c in commits:
        if c["sha"].startswith(commit_sha) or c.get("sha_short", c["sha"][:8]) == commit_sha:
            return _scrub_author({
                "sha": c["sha"],
                "short_sha": c.get("sha_short", c["sha"][:8]),
                "repo": c.get("repo", repo),
                "timestamp": c.get("timestamp") or c["date"],
                "message": c["message"],
                "body": c.get("body", ""),
                "files_changed": c.get("files_changed", []),
                "diff_summary": c.get("diff_summary") or {"patch": c.get("diff", "")[:2000]},
                "pr_number": c.get("pr_number"),
                "pr_title": c.get("pr_title"),
                "ci_status": c.get("ci_status"),
            })
    return {"error": f"Commit {commit_sha!r} not found in mock data for repo {repo!r}"}


_SECURITY_FIX_TERMS = frozenset({
    "disable", "restrict", "patch", "block",
    "cve", "log4j2-3", "log4j2-2", "security", "vulnerability", "exploit",
})


def _mock_search_commits(repo: str, keyword: str, hours_back: int) -> list[dict[str, Any]]:
    commits = _load_seed_commits()
    if not commits:
        return []
    kw = keyword.lower()
    ref_time = max(_commit_ts(c) for c in commits)
    cutoff = ref_time - timedelta(hours=hours_back)

    results = []
    for c in commits:
        if _commit_ts(c) < cutoff:
            continue
        msg_lower   = c.get("message", "").lower()
        files_lower = " ".join(c.get("files_changed", [])).lower()
        body_lower  = c.get("body", "").lower()
        diff_lower  = c.get("diff", "")[:2000].lower()
        searchable  = " ".join([msg_lower, body_lower, files_lower, diff_lower])
        if kw not in searchable:
            continue

        name_match = int(kw in msg_lower or kw in files_lower)
        # Security-fix commits rank highest: name match + fix keyword in message/files.
        # Prevents documentation/test commits (same file, no fix term) from burying
        # the actual security patch in ranked results.
        is_fix = int(name_match and any(t in msg_lower or t in files_lower for t in _SECURITY_FIX_TERMS))
        results.append((_slim(_scrub_author(c)), is_fix, name_match))

    # Tier 1: security fix + name match; Tier 2: name match only; Tier 3: diff-only
    results.sort(key=lambda x: (x[1], x[2], x[0]["timestamp"]), reverse=True)
    return [r for r, *_ in results[:10]]


# Live implementations (GitHub GraphQL API v4)

def _split_repo(repo: str) -> tuple[str, str]:
    """Split 'owner/name' into (owner, name)."""
    owner, _, name = repo.partition("/")
    return owner, name


def _gql(query: str, variables: dict) -> dict:
    """POST a GraphQL query to api.github.com/graphql and return data dict."""
    with httpx.Client(timeout=15) as client:
        resp = client.post(
            _GITHUB_GRAPHQL_URL,
            headers=_github_headers(),
            json={"query": query, "variables": variables},
        )
        resp.raise_for_status()
    payload = resp.json()
    if "errors" in payload:
        raise RuntimeError(f"GitHub GraphQL error: {payload['errors']}")
    return payload["data"]


_RECENT_COMMITS_GQL = """
query RecentCommits($owner: String!, $name: String!, $since: GitTimestamp!) {
  repository(owner: $owner, name: $name) {
    defaultBranchRef {
      target {
        ... on Commit {
          history(first: 30, since: $since) {
            nodes {
              oid
              committedDate
              message
              changedFilesIfAvailable
              associatedPullRequests(first: 1) {
                nodes { number title }
              }
            }
          }
        }
      }
    }
  }
}
"""

_COMMIT_DETAIL_GQL = """
query CommitDetail($owner: String!, $name: String!, $oid: String!) {
  repository(owner: $owner, name: $name) {
    object(expression: $oid) {
      ... on Commit {
        oid
        committedDate
        message
        additions
        deletions
        changedFilesIfAvailable
        associatedPullRequests(first: 1) {
          nodes { number title state }
        }
      }
    }
  }
}
"""

# GitHub GraphQL v4 SearchResultItem union (Issue/PR/Repo/User/Discussion) does not
# include Commit. Fetch recent history and filter client-side instead.
_SEARCH_HISTORY_GQL = """
query SearchHistory($owner: String!, $name: String!, $since: GitTimestamp!) {
  repository(owner: $owner, name: $name) {
    defaultBranchRef {
      target {
        ... on Commit {
          history(first: 100, since: $since) {
            nodes {
              oid
              committedDate
              message
              associatedPullRequests(first: 1) {
                nodes { number title }
              }
            }
          }
        }
      }
    }
  }
}
"""


def _live_recent_commits(repo: str, hours_back: int) -> list[dict[str, Any]]:
    owner, name = _split_repo(repo)
    since = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()
    data = _gql(_RECENT_COMMITS_GQL, {"owner": owner, "name": name, "since": since})
    nodes = data["repository"]["defaultBranchRef"]["target"]["history"]["nodes"]
    return [
        {
            "sha": n["oid"],
            "short_sha": n["oid"][:8],
            "repo": repo,
            "timestamp": n["committedDate"],
            "message": n["message"].split("\n")[0],
            "files_changed": [],  # count only via GraphQL; call get_commit_diff for list
            "author_team": "unknown",
        }
        for n in nodes
    ]


def _live_commit_diff(commit_sha: str, repo: str) -> dict[str, Any]:
    owner, name = _split_repo(repo)
    data = _gql(_COMMIT_DETAIL_GQL, {"owner": owner, "name": name, "oid": commit_sha})
    obj = data["repository"]["object"]
    if obj is None:
        return {"error": f"Commit {commit_sha!r} not found in {repo!r}"}
    pr_nodes = obj.get("associatedPullRequests", {}).get("nodes", [])
    pr = pr_nodes[0] if pr_nodes else {}
    return {
        "sha": obj["oid"],
        "short_sha": obj["oid"][:8],
        "repo": repo,
        "timestamp": obj["committedDate"],
        "message": obj["message"].split("\n")[0],
        "files_changed": [],  # GraphQL v4 exposes count only; per-file patches require REST
        "diff_summary": {
            "additions": obj.get("additions", 0),
            "deletions": obj.get("deletions", 0),
            "changed_files_count": obj.get("changedFilesIfAvailable"),
        },
        "pr_number": pr.get("number"),
        "pr_title": pr.get("title"),
        "ci_status": None,
    }


def _live_search_commits(repo: str, keyword: str, hours_back: int) -> list[dict[str, Any]]:
    owner, name = _split_repo(repo)
    since = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()
    data = _gql(_SEARCH_HISTORY_GQL, {"owner": owner, "name": name, "since": since})
    nodes = data["repository"]["defaultBranchRef"]["target"]["history"]["nodes"]
    kw = keyword.lower()
    results = [
        {
            "sha": n["oid"],
            "short_sha": n["oid"][:8],
            "repo": repo,
            "timestamp": n["committedDate"],
            "message": n["message"].split("\n")[0],
        }
        for n in nodes
        if kw in n["message"].lower()
    ]
    return results[:20]


# Tools

@mcp.tool()
def get_recent_commits(repo: str, hours_back: int = 48) -> list[dict[str, Any]]:
    """
    Return commits merged to the default branch within a lookback window.

    Args:
        repo:       Repository in "owner/repo" format (e.g. "company/payment-svc").
        hours_back: How many hours before now (or before seed ref time) to look.

    Returns:
        List of commits (newest first) with sha, short_sha, repo, timestamp,
        message, files_changed where available, and author_team (never author name).
    """
    if GITHUB_MODE == "live":
        return _live_recent_commits(repo, hours_back)
    return _mock_recent_commits(repo, hours_back)


@mcp.tool()
def get_commit_diff(commit_sha: str, repo: str = f"{GITHUB_ORG}/payment-svc") -> dict[str, Any]:
    """
    Return the full diff metadata for a single commit.

    Args:
        commit_sha: Full or short (>=7 chars) commit SHA.
        repo:       Repository in "owner/repo" format.

    Returns:
        Dict with sha, repo, timestamp, message, files_changed list,
        diff_summary dict (filename → patch snippet), and PR linkage if available.
    """
    if GITHUB_MODE == "live":
        return _live_commit_diff(commit_sha, repo)
    return _mock_commit_diff(commit_sha, repo)


@mcp.tool()
def search_commits_by_keyword(
    repo: str,
    keyword: str,
    hours_back: int = 336,
) -> list[dict[str, Any]]:
    """
    Search commit messages and file paths for a keyword (e.g. "log4j", "pom.xml").

    Args:
        repo:       Repository in "owner/repo" format.
        keyword:    Search term (case-insensitive).
        hours_back: Search window in hours (default 336 = 14 days).

    Returns:
        Matching commits (newest first) with sha, message, files_changed, timestamp.
    """
    if GITHUB_MODE == "live":
        return _live_search_commits(repo, keyword, hours_back)
    return _mock_search_commits(repo, keyword, hours_back)




if __name__ == "__main__":
    mcp.run()
