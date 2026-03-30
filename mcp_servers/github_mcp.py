"""
GitHub MCP Server
-----------------
Exposes Git/code analysis tools for incident root-cause analysis.

Modes (set GITHUB_MODE in .env):
  mock: uses local seed data (log4shell_commits.json). No API calls. Default.
  live: queries the GitHub REST API. Requires GITHUB_TOKEN.

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
    GITHUB_API_URL,
    GITHUB_MODE,
    GITHUB_TOKEN,
)

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
    ref_time = max(_commit_ts(c) for c in commits)
    cutoff = ref_time - timedelta(hours=hours_back)
    # Mock data has no 'repo' field — return all commits within the time window
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


def _mock_search_commits(repo: str, keyword: str, hours_back: int) -> list[dict[str, Any]]:
    commits = _load_seed_commits()
    kw = keyword.lower()
    ref_time = max(_commit_ts(c) for c in commits)
    cutoff = ref_time - timedelta(hours=hours_back)

    results = []
    for c in commits:
        if _commit_ts(c) < cutoff:
            continue
        searchable = " ".join([
            c.get("message", ""),
            c.get("body", ""),
            " ".join(c.get("files_changed", [])),
            c.get("diff", "")[:2000],  # also search diff content
        ]).lower()
        if kw in searchable:
            results.append(_slim(_scrub_author(c)))
    return sorted(results, key=lambda c: c["timestamp"], reverse=True)[:10]


# Live implementations

def _live_recent_commits(repo: str, hours_back: int) -> list[dict[str, Any]]:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()
    url = f"{GITHUB_API_URL}/repos/{repo}/commits"
    with httpx.Client(timeout=15) as client:
        resp = client.get(url, headers=_github_headers(), params={"since": since, "per_page": 30})
        resp.raise_for_status()
    results = []
    for item in resp.json():
        c = item.get("commit", {})
        results.append({
            "sha": item["sha"],
            "short_sha": item["sha"][:8],
            "repo": repo,
            "timestamp": c.get("author", {}).get("date", ""),
            "message": c.get("message", "").split("\n")[0],
            "author_team": "unknown",  # GitHub API returns username; we omit for PII
        })
    return results


def _live_commit_diff(commit_sha: str, repo: str) -> dict[str, Any]:
    url = f"{GITHUB_API_URL}/repos/{repo}/commits/{commit_sha}"
    with httpx.Client(timeout=15) as client:
        resp = client.get(url, headers=_github_headers())
        resp.raise_for_status()
    data = resp.json()
    c = data.get("commit", {})
    files = data.get("files", [])
    return {
        "sha": data["sha"],
        "short_sha": data["sha"][:8],
        "repo": repo,
        "timestamp": c.get("author", {}).get("date", ""),
        "message": c.get("message", "").split("\n")[0],
        "files_changed": [f["filename"] for f in files],
        "diff_summary": {f["filename"]: f.get("patch", "")[:500] for f in files},
    }


def _live_search_commits(repo: str, keyword: str, hours_back: int) -> list[dict[str, Any]]:
    # GitHub search API — requires auth for higher rate limits
    since = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()
    url = f"{GITHUB_API_URL}/search/commits"
    query = f"repo:{repo} {keyword} committer-date:>={since[:10]}"
    with httpx.Client(timeout=15) as client:
        resp = client.get(
            url, headers=_github_headers(),
            params={"q": query, "per_page": 20, "sort": "committer-date"},
        )
        resp.raise_for_status()
    results = []
    for item in resp.json().get("items", []):
        c = item.get("commit", {})
        results.append({
            "sha": item["sha"],
            "short_sha": item["sha"][:8],
            "repo": repo,
            "timestamp": c.get("author", {}).get("date", ""),
            "message": c.get("message", "").split("\n")[0],
        })
    return results


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
def get_commit_diff(commit_sha: str, repo: str = "company/payment-svc") -> dict[str, Any]:
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
