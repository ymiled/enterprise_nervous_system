"""
Log4Shell Real Data Fetcher
---------------------------
Fetches real commits, JIRA tickets, and log samples for CVE-2021-44228
(Log4Shell) from public APIs and writes them as seed JSON files used by
the MCP servers.

Sources:
  Commits : https://github.com/apache/logging-log4j2  (public, no auth needed)
  JIRA    : https://issues.apache.org/jira             (public Apache JIRA)
  Logs    : Issues/comments from two public GitHub repos that contain real
            log output showing JNDI attack patterns and Log4j responses:
              - christophetd/log4shell-vulnerable-app
              - apache/logging-log4j2

Tickets fetched:
  LOG4J2-3198  Message lookups should be disabled by default   (fix: 2.15.0)
  LOG4J2-3201  Limit the protocols JNDI can use                (fix: 2.15.0)
  LOG4J2-3208  Disable JNDI by default                         (fix: 2.16.0)

Usage:
    uv run python data/loaders/log4shell_fetcher.py --token ghp_...

    # Custom output paths:
    uv run python data/loaders/log4shell_fetcher.py --token ghp_... \\
        --commits-out data/seeds/log4shell_commits.json \\
        --tickets-out data/seeds/log4shell_tickets.json \\
        --logs-out    data/seeds/log4shell_logs.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

import httpx

GITHUB_API    = "https://api.github.com"
JIRA_API      = "https://issues.apache.org/jira/rest/api/2"
REPO          = "apache/logging-log4j2"
COMMITS_SINCE = "2021-12-01T00:00:00Z"
COMMITS_UNTIL = "2021-12-15T00:00:00Z"
TICKET_IDS    = ["LOG4J2-3198", "LOG4J2-3201", "LOG4J2-3208"]

# Repos mined for real log output in issues/comments
LOG_SOURCE_REPOS = [
    "christophetd/log4shell-vulnerable-app",
    "apache/logging-log4j2",
]

DEFAULT_COMMITS_OUT = Path("data/seeds/log4shell_commits.json")
DEFAULT_TICKETS_OUT = Path("data/seeds/log4shell_tickets.json")
DEFAULT_LOGS_OUT    = Path("data/seeds/log4shell_logs.json")

# Patterns that identify a line as real log output containing JNDI activity
_LOG_LINE_RE = re.compile(
    r"(\$\{jndi:)"                              # JNDI payload in user input
    r"|JndiManager"                             # Log4j JNDI manager class
    r"|JndiLookup"                              # Log4j JNDI lookup class
    r"|log4j\.core\.net\.Jndi"                 # fully-qualified log4j class
    r"|ldap://\S+"                              # raw LDAP URI
    r"|Invalid JNDI"                            # log4j warning message
    r"|JNDI lookup"                             # generic JNDI log phrase
    r"|log4j2?\.enableJndi"                     # system property log line
    r"|org\.apache\.logging\.log4j\S+Exception" # log4j exception in stack trace
)

# Patterns that hint at log level + logger — used to infer structured fields
_LEVEL_RE   = re.compile(r"\b(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\b")
_LOGGER_RE  = re.compile(r"(org\.apache\.logging\.log4j[\w.$]+|"
                         r"com\.example[\w.$]+|"
                         r"JndiManager|JndiLookup)")

# GitHub token — set by main() from --token arg or GITHUB_TOKEN env var
_TOKEN: str | None = None


# GitHub helpers

def _github_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    if _TOKEN:
        headers["Authorization"] = f"Bearer {_TOKEN}"
    return headers


def fetch_commits(client: httpx.Client) -> list[dict]:
    """
    Page through commits on apache/logging-log4j2 between Dec 1-15 2021
    and fetch the full diff for each one. Returns a list in our seed schema.
    """
    print(f"Fetching commits from {REPO} ({COMMITS_SINCE[:10]} to {COMMITS_UNTIL[:10]})...")

    page, commits_raw = 1, []
    while True:
        resp = client.get(
            f"{GITHUB_API}/repos/{REPO}/commits",
            headers=_github_headers(),
            params={
                "since":    COMMITS_SINCE,
                "until":    COMMITS_UNTIL,
                "per_page": 100,
                "page":     page,
            },
        )
        resp.raise_for_status()
        batch = resp.json()
        if not batch:
            break
        commits_raw.extend(batch)
        print(f"  page {page}: {len(batch)} commits")
        page += 1
        time.sleep(0.3)

    print(f"  total: {len(commits_raw)} commits — fetching diffs...")

    results = []
    for i, c in enumerate(commits_raw, 1):
        sha  = c["sha"]
        resp = client.get(
            f"{GITHUB_API}/repos/{REPO}/commits/{sha}",
            headers=_github_headers(),
        )
        resp.raise_for_status()
        detail = resp.json()

        files_changed = [f["filename"] for f in detail.get("files", [])]

        # Concatenate patches — truncate large diffs so the seed stays readable
        diff_parts = []
        for f in detail.get("files", []):
            patch = f.get("patch", "")
            if patch:
                diff_parts.append(f"--- {f['filename']}\n{patch[:800]}")
        diff = "\n\n".join(diff_parts)[:4000]

        results.append({
            "sha":           sha,
            "sha_short":     sha[:12],
            "message":       detail["commit"]["message"],
            "author":        detail["commit"]["author"]["name"],
            "date":          detail["commit"]["author"]["date"],
            "files_changed": files_changed,
            "diff":          diff,
            "url":           detail["html_url"],
        })

        if i % 10 == 0:
            print(f"  {i}/{len(commits_raw)} diffs fetched")
        time.sleep(0.2)

    results.sort(key=lambda r: r["date"])
    return results


# JIRA helpers

def fetch_ticket(client: httpx.Client, ticket_id: str) -> dict:
    """Fetch a single Apache JIRA ticket and return it in our seed schema."""
    print(f"  Fetching {ticket_id}...")
    resp = client.get(
        f"{JIRA_API}/issue/{ticket_id}",
        params={"fields": "summary,status,priority,created,description,fixVersions,reporter,comment"},
    )
    resp.raise_for_status()
    raw    = resp.json()
    fields = raw["fields"]

    fix_versions = [v["name"] for v in fields.get("fixVersions", [])]

    comments = []
    for c in fields.get("comment", {}).get("comments", [])[:5]:
        body = c.get("body", "").strip()[:300]
        if body:
            comments.append(body)

    description = (fields.get("description") or "").strip()[:600]

    return {
        "id":           ticket_id,
        "title":        fields.get("summary", ""),
        "status":       fields.get("status", {}).get("name", ""),
        "priority":     fields.get("priority", {}).get("name", ""),
        "created":      fields.get("created", "")[:10],
        "fix_versions": fix_versions,
        "reporter":     (fields.get("reporter") or {}).get("displayName", ""),
        "description":  description,
        "comments":     comments,
        "url":          f"https://issues.apache.org/jira/browse/{ticket_id}",
        "labels":       ["log4shell", "cve-2021-44228", "jndi", "security"],
    }


def fetch_tickets(client: httpx.Client) -> list[dict]:
    print(f"Fetching JIRA tickets: {', '.join(TICKET_IDS)}...")
    tickets = []
    for tid in TICKET_IDS:
        tickets.append(fetch_ticket(client, tid))
        time.sleep(0.3)
    return tickets


# Log helpers

def _extract_log_lines(text: str) -> list[str]:
    """Return lines from raw issue/comment text that look like real log output."""
    results = []
    for line in text.splitlines():
        line = line.strip()
        if len(line) < 20:
            continue
        if _LOG_LINE_RE.search(line):
            results.append(line[:400])
    return results


def _line_to_entry(line: str, seq: int, source_url: str) -> dict:
    """Convert a raw log line extracted from a GitHub issue into our seed schema."""
    level_match  = _LEVEL_RE.search(line)
    logger_match = _LOGGER_RE.search(line)

    level  = level_match.group(1)  if level_match  else "WARN"
    logger = logger_match.group(1) if logger_match else "org.apache.logging.log4j.core.net.JndiManager"

    uid = hashlib.md5(line.encode()).hexdigest()[:8]

    return {
        "id":         f"ls-real-{seq:04d}-{uid}",
        "timestamp":  "2021-12-10T03:14:59Z",
        "service":    "payment-svc",
        "level":      level,
        "trace_id":   f"t-ls-{seq:04d}",
        "logger":     logger,
        "message":    line,
        "env":        "production",
        "source_url": source_url,
    }


def _fetch_issue_texts(client: httpx.Client, repo: str) -> list[tuple[str, str]]:
    """Collect (text, url) pairs from issues and comments in a repo (Nov 2021 – Feb 2022)."""
    print(f"  Scanning issues in {repo}...")
    texts: list[tuple[str, str]] = []
    page = 1
    while True:
        resp = client.get(
            f"{GITHUB_API}/repos/{repo}/issues",
            headers=_github_headers(),
            params={"state": "all", "since": "2021-11-01T00:00:00Z",
                    "per_page": 100, "page": page},
        )
        resp.raise_for_status()
        issues = resp.json()
        if not issues:
            break
        for issue in issues:
            if issue.get("created_at", "") > "2022-02-01":
                continue
            url = issue.get("html_url", "")
            if issue.get("body"):
                texts.append((issue["body"], url))
            if issue.get("comments", 0) > 0:
                c_resp = client.get(issue["comments_url"], headers=_github_headers(),
                                    params={"per_page": 50})
                if c_resp.status_code == 200:
                    for c in c_resp.json():
                        if c.get("body"):
                            texts.append((c["body"], url))
                time.sleep(0.15)
        page += 1
        time.sleep(0.3)
    print(f"    {len(texts)} bodies collected from {repo}")
    return texts


def fetch_logs(client: httpx.Client) -> list[dict]:
    """
    Mine real JNDI-related log lines from issues/comments in LOG_SOURCE_REPOS.
    Returns entries in the project's log seed schema.
    """
    print("Fetching log samples from GitHub issue/comment bodies...")
    all_lines: list[tuple[str, str]] = []
    seen: set[str] = set()

    for repo in LOG_SOURCE_REPOS:
        try:
            texts = _fetch_issue_texts(client, repo)
        except httpx.HTTPStatusError as e:
            print(f"  [WARN] Could not fetch {repo}: {e.response.status_code}")
            continue
        for body, url in texts:
            for line in _extract_log_lines(body):
                if line not in seen:
                    seen.add(line)
                    all_lines.append((line, url))

    print(f"  {len(all_lines)} unique log lines extracted")
    return [_line_to_entry(line, i, url) for i, (line, url) in enumerate(all_lines, 1)]


# Main

def _rate_limit_error() -> None:
    print(
        "\n[ERROR] GitHub rate limit hit. Pass your token with --token:\n"
        "  uv run python data/loaders/log4shell_fetcher.py --token ghp_...\n"
    )
    sys.exit(1)


def main() -> None:
    global _TOKEN

    parser = argparse.ArgumentParser(description="Fetch real Log4Shell data from public APIs")
    parser.add_argument("--token",       default=os.getenv("GITHUB_TOKEN"),
                        help="GitHub personal access token (or set GITHUB_TOKEN env var)")
    parser.add_argument("--commits-out", type=Path, default=DEFAULT_COMMITS_OUT)
    parser.add_argument("--tickets-out", type=Path, default=DEFAULT_TICKETS_OUT)
    parser.add_argument("--logs-out",    type=Path, default=DEFAULT_LOGS_OUT)
    args = parser.parse_args()

    _TOKEN = args.token
    if _TOKEN:
        print(f"Using GitHub token: {_TOKEN[:8]}...")
    else:
        print("[WARN] No token — rate-limited to 60 req/hr. Pass --token ghp_...")

    for p in (args.commits_out, args.tickets_out, args.logs_out):
        p.parent.mkdir(parents=True, exist_ok=True)

    with httpx.Client(timeout=30.0) as client:
        # Commits
        try:
            commits = fetch_commits(client)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                _rate_limit_error()
            raise
        args.commits_out.write_text(json.dumps(commits, indent=2), encoding="utf-8")
        print(f"\nWrote {len(commits)} commits -> {args.commits_out}")

        # JIRA tickets
        try:
            tickets = fetch_tickets(client)
        except httpx.HTTPStatusError as e:
            print(f"\n[ERROR] JIRA fetch failed: {e.response.status_code} {e.response.text[:200]}")
            sys.exit(1)
        args.tickets_out.write_text(json.dumps(tickets, indent=2), encoding="utf-8")
        print(f"Wrote {len(tickets)} tickets -> {args.tickets_out}")

        # Logs
        try:
            logs = fetch_logs(client)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                _rate_limit_error()
            raise
        args.logs_out.write_text(json.dumps(logs, indent=2), encoding="utf-8")
        print(f"Wrote {len(logs)} log entries -> {args.logs_out}")

    print("\nKey CVE fix commits (use sha_short as oracle in benchmarks/scenarios.py):")
    key_keywords = ["JNDI", "Lookup", "3208", "3201", "3198", "3211", "CVE"]
    for c in commits:
        if any(kw in c["message"] for kw in key_keywords):
            print(f"  {c['sha_short']}  {c['date'][:10]}  {c['message'][:80]}")

    print("\nDone. Update expected_commit_sha_prefix in benchmarks/scenarios.py with a SHA above.")


if __name__ == "__main__":
    main()
