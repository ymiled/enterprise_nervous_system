"""
Oracle Fetcher
--------------
Fetches ground-truth oracle values for benchmark scenarios from public APIs
and writes them to data/oracles/log4shell.json.

The oracle file is then read by benchmarks/scenarios.py at import time,
so no oracle values are ever hardcoded in the source.

Sources:
  GitHub : apache/logging-log4j2 — CVE-fix commits (Dec 2021)
  JIRA   : issues.apache.org     — LOG4J2-3198, LOG4J2-3201, LOG4J2-3208

What gets extracted:
  commit_sha_prefix   — SHA of the primary JNDI-disable commit
  ticket_ids          — IDs of all CVE-response JIRA tickets
  logger_keywords     — Java class names from the changed files
  root_cause_keywords — keywords derived from ticket summaries/descriptions

Usage:
    uv run python data/loaders/oracle_fetcher.py --token ghp_...

    # Custom output:
    uv run python data/loaders/oracle_fetcher.py --token ghp_... \\
        --out data/oracles/log4shell.json
"""
from __future__ import annotations

import argparse
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

DEFAULT_OUT = Path("data/oracles/log4shell.json")

# Keywords that identify a CVE-fix commit
CVE_KEYWORDS = ["JNDI", "jndi", "3208", "3201", "3198", "3211", "CVE", "Lookup", "lookup"]

# Java class names that appear in Log4j logs when JNDI is involved
LOGGER_CLASS_RE = re.compile(
    r"(JndiManager|JndiLookup|JndiContextSelector|MessagePatternConverter|Interpolator)"
)

# Words to extract from JIRA summaries/descriptions as root-cause keywords
ROOT_CAUSE_RE = re.compile(
    r"\b(jndi|ldap|lookup|exploit|rce|remote\s+code|cve-2021-44228)\b",
    re.IGNORECASE,
)

_TOKEN: str | None = None


def _gh_headers() -> dict[str, str]:
    h = {"Accept": "application/vnd.github+json"}
    if _TOKEN:
        h["Authorization"] = f"Bearer {_TOKEN}"
    return h


# GitHub

def _fetch_cve_commits(client: httpx.Client) -> list[dict]:
    """Return all commits in the fix window that touch JNDI-related code."""
    print(f"Fetching commits from {REPO} ({COMMITS_SINCE[:10]} to {COMMITS_UNTIL[:10]})...")
    page, raw = 1, []
    while True:
        resp = client.get(
            f"{GITHUB_API}/repos/{REPO}/commits",
            headers=_gh_headers(),
            params={"since": COMMITS_SINCE, "until": COMMITS_UNTIL,
                    "per_page": 100, "page": page},
        )
        resp.raise_for_status()
        batch = resp.json()
        if not batch:
            break
        raw.extend(batch)
        page += 1
        time.sleep(0.3)

    print(f"  {len(raw)} commits total — filtering CVE-fix commits...")
    fix_commits = []
    for c in raw:
        msg = c["commit"]["message"]
        if any(kw in msg for kw in CVE_KEYWORDS):
            fix_commits.append(c)

    print(f"  {len(fix_commits)} CVE-fix commits found")
    return fix_commits


def _fetch_commit_detail(client: httpx.Client, sha: str) -> dict:
    resp = client.get(
        f"{GITHUB_API}/repos/{REPO}/commits/{sha}",
        headers=_gh_headers(),
    )
    resp.raise_for_status()
    return resp.json()


def _primary_fix_commit(client: httpx.Client, fix_commits: list[dict]) -> dict:
    """
    Pick the single most important fix commit to use as the SHA oracle.
    Priority: commit whose message contains '3208' (Disable JNDI by default)
    — the broadest security fix. Falls back to the earliest fix commit.
    """
    for c in fix_commits:
        if "3208" in c["commit"]["message"]:
            return c
    # fallback: earliest
    return sorted(fix_commits, key=lambda c: c["commit"]["author"]["date"])[0]


def _extract_logger_keywords(detail: dict) -> list[str]:
    """Extract Java class names from the files changed in a commit."""
    keywords: list[str] = []
    for f in detail.get("files", []):
        filename = f["filename"]
        # e.g. log4j-core/.../JndiManager.java -> JndiManager
        stem = Path(filename).stem
        if LOGGER_CLASS_RE.match(stem):
            keywords.append(stem)
        patch = f.get("patch", "")
        for m in LOGGER_CLASS_RE.finditer(patch):
            kw = m.group(1)
            if kw not in keywords:
                keywords.append(kw)
    return keywords


# JIRA 

def _fetch_ticket(client: httpx.Client, ticket_id: str) -> dict:
    print(f"  Fetching {ticket_id}...")
    resp = client.get(
        f"{JIRA_API}/issue/{ticket_id}",
        params={"fields": "summary,status,priority,created,description,fixVersions"},
    )
    resp.raise_for_status()
    raw    = resp.json()
    fields = raw["fields"]
    return {
        "id":          ticket_id,
        "summary":     fields.get("summary", ""),
        "status":      fields.get("status", {}).get("name", ""),
        "priority":    fields.get("priority", {}).get("name", ""),
        "created":     (fields.get("created") or "")[:10],
        "fix_version": [v["name"] for v in fields.get("fixVersions", [])],
        "description": (fields.get("description") or "")[:400],
    }


def _extract_root_cause_keywords(tickets: list[dict]) -> list[str]:
    """Pull root-cause keywords from ticket summaries and descriptions."""
    seen: set[str] = set()
    keywords: list[str] = []
    for t in tickets:
        text = t["summary"] + " " + t["description"]
        for m in ROOT_CAUSE_RE.finditer(text):
            kw = m.group(1).lower().replace(" ", "_")
            if kw not in seen:
                seen.add(kw)
                keywords.append(kw)
    return keywords




def main() -> None:
    global _TOKEN

    parser = argparse.ArgumentParser(description="Fetch oracle values for Log4Shell benchmark scenarios")
    parser.add_argument("--token", default=os.getenv("GITHUB_TOKEN"),
                        help="GitHub token (or set GITHUB_TOKEN env var)")
    parser.add_argument("--out",   type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    _TOKEN = args.token
    if _TOKEN:
        print(f"GitHub token: {_TOKEN[:8]}...")
    else:
        print("[WARN] No token — rate-limited to 60 req/hr. Pass --token ghp_...")

    args.out.parent.mkdir(parents=True, exist_ok=True)

    with httpx.Client(timeout=30.0) as client:
        # 1. Commits
        try:
            fix_commits = _fetch_cve_commits(client)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                print("\n[ERROR] GitHub rate limit. Pass --token ghp_...\n")
                sys.exit(1)
            raise

        primary = _primary_fix_commit(client, fix_commits)
        sha      = primary["sha"]
        print(f"\nPrimary fix commit: {sha[:12]}  {primary['commit']['author']['date'][:10]}")
        print(f"  {primary['commit']['message'][:80]}")

        detail          = _fetch_commit_detail(client, sha)
        logger_keywords = _extract_logger_keywords(detail)

        all_fix_shas = [
            {"sha": c["sha"], "sha_short": c["sha"][:12],
             "date": c["commit"]["author"]["date"][:10],
             "message": c["commit"]["message"][:80]}
            for c in sorted(fix_commits, key=lambda c: c["commit"]["author"]["date"])
        ]

        # 2. JIRA tickets
        print("\nFetching JIRA tickets...")
        tickets = []
        for tid in TICKET_IDS:
            tickets.append(_fetch_ticket(client, tid))
            time.sleep(0.3)

        root_cause_keywords = _extract_root_cause_keywords(tickets)

    # 3. Build oracle document
    oracle = {
        "_comment": (
            "Auto-generated by data/loaders/oracle_fetcher.py. "
            "All values sourced from apache/logging-log4j2 GitHub and Apache JIRA."
        ),
        "incident": "CVE-2021-44228 (Log4Shell)",
        "primary_fix_commit": {
            "sha":       sha,
            "sha_short": sha[:12],
            "sha_prefix_8": sha[:8],
            "date":      primary["commit"]["author"]["date"][:10],
            "message":   primary["commit"]["message"][:120],
            "url":       f"https://github.com/{REPO}/commit/{sha}",
        },
        "all_fix_commits": all_fix_shas,
        "ticket_ids":            [t["id"] for t in tickets],
        "tickets":               tickets,
        "logger_keywords":       logger_keywords if logger_keywords else ["JndiManager", "JndiLookup"],
        "root_cause_keywords":   root_cause_keywords,
    }

    args.out.write_text(json.dumps(oracle, indent=2), encoding="utf-8")
    print(f"\nOracle written -> {args.out}")
    print(f"  commit_sha_prefix : {sha[:8]}")
    print(f"  ticket_ids        : {oracle['ticket_ids']}")
    print(f"  logger_keywords   : {oracle['logger_keywords']}")
    print(f"  root_cause_kws    : {oracle['root_cause_keywords']}")


if __name__ == "__main__":
    main()
