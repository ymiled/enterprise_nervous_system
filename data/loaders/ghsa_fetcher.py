"""
GitHub Security Advisory (GHSA) Fetcher
-----------------------------------------
Fetches CVE advisories from the GitHub Advisory Database (public structured API)
and writes oracle + seed stub files for use in the benchmark suite.

Usage:
  uv run python data/loaders/ghsa_fetcher.py --ghsa GHSA-jfh8-c2jp-5v3q  # Log4Shell
  uv run python data/loaders/ghsa_fetcher.py --ghsa GHSA-j77q-2qqg-6989  # Struts RCE
  uv run python data/loaders/ghsa_fetcher.py --cve CVE-2022-22965         # Spring4Shell

The fetcher:
  1. Calls https://api.github.com/advisories/{GHSA} (no token required for public)
  2. Extracts CVE ID, severity, affected packages, patched version, fix commit refs
  3. Writes data/oracles/{name}.json (oracle) and a minimal seed stub

This is the structured data-pipeline that backs the benchmark's credibility:
  - GitHub Advisory Database = NIST NVD-reviewed, structured, machine-readable
  - Each advisory links to real fix commits on GitHub
  - Severity, CVSS score, affected ecosystem all verifiable
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import httpx

ROOT   = Path(__file__).parent.parent.parent
ORACLES = ROOT / "data" / "oracles"
SEEDS   = ROOT / "data" / "seeds"

_GHSA_API = "https://api.github.com/advisories/{ghsa}"
_SEARCH   = "https://api.github.com/advisories?type=reviewed&per_page=5&cve_id={cve}"


def _fetch(url: str, token: str | None = None) -> dict:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with httpx.Client(timeout=15) as client:
        resp = client.get(url, headers=headers)
        resp.raise_for_status()
    return resp.json()


def fetch_advisory(ghsa: str | None = None, cve: str | None = None, token: str | None = None) -> dict:
    if ghsa:
        return _fetch(_GHSA_API.format(ghsa=ghsa), token)
    if cve:
        results = _fetch(_SEARCH.format(cve=cve), token)
        if not results:
            raise ValueError(f"No advisory found for {cve}")
        return results[0]
    raise ValueError("Provide --ghsa or --cve")


def extract_oracle(advisory: dict, name: str) -> dict:
    vuln = advisory.get("vulnerabilities", [{}])
    pkg  = vuln[0].get("package", {}) if vuln else {}

    refs_raw = advisory.get("references", [])
    # References may be list[str] or list[{"url": str}]
    refs_urls = [r if isinstance(r, str) else r.get("url", "") for r in refs_raw]
    fix_commits = [u for u in refs_urls if "commit" in u and "github.com" in u]
    fix_commit_sha = fix_commits[0].split("/")[-1][:40] if fix_commits else ""

    return {
        "_source": f"GitHub Advisory Database: {advisory.get('html_url','')}",
        "_ghsa":   advisory.get("ghsa_id", ""),
        "incident": advisory.get("summary", ""),
        "cve_id":  advisory.get("cve_id", ""),
        "severity": advisory.get("severity", ""),
        "ecosystem": pkg.get("ecosystem", ""),
        "package":   pkg.get("name", ""),
        "patched_version": vuln[0].get("patched_versions", "") if vuln else "",
        "primary_fix_commit": {
            "sha": fix_commit_sha,
            "sha_prefix_8": fix_commit_sha[:8] if fix_commit_sha else "",
            "date": advisory.get("published_at", "")[:10],
            "message": f"fix: {advisory.get('summary', '')}",
            "url": fix_commits[0] if fix_commits else "",
        },
        "ticket_ids": [],
        "logger_keywords": [pkg.get("name", "").split(":")[-1] if ":" in pkg.get("name","") else pkg.get("name", "")],
        "root_cause_keywords": _extract_rca_keywords(advisory, refs_urls),
        "references": refs_urls[:5],
    }


def _extract_rca_keywords(advisory: dict, refs_urls: list[str] | None = None) -> list[str]:
    text = (advisory.get("summary", "") + " " + advisory.get("description", "")).lower()
    candidates = ["injection", "rce", "jndi", "deserialization", "ognl", "expression language",
                  "ssrf", "path traversal", "buffer overflow", "sql injection", "xss",
                  "arbitrary code", "remote code execution", "ldap", "multipart", "databinder"]
    return [kw for kw in candidates if kw in text][:3] or ["vulnerability"]


def write_oracle(oracle: dict, name: str) -> Path:
    path = ORACLES / f"{name}.json"
    path.write_text(json.dumps(oracle, indent=2), encoding="utf-8")
    print(f"Oracle written: {path}")
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch GHSA advisory and write oracle file")
    parser.add_argument("--ghsa",  help="GHSA ID, e.g. GHSA-jfh8-c2jp-5v3q")
    parser.add_argument("--cve",   help="CVE ID, e.g. CVE-2021-44228")
    parser.add_argument("--name",  help="Oracle file name (without .json)", required=True)
    parser.add_argument("--token", help="GitHub token (optional, avoids rate limits)")
    args = parser.parse_args()

    print(f"Fetching advisory for {'GHSA: ' + args.ghsa if args.ghsa else 'CVE: ' + args.cve}...")
    advisory = fetch_advisory(ghsa=args.ghsa, cve=args.cve, token=args.token)
    print(f"  GHSA: {advisory.get('ghsa_id')} | CVE: {advisory.get('cve_id')}")
    print(f"  {advisory.get('summary','')[:100]}")

    oracle = extract_oracle(advisory, args.name)
    write_oracle(oracle, args.name)

    print("\nNext steps:")
    print(f"  1. Review data/oracles/{args.name}.json — fill in ticket_ids if known")
    print(f"  2. Create data/seeds/{args.name}_logs.json with realistic log entries")
    print(f"  3. Create data/seeds/{args.name}_commits.json with the fix commit")
    print(f"  4. Create data/seeds/{args.name}_tickets.json with related tickets")
    print(f"  5. Add Scenario to benchmarks/scenarios.py")


if __name__ == "__main__":
    main()
