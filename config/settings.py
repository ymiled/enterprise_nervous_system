from __future__ import annotations

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")


ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
SLACK_SIGNING_SECRET: str = os.getenv("SLACK_SIGNING_SECRET", "")
SLACK_WEBHOOK_URL: str = os.getenv("SLACK_WEBHOOK_URL", "")  # Incoming webhook for postmortem posts
PAGERDUTY_WEBHOOK_SECRET: str = os.getenv("PAGERDUTY_WEBHOOK_SECRET", "")  # V3 webhook signature secret
API_KEY: str = os.getenv("API_KEY", "")  # If set, required on X-API-Key header for POST /analyze

# MCP server modes
GITHUB_MODE: str = os.getenv("GITHUB_MODE", "mock")
JIRA_MODE: str = os.getenv("JIRA_MODE", "mock")
LOGS_MODE: str = os.getenv("LOGS_MODE", "mock")

# GitHub
GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")
GITHUB_ORG: str = os.getenv("GITHUB_ORG", "company")
GITHUB_API_URL: str = "https://api.github.com"

# Jira
JIRA_URL: str = os.getenv("JIRA_URL", "https://issues.apache.org/jira")
JIRA_TOKEN: str = os.getenv("JIRA_TOKEN", "")
JIRA_EMAIL: str = os.getenv("JIRA_EMAIL", "")

# Elasticsearch (logs live backend)
ES_URL: str   = os.getenv("ES_URL",   "http://localhost:9200")
ES_INDEX: str = os.getenv("ES_INDEX", "ens-logs")

# Seed data paths — overridable per-scenario via env vars (used by benchmark runner)
SEEDS_DIR: Path = Path(__file__).parent.parent / "data" / "seeds"
LOGS_SEED_FILE: Path = Path(os.getenv("LOGS_SEED_FILE", str(SEEDS_DIR / "log4shell_logs.json")))
COMMITS_SEED_FILE: Path = Path(os.getenv("COMMITS_SEED_FILE", str(SEEDS_DIR / "log4shell_commits.json")))
TICKETS_SEED_FILE: Path = Path(os.getenv("TICKETS_SEED_FILE", str(SEEDS_DIR / "log4shell_tickets.json")))

DEFAULT_INCIDENT_SERVICE: str = os.getenv("DEFAULT_INCIDENT_SERVICE", "payment-svc")
DEFAULT_INCIDENT_TIME: str = os.getenv("DEFAULT_INCIDENT_TIME", "2021-12-10T06:15:00Z")
DEFAULT_INCIDENT_SEVERITY: str = os.getenv("DEFAULT_INCIDENT_SEVERITY", "P0")
DEFAULT_JIRA_PROJECT: str = os.getenv("DEFAULT_JIRA_PROJECT", "LOG4J2")

# AG2 LLM config — Groq via OpenAI-compatible endpoint (free tier)
# api_type "openai" + base_url routes through AG2's well-tested OpenAI client,
# which supports function/tool calling that the MCP toolkit registration requires.
LLM_CONFIG: dict = {
    "config_list": [
        {
            "model": "llama-3.3-70b-versatile",
            "api_key": GROQ_API_KEY,
            "api_type": "openai",
            "base_url": "https://api.groq.com/openai/v1",
        }
    ],
    "temperature": 0.0,
    "cache_seed": None,
}
