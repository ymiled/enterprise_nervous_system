# Enterprise Nervous System
### Cross-silo incident resolution swarm

An autonomous root-cause analysis system that queries GitHub, Jira, and application logs in parallel to debug production incidents, without a human jumping between tabs.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Incident Trigger                     │
│              (service name + timestamp + severity)          │
└──────────────────────────┬──────────────────────────────────┘
                           │
              ┌────────────▼────────────┐
              │     AG2 Orchestrator    │  ← swarm/orchestrator.py
              │   (MCPClientSession     │
              │      Manager)           │
              └──┬──────────┬───────────┘
                 │          │           │
    ┌────────────▼─┐  ┌─────▼──────┐  ┌▼────────────┐
    │  DevOps Agent│  │  SWE Agent │  │   PM Agent  │
    │  (logs MCP)  │  │(github MCP)│  │ (jira MCP)  │
    └──────┬───────┘  └─────┬──────┘  └──────┬──────┘
           │                │                │
    ┌──────▼───────┐  ┌─────▼──────┐  ┌──────▼──────┐
    │  logs_mcp.py │  │github_mcp  │  │  jira_mcp   │
    │  (ELK/mock)  │  │ .py (API)  │  │  .py (API)  │
    └──────────────┘  └────────────┘  └─────────────┘
                           │
              ┌────────────▼────────────┐
              │    AG2 Critic Agent     │  ← swarm/orchestrator.py
              │  (PII check, citation   │
              │   enforcement, rules)   │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │   PostMortem (JSON)     │  ← schemas/postmortem.py
              │  validated by Pydantic  │
              └─────────────────────────┘
```

**Stack:**
| Layer | Technology | Role |
|---|---|---|
| Connectors | [FastMCP](https://github.com/jlowin/fastmcp) | Secure, scoped data access |
| Swarm | [AG2](https://ag2.ai) | Multi-agent debate, orchestration & output enforcement |
| Schema | Pydantic v2 | Post-mortem contract enforcement |

---

## Project Structure

```
enterprise_nervous_system/
├── mcp_servers/
│   ├── logs_mcp.py          # Tools: query_logs, get_error_spike, get_trace
│   ├── github_mcp.py        # Tools: get_recent_commits, get_commit_diff, search_commits_by_keyword
│   └── jira_mcp.py          # Tools: get_recent_tickets, get_ticket, search_tickets
├── agents/                  # AG2 agent definitions (DevOps, SWE, PM, Critic)
├── swarm/
│   └── orchestrator.py      # AG2 MCPClientSessionManager wiring + Critic agent
├── schemas/
│   └── postmortem.py        # Pydantic PostMortem output contract
├── config/
│   └── settings.py          # Env config, governor rules, seed paths
├── data/seeds/
│   ├── log4shell_logs.json  # 12 realistic log entries (JNDI attack pattern)
│   ├── log4shell_commits.json  # 5 commits: vulnerable upgrade → hotfix
│   └── log4shell_tickets.json  # 5 Jira tickets: warning → remediation
└── tests/
```

---

## Quickstart

**1. Install dependencies**
```bash
uv sync          # installs all runtime deps into .venv automatically
uv sync --extra dev  # also installs pytest
```

**2. Configure environment**
```bash
cp .env.example .env
# Edit .env — at minimum set ANTHROPIC_API_KEY
```

**3. Inspect MCP servers interactively (MCP Inspector UI)**
```bash
# Opens a browser-based playground to call tools manually and see raw responses
uv run fastmcp dev inspector mcp_servers/logs_mcp.py
uv run fastmcp dev inspector mcp_servers/github_mcp.py
uv run fastmcp dev inspector mcp_servers/jira_mcp.py
```
Navigate to `http://localhost:5173` — you can invoke any tool and inspect the JSON output before wiring agents.

**4. Run each MCP server as a standalone stdio process**
```bash
# Useful for manual testing or connecting external MCP clients
uv run python mcp_servers/logs_mcp.py
uv run python mcp_servers/github_mcp.py
uv run python mcp_servers/jira_mcp.py
```

**5. Run the MCP unit tests**
```bash
uv run pytest tests/test_mcp_servers.py -v
```

**6. Run the full swarm against the Log4Shell scenario**
```bash
uv run python swarm/orchestrator.py
# with explicit args:
uv run python swarm/orchestrator.py --service payment-svc --since 2021-12-10T06:15:00Z --severity P0
# write output to file:
uv run python swarm/orchestrator.py --output postmortem.json
```

---

## Test Scenario — Log4Shell (CVE-2021-44228)

The seed data encodes the complete causal chain of a real-world incident:

| Time (UTC) | Event |
|---|---|
| 2021-11-28 14:32 | Commit `a3b4c5d6` upgrades `log4j-core` 2.13.3 → **2.14.1** (PR-2847) |
| 2021-12-01 09:15 | Commit `b9c8d7e6` adds MDC logging of user-controlled HTTP headers |
| 2021-12-08 10:00 | Ticket **PAY-441** flags suspicious JNDI outbound traffic |
| 2021-12-10 06:14 | First JNDI exploit attempt logged in `payment-svc` |
| 2021-12-10 06:15 | Error spike — 42 HTTP 500s/min, JVM crash on pod-02 |
| 2021-12-10 08:30 | Hotfix commit `e7f8a9b0` applies `-Dlog4j2.formatMsgNoLookups=true` |

**Expected RCA output:** The swarm should identify commit `a3b4c5d6` as root cause, cite ticket `PAY-441` as prior warning, and recommend upgrade to `log4j-core 2.15.0` tracked in `PAY-442`.

---

## MCP Server Reference

### logs_mcp.py
| Tool | Args | Returns |
|---|---|---|
| `query_logs` | `service`, `severity`, `time_range_hours` | Filtered log entries, PII-scrubbed |
| `get_error_spike` | `service`, `window_minutes` | Error rate analysis + spike detection |
| `get_trace` | `trace_id` | All spans for a distributed trace |

### github_mcp.py
| Tool | Args | Returns |
|---|---|---|
| `get_recent_commits` | `repo`, `hours_back` | Commits in window, author identity scrubbed |
| `get_commit_diff` | `commit_sha`, `repo` | Diff summary + files changed |
| `search_commits_by_keyword` | `repo`, `keyword`, `hours_back` | Keyword-matched commits |

### jira_mcp.py
| Tool | Args | Returns |
|---|---|---|
| `get_recent_tickets` | `project`, `hours_back` | Tickets sorted by priority |
| `get_ticket` | `ticket_id` | Full ticket detail, reporter/assignee scrubbed |
| `search_tickets` | `query`, `project` | Full-text search results |

All tools operate in `mock` mode by default (seed data, no external calls).
Set `GITHUB_MODE=live`, `JIRA_MODE=live` in `.env` to hit real APIs.

---

## Critic Agent Rules

The AG2 Critic agent enforces these constraints before emitting the PostMortem:

1. `root_cause` **must** cite an exact Git commit SHA (≥7 chars).
2. `root_cause` **must** cite a logger name or trace ID from the logs.
3. Every `recommended_action` **must** include a Jira `ticket_id`.
4. Output **must not** contain real names, emails, or usernames — team names only.
5. If `confidence_score < 0.7`, set `inconclusive=true` with a reason.
6. Never speculate beyond what the three specialist agents found.

---

## Roadmap

- [x] MCP servers — logs, GitHub, Jira (mock + live modes)
- [x] Pydantic PostMortem schema
- [x] Log4Shell seed data (logs, commits, tickets)
- [x] AG2 agent prompts (DevOps, SWE, PM, Critic)
- [x] AG2 swarm orchestrator with MCP wiring
- [x] Smoke tests for all MCP tools
- [ ] CLI entrypoint `python -m ens diagnose --service payment-svc --since 2h`
- [ ] Integration test — run full swarm against seed data, assert PostMortem fields
