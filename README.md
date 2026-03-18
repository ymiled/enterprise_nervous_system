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
              │    BeeAI Governor       │  ← governor/beeai_governor.py
              │  (deterministic rules,  │
              │   PII strip, schema     │
              │   enforcement)          │
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
| Swarm | [AG2](https://ag2.ai) | Multi-agent debate & orchestration |
| Governor | [BeeAI](https://github.com/i-am-bee/bee-agent-framework) | Deterministic output rules |
| Schema | Pydantic v2 | Post-mortem contract enforcement |

---

## Project Structure

```
enterprise_nervous_system/
├── mcp_servers/
│   ├── logs_mcp.py          # Tools: query_logs, get_error_spike, get_trace
│   ├── github_mcp.py        # Tools: get_recent_commits, get_commit_diff, search_commits_by_keyword
│   └── jira_mcp.py          # Tools: get_recent_tickets, get_ticket, search_tickets
├── agents/                  # AG2 agent definitions (DevOps, SWE, PM)
├── swarm/
│   └── orchestrator.py      # AG2 MCPClientSessionManager wiring
├── governor/
│   └── beeai_governor.py    # BeeAI rules engine
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
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

**2. Configure environment**
```bash
cp .env.example .env
# Edit .env — at minimum set ANTHROPIC_API_KEY
```

**3. Smoke-test each MCP server standalone**
```bash
# Logs
python mcp_servers/logs_mcp.py

# GitHub (mock mode, no token needed)
python mcp_servers/github_mcp.py

# Jira (mock mode, no token needed)
python mcp_servers/jira_mcp.py
```

**4. Run the full swarm against the Log4Shell scenario**
```bash
python swarm/orchestrator.py
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
