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
│   ├── logs_mcp.py              # Tools: query_logs, get_error_spike, get_trace
│   ├── github_mcp.py            # Tools: get_recent_commits, get_commit_diff, search_commits_by_keyword
│   └── jira_mcp.py              # Tools: get_recent_tickets, get_ticket, search_tickets
├── agents/
│   └── prompts.py               # System prompts for DevOps, SWE, PM, Critic agents
├── swarm/
│   └── orchestrator.py          # AG2 MCPClientSessionManager wiring + Critic agent
├── schemas/
│   └── postmortem.py            # Pydantic PostMortem output contract
├── config/
│   └── settings.py              # Env config, governor rules, seed paths
├── data/
│   ├── seeds/                   # Synthetic + real-incident seed JSON (committed)
│   │   ├── log4shell_*.json     # Log4Shell CVE-2021-44228 (synthetic)
│   │   ├── oom_*.json           # OOM unbounded cache (synthetic)
│   │   ├── config_error_*.json  # Redis misconfiguration (synthetic)
│   │   ├── cloudflare_2019_*.json  # Cloudflare WAF outage (real)
│   │   ├── github_2018_*.json      # GitHub MySQL failover (real)
│   │   └── fastly_2021_*.json      # Fastly VCL compiler bug (real)
│   ├── loaders/
│   │   └── hdfs_loader.py       # Converts LogHub HDFS_v1 dataset → seed JSON
│   └── raw/                     # Large downloaded datasets (git-ignored)
├── benchmarks/
│   ├── scenarios.py             # 20 synthetic scenarios (Scenario dataclass)
│   ├── evaluator.py             # 6 deterministic metrics (EvalResult)
│   ├── runner.py                # Benchmark runner for synthetic scenarios
│   ├── scenarios.py        # 12 real-incident scenarios (RealScenario dataclass)
│   ├── evaluator.py        # Keyword-based metrics for real incidents
│   ├── runner.py           # Runner for real + combined (32) scenarios
│   └── results/                 # JSON output files (git-ignored)
└── tests/
    └── test_mcp_servers.py      # Smoke tests for all 9 MCP tools
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

## Benchmark Suite

The benchmark evaluates the swarm on **28 scenarios** across two tiers:

### Tier 1 — Synthetic (20 scenarios)
Hand-crafted scenarios with real SHA-prefix ground-truth oracles:
- **12 Log4Shell variants** — commits/tickets from real `apache/logging-log4j2` repo + Apache JIRA
- **4 OOM variants** — unbounded HashMap in order-svc
- **4 Config error variants** — auth-svc pointing at wrong Redis endpoint

### Tier 2 — Real labeled datasets (8 scenarios, download required)
Ground truth from publicly available HPC cluster logs with anomaly labels:

| ID | Dataset | Source |
|---|---|---|
| `bgl-01..04` | **BGL** — IBM Blue Gene/L supercomputer at LLNL. Real RAS failure logs with node-level anomaly labels. | [LogHub / Zenodo](https://zenodo.org/records/8196385) |
| `tb-01..04` | **Thunderbird** — Sandia National Lab Thunderbird HPC cluster. 211M lines, node DOWN/FAIL labels. | [LogHub / Zenodo](https://zenodo.org/records/8196385) |

### Evaluation Metrics (6 dimensions)

| Metric | What it measures | Full credit |
|---|---|---|
| **RCA accuracy** | Root cause correctly identified | All oracle keywords in `root_cause` |
| **Evidence quality** | Logs + commits + tickets all cited | All 3 evidence types present |
| **Actionability** | Actions tied to tracked tickets | ≥1 recommended action has a valid `ticket_id` |
| **Reliability** | Swarm completed without crash | Run did not raise an exception |
| **PII compliance** | No emails or usernames in output | Zero regex matches on PII patterns |
| **Citation integrity** | Evidence traceable to source | Log entry + ticket + logger keyword cited |

Overall score = `mean(6 metrics)`.

### Running benchmarks

```bash
# Run all 8 real scenarios 
uv run python benchmarks/runner.py

# Save results to custom path
uv run python benchmarks/runner.py --output benchmarks/results/my_run.json
```

---

## Labelled Dataset — LogHub HDFS

The project includes a loader for the [LogHub HDFS_v1](https://github.com/logpai/loghub) dataset — 11M real HDFS log lines with block-level anomaly labels. This enables benchmarking on genuinely labelled production data beyond the manually-seeded scenarios.

**Download the dataset (~500 MB compressed):**
```bash
curl -L -o HDFS_v1.tar.gz https://zenodo.org/records/8196385/files/HDFS_v1.tar.gz
tar -xzf HDFS_v1.tar.gz -C data/raw/hdfs/
```

**Convert to seed JSON (200 entries, 75% anomaly / 25% normal):**
```bash
uv run python data/loaders/hdfs_loader.py \
    --hdfs-log  data/raw/hdfs/HDFS_v1/HDFS.log \
    --labels    data/raw/hdfs/HDFS_v1/anomaly_label.csv \
    --output    data/seeds/hdfs_anomaly_logs.json \
    --sample    200
```

The loader strips PII-adjacent fields, annotates each entry with anomaly status, balances the sample, and outputs the project's standard seed JSON schema.

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
- [x] OOM + Config error seed scenarios
- [x] AG2 agent prompts (DevOps, SWE, PM, Critic)
- [x] AG2 swarm orchestrator with MCP wiring
- [x] Smoke tests for all 9 MCP tools
- [x] 20-scenario synthetic benchmark suite with real oracle SHAs (apache/logging-log4j2 + Apache JIRA)
- [x] 8-scenario real-dataset benchmark tier (LogHub BGL + Thunderbird)
- [x] LogHub HDFS_v1 data loader (11M log entries, block-level labels)
- [x] LogHub BGL data loader (Blue Gene/L supercomputer failure logs)
- [x] LogHub Thunderbird data loader (Sandia NL HPC, 211M lines)
- [ ] CLI entrypoint `python -m ens diagnose --service payment-svc --since 2h`
- [ ] Integration test — run full swarm against seed data, assert PostMortem fields
