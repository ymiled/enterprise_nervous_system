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

## Quickstart


**1. Install dependencies**
```bash
uv sync          # installs all runtime deps into .venv automatically
uv sync --extra dev  # also installs pytest (optional, for development/testing)
```

**2. Configure environment**
```bash
cp .env.example .env
# Edit .env — at minimum set ANTHROPIC_API_KEY
```

**3. Inspect MCP servers interactively** (optional, for manual exploration/debugging)
```bash
# Opens a browser-based playground to call tools manually and see raw responses
uv run fastmcp dev inspector mcp_servers/logs_mcp.py
uv run fastmcp dev inspector mcp_servers/github_mcp.py
uv run fastmcp dev inspector mcp_servers/jira_mcp.py
```
Navigate to `http://localhost:5173` — you can invoke any tool and inspect the JSON output before wiring agents.

**4. Run each MCP server as a standalone stdio process** (optional, for manual testing or connecting external MCP clients)
```bash
uv run python mcp_servers/logs_mcp.py
uv run python mcp_servers/github_mcp.py
uv run python mcp_servers/jira_mcp.py
```

**5. Run the full swarm against the Log4Shell scenario**
```bash
uv run python swarm/orchestrator.py
# with explicit args:
uv run python swarm/orchestrator.py --service payment-svc --since 2021-12-10T06:15:00Z --severity P0
# write output to file:
uv run python swarm/orchestrator.py --output postmortem.json
```

---

## Benchmark Suite

The benchmark evaluates the swarm on **31 scenarios** across 5 incident families, covering CVE exploits, infra failures, config drift, and negative controls.

### Benchmark results

| Group        | Median Overall Score | Median Det. Score | Median Time (s) |
|--------------|----------------------|-------------------|-----------------|
| Log4Shell    | 0.748                | 0.82              | 19.4            |
| Text4Shell   | 0.905                | 0.94              | 17.25           |
| Negative     | 0.810                | 0.89              | 21.9            |
| OOM          | 0.810                | 0.945             | 7.8             |
| BadDeploy    | 0.952                | 0.945             | 8.9             |
| Deadlock     | 0.810                | 0.86              | 6.2             |
| DepFail      | 0.810                | 0.945             | 6.8             |
| RateLimit    | 0.810                | 0.945             | 6.6             |
| **All (31)** | **0.838**            | **0.912**         | **~15**         |

_Det. Score = deterministic-only (no LLM judge). See `benchmarks/results/run_latest.json` for full per-scenario data._

### Evaluation Metrics (8 dimensions)

| Metric | What it measures | Full credit | Type |
|---|---|---|---|
| **RCA accuracy** | Root cause correctly identified | LLM judge score | LLM judge |
| **RCA keyword match** | Expected keyword in root_cause | Case-insensitive substring match | Deterministic |
| **Evidence quality** | Right commit + logs + tickets cited | Correct SHA + all 3 evidence types | Deterministic |
| **Actionability** | Actions tied to tracked tickets | ≥1 action has valid `ticket_id` | Deterministic |
| **Reliability** | Swarm handled scenario correctly | Completed + correct inconclusive flag | Deterministic |
| **PII compliance** | No emails or usernames in output | Zero regex matches | Deterministic |
| **Citation integrity** | Evidence traceable to source | SHA + logger keyword + log entry cited | Deterministic |
| **Reasoning quality** | Causal chain is logically sound | LLM judge score | LLM judge |

`overall_score = mean(7 metrics)` · `deterministic_score = mean(6 non-judge metrics)`

### Running benchmarks

```bash
# Run all 31 scenarios (original CVE + 10 new non-CVE)
uv run python benchmarks/runner.py

# Run specific scenario IDs
uv run python benchmarks/runner.py --ids oom-01 dep-01 dbl-01 svc-01 rlt-01

# Save results to custom path
uv run python benchmarks/runner.py --output benchmarks/results/my_run.json
```

### Non-CVE scenarios (10 new)

| Group | IDs | Incident type |
|---|---|---|
| OOM | oom-01, oom-02 | JVM heap exhaustion / OOMKilled |
| BadDeploy | dep-01, dep-02 | Wrong DB_HOST env var in production config |
| Deadlock | dbl-01, dbl-02 | HikariCP pool exhaustion + DB deadlock |
| DepFail | svc-01, svc-02 | auth-svc 503 cascade |
| RateLimit | rlt-01, rlt-02 | Stripe 429 retry storm |

### Real integration (live GitHub + Jira)

Set credentials in `.env`:
```bash
GITHUB_ORG=apache
GITHUB_TOKEN=ghp_...   # needs repo:read scope
GITHUB_MODE=live
JIRA_MODE=live
```

Run the live scenario against the real `apache/logging-log4j2` repo and Apache JIRA:
```bash
uv run python benchmarks/runner.py --ids ls-live-01
```

Expected: commit `c362aff4` appears in `evidence.commits` (the real Log4Shell fix commit).

---

## API Server

Start the REST API:

```bash
uv run uvicorn api.server:app --reload --port 8000
```

### POST /analyze

Trigger an RCA and get back a PostMortem JSON:

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"service": "payment-svc", "incident_time": "2021-12-10T06:15:00Z", "severity": "P0", "jira_project": "LOG4J2"}'
```

### POST /slack/analyze (Slack slash command)

1. Create a Slack app at [api.slack.com/apps](https://api.slack.com/apps)
2. Add a slash command (e.g. `/analyze`) pointing to `https://<your-host>/slack/analyze`
3. Copy the **Signing Secret** from Basic Information → set `SLACK_SIGNING_SECRET` in `.env`
4. Invoke from Slack: `/analyze payment-svc 2021-12-10T06:15:00Z P0`

The bot acknowledges immediately and posts the root cause + top actions once the swarm completes (~20s).