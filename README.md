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

The benchmark evaluates the swarm on 21 scenarios across Log4Shell, Text4Shell, and negative-control incident types, covering a range of services, severities, and root-cause complexities

### Benchmark results

| Group        | Median Overall Score | Median Time (s) |
|--------------|----------------------|-----------------|
| Log4Shell    | 0.748                | 19.4            |
| Text4Shell   | 0.905                | 17.25           |
| Negative     | 0.81                 | 21.9            |
| All Scenarios| 0.81                 | 18.55           |

_See benchmarks/results/run_latest.json for full details and per-scenario notes._

The benchmark evaluates the swarm on **21 scenarios** across 



### Evaluation Metrics (7 dimensions)

| Metric | What it measures | Full credit |
|---|---|---|
| **RCA accuracy** | Root cause correctly identified | All oracle keywords in `root_cause` |
| **Evidence quality** | Logs + commits + tickets all cited | All 3 evidence types present |
| **Actionability** | Actions tied to tracked tickets | ≥1 recommended action has a valid `ticket_id` |
| **Reliability** | Swarm completed without crash | Run did not raise an exception |
| **PII compliance** | No emails or usernames in output | Zero regex matches on PII patterns |
| **Citation integrity** | Evidence traceable to source | Log entry + ticket + logger keyword cited |
| **Reasoning quality** | Causal chain is logically sound | LLM judge: high-quality reasoning |

Overall score = `mean(7 metrics)`.

### Running benchmarks

```bash
# Run all 8 real scenarios 
uv run python benchmarks/runner.py

# Save results to custom path
uv run python benchmarks/runner.py --output benchmarks/results/my_run.json
```