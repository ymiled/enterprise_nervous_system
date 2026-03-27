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

The benchmark evaluates the swarm on **8 scenarios** across two tiers:

### Real labeled datasets (8 scenarios, download required)
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
