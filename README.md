# Enterprise Nervous System
### Cross-silo incident resolution swarm

An autonomous root-cause analysis system that queries GitHub, Jira, and application logs in parallel to debug production incidents, without a human jumping between tabs.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Incident Trigger                         │
│    PagerDuty webhook / API / Slack slash command            │
└──────────────────────────┬──────────────────────────────────┘
                           │
                      ┌────▼────┐   LogisticRegression classifier
                      │ Router  │   trained on ablation outcomes
                      └─┬─────┬─┘   (swarm/routing.py)
                        │     │
          CVE/structured│     │OOM/resource/ambiguous
                        │     │
          ┌─────────────▼──┐ ┌▼────────────────────────┐
          │  AG2 Swarm     │ │  Single-Agent Baseline  │
          │  Orchestrator  │ │  (benchmarks/baseline.py│
          │  (4 agents)    │ │   one LLM call, all 3   │
          └──┬──────────┬──┘ │   MCP tools available)  │
             │          │    └──────────┬──────────────┘
    ┌────────▼─┐  ┌─────▼──────┐        │
    │  DevOps  │  │  SWE Agent │  ┌─────▼─────────────┐
    │  Agent   │  │(github MCP)│  │  PM Agent         │
    │(logs MCP)│  └─────┬──────┘  │  (jira MCP)       │
    └────┬─────┘        │         └────┬──────────────┘
  DEVOPS_DONE      SWE_DONE        PM_DONE
         └──────────────┼──────────────┘
                        │
                        │  (smart speaker selection blocks
                        │   Critic until all 3 sentinels present)
                        │
          ┌─────────────▼───────────┐
          │    AG2 Critic Agent     │  ← synthesises PostMortem JSON
          │  (PII check, citation   │
          │   enforcement, rules)   │
          └─────────────┬───────────┘
                        │                        │ (baseline path
          ┌─────────────▼───────────┐            │  skips to here)
          │   PostMortem (JSON)     │◄───────────┘
          │  validated by Pydantic  │  ← schemas/postmortem.py
          └─────────────┬───────────┘
                        │
          ┌─────────────▼───────────┐
          │   Slack / Confluence    │  ← POST /pagerduty/webhook
          │   (on-call review)      │     → _post_to_slack()
          └─────────────────────────┘
```
---

## Quickstart

**1. Install dependencies**
```bash
uv sync
```

**2. Configure environment**
```bash
cp .env.example .env
# Swarm LLM: agents try gpt-4o → gpt-4o-mini → Groq Llama-3.3-70b (set OPENAI_API_KEY
#   and/or GROQ_API_KEY). gpt-4o strongly recommended — a weaker model can hallucinate
#   evidence on live data (see TECHNICAL_NOTES, "All-Live Run").
# Judge (independent eval): OPENAI_API_KEY → ANTHROPIC_API_KEY → GROQ_API_KEY
# Optional: SLACK_WEBHOOK_URL, PAGERDUTY_WEBHOOK_SECRET, REDIS_URL (durable jobs + worker)
```

**3. Run the swarm against the Log4Shell scenario**
```bash
uv run python swarm/orchestrator.py
uv run python swarm/orchestrator.py --service payment-svc --since 2021-12-10T06:15:00Z --severity P0
uv run python swarm/orchestrator.py --output postmortem.json
```

**Mock vs live backends.** Each MCP server has a `mock` mode (seed JSON, deterministic)
and a `live` mode, set per-server via `LOGS_MODE` / `GITHUB_MODE` / `JIRA_MODE`:
- **GitHub live**: hybrid GraphQL v4 + REST (history & PR linkage via GraphQL; full-text
  commit search via REST `/search/commits`; raw patches via REST). Requires `GITHUB_TOKEN`.
- **Jira live**: Apache public Jira REST v2 (no auth needed).
- **Logs live**: Elasticsearch (`docker compose up -d elasticsearch`, then
  `uv run python data/loaders/es_ingestor.py` to populate the index).

Run the full durable stack (api + rq worker + redis + elasticsearch) with `docker compose up`.

---

## Real-time integration: PagerDuty → Slack

Start the API server:
```bash
uv run uvicorn api.server:app --reload --port 8000
```

Wire PagerDuty → Slack:
1. Set `SLACK_WEBHOOK_URL` (Slack incoming webhook) and `PAGERDUTY_WEBHOOK_SECRET` in `.env`
2. Point a PagerDuty V3 webhook at `POST https://<your-host>/pagerduty/webhook`
3. When an alert fires: severity mapped (`critical→P0`, `high→P1`), swarm runs async, PostMortem posted to Slack:

```
:rotating_light: *[ENS] RCA complete — payment-svc P0* (PD: P1TEST01)
*Root cause:* Log4j2 2.14.1 JNDI lookup via CVE-2021-44228 in payment-svc.
*Actions (1):*
  • [immediate] Upgrade log4j-core to 2.16.0 (`LOG4J2-3208`)
*Confidence:* 95%  |  Tokens: 5,371
```

### POST /analyze — async job queue + adaptive routing

`POST /analyze` enqueues the analysis and returns immediately (HTTP 202); you poll
`GET /analyze/{job_id}` for the result. This keeps Slack/PagerDuty webhooks fast and
lets long RCAs run without holding a request open.

```bash
# 1. submit — returns {"job_id": "...", "status": "queued", "transport": "rq"|"background"}
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"service": "payment-svc", "incident_time": "2021-12-10T06:15:00Z", "severity": "P0", "mode": "auto"}'

# 2. poll — {"status": "running"|"done"|"failed", "result": {...}}
curl http://localhost:8000/analyze/<job_id>
```

**Execution transport** (chosen automatically by `REDIS_URL`):
- **rq worker** when `REDIS_URL` is set — `POST /analyze` only enqueues; a separate
  worker process (`uv run python -m api.worker`) runs the swarm, so an API crash cannot
  orphan an in-flight job. Start the full stack with `docker compose up` (api + worker +
  redis + elasticsearch).
- **BackgroundTasks** otherwise — runs in the API process; fine for a single dev replica.

Job state lives in a Redis-backed store (durable, TTL-evicted) when `REDIS_URL` is set,
else an in-memory store with TTL eviction.

`mode` options: `auto` (default — `LogisticRegression` classifier in `swarm/routing.py`
routes based on incident context; JNDI/CVE → swarm, OOM/resource → single), `swarm`, `single`.

### POST /slack/analyze (Slack slash command)

1. Create a Slack app, add slash command pointing to `https://<your-host>/slack/analyze`
2. Set `SLACK_SIGNING_SECRET` in `.env`
3. `/analyze payment-svc 2021-12-10T06:15:00Z P0`

---

## Benchmarks

50 scenarios across 15 incident families (real CVEs + cited public postmortems + synthetic variants), scored by an independent LLM judge (gpt-4o-mini, separate from the swarm model).

**Headline — 4-agent swarm vs 1-agent baseline:**

| | Swarm | Baseline |
|---|---|---|
| Aggregate score | **0.769 ± 0.187** | 0.746 ± 0.128 |
| Avg tokens | 6,543 | 4,502 |

Swarm wins on multi-source CVE/deploy incidents; baseline wins on resource/ambiguous ones. Swarm costs +45% more tokens — a quality-vs-cost tradeoff, not a saving.

Full per-scenario tables, the 50-scenario catalog, the 7 evaluation dimensions, and reproduce/fetch commands: **[docs/BENCHMARKS.md](docs/BENCHMARKS.md)**.

```bash
uv run python -m pytest tests/        # test suite
uv run python benchmarks/runner.py    # all 50 scenarios
```
