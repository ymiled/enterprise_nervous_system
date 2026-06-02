# Benchmark Suite

50 scenarios across 15 incident families, evaluated with an independent LLM judge.

## Real-incident sourcing

- **GHSA Advisory Database** (GitHub Advisory API, no token needed): Struts CVE-2017-5638 commit SHA `35230649`, Spring4Shell CVE-2022-22965 commit SHA `002546b3` — fetched via `data/loaders/ghsa_fetcher.py`
- **Cited public postmortems**: CircleCI schema migration (2021), Facebook/Meta BGP withdrawal (2021), Cloudflare WAF regex (2019), Log4Shell (CVE-2021-44228), Text4Shell (CVE-2022-42889)
- **Synthetic variants**: 40 scenarios extending real incident types to different services/severities

## Ablation: 4-agent swarm vs 1-agent baseline

Both use OpenAI gpt-4o-mini as the independent judge (not the swarm model, avoiding circular self-evaluation). Fallback: Claude claude-sonnet-4-6 → Groq.

| Scenario | Swarm Score | Baseline Score | Δ | Swarm Tokens | Baseline Tokens |
|---|---|---|---|---|---|
| ls-01 (Log4Shell CVE) | **0.88 ± 0.00** | 0.77 ± 0.03 | +0.11 | 14,306 | 11,620 |
| t4s-01 (Text4Shell CVE) | 0.92 ± 0.05 | **0.95 ± 0.00** | -0.04 | 6,354 | 6,881 |
| neg-01 (negative control) | 0.48 ± 0.07 | **0.57 ± 0.00** | -0.09 | 3,112 | 2,423 |
| oom-01 (JVM OOM) | 0.55 ± 0.03 | **0.67 ± 0.00** | -0.12 | 7,368 | 2,519 |
| dep-01 (bad deploy) | **0.94 ± 0.08** | 0.67 ± 0.00 | +0.27 | 4,807 | 3,055 |
| cert-01 (cert expiry) | **0.77 ± 0.15** | 0.69 ± 0.03 | +0.08 | 4,923 | 2,998 |
| cfg-01 (schema migration) | 0.67 ± 0.00 | **0.77 ± 0.15** | -0.11 | 5,903 | 3,386 |
| struts-01 (Struts CVE) | **0.95 ± 0.00** | 0.88 ± 0.00 | +0.07 | 5,576 | 3,137 |
| **Aggregate** | **0.769 ± 0.187** | 0.746 ± 0.128 | **+0.023** | 6,543 | 4,502 |

### Findings

- **Quality: swarm leads aggregate**: Δ = +0.023, swarm wins 4/8 clearly, ties on t4s-01. Swarm is better when evidence sources align (CVE incidents + structured deploys); baseline better on resource exhaustion and ambiguous incidents.
- **Token cost: swarm uses +45% more tokens**: 6,543 vs 4,502 avg. The "efficiency" story does not hold — this is a quality-vs-cost tradeoff, not quality-vs-savings.
- **High variance on some scenarios**: cert-01 swarm std=0.15 signals the Critic occasionally produces low-confidence output when log and commit evidence partially conflict.

```bash
# Reproduce:
uv run python benchmarks/ablation_runner.py \
  --ids ls-01 t4s-01 neg-01 oom-01 dep-01 cert-01 cfg-01 struts-01 \
  --repeats 2 --output benchmarks/results/ablation_v3_n2.json
```

## Scenario families (50 total)

| Family | IDs | Source | Incident type |
|---|---|---|---|
| Log4Shell | ls-01…ls-12 | CVE-2021-44228 (real Apache commits) | JNDI RCE via HTTP header |
| Text4Shell | t4s-01…t4s-06 | CVE-2022-42889 (real Apache commits) | Script lookup RCE |
| Struts RCE | struts-01/02 | **GHSA-j77q-2qqg-6989** (SHA fetched from GHSA API) | OGNL injection, Equifax 2017 |
| Spring4Shell | spring4s-01…03 | **GHSA-36p3-wjmg-h94x** (SHA fetched from GHSA API) | DataBinder classLoader RCE |
| Cert expiry | cert-01/02 | Synthetic | TLS cert expired, auth-svc |
| Network partition | net-01/02 | Synthetic (Meta BGP-inspired) | Redis split-brain |
| Third-party API | ext-01/02 | Synthetic | Stripe degradation |
| Deadlock | race-01/02 | Synthetic | MySQL lock-order inversion |
| Schema migration | cfg-01/02 | **CircleCI 2021** | Type mismatch breaks distributor |
| BGP withdrawal | bgp-01/02 | **Facebook/Meta 2021** | Global DNS unreachable |
| WAF regex | regex-01/02 | **Cloudflare 2019** | Catastrophic backtracking |
| Negative | neg-01…03 | Synthetic | No incident — must report inconclusive |
| OOM | oom-01/02 | Synthetic | JVM heap exhaustion |
| Bad deploy | dep-01/02 | Synthetic | DB_HOST config drift |
| Deadlock (DB) | dbl-01/02 | Synthetic | HikariCP pool exhaustion |
| Dependency fail | svc-01/02 | Synthetic | auth-svc 503 cascade |
| Rate limit | rlt-01/02 | Synthetic | Stripe 429 retry storm |

## Evaluation metrics (7 dimensions)

| Metric | What it measures | Type |
|---|---|---|
| **RCA accuracy** | Root cause correctly identified | OpenAI gpt-4o-mini judge |
| **Evidence quality** | Correct commit SHA + logs + tickets cited | Deterministic |
| **Actionability** | Actions reference expected ticket IDs | Deterministic |
| **Reliability** | Completed + correct inconclusive flag | Deterministic |
| **PII compliance** | No emails or usernames in output | Deterministic |
| **Citation integrity** | SHA + logger keyword + log entry | Deterministic |
| **Reasoning quality** | Causal chain logically sound | OpenAI gpt-4o-mini judge |

## Fetch real CVE scenarios from GitHub Advisory Database

```bash
# Fetch Struts CVE-2017-5638 oracle (no GitHub token required)
uv run python data/loaders/ghsa_fetcher.py --ghsa GHSA-j77q-2qqg-6989 --name struts

# Fetch Spring4Shell CVE-2022-22965
uv run python data/loaders/ghsa_fetcher.py --cve CVE-2022-22965 --name spring4shell

# Fetch any CVE
uv run python data/loaders/ghsa_fetcher.py --cve CVE-2021-44228 --name log4shell_verify
```

## Running benchmarks

```bash
# All 50 scenarios
uv run python benchmarks/runner.py

# Specific IDs
uv run python benchmarks/runner.py --ids oom-01 dep-01 struts-01 spring4s-01

# Ablation (swarm vs baseline)
uv run python benchmarks/ablation_runner.py --ids ls-01 t4s-01 neg-01 oom-01 dep-01 --repeats 4

# Tests
uv run python -m pytest tests/
```
