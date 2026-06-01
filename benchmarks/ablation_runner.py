"""
Ablation Runner
---------------
Compares 4-agent swarm vs single-agent baseline on the same scenarios.
Produces a side-by-side table showing overall_score, deterministic_score,
estimated_tokens, and elapsed_seconds for both approaches.

Usage:
    # Compare on all scenarios
    uv run python benchmarks/ablation_runner.py

    # Compare on specific IDs
    uv run python benchmarks/ablation_runner.py --ids ls-01 oom-01 dep-01

    # Save results JSON
    uv run python benchmarks/ablation_runner.py --output benchmarks/results/ablation.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path
from statistics import mean, stdev

from rich.console import Console
from rich.table import Table
from rich import box

sys.path.insert(0, str(Path(__file__).parent.parent))

from benchmarks.baseline   import run_baseline
from benchmarks.evaluator  import EvalResult, evaluate, failed_run
from benchmarks.scenarios  import ALL_SCENARIOS, SCENARIO_MAP, Scenario
from swarm.orchestrator    import run_incident_analysis

RESULTS_DIR = Path(__file__).parent / "results"


# Per-scenario runner

async def _run_swarm(scenario: Scenario, start: float) -> EvalResult:
    seed_overrides = {
        "LOGS_SEED_FILE":    str(scenario.logs_seed),
        "COMMITS_SEED_FILE": str(scenario.commits_seed),
        "TICKETS_SEED_FILE": str(scenario.tickets_seed),
        "GITHUB_MODE":       scenario.github_mode,
        "JIRA_MODE":         scenario.jira_mode,
        "LOGS_MODE":         scenario.logs_mode,
    }
    try:
        pm, usage = await run_incident_analysis(
            service=scenario.service,
            incident_time=scenario.incident_time,
            severity=scenario.severity,
            jira_project=scenario.jira_project,
            seed_overrides=seed_overrides,
        )
        elapsed = time.monotonic() - start
        if pm is None:
            return failed_run(scenario, elapsed, "Swarm returned None")
        return evaluate(pm, scenario, elapsed, usage=usage)
    except Exception as exc:
        return failed_run(scenario, time.monotonic() - start, str(exc)[:120])


async def _run_base(scenario: Scenario, start: float) -> EvalResult:
    try:
        pm, usage = await run_baseline(scenario)
        elapsed = time.monotonic() - start
        if pm is None:
            return failed_run(scenario, elapsed, "Baseline returned None")
        return evaluate(pm, scenario, elapsed, usage=usage)
    except Exception as exc:
        return failed_run(scenario, time.monotonic() - start, str(exc)[:120])


# Retry wrapper: a 0-token result means the LLM produced nothing (transient
# Groq failure or anyio teardown crash), not a genuine answer. Retry those so a
# random API hiccup can't zero out a scenario and skew the comparison.
_RETRY_WAITS = [20, 40]  # seconds; also drains Groq's per-minute token window


def _run_with_retry(runner, scenario: Scenario, label: str, console: Console) -> EvalResult:
    # Fresh event loop per attempt (asyncio.run) — prevents anyio cancel-scope
    # leakage from a crashed teardown bleeding into the next try.
    result = asyncio.run(runner(scenario, time.monotonic()))
    for attempt, wait in enumerate(_RETRY_WAITS, start=2):
        if result.estimated_tokens > 0:
            break
        console.print(f"       [retry] {label} produced 0 tokens — waiting {wait}s, attempt {attempt}...")
        time.sleep(wait)
        result = asyncio.run(runner(scenario, time.monotonic()))
    return result


# Rendering

def _style(v: float) -> str:
    if v >= 0.9: return "bold green"
    if v >= 0.7: return "yellow"
    return "bold red"


def _fmt(v: float) -> str:
    return f"{v:.2f}"


def _delta_style(d: float) -> str:
    if d > 0.05:  return "bold green"
    if d < -0.05: return "bold red"
    return "dim"


def render_ablation_table(
    pairs: list[tuple[EvalResult, EvalResult]],
    console: Console,
) -> None:
    table = Table(
        title="Ablation: 4-Agent Swarm vs Single-Agent Baseline",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("ID",              style="dim",     width=8)
    table.add_column("Scenario",                         width=30)
    table.add_column("Swarm\nScore",    justify="right", width=7)
    table.add_column("Base\nScore",     justify="right", width=7)
    table.add_column("Δ Score",         justify="right", width=7)
    table.add_column("Swarm\nDet.",     justify="right", width=7)
    table.add_column("Base\nDet.",      justify="right", width=7)
    table.add_column("Swarm\nTok",      justify="right", width=7)
    table.add_column("Base\nTok",       justify="right", width=7)
    table.add_column("Swarm\nTime(s)",  justify="right", width=9)
    table.add_column("Base\nTime(s)",   justify="right", width=9)

    for swarm, base in pairs:
        delta = swarm.overall_score - base.overall_score
        table.add_row(
            swarm.scenario_id,
            swarm.scenario_name[:30],
            f"[{_style(swarm.overall_score)}]{_fmt(swarm.overall_score)}[/]",
            f"[{_style(base.overall_score)}]{_fmt(base.overall_score)}[/]",
            f"[{_delta_style(delta)}]{delta:+.2f}[/]",
            f"[{_style(swarm.deterministic_score)}]{_fmt(swarm.deterministic_score)}[/]",
            f"[{_style(base.deterministic_score)}]{_fmt(base.deterministic_score)}[/]",
            str(swarm.estimated_tokens) if swarm.estimated_tokens else "-",
            str(base.estimated_tokens)  if base.estimated_tokens  else "-",
            str(swarm.elapsed_seconds),
            str(base.elapsed_seconds),
        )

    # Summary
    swarm_scores = [s.overall_score for s, _ in pairs]
    base_scores  = [b.overall_score for _, b in pairs]
    swarm_det    = [s.deterministic_score for s, _ in pairs]
    base_det     = [b.deterministic_score for _, b in pairs]
    swarm_toks   = [s.estimated_tokens for s, _ in pairs]
    base_toks    = [b.estimated_tokens for _, b in pairs]

    summary = Table(title="Ablation Summary", box=box.SIMPLE, header_style="bold magenta")
    summary.add_column("Metric",       style="bold")
    summary.add_column("4-Agent Swarm", justify="right")
    summary.add_column("1-Agent Base",  justify="right")
    summary.add_column("Δ (swarm−base)", justify="right")

    def row(label: str, sv: list[float], bv: list[float]) -> None:
        sm, bm = mean(sv), mean(bv)
        d = sm - bm
        ds = "bold green" if d > 0.02 else ("bold red" if d < -0.02 else "dim")
        summary.add_row(label, f"{sm:.3f}", f"{bm:.3f}", f"[{ds}]{d:+.3f}[/]")

    row("Overall score",       swarm_scores, base_scores)
    row("Deterministic score", swarm_det,    base_det)

    st, bt = mean(swarm_toks), mean(base_toks)
    summary.add_row(
        "Avg tokens (est)",
        f"{st:,.0f}",
        f"{bt:,.0f}",
        f"{st - bt:+,.0f}",
    )

    console.print(table)
    console.print(summary)


# Persistence

def save_ablation(
    pairs: list[tuple[EvalResult, EvalResult]],
    path: Path,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [
        {
            "scenario_id":   s.scenario_id,
            "scenario_name": s.scenario_name,
            "swarm": {
                "overall_score":       s.overall_score,
                "deterministic_score": s.deterministic_score,
                "rca_accuracy":        s.rca_accuracy,
                "rca_keyword_match":   s.rca_keyword_match,
                "evidence_quality":    s.evidence_quality,
                "reliability":         s.reliability,
                "estimated_tokens":    s.estimated_tokens,
                "estimated_cost_usd":  s.estimated_cost_usd,
                "elapsed_seconds":     s.elapsed_seconds,
            },
            "baseline": {
                "overall_score":       b.overall_score,
                "deterministic_score": b.deterministic_score,
                "rca_accuracy":        b.rca_accuracy,
                "rca_keyword_match":   b.rca_keyword_match,
                "evidence_quality":    b.evidence_quality,
                "reliability":         b.reliability,
                "estimated_tokens":    b.estimated_tokens,
                "estimated_cost_usd":  b.estimated_cost_usd,
                "elapsed_seconds":     b.elapsed_seconds,
            },
            "delta_overall":       round(s.overall_score - b.overall_score, 3),
            "delta_deterministic": round(s.deterministic_score - b.deterministic_score, 3),
        }
        for s, b in pairs
    ]
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    Console().print(f"\n[green]Ablation results saved ->[/green] {path}")


# Repeated runs (mean ± std) — quantifies LLM non-determinism so a single
# noisy run can't be mistaken for a real swarm-vs-baseline difference.

def _ms(values: list[float]) -> tuple[float, float]:
    """Return (mean, sample-stdev). Stdev is 0.0 when fewer than 2 samples."""
    return mean(values), (stdev(values) if len(values) > 1 else 0.0)


def run_repeated(scenarios: list[Scenario], repeats: int, console: Console) -> dict:
    # per_scenario[id] = {"swarm": {metric: [vals]}, "baseline": {metric: [vals]}}
    metrics = ("overall_score", "deterministic_score", "estimated_tokens")
    per_scenario: dict[str, dict] = {
        sc.id: {
            "name": sc.name,
            "swarm":    {m: [] for m in metrics},
            "baseline": {m: [] for m in metrics},
        }
        for sc in scenarios
    }

    for rep in range(1, repeats + 1):
        console.print(f"\n[bold cyan]── Repeat {rep}/{repeats} ──[/bold cyan]")
        for i, scenario in enumerate(scenarios, 1):
            console.print(f"  [{i}/{len(scenarios)}] [bold]{scenario.id}[/bold]")

            console.print("    → swarm...")
            sw = _run_with_retry(_run_swarm, scenario, "swarm", console)
            console.print(f"       score={sw.overall_score:.2f}  det={sw.deterministic_score:.2f}  tok={sw.estimated_tokens}")
            time.sleep(5)

            console.print("    → baseline...")
            bs = _run_with_retry(_run_base, scenario, "baseline", console)
            console.print(f"       score={bs.overall_score:.2f}  det={bs.deterministic_score:.2f}  tok={bs.estimated_tokens}")
            time.sleep(5)

            d = per_scenario[scenario.id]
            for m in metrics:
                d["swarm"][m].append(getattr(sw, m))
                d["baseline"][m].append(getattr(bs, m))

    return {"repeats": repeats, "scenarios": per_scenario}


def render_repeated(agg: dict, console: Console) -> None:
    repeats = agg["repeats"]
    rows = agg["scenarios"]

    table = Table(
        title=f"Ablation (N={repeats} repeats): mean ± std",
        box=box.ROUNDED, show_lines=True, header_style="bold cyan",
    )
    table.add_column("ID", style="dim", width=8)
    table.add_column("Swarm Score",   justify="right", width=15)
    table.add_column("Base Score",    justify="right", width=15)
    table.add_column("Swarm Tok",     justify="right", width=14)
    table.add_column("Base Tok",      justify="right", width=14)

    for sid, d in rows.items():
        sm, ss = _ms(d["swarm"]["overall_score"])
        bm, bs = _ms(d["baseline"]["overall_score"])
        stk, _ = _ms(d["swarm"]["estimated_tokens"])
        btk, _ = _ms(d["baseline"]["estimated_tokens"])
        table.add_row(
            sid,
            f"[{_style(sm)}]{sm:.2f} ± {ss:.2f}[/]",
            f"[{_style(bm)}]{bm:.2f} ± {bs:.2f}[/]",
            f"{stk:,.0f}", f"{btk:,.0f}",
        )
    console.print(table)

    # Aggregate across all scenarios × repeats (pooled samples).
    def pool(side: str, metric: str) -> list[float]:
        return [v for d in rows.values() for v in d[side][metric]]

    summary = Table(title="Aggregate (pooled over scenarios × repeats)", box=box.SIMPLE, header_style="bold magenta")
    summary.add_column("Metric", style="bold")
    summary.add_column("4-Agent Swarm", justify="right")
    summary.add_column("1-Agent Base",  justify="right")
    summary.add_column("Δ (swarm−base)", justify="right")

    for label, metric in [("Overall score", "overall_score"), ("Deterministic score", "deterministic_score")]:
        sm, ss = _ms(pool("swarm", metric))
        bm, bsd = _ms(pool("baseline", metric))
        d = sm - bm
        verdict = "tie (within noise)" if abs(d) <= max(ss, bsd) else ("swarm" if d > 0 else "baseline")
        style = "dim" if verdict.startswith("tie") else ("bold green" if d > 0 else "bold red")
        summary.add_row(label, f"{sm:.3f} ± {ss:.3f}", f"{bm:.3f} ± {bsd:.3f}", f"[{style}]{d:+.3f} → {verdict}[/]")

    stk, stks = _ms(pool("swarm", "estimated_tokens"))
    btk, btks = _ms(pool("baseline", "estimated_tokens"))
    summary.add_row("Avg tokens (est)", f"{stk:,.0f} ± {stks:,.0f}", f"{btk:,.0f} ± {btks:,.0f}", f"{stk - btk:+,.0f}")

    console.print(summary)


def save_repeated(agg: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = agg["scenarios"]

    def pool(side: str, metric: str) -> list[float]:
        return [v for d in rows.values() for v in d[side][metric]]

    out = {"repeats": agg["repeats"], "per_scenario": {}, "aggregate": {}}
    for sid, d in rows.items():
        entry = {"name": d["name"], "swarm": {}, "baseline": {}}
        for side in ("swarm", "baseline"):
            for m, vals in d[side].items():
                mn, sd = _ms(vals)
                entry[side][m] = {"mean": round(mn, 4), "std": round(sd, 4), "samples": vals}
        out["per_scenario"][sid] = entry
    for side in ("swarm", "baseline"):
        out["aggregate"][side] = {}
        for m in ("overall_score", "deterministic_score", "estimated_tokens"):
            mn, sd = _ms(pool(side, m))
            out["aggregate"][side][m] = {"mean": round(mn, 4), "std": round(sd, 4)}
    path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    Console().print(f"\n[green]Repeated ablation saved ->[/green] {path}")


# Entry point

def main(scenario_ids: list[str], output: Path | None, repeats: int = 1) -> None:
    console = Console()

    if scenario_ids:
        scenarios = [SCENARIO_MAP[sid] for sid in scenario_ids if sid in SCENARIO_MAP]
    else:
        scenarios = ALL_SCENARIOS

    if not scenarios:
        console.print("[red]No scenarios to run.[/red]")
        sys.exit(1)

    if repeats > 1:
        console.print(f"\n[bold cyan]Ablation: {len(scenarios)} scenario(s) × 2 approaches × {repeats} repeats...[/bold cyan]")
        agg = run_repeated(scenarios, repeats, console)
        out_path = output or (RESULTS_DIR / "ablation_repeated.json")
        save_repeated(agg, out_path)
        console.print()
        render_repeated(agg, console)
        return

    console.print(f"\n[bold cyan]Ablation: running {len(scenarios)} scenario(s) × 2 approaches...[/bold cyan]\n")

    pairs: list[tuple[EvalResult, EvalResult]] = []
    for i, scenario in enumerate(scenarios, 1):
        console.print(f"  [{i}/{len(scenarios)}] [bold]{scenario.id}[/bold] — {scenario.name}")

        # Swarm run
        console.print("    → swarm...")
        swarm_result = _run_with_retry(_run_swarm, scenario, "swarm", console)
        console.print(f"       score={swarm_result.overall_score:.2f}  det={swarm_result.deterministic_score:.2f}  tok={swarm_result.estimated_tokens}  t={swarm_result.elapsed_seconds}s")

        time.sleep(5)  # cooldown between LLM calls

        # Baseline run
        console.print("    → baseline...")
        base_result = _run_with_retry(_run_base, scenario, "baseline", console)
        console.print(f"       score={base_result.overall_score:.2f}  det={base_result.deterministic_score:.2f}  tok={base_result.estimated_tokens}  t={base_result.elapsed_seconds}s\n")

        pairs.append((swarm_result, base_result))

        if i < len(scenarios):
            time.sleep(5)

    out_path = output or (RESULTS_DIR / "ablation_latest.json")
    save_ablation(pairs, out_path)
    console.print()
    render_ablation_table(pairs, console)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ablation: swarm vs baseline")
    parser.add_argument("--ids",     nargs="*", default=[])
    parser.add_argument("--output",  type=Path, default=None)
    parser.add_argument("--repeats", type=int,  default=1,
                        help="Run each scenario N times and report mean ± std (quantifies LLM noise).")
    args = parser.parse_args()
    main(scenario_ids=args.ids, output=args.output, repeats=args.repeats)
