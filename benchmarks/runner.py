"""
Benchmark Runner
----------------
Runs the incident swarm against all (or selected) scenarios, evaluates
6 metrics per run, prints a rich table, and saves results to JSON.

Usage:
    # Run all 20 scenarios
    uv run python benchmarks/runner.py

    # Run a specific subset by ID
    uv run python benchmarks/runner.py --ids ls-01 oom-01 cfg-01

    # Save results to a custom path
    uv run python benchmarks/runner.py --output benchmarks/results/run_latest.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path
from statistics import mean, median

from rich.console import Console
from rich.table import Table
from rich import box

sys.path.insert(0, str(Path(__file__).parent.parent))

from benchmarks.scenarios import ALL_SCENARIOS, SCENARIO_MAP, Scenario
from benchmarks.evaluator import EvalResult, evaluate, failed_run

RESULTS_DIR = Path(__file__).parent / "results"


# Per-scenario runner
async def _run_scenario(scenario: Scenario) -> EvalResult:
    from swarm.orchestrator import run_incident_analysis

    start = time.monotonic()
    try:
        pm = await run_incident_analysis(
            service=scenario.service,
            incident_time=scenario.incident_time,
            severity=scenario.severity,
            jira_project=scenario.jira_project,
            seed_overrides={
                "LOGS_SEED_FILE":    str(scenario.logs_seed),
                "COMMITS_SEED_FILE": str(scenario.commits_seed),
                "TICKETS_SEED_FILE": str(scenario.tickets_seed),
            },
        )
        elapsed = time.monotonic() - start
        if pm is None:
            return failed_run(scenario, elapsed, "Swarm returned None — no JSON block from Critic")
        return evaluate(pm, scenario, elapsed)
    except Exception as exc:
        elapsed = time.monotonic() - start
        return failed_run(scenario, elapsed, str(exc)[:120])


# Table rendering

def _style(v: float) -> str:
    if v >= 0.9: return "bold green"
    if v >= 0.7: return "yellow"
    return "bold red"


def _fmt(v: float) -> str:
    return f"{v:.2f}"


def render_table(results: list[EvalResult], console: Console) -> None:
    table = Table(
        title="Enterprise Nervous System — Benchmark Results",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("ID",            style="dim",     width=8)
    table.add_column("Scenario",                       width=42)
    table.add_column("RCA\nAcc.",     justify="right", width=6)
    table.add_column("Evid.\nQual.",  justify="right", width=6)
    table.add_column("Action\n-able", justify="right", width=7)
    table.add_column("Reli-\nable",   justify="right", width=6)
    table.add_column("PII\nSafe",     justify="right", width=5)
    table.add_column("Cit.\nInteg.",  justify="right", width=6)
    table.add_column("Score",         justify="right", width=6)
    table.add_column("Time\n(s)",     justify="right", width=6)

    for r in results:
        table.add_row(
            r.scenario_id,
            r.scenario_name[:42],
            f"[{_style(r.rca_accuracy)}]{_fmt(r.rca_accuracy)}[/]",
            f"[{_style(r.evidence_quality)}]{_fmt(r.evidence_quality)}[/]",
            f"[{_style(r.actionability)}]{_fmt(r.actionability)}[/]",
            f"[{_style(r.reliability)}]{_fmt(r.reliability)}[/]",
            f"[{_style(r.pii_compliance)}]{_fmt(r.pii_compliance)}[/]",
            f"[{_style(r.citation_integrity)}]{_fmt(r.citation_integrity)}[/]",
            f"[bold]{_fmt(r.overall_score)}[/bold]",
            str(r.elapsed_seconds),
        )

    console.print(table)
    _render_summary(results, console)


def _render_summary(results: list[EvalResult], console: Console) -> None:
    n          = len(results)
    completed  = [r for r in results if r.reliability == 1.0]
    times      = [r.elapsed_seconds for r in completed]

    def avg(attr: str) -> str:
        return f"{mean(getattr(r, attr) for r in results):.3f}"

    summary = Table(title="Summary Statistics", box=box.SIMPLE, header_style="bold magenta")
    summary.add_column("Metric",      style="bold")
    summary.add_column("Value",       justify="right")
    summary.add_column("Baseline",    justify="right", style="dim")
    summary.add_column("vs Baseline", justify="right")

    median_s   = median(times) if times else 0.0
    baseline_s = 35 * 60   # ~35 min estimated manual triage

    def improvement(actual_s: float) -> str:
        pct = (baseline_s - actual_s) / baseline_s * 100
        return f"[green]↓{pct:.0f}%[/green]" if pct > 0 else "—"

    summary.add_row("Scenarios run",       str(n),                          "—",         "—")
    summary.add_row("Completed",           f"{len(completed)}/{n}",         "—",         "—")
    summary.add_row("Median time-to-RCA",  f"{median_s:.1f}s",              "~35 min",   improvement(median_s))
    summary.add_row("RCA accuracy",        avg("rca_accuracy"),             "—",         "—")
    summary.add_row("Evidence quality",    avg("evidence_quality"),         "—",         "—")
    summary.add_row("Actionability",       avg("actionability"),            "—",         "—")
    summary.add_row("PII compliance",      avg("pii_compliance"),           "100%",      "✓" if float(avg("pii_compliance")) == 1.0 else "[red]✗[/red]")
    summary.add_row("Citation integrity",  avg("citation_integrity"),       "—",         "—")
    summary.add_row("Overall score",       avg("overall_score"),            "—",         "—")

    console.print(summary)


# Persistence 

def save_results(results: list[EvalResult], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [
        {
            "scenario_id":           r.scenario_id,
            "scenario_name":         r.scenario_name,
            "rca_accuracy":          r.rca_accuracy,
            "evidence_quality":      r.evidence_quality,
            "actionability":         r.actionability,
            "reliability":           r.reliability,
            "pii_compliance":        r.pii_compliance,
            "citation_integrity":    r.citation_integrity,
            "overall_score":         r.overall_score,
            "elapsed_seconds":       r.elapsed_seconds,
            "postmortem_confidence": r.postmortem_confidence,
            "notes":                 r.notes,
        }
        for r in results
    ]
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    console = Console()
    console.print(f"\n[green]Results saved →[/green] {path}")



async def main(scenario_ids: list[str], output: Path | None) -> None:
    console = Console()

    scenarios = (
        [SCENARIO_MAP[sid] for sid in scenario_ids if sid in SCENARIO_MAP]
        if scenario_ids else ALL_SCENARIOS
    )

    if not scenarios:
        console.print("[red]No matching scenario IDs found.[/red]")
        console.print(f"Available: {', '.join(SCENARIO_MAP)}")
        sys.exit(1)

    console.print(f"\n[bold cyan]Running {len(scenarios)} scenario(s)...[/bold cyan]\n")

    results: list[EvalResult] = []
    for i, scenario in enumerate(scenarios, 1):
        console.print(f"  [{i}/{len(scenarios)}] [bold]{scenario.id}[/bold] — {scenario.name}")
        result = await _run_scenario(scenario)
        results.append(result)
        icon = "[green]✓[/green]" if result.reliability == 1.0 else "[red]✗[/red]"
        console.print(f"           {icon}  score={result.overall_score:.2f}  time={result.elapsed_seconds}s\n")

    console.print()
    render_table(results, console)

    out_path = output or (RESULTS_DIR / "run_latest.json")
    save_results(results, out_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run ENS benchmark suite")
    parser.add_argument("--ids",    nargs="*", default=[],
                        help="Scenario IDs to run (default: all 20)")
    parser.add_argument("--output", type=Path, default=None,
                        help="Path to save results JSON (default: benchmarks/results/run_latest.json)")
    args = parser.parse_args()

    asyncio.run(main(scenario_ids=args.ids, output=args.output))
