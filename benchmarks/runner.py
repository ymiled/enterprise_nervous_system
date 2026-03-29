"""
Benchmark Runner
----------------
Runs the incident swarm against Log4Shell benchmark scenarios.

Seed files must be generated first:
    uv run python data/loaders/oracle_fetcher.py --token ghp_...
    uv run python data/loaders/log4shell_fetcher.py --token ghp_...

Usage:
    # Run all 12 scenarios
    uv run python benchmarks/runner.py

    # Run specific IDs
    uv run python benchmarks/runner.py --ids ls-01 ls-02

    # Save to custom path
    uv run python benchmarks/runner.py --output benchmarks/results/run.json
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

# Waits after a 429; also used when the swarm returns None (Critic failed to emit JSON).
# A short wait drains Groq's token-per-minute window so the retry has a clean budget.
_RETRY_WAITS = [30, 60, 120]  # seconds


async def _run_scenario(scenario: Scenario, start: float) -> EvalResult:
    """Single attempt — no sleeps. Retry logic lives in main() using time.sleep()."""
    from swarm.orchestrator import run_incident_analysis

    seed_overrides = {
        "LOGS_SEED_FILE":    str(scenario.logs_seed),
        "COMMITS_SEED_FILE": str(scenario.commits_seed),
        "TICKETS_SEED_FILE": str(scenario.tickets_seed),
    }

    try:
        pm = await run_incident_analysis(
            service=scenario.service,
            incident_time=scenario.incident_time,
            severity=scenario.severity,
            jira_project=scenario.jira_project,
            seed_overrides=seed_overrides,
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


def render_table(
    results: list[EvalResult],
    console: Console,
    manual_baseline_seconds: float | None = None,
) -> None:
    table = Table(
        title="Enterprise Nervous System — Benchmark Results",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("ID",            style="dim",     width=8)
    table.add_column("Scenario",                       width=40)
    table.add_column("RCA\nAcc.",     justify="right", width=6)
    table.add_column("Evid.\nQual.",  justify="right", width=6)
    table.add_column("Action\n-able", justify="right", width=7)
    table.add_column("Reli-\nable",   justify="right", width=6)
    table.add_column("PII\nSafe",     justify="right", width=5)
    table.add_column("Cit.\nInteg.",  justify="right", width=6)
    table.add_column("Reason\n-ing",  justify="right", width=7)
    table.add_column("Score",         justify="right", width=6)
    table.add_column("Time\n(s)",     justify="right", width=6)

    for r in results:
        table.add_row(
            r.scenario_id,
            r.scenario_name[:40],
            f"[{_style(r.rca_accuracy)}]{_fmt(r.rca_accuracy)}[/]",
            f"[{_style(r.evidence_quality)}]{_fmt(r.evidence_quality)}[/]",
            f"[{_style(r.actionability)}]{_fmt(r.actionability)}[/]",
            f"[{_style(r.reliability)}]{_fmt(r.reliability)}[/]",
            f"[{_style(r.pii_compliance)}]{_fmt(r.pii_compliance)}[/]",
            f"[{_style(r.citation_integrity)}]{_fmt(r.citation_integrity)}[/]",
            f"[{_style(r.reasoning_quality)}]{_fmt(r.reasoning_quality)}[/]",
            f"[bold]{_fmt(r.overall_score)}[/bold]",
            str(r.elapsed_seconds),
        )

    console.print(table)
    _render_summary(results, console, manual_baseline_seconds=manual_baseline_seconds)


def _render_summary(
    results: list[EvalResult],
    console: Console,
    manual_baseline_seconds: float | None = None,
) -> None:
    n         = len(results)
    completed = [r for r in results if r.reliability == 1.0]
    times     = [r.elapsed_seconds for r in completed]

    def avg(attr: str) -> str:
        return f"{mean(getattr(r, attr) for r in results):.3f}"

    median_s = median(times) if times else 0.0

    def improvement() -> str:
        if not manual_baseline_seconds:
            return "n/a"
        pct = (manual_baseline_seconds - median_s) / manual_baseline_seconds * 100
        return f"[green]↓{pct:.0f}%[/green]" if pct > 0 else "—"

    baseline_label = (
        f"{manual_baseline_seconds:.1f}s"
        if manual_baseline_seconds
        else "n/a"
    )

    summary = Table(title="Summary", box=box.SIMPLE, header_style="bold magenta")
    summary.add_column("Metric",      style="bold")
    summary.add_column("Value",       justify="right")
    summary.add_column("Baseline",    justify="right", style="dim")
    summary.add_column("vs Baseline", justify="right")

    summary.add_row("Scenarios run",       str(n),                    "—",         "—")
    summary.add_row("Completed",           f"{len(completed)}/{n}",   "—",         "—")
    summary.add_row("Median time-to-RCA",  f"{median_s:.1f}s",        baseline_label, improvement())
    summary.add_row("RCA accuracy",        avg("rca_accuracy"),        "—",    "—")
    summary.add_row("Evidence quality",    avg("evidence_quality"),    "—",    "—")
    summary.add_row("Actionability",       avg("actionability"),       "—",    "—")
    summary.add_row("PII compliance",      avg("pii_compliance"),      "100%", "✓")
    summary.add_row("Citation integrity",  avg("citation_integrity"),  "—",    "—")
    summary.add_row("Reasoning quality",   avg("reasoning_quality"),   "—",    "—")
    summary.add_row("Overall score",       avg("overall_score"),       "—",    "—")

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
            "reasoning_quality":     r.reasoning_quality,
            "overall_score":         r.overall_score,
            "elapsed_seconds":       r.elapsed_seconds,
            "postmortem_confidence": r.postmortem_confidence,
            "notes":                 r.notes,
        }
        for r in results
    ]
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    Console().print(f"\n[green]Results saved →[/green] {path}")


# Entry point

def main(
    scenario_ids: list[str],
    output: Path | None,
    manual_baseline_seconds: float | None,
) -> None:
    """
    Run each scenario in its own asyncio.run() call so that anyio cancel-scope
    teardown from one MCP stdio session cannot leak into the next scenario's
    event loop (a Windows anyio bug that kills session.initialize() on loop reuse).
    """
    console = Console()

    if scenario_ids:
        scenarios = [SCENARIO_MAP[sid] for sid in scenario_ids if sid in SCENARIO_MAP]
        missing   = [sid for sid in scenario_ids if sid not in SCENARIO_MAP]
        if missing:
            console.print(f"[yellow]Unknown IDs (skipped): {', '.join(missing)}[/yellow]")
    else:
        scenarios = ALL_SCENARIOS

    if not scenarios:
        console.print("[red]No scenarios to run.[/red]")
        console.print(f"Available: {', '.join(SCENARIO_MAP)}")
        sys.exit(1)

    console.print(f"\n[bold cyan]Running {len(scenarios)} scenario(s)...[/bold cyan]\n")

    results: list[EvalResult] = []
    for i, scenario in enumerate(scenarios, 1):
        console.print(f"  [{i}/{len(scenarios)}] [bold]{scenario.id}[/bold] — {scenario.name}")
        start = time.monotonic()
        result = None
        for attempt, wait in enumerate([0] + _RETRY_WAITS, start=1):
            if wait:
                console.print(f"  [retry] waiting {wait}s before attempt {attempt}...")
                time.sleep(wait)
            # Fresh event loop per attempt — prevents anyio cancel-scope leakage
            result = asyncio.run(_run_scenario(scenario, start))
            msg = result.notes or ""
            retriable = (
                "Swarm returned None" in msg
                or "429" in msg or "400" in msg or "403" in msg
                or "500" in msg or "502" in msg or "503" in msg
                or "rate_limit" in msg.lower()
                or "tool call validation" in msg.lower()
            ) and "401" not in msg
            if not retriable or attempt > len(_RETRY_WAITS):
                break
            console.print(f"  [retry] attempt {attempt} failed: {msg[:80]}")
        if result is None:
            result = failed_run(scenario, time.monotonic() - start, "all retries exhausted")
        results.append(result)
        icon = "[green]OK[/green]" if result.reliability == 1.0 else "[red]FAIL[/red]"
        console.print(f"           {icon}  score={result.overall_score:.2f}  time={result.elapsed_seconds}s\n")
        # Brief cooldown between scenarios to avoid Groq TPM exhaustion
        if i < len(scenarios):
            time.sleep(5)

    out_path = output or (RESULTS_DIR / "run_latest.json")
    save_results(results, out_path)

    console.print()
    render_table(results, console, manual_baseline_seconds=manual_baseline_seconds)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run ENS Log4Shell benchmark suite")
    parser.add_argument("--ids",    nargs="*", default=[],
                        help="Scenario IDs to run (default: all 12)")
    parser.add_argument("--output", type=Path, default=None,
                        help="Path to save results JSON")
    parser.add_argument(
        "--manual-baseline-seconds",
        type=float,
        default=None,
        help=(
            "Observed/manual median triage time in seconds. "
            "Use only measured data; no default assumption is applied."
        ),
    )
    args = parser.parse_args()

    main(
        scenario_ids=args.ids,
        output=args.output,
        manual_baseline_seconds=args.manual_baseline_seconds,
    )
