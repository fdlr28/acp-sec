"""Rich terminal reporter and JSON output for ACP-SEC results."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from .models import (
    AssessmentResult,
    CheckStatus,
    DimensionResult,
    InjectionSuiteResult,
    Severity,
)

console = Console()

BAND_COLORS = {
    "SECURE": "bold green",
    "HARDENED": "green",
    "VULNERABLE": "yellow",
    "CRITICAL": "bold red",
    "COMPROMISED": "red on white",
}

STATUS_SYMBOLS = {
    CheckStatus.PASS: "[green]PASS[/green]",
    CheckStatus.FAIL: "[red]FAIL[/red]",
    CheckStatus.WARN: "[yellow]WARN[/yellow]",
    CheckStatus.SKIP: "[dim]SKIP[/dim]",
    CheckStatus.ERROR: "[bold red]ERR [/bold red]",
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "dim",
    Severity.INFO: "blue",
}


def print_assessment(result: AssessmentResult) -> None:
    band_color = BAND_COLORS.get(result.band, "white")

    console.print()
    console.print(
        Panel(
            f"[bold]{result.agent_name}[/bold] v{result.agent_version}\n"
            f"Score: [{band_color}]{result.final_score:.1f} / "
            f"{result.max_score:.0f}[/{band_color}]  "
            f"({result.score_pct:.1f}%)  "
            f"Band: [{band_color}]{result.band}[/{band_color}]\n"
            f"{result.verdict}",
            title="[bold]ACP-SEC Assessment Report[/bold]",
            border_style=band_color,
        )
    )

    for dim in result.dimensions:
        _print_dimension(dim)

    _print_summary(result)


def _print_dimension(dim: DimensionResult) -> None:
    pct = dim.score_pct
    color = "green" if pct >= 80 else "yellow" if pct >= 50 else "red"

    table = Table(
        title=f"[bold]{dim.dimension_id}[/bold] — {dim.name}  "
              f"[{color}]{dim.score:.1f}/{dim.max_score:.1f}[/{color}]",
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold",
    )
    table.add_column("ID", width=8)
    table.add_column("Check", min_width=40)
    table.add_column("Status", width=8)
    table.add_column("Score", width=10)
    table.add_column("Severity", width=10)

    for check in dim.checks:
        sev_color = SEVERITY_COLORS.get(check.severity, "white")
        table.add_row(
            check.check_id,
            check.name,
            STATUS_SYMBOLS.get(check.status, check.status),
            f"{check.score:.1f}/{check.max_score:.1f}",
            f"[{sev_color}]{check.severity.value}[/{sev_color}]",
        )

    console.print(table)


def _print_summary(result: AssessmentResult) -> None:
    failures = result.critical_failures
    if not failures:
        console.print("[green]No CRITICAL failures detected.[/green]\n")
        return

    console.print(f"\n[bold red]CRITICAL Failures ({len(failures)}):[/bold red]")
    for check in failures:
        console.print(f"  [red]• {check.check_id}[/red] {check.name}")
        for rec in check.recommendations[:2]:
            console.print(f"    [dim]→ {rec}[/dim]")
    console.print()


def print_injection_report(result: InjectionSuiteResult) -> None:
    color = "green" if result.resistance_score >= 80 else "yellow" if result.resistance_score >= 50 else "red"

    console.print()
    console.print(
        Panel(
            f"[bold]{result.agent_name}[/bold]\n"
            f"Resistance Score: [{color}]{result.resistance_score:.1f}/100[/{color}]\n"
            f"Injected: [red]{result.injected_count}[/red] / {result.total_tests} tests  "
            f"(Injection Rate: {result.injection_rate:.1f}%)",
            title="[bold]ACP-SEC Injection Test Report[/bold]",
            border_style=color,
        )
    )

    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold")
    table.add_column("ID", width=8)
    table.add_column("Category", width=18)
    table.add_column("Name", min_width=30)
    table.add_column("Result", width=12)
    table.add_column("Confidence", width=12)

    for r in result.results:
        status = "[red]INJECTED[/red]" if r.injected else "[green]BLOCKED[/green]"
        conf = f"{r.confidence:.0%}"
        table.add_row(r.test_id, r.category, r.payload[:50], status, conf)

    console.print(table)


def save_json(data: AssessmentResult | InjectionSuiteResult, output: str | Path) -> None:
    Path(output).write_text(json.dumps(data.model_dump(), indent=2, default=str))
    console.print(f"[dim]Results saved to {output}[/dim]")
