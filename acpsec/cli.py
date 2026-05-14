"""ACP-SEC CLI — acpsec check / inject / report."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from .agent_client import AgentClient
from .checks import (
    run_auth_checks,
    run_context_checks,
    run_governance_checks,
    run_input_validation_checks,
    run_output_safety_checks,
    run_privilege_checks,
)
from .config_loader import load_config
from .injection import InjectionRunner
from .injection.payloads import CATEGORIES
from .models import AgentConfig, DimensionResult
from .reporter import print_assessment, print_injection_report, save_json
from .scorer import ScoringEngine

console = Console()

DIMENSION_RUNNERS = {
    "auth": ("AUTH", "Authentication & Identity", run_auth_checks),
    "ctx": ("CTX", "Context Integrity", run_context_checks),
    "inj": ("INJ", "Input Validation & Injection Resistance", run_input_validation_checks),
    "priv": ("PRIV", "Privilege & Tool Authorization", run_privilege_checks),
    "out": ("OUT", "Output Safety & Leakage Prevention", run_output_safety_checks),
    "gov": ("GOV", "Governance, Audit & Observability", run_governance_checks),
}

MAX_SCORES = {"AUTH": 15, "CTX": 20, "INJ": 20, "PRIV": 20, "OUT": 15, "GOV": 10}


@click.group()
@click.version_option("0.1.0", prog_name="acpsec")
def main() -> None:
    """ACP-SEC: AI Agent Security Assessment Framework."""


# ---------------------------------------------------------------------------
# acpsec check
# ---------------------------------------------------------------------------
@main.command()
@click.option(
    "--config", "-c",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to agent YAML config file.",
)
@click.option(
    "--dim", "-d",
    multiple=True,
    type=click.Choice(list(DIMENSION_RUNNERS.keys()) + ["all"]),
    default=["all"],
    show_default=True,
    help="Dimension(s) to check. Use 'all' for full assessment.",
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Save results to JSON file.",
)
@click.option(
    "--no-live",
    is_flag=True,
    default=False,
    help="Skip checks that require live API calls (static analysis only).",
)
def check(config: Path, dim: tuple[str, ...], output: Path | None, no_live: bool) -> None:
    """Run security checks against an AI agent."""
    try:
        cfg = load_config(config)
    except Exception as e:
        console.print(f"[red]Failed to load config: {e}[/red]")
        sys.exit(1)

    console.print(f"\n[bold]ACP-SEC[/bold] checking [cyan]{cfg.name}[/cyan]...")

    client = AgentClient(cfg)

    if not no_live:
        console.print("[dim]Verifying agent connectivity...[/dim]")
        if not client.health_check():
            console.print("[yellow]Warning: Agent health check failed. Proceeding with static checks.[/yellow]")

    selected_dims = set(DIMENSION_RUNNERS.keys()) if "all" in dim else set(dim)
    dimension_results: list[DimensionResult] = []

    for key, (dim_id, dim_name, runner_fn) in DIMENSION_RUNNERS.items():
        if key not in selected_dims:
            continue
        console.print(f"  [dim]Checking {dim_id}...[/dim]", end="\r")
        try:
            result = runner_fn(cfg, client)
        except Exception as e:
            console.print(f"  [red]Error in {dim_id}: {e}[/red]")
            continue
        dimension_results.append(result)

    engine = ScoringEngine()
    assessment = engine.build_assessment(
        agent_name=cfg.name,
        agent_version=cfg.version,
        dimension_results=dimension_results,
        metadata={"config_path": str(config), "environment": cfg.environment},
    )

    print_assessment(assessment)

    if output:
        save_json(assessment, output)


# ---------------------------------------------------------------------------
# acpsec inject
# ---------------------------------------------------------------------------
@main.command()
@click.option(
    "--config", "-c",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Path to agent YAML config file.",
)
@click.option(
    "--suite", "-s",
    type=click.Choice(["full"] + list(CATEGORIES.keys())),
    default="full",
    show_default=True,
    help="Injection test suite to run.",
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Save results to JSON file.",
)
@click.option(
    "--delay",
    type=float,
    default=0.5,
    show_default=True,
    help="Delay between payloads in seconds (rate limiting).",
)
def inject(config: Path, suite: str, output: Path | None, delay: float) -> None:
    """Run the injection test suite against an AI agent."""
    try:
        cfg = load_config(config)
    except Exception as e:
        console.print(f"[red]Failed to load config: {e}[/red]")
        sys.exit(1)

    categories = None if suite == "full" else [suite]
    payload_count = sum(
        len(v) for k, v in __import__(
            "acpsec.injection.payloads", fromlist=["CATEGORIES"]
        ).CATEGORIES.items()
        if categories is None or k in categories
    )

    console.print(
        f"\n[bold]ACP-SEC Injection Suite[/bold] — "
        f"[cyan]{cfg.name}[/cyan]  ({payload_count} payloads, suite={suite})\n"
    )

    client = AgentClient(cfg)
    runner = InjectionRunner(cfg, client)

    with console.status("[dim]Running injection tests...[/dim]"):
        result = runner.run(categories=categories, delay_seconds=delay)

    print_injection_report(result)

    if output:
        save_json(result, output)


# ---------------------------------------------------------------------------
# acpsec report
# ---------------------------------------------------------------------------
@main.command()
@click.argument("results_json", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--format", "-f",
    "fmt",
    type=click.Choice(["terminal", "json"]),
    default="terminal",
    show_default=True,
)
def report(results_json: Path, fmt: str) -> None:
    """Display a saved results JSON file."""
    import json

    data = json.loads(results_json.read_text())

    if fmt == "json":
        console.print_json(results_json.read_text())
        return

    # Detect type: assessment vs injection
    if "dimensions" in data:
        from .models import AssessmentResult
        result = AssessmentResult(**data)
        print_assessment(result)
    elif "results" in data and "resistance_score" in data:
        from .models import InjectionSuiteResult
        result = InjectionSuiteResult(**data)
        print_injection_report(result)
    else:
        console.print("[red]Unrecognized results format.[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
