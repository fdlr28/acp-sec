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
    run_mcp_checks,
    run_output_safety_checks,
    run_plugin_checks,
    run_privilege_checks,
    run_x402_checks,
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

OPTIONAL_DIMENSION_RUNNERS = {
    "x402":   ("X402",   "x402 Protocol Posture",   run_x402_checks),
    "mcp":    ("MCP",    "MCP Server Security",     run_mcp_checks),
    "plugin": ("PLUGIN", "Skill-Plugin Security",   run_plugin_checks),
}

MAX_SCORES = {"AUTH": 15, "CTX": 20, "INJ": 20, "PRIV": 20, "OUT": 15, "GOV": 10}


@click.group()
@click.version_option("0.3.1", prog_name="acpsec")
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
@click.option(
    "--x402",
    "x402_only",
    is_flag=True,
    default=False,
    help="Run ONLY the X402 dimension. Requires x402.enabled in the YAML.",
)
@click.option(
    "--azul",
    "azul_only",
    is_flag=True,
    default=False,
    help="Run ONLY the X402-AZUL-01 multiproof-finality check.",
)
@click.option(
    "--skip-x402",
    is_flag=True,
    default=False,
    help="Force-skip the X402 dimension even if x402.enabled is true.",
)
@click.option(
    "--mcp",
    "mcp_only",
    is_flag=True,
    default=False,
    help="Run ONLY the MCP dimension. Requires mcp.enabled in the YAML.",
)
@click.option(
    "--skip-mcp",
    is_flag=True,
    default=False,
    help="Force-skip the MCP dimension even if mcp.enabled is true.",
)
@click.option(
    "--plugin",
    "plugin_only",
    is_flag=True,
    default=False,
    help="Run ONLY the PLUGIN dimension. Requires plugin.enabled in the YAML.",
)
@click.option(
    "--skip-plugin",
    is_flag=True,
    default=False,
    help="Force-skip the PLUGIN dimension even if plugin.enabled is true.",
)
def check(
    config: Path,
    dim: tuple[str, ...],
    output: Path | None,
    no_live: bool,
    x402_only: bool,
    azul_only: bool,
    skip_x402: bool,
    mcp_only: bool,
    skip_mcp: bool,
    plugin_only: bool,
    skip_plugin: bool,
) -> None:
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

    # --x402 / --azul / --mcp / --plugin are mutually exclusive shortcuts.
    if sum([x402_only, azul_only, mcp_only, plugin_only]) > 1:
        console.print(
            "[red]--x402, --azul, --mcp, and --plugin are mutually exclusive.[/red]"
        )
        sys.exit(2)

    if x402_only or azul_only or mcp_only or plugin_only:
        # Skip the standard 6 dimensions entirely.
        selected_dims: set[str] = set()
    else:
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

    # X402 dimension — opt-in, runs only when cfg.x402.enabled (unless --skip-x402).
    if not skip_x402 and (cfg.x402.enabled or x402_only or azul_only):
        if not cfg.x402.enabled:
            console.print(
                "[yellow]--x402/--azul requested but x402.enabled is false in "
                "the YAML. Set x402.enabled: true to run the dimension.[/yellow]"
            )
        else:
            console.print(f"  [dim]Checking X402...[/dim]", end="\r")
            try:
                x402_result = run_x402_checks(cfg, client)
                if azul_only:
                    # Filter down to just the AZUL check (max_score becomes 1).
                    azul = [c for c in x402_result.checks if c.check_id == "X402-AZUL-01"]
                    x402_result.checks = azul
                    x402_result.score = sum(c.score for c in azul)
                    x402_result.max_score = sum(c.max_score for c in azul)
                dimension_results.append(x402_result)
            except Exception as e:
                console.print(f"  [red]Error in X402: {e}[/red]")

    # MCP dimension — opt-in, runs only when cfg.mcp.enabled (unless --skip-mcp).
    if not skip_mcp and (cfg.mcp.enabled or mcp_only):
        if not cfg.mcp.enabled:
            console.print(
                "[yellow]--mcp requested but mcp.enabled is false in "
                "the YAML. Set mcp.enabled: true to run the dimension.[/yellow]"
            )
        else:
            console.print(f"  [dim]Checking MCP...[/dim]", end="\r")
            try:
                mcp_result = run_mcp_checks(cfg, client)
                dimension_results.append(mcp_result)
            except Exception as e:
                console.print(f"  [red]Error in MCP: {e}[/red]")

    # PLUGIN dimension — opt-in, runs only when cfg.plugin.enabled.
    if not skip_plugin and (cfg.plugin.enabled or plugin_only):
        if not cfg.plugin.enabled:
            console.print(
                "[yellow]--plugin requested but plugin.enabled is false in "
                "the YAML. Set plugin.enabled: true to run the dimension.[/yellow]"
            )
        else:
            console.print(f"  [dim]Checking PLUGIN...[/dim]", end="\r")
            try:
                plugin_result = run_plugin_checks(cfg, client)
                dimension_results.append(plugin_result)
            except Exception as e:
                console.print(f"  [red]Error in PLUGIN: {e}[/red]")

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


# ---------------------------------------------------------------------------
# acpsec monitor (subcommand group)
# ---------------------------------------------------------------------------
@main.group()
def monitor() -> None:
    """Continuous monitoring — watchlist, scheduled scans, drift alerts."""


@monitor.command("add")
@click.argument("url")
@click.option(
    "--schedule", "-s",
    type=click.Choice(["hourly", "daily", "weekly"]),
    default="daily",
    show_default=True,
    help="How often to scan this agent.",
)
@click.option(
    "--db",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to the monitor SQLite database.",
)
def monitor_add(url: str, schedule: str, db: Path | None) -> None:
    """Add an agent URL to the watchlist."""
    from .monitor import Monitor
    mon = Monitor(db)
    entry = mon.add_agent(url, schedule)
    mon.close()
    console.print(f"[green]Added[/green] {url} (schedule: {schedule})")


@monitor.command("list")
@click.option(
    "--db",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to the monitor SQLite database.",
)
def monitor_list(db: Path | None) -> None:
    """List all agents on the watchlist."""
    from .monitor import Monitor
    mon = Monitor(db)
    agents = mon.list_agents()
    mon.close()

    if not agents:
        console.print("[dim]Watchlist is empty. Use 'acpsec monitor add <url>' to add agents.[/dim]")
        return

    console.print(f"\n[bold]Watchlist[/bold] ({len(agents)} agents)\n")
    for agent in agents:
        score_str = f"{agent.last_score}" if agent.last_score is not None else "—"
        last_scan = "Never" if agent.last_scan is None else f"{agent.last_scan:.0f}"
        status = "[green]active[/green]" if agent.enabled else "[dim]disabled[/dim]"
        console.print(
            f"  {agent.url:<50} {agent.schedule:<10} score={score_str:<8} "
            f"last_scan={last_scan:<20} {status}"
        )
    console.print()


@monitor.command("run")
@click.option(
    "--db",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to the monitor SQLite database.",
)
@click.option(
    "--webhook",
    type=str,
    default=None,
    help="Webhook URL for drift notifications (Discord/Slack/Telegram).",
)
def monitor_run(db: Path | None, webhook: str | None) -> None:
    """Manually trigger scans for all due agents."""
    from .monitor import Monitor
    mon = Monitor(db)
    due = mon.get_due_agents()

    if not due:
        console.print("[dim]No agents due for scanning.[/dim]")
        mon.close()
        return

    console.print(f"\n[bold]Scanning {len(due)} agent(s)...[/bold]\n")
    engine = ScoringEngine()

    for entry in due:
        console.print(f"  Scanning {entry.url}...", end=" ")
        try:
            cfg = load_config(entry.url)
            client = AgentClient(cfg)
            dim_results: list[DimensionResult] = []

            # Run base dimensions
            dim_results.extend([
                run_auth_checks(cfg, client),
                run_context_checks(cfg, client),
                run_input_validation_checks(cfg, client),
                run_privilege_checks(cfg, client),
                run_output_safety_checks(cfg, client),
                run_governance_checks(cfg, client),
            ])

            # Optional dimensions
            if cfg.x402.enabled:
                dim_results.append(run_x402_checks(cfg, client))
            if cfg.mcp.enabled:
                dim_results.append(run_mcp_checks(cfg, client))

            assessment = engine.build_assessment(cfg.name, cfg.version, dim_results)
            old_entry = mon.get_agent(entry.url)
            old_score = old_entry.last_score if old_entry else None

            record = mon.record_score(
                entry.url, assessment.score, assessment.max_score, assessment.band
            )

            console.print(
                f"[green]{assessment.band}[/green] "
                f"score={assessment.score}/{assessment.max_score}"
            )

            # Check if drift alert was created
            if old_score is not None and old_score - assessment.score > 10:
                console.print(
                    f"    [red]DRIFT ALERT: score dropped from {old_score} to "
                    f"{assessment.score} (−{old_score - assessment.score:.1f} pts)[/red]"
                )
                if webhook:
                    Monitor.send_webhook(
                        webhook,
                        title=f"ACP-SEC Drift Alert: {cfg.name}",
                        description=f"Score dropped from {old_score} to {assessment.score}",
                        fields={
                            "Agent": entry.url,
                            "Old Score": str(old_score),
                            "New Score": str(assessment.score),
                            "Band": assessment.band,
                        },
                    )

        except Exception as e:
            console.print(f"[red]ERROR: {e}[/red]")

    mon.close()
    console.print(f"\n[bold]Done.[/bold]\n")


@monitor.command("history")
@click.argument("url")
@click.option(
    "--limit", "-n",
    type=int,
    default=10,
    show_default=True,
    help="Number of history entries to show.",
)
@click.option(
    "--db",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to the monitor SQLite database.",
)
def monitor_history(url: str, limit: int, db: Path | None) -> None:
    """Show score history for an agent."""
    from .monitor import Monitor
    mon = Monitor(db)
    history = mon.get_history(url, limit)
    trust = mon.get_trust_index(url)
    alerts = mon.get_alerts(url)
    mon.close()

    if not history:
        console.print(f"[dim]No score history for {url}[/dim]")
        return

    console.print(f"\n[bold]Score History[/bold] — {url}\n")
    if trust is not None:
        console.print(f"  Trust Index (5-window avg): [cyan]{trust}[/cyan]\n")

    for record in history:
        from datetime import datetime
        ts = datetime.fromtimestamp(record.timestamp).strftime("%Y-%m-%d %H:%M")
        color = "green" if record.score >= 70 else "yellow" if record.score >= 50 else "red"
        console.print(
            f"  [{color}]{record.score:>6.1f}[/{color}] / {record.max_score}  "
            f"({record.band:<12})  {ts}"
        )

    if alerts:
        console.print(f"\n  [red]Drift Alerts:[/red]")
        for alert in alerts:
            ts = datetime.fromtimestamp(alert.timestamp).strftime("%Y-%m-%d %H:%M")
            console.print(
                f"    [red]−{alert.delta:.1f} pts[/red]  "
                f"{alert.old_score} → {alert.new_score}  ({ts})"
            )

    console.print()


if __name__ == "__main__":
    main()
