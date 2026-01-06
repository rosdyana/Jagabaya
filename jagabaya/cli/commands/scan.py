"""
Scan commands for Jagabaya CLI.
"""

from __future__ import annotations

import asyncio
import signal
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.live import Live

from jagabaya.models.config import JagabayaConfig, LLMConfig
from jagabaya.models.findings import Finding

app = typer.Typer(help="Run security scans")
console = Console()

# Global reference for signal handler
_current_orchestrator = None
_shutdown_requested = False


def _signal_handler(signum, frame):
    """Handle SIGINT/SIGTERM for graceful shutdown."""
    global _shutdown_requested

    if _shutdown_requested:
        # Second signal - force exit
        console.print("\n[red]Forced exit[/]")
        sys.exit(1)

    _shutdown_requested = True
    console.print("\n[yellow]Graceful shutdown requested (Ctrl+C again to force)[/]")

    if _current_orchestrator:
        _current_orchestrator.stop()


def _setup_signal_handlers():
    """Set up signal handlers for graceful shutdown."""
    # SIGINT is Ctrl+C
    signal.signal(signal.SIGINT, _signal_handler)

    # SIGTERM is sent by kill command (not available on Windows)
    if sys.platform != "win32":
        signal.signal(signal.SIGTERM, _signal_handler)


@app.command("run")
def scan_run(
    target: str = typer.Argument(..., help="Target to scan"),
    scope: Optional[list[str]] = typer.Option(None, "--scope", "-s"),
    blacklist: Optional[list[str]] = typer.Option(None, "--blacklist", "-b"),
    max_steps: int = typer.Option(100, "--max-steps", "-n"),
    safe_mode: bool = typer.Option(True, "--safe-mode/--no-safe-mode"),
    output_dir: str = typer.Option("./jagabaya_output", "--output-dir", "-o"),
    verbose: bool = typer.Option(False, "--verbose", "-V"),
):
    """Run an autonomous security scan."""
    from jagabaya.cli.ui.console import show_banner

    show_banner()

    asyncio.run(
        run_scan(
            target=target,
            scope=scope or [],
            blacklist=blacklist or [],
            max_steps=max_steps,
            safe_mode=safe_mode,
            output_dir=output_dir,
            verbose=verbose,
        )
    )


@app.command("quick")
def scan_quick(
    target: str = typer.Argument(..., help="Target to scan"),
    scan_type: str = typer.Option("recon", "--type", "-t"),
):
    """Run a quick pre-defined scan."""
    asyncio.run(run_quick_scan(target, scan_type))


@app.command("resume")
def scan_resume(
    session_id: str = typer.Argument(..., help="Session ID to resume"),
    max_steps: int = typer.Option(None, "--max-steps", "-n", help="Override max steps"),
    verbose: bool = typer.Option(False, "--verbose", "-V", help="Enable verbose output"),
):
    """Resume a previous scan session."""
    asyncio.run(resume_scan(session_id, max_steps, verbose))


async def run_scan(
    target: str,
    scope: list[str],
    blacklist: list[str],
    max_steps: int,
    safe_mode: bool,
    output_dir: str,
    verbose: bool,
    model: str | None = None,
    provider: str | None = None,
) -> None:
    """Run the main scan workflow."""
    global _current_orchestrator, _shutdown_requested

    from jagabaya.core.orchestrator import Orchestrator
    from jagabaya.cli.ui.progress import ScanProgress

    # Reset shutdown flag
    _shutdown_requested = False

    # Set up signal handlers
    _setup_signal_handlers()

    # Load or create config
    config = JagabayaConfig.load()

    # Override with CLI options
    config.scan.safe_mode = safe_mode
    config.output.directory = output_dir

    if model:
        config.llm.model = model
    if provider:
        config.llm.provider = provider

    # Check for API key
    if not config.llm.is_configured():
        provider = config.llm.provider
        env_var = f"{provider.upper()}_API_KEY"
        console.print(f"[red]Error: No API key configured for {provider}![/]")
        console.print(f"\nSet the API key using one of these methods:")
        console.print(f"  1. Environment variable: [cyan]export {env_var}=your-key[/]")
        console.print(f"  2. .env file: Add [cyan]{env_var}=your-key[/] to .env")
        console.print(f"  3. Config file: [cyan]jagabaya config set llm.api_key YOUR_KEY[/]")
        console.print(
            f"\nOr switch provider: [cyan]jagabaya run --provider ollama --model llama3 {target}[/]"
        )
        raise typer.Exit(1)

    # Show scan info
    console.print(
        Panel.fit(
            f"[bold]Target:[/] {target}\n"
            f"[bold]Scope:[/] {', '.join(scope) if scope else target}\n"
            f"[bold]Safe Mode:[/] {'Enabled' if safe_mode else 'Disabled'}\n"
            f"[bold]Model:[/] {config.llm.get_model_string()}\n"
            f"[bold]Max Steps:[/] {max_steps}",
            title="[bold blue]Scan Configuration[/]",
        )
    )

    # Create progress tracker
    progress = ScanProgress(console)

    # Callbacks
    findings_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    def on_finding(finding: Finding):
        severity = finding.severity.value
        findings_count[severity] = findings_count.get(severity, 0) + 1
        progress.add_finding(finding)

    def on_progress(stage: str, pct: float):
        progress.update(stage, pct)

    def on_action(action: str, data: dict):
        progress.add_action(action, data.get("tool"), data.get("reasoning", ""))

    # Create orchestrator and set global reference for signal handler
    orchestrator = Orchestrator(
        config=config,
        on_finding=on_finding,
        on_progress=on_progress,
        on_action=on_action,
        verbose=verbose,
    )
    _current_orchestrator = orchestrator

    try:
        with progress.live():
            result = await orchestrator.run(
                target=target,
                scope=scope if scope else None,
                blacklist=blacklist if blacklist else None,
                max_steps=max_steps,
            )

        # Show results
        console.print()
        show_results(result, findings_count)

        # Generate report if findings exist
        if result.findings:
            report_path = orchestrator.session_manager.output_dir / result.session_id / "report.md"
            report_content = await orchestrator.generate_report(format="markdown")

            with open(report_path, "w") as f:
                f.write(report_content)

            console.print(f"\n[green]Report saved to:[/] {report_path}")

        console.print(f"\n[green]Session data saved to:[/] {output_dir}/{result.session_id}/")

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/]")
        if orchestrator.current_session:
            session_id = orchestrator.current_session.session_id
            console.print("[dim]Session saved. Resume with:[/]")
            console.print(f"  [cyan]jagabaya scan resume {session_id}[/]")
        orchestrator.stop()
    except Exception as e:
        console.print(f"\n[red]Error during scan: {e}[/]")
        if verbose:
            console.print_exception()
        raise typer.Exit(1)
    finally:
        _current_orchestrator = None


async def run_quick_scan(target: str, scan_type: str) -> None:
    """Run a quick pre-defined scan without AI planning."""
    from jagabaya.tools.registry import ToolRegistry
    from jagabaya.cli.ui.progress import ScanProgress

    console.print(f"[bold]Running quick {scan_type} scan on {target}[/]")

    registry = ToolRegistry()
    registry.register_all()

    # Define quick scan workflows
    workflows = {
        "recon": ["subfinder", "httpx", "whatweb"],
        "web": ["httpx", "nuclei", "nikto"],
        "network": ["nmap", "masscan"],
        "full": ["subfinder", "httpx", "nmap", "nuclei", "nikto", "testssl"],
    }

    tools_to_run = workflows.get(scan_type, workflows["recon"])

    # Check tool availability
    available = []
    for tool_name in tools_to_run:
        tool = registry.get_tool(tool_name)
        if tool and tool.is_available:
            available.append(tool)
        else:
            console.print(f"[yellow]Warning: {tool_name} not available[/]")

    if not available:
        console.print("[red]No tools available for this scan type[/]")
        raise typer.Exit(1)

    # Run tools
    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Running scan...", total=len(available))

        for tool in available:
            progress.update(task, description=f"Running {tool.name}...")

            result = await tool.execute(target)
            results.append(result)

            status = "[green]OK[/]" if result.success else "[red]FAIL[/]"
            console.print(f"  {tool.name}: {status} ({result.duration:.1f}s)")

            progress.advance(task)

    # Show summary
    successful = sum(1 for r in results if r.success)
    console.print(f"\n[bold]Completed:[/] {successful}/{len(results)} tools succeeded")


async def resume_scan(
    session_id: str,
    max_steps: int | None,
    verbose: bool,
) -> None:
    """Resume an interrupted scan session."""
    global _current_orchestrator, _shutdown_requested

    from jagabaya.core.orchestrator import Orchestrator
    from jagabaya.core.storage import SessionStorage
    from jagabaya.cli.ui.console import show_banner
    from jagabaya.cli.ui.progress import ScanProgress

    # Reset shutdown flag
    _shutdown_requested = False

    # Set up signal handlers
    _setup_signal_handlers()

    show_banner()

    # Load config
    config = JagabayaConfig.load()

    # Check if session exists
    storage = SessionStorage(config.output.output_dir)
    info = storage.get_session_info(session_id)

    if not info:
        console.print(f"[red]Session '{session_id}' not found[/]")
        console.print("\nAvailable sessions:")
        sessions = storage.list_sessions(limit=10)
        if sessions:
            for s in sessions:
                status_color = {
                    "running": "yellow",
                    "interrupted": "yellow",
                    "completed": "green",
                    "failed": "red",
                }.get(s["status"], "dim")
                console.print(
                    f"  [{status_color}]{s['session_id']}[/] - {s['target']} ({s['status']})"
                )
        else:
            console.print("  [dim]No sessions found[/]")
        raise typer.Exit(1)

    if info["status"] not in ("running", "interrupted"):
        console.print(
            f"[red]Session '{session_id}' cannot be resumed (status: {info['status']})[/]"
        )
        raise typer.Exit(1)

    # Show session info
    console.print(
        Panel.fit(
            f"[bold]Session ID:[/] {info['session_id']}\n"
            f"[bold]Target:[/] {info['target']}\n"
            f"[bold]Status:[/] {info['status']}\n"
            f"[bold]Phase:[/] {info['current_phase']}\n"
            f"[bold]Progress:[/] Step {info['current_step']}/{info['max_steps']}\n"
            f"[bold]Started:[/] {info['started_at']}\n"
            f"[bold]Last Updated:[/] {info['updated_at']}",
            title="[bold blue]Resuming Session[/]",
        )
    )

    # Check for API key
    if not config.llm.is_configured():
        provider = config.llm.provider
        env_var = f"{provider.upper()}_API_KEY"
        console.print(f"[red]Error: No API key configured for {provider}![/]")
        raise typer.Exit(1)

    # Create progress tracker
    progress = ScanProgress(console)

    # Callbacks
    findings_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    def on_finding(finding: Finding):
        severity = finding.severity.value
        findings_count[severity] = findings_count.get(severity, 0) + 1
        progress.add_finding(finding)

    def on_progress(stage: str, pct: float):
        progress.update(stage, pct)

    def on_action(action: str, data: dict):
        progress.add_action(action, data.get("tool"), data.get("reasoning", ""))

    # Create orchestrator and set global reference for signal handler
    orchestrator = Orchestrator(
        config=config,
        on_finding=on_finding,
        on_progress=on_progress,
        on_action=on_action,
        verbose=verbose,
    )
    _current_orchestrator = orchestrator

    try:
        with progress.live():
            result = await orchestrator.resume(
                session_id=session_id,
                max_steps=max_steps,
            )

        # Show results
        console.print()
        show_results(result, findings_count)

        # Generate report if findings exist
        if result.findings:
            report_path = orchestrator.session_manager.output_dir / result.session_id / "report.md"
            report_content = await orchestrator.generate_report(format="markdown")

            with open(report_path, "w") as f:
                f.write(report_content)

            console.print(f"\n[green]Report saved to:[/] {report_path}")

        console.print(
            f"\n[green]Session data saved to:[/] {config.output.output_dir}/{result.session_id}/"
        )

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/]")
        console.print("[dim]Session saved. Resume with:[/]")
        console.print(f"  [cyan]jagabaya scan resume {session_id}[/]")
        orchestrator.stop()
    except Exception as e:
        console.print(f"\n[red]Error during scan: {e}[/]")
        if verbose:
            console.print_exception()
        raise typer.Exit(1)
    finally:
        _current_orchestrator = None


def show_results(result, findings_count: dict) -> None:
    """Display scan results."""
    from jagabaya.models.session import SessionResult

    # Findings summary table
    table = Table(title="Findings Summary", show_header=True)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")

    colors = {
        "critical": "red",
        "high": "orange1",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    for severity in ["critical", "high", "medium", "low", "info"]:
        count = findings_count.get(severity, 0)
        if count > 0:
            table.add_row(
                f"[{colors[severity]}]{severity.upper()}[/]",
                str(count),
            )

    table.add_row("[bold]Total[/]", f"[bold]{sum(findings_count.values())}[/]")

    console.print(table)

    # Top findings
    if result.findings:
        console.print("\n[bold]Top Findings:[/]")

        critical_high = [f for f in result.findings if f.severity.value in ["critical", "high"]]
        for finding in critical_high[:5]:
            color = colors.get(finding.severity.value, "white")
            console.print(f"  [{color}][{finding.severity.value.upper()}][/] {finding.title}")

    # Stats
    console.print(f"\n[dim]Tools run: {result.total_tools_run}[/]")
    console.print(f"[dim]AI decisions: {result.total_ai_calls}[/]")

    duration = result.completed_at - result.started_at
    console.print(f"[dim]Duration: {duration}[/]")
