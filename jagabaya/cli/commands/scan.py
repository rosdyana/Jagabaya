"""
Scan commands for Jagabaya CLI.
"""

from __future__ import annotations

import asyncio
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
    
    asyncio.run(run_scan(
        target=target,
        scope=scope or [],
        blacklist=blacklist or [],
        max_steps=max_steps,
        safe_mode=safe_mode,
        output_dir=output_dir,
        verbose=verbose,
    ))


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
):
    """Resume a previous scan session."""
    console.print(f"[yellow]Resuming session: {session_id}[/]")
    # TODO: Implement session resume
    console.print("[red]Session resume not yet implemented[/]")


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
    from jagabaya.core.orchestrator import Orchestrator
    from jagabaya.cli.ui.progress import ScanProgress
    
    # Load or create config
    config = JagabayaConfig.from_env()
    
    # Override with CLI options
    config.scan.safe_mode = safe_mode
    config.output.output_dir = output_dir
    
    if model:
        config.llm.model = model
    if provider:
        config.llm.provider = provider
    
    # Check for API key
    if not config.llm.api_key:
        console.print("[red]Error: No API key configured![/]")
        console.print("Set OPENAI_API_KEY, ANTHROPIC_API_KEY, or another provider's key.")
        console.print("Or run: jagabaya config set llm.api_key YOUR_KEY")
        raise typer.Exit(1)
    
    # Show scan info
    console.print(Panel.fit(
        f"[bold]Target:[/] {target}\n"
        f"[bold]Scope:[/] {', '.join(scope) if scope else target}\n"
        f"[bold]Safe Mode:[/] {'Enabled' if safe_mode else 'Disabled'}\n"
        f"[bold]Model:[/] {config.llm.get_model_string()}\n"
        f"[bold]Max Steps:[/] {max_steps}",
        title="[bold blue]Scan Configuration[/]",
    ))
    
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
    
    # Create and run orchestrator
    orchestrator = Orchestrator(
        config=config,
        on_finding=on_finding,
        on_progress=on_progress,
        on_action=on_action,
        verbose=verbose,
    )
    
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
        orchestrator.stop()
    except Exception as e:
        console.print(f"\n[red]Error during scan: {e}[/]")
        if verbose:
            console.print_exception()
        raise typer.Exit(1)


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
