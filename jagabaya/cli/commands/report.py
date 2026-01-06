"""
Report commands for Jagabaya CLI.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console

app = typer.Typer(help="Generate and manage reports")
console = Console()


@app.command("generate")
def report_generate(
    session_id: str = typer.Argument(..., help="Session ID to generate report from"),
    format: str = typer.Option(
        "markdown",
        "--format",
        "-f",
        help="Report format (markdown, html, pdf)",
    ),
    output: str = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path",
    ),
):
    """Generate a report from a session."""
    from jagabaya.core.session import SessionManager
    from jagabaya.reports.generator import ReportGenerator, ReportConfig
    
    # Validate format
    if format not in ("markdown", "html", "pdf"):
        console.print(f"[red]Invalid format: {format}. Use markdown, html, or pdf[/]")
        raise typer.Exit(1)
    
    # Check for PDF dependencies
    if format == "pdf":
        try:
            import fpdf
        except ImportError:
            console.print("[red]PDF export requires fpdf2. Install it with:[/]")
            console.print("  pip install fpdf2")
            raise typer.Exit(1)

    # Load session
    manager = SessionManager()
    session = manager.load_session(session_id)

    if not session:
        console.print(f"[red]Session '{session_id}' not found[/]")
        raise typer.Exit(1)

    console.print(f"[bold]Generating {format} report for session {session_id}...[/]")
    
    # Generate report
    config = ReportConfig()
    generator = ReportGenerator(config)
    report_data = generator.generate(session)
    
    # Determine output path
    if output:
        output_path = Path(output)
    else:
        ext = "md" if format == "markdown" else format
        output_path = manager.get_session_dir(session) / f"report.{ext}"
    
    # Save report
    saved_path = generator.save(report_data, output_path, format)

    console.print(f"[green]Report saved to: {saved_path}[/]")


@app.command("view")
def report_view(
    session_id: str = typer.Argument(..., help="Session ID"),
):
    """View a session's report."""
    from jagabaya.core.session import SessionManager
    from rich.markdown import Markdown

    manager = SessionManager()
    session_dir = manager.output_dir / session_id

    # Look for report files
    report_files = [
        session_dir / "report.md",
        session_dir / "report.html",
    ]

    for report_file in report_files:
        if report_file.exists():
            with open(report_file) as f:
                content = f.read()

            if report_file.suffix == ".md":
                console.print(Markdown(content))
            else:
                console.print(content)
            return

    console.print(f"[yellow]No report found for session {session_id}[/]")
    console.print("Run 'jagabaya report generate' to create one.")


@app.command("export")
def report_export(
    session_id: str = typer.Argument(..., help="Session ID"),
    format: str = typer.Option(
        "json",
        "--format",
        "-f",
        help="Export format (json, csv)",
    ),
    output: str = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path",
    ),
):
    """Export findings from a session."""
    from jagabaya.core.session import SessionManager

    manager = SessionManager()
    session = manager.load_session(session_id)

    if not session:
        console.print(f"[red]Session '{session_id}' not found[/]")
        raise typer.Exit(1)

    content = manager.export_findings(session, format)

    if output:
        output_path = Path(output)
        with open(output_path, "w") as f:
            f.write(content)
        console.print(f"[green]Exported to: {output_path}[/]")
    else:
        console.print(content)


@app.command("summary")
def report_summary(
    session_id: str = typer.Argument(..., help="Session ID"),
):
    """Show a quick summary of findings."""
    from jagabaya.core.session import SessionManager
    from rich.table import Table

    manager = SessionManager()
    session = manager.load_session(session_id)

    if not session:
        console.print(f"[red]Session '{session_id}' not found[/]")
        raise typer.Exit(1)

    # Summary table
    summary = session.get_findings_summary()

    table = Table(title=f"Findings Summary - {session_id}")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")

    colors = {
        "critical": "red",
        "high": "orange1",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    for severity, count in [
        ("critical", summary.critical),
        ("high", summary.high),
        ("medium", summary.medium),
        ("low", summary.low),
        ("info", summary.info),
    ]:
        if count > 0:
            table.add_row(
                f"[{colors[severity]}]{severity.upper()}[/]",
                str(count),
            )

    table.add_row("[bold]Total[/]", f"[bold]{summary.total}[/]")

    console.print(table)

    # Top findings
    if session.findings:
        console.print("\n[bold]Top Findings:[/]")
        for finding in session.findings[:10]:
            color = colors.get(finding.severity.value, "white")
            console.print(f"  [{color}][{finding.severity.value.upper()}][/] {finding.title}")
