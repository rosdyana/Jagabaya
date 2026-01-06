"""
Session management commands for Jagabaya CLI.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Session management")
console = Console()


@app.command("list")
def session_list(
    resumable: bool = typer.Option(False, "--resumable", "-r", help="Show only resumable sessions"),
):
    """List all saved sessions."""
    from jagabaya.core.session import SessionManager
    from jagabaya.core.storage import SessionStorage
    from jagabaya.models.config import JagabayaConfig

    config = JagabayaConfig.load()
    storage = SessionStorage(config.output.output_dir)

    if resumable:
        sessions = storage.get_resumable_sessions()
        title = "Resumable Sessions"
    else:
        sessions = storage.list_sessions(limit=20)
        title = "Saved Sessions"

    if not sessions:
        if resumable:
            console.print("[dim]No resumable sessions found[/]")
        else:
            # Fall back to JSON-based session list
            manager = SessionManager(output_dir=config.output.output_dir)
            json_sessions = manager.list_sessions()
            if not json_sessions:
                console.print("[dim]No sessions found[/]")
                return

            table = Table(title=title, show_header=True)
            table.add_column("Session ID", style="bold")
            table.add_column("Target")
            table.add_column("Started")
            table.add_column("Phase")
            table.add_column("Findings", justify="right")

            for session in json_sessions:
                table.add_row(
                    session["session_id"],
                    session["target"],
                    session["started_at"][:19] if session["started_at"] else "N/A",
                    session["current_phase"],
                    str(session["findings_count"]),
                )

            console.print(table)
            return
        return

    table = Table(title=title, show_header=True)
    table.add_column("Session ID", style="bold")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Progress")
    table.add_column("Phase")
    table.add_column("Updated")

    status_colors = {
        "running": "yellow",
        "interrupted": "yellow",
        "completed": "green",
        "failed": "red",
        "cancelled": "dim",
    }

    for session in sessions:
        status = session["status"]
        color = status_colors.get(status, "white")
        progress = f"{session['current_step']}/{session['max_steps']}"

        # Add resume hint for resumable sessions
        status_display = f"[{color}]{status}[/]"
        if status in ("running", "interrupted"):
            status_display += " [dim](resumable)[/]"

        table.add_row(
            session["session_id"],
            session["target"],
            status_display,
            progress,
            session["current_phase"],
            session["updated_at"][:19] if session["updated_at"] else "N/A",
        )

    console.print(table)

    if resumable and sessions:
        console.print("\n[dim]Resume with:[/] [cyan]jagabaya scan resume <session_id>[/]")


@app.command("show")
def session_show(
    session_id: str = typer.Argument(..., help="Session ID to show"),
):
    """Show details of a session."""
    from jagabaya.core.session import SessionManager
    from rich.panel import Panel

    manager = SessionManager()
    session = manager.load_session(session_id)

    if not session:
        console.print(f"[red]Session '{session_id}' not found[/]")
        raise typer.Exit(1)

    # Session info
    duration = "In progress"
    if session.completed_at:
        dur = session.completed_at - session.started_at
        hours = int(dur.total_seconds() // 3600)
        mins = int((dur.total_seconds() % 3600) // 60)
        duration = f"{hours}h {mins}m"

    summary = session.get_findings_summary()

    content = f"""
[bold]Target:[/] {session.target}
[bold]Scope:[/] {", ".join(session.scope) if session.scope else session.target}
[bold]Phase:[/] {session.current_phase.value}
[bold]Started:[/] {session.started_at}
[bold]Duration:[/] {duration}

[bold]Findings:[/]
  Critical: {summary.critical}
  High: {summary.high}
  Medium: {summary.medium}
  Low: {summary.low}
  Info: {summary.info}
  Total: {summary.total}

[bold]Tools Run:[/] {len(session.tool_executions)}
[bold]AI Decisions:[/] {len(session.ai_decisions)}
[bold]Assets Discovered:[/] {len(session.discovered_assets)}
"""

    console.print(Panel(content, title=f"[bold]Session: {session_id}[/]"))


@app.command("delete")
def session_delete(
    session_id: str = typer.Argument(..., help="Session ID to delete"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
):
    """Delete a session."""
    from jagabaya.core.session import SessionManager

    manager = SessionManager()

    if not force:
        confirm = typer.confirm(f"Delete session {session_id}?")
        if not confirm:
            console.print("[yellow]Cancelled[/]")
            return

    if manager.delete_session(session_id):
        console.print(f"[green]Deleted session: {session_id}[/]")
    else:
        console.print(f"[red]Session '{session_id}' not found[/]")


@app.command("clean")
def session_clean(
    days: int = typer.Option(30, "--days", "-d", help="Delete sessions older than N days"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
):
    """Clean old sessions."""
    from datetime import datetime, timedelta
    from jagabaya.core.session import SessionManager

    manager = SessionManager()
    sessions = manager.list_sessions()

    cutoff = datetime.now() - timedelta(days=days)
    old_sessions = []

    for session in sessions:
        started = session.get("started_at")
        if started:
            try:
                started_dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
                if started_dt < cutoff:
                    old_sessions.append(session["session_id"])
            except (ValueError, TypeError):
                pass

    if not old_sessions:
        console.print(f"[dim]No sessions older than {days} days[/]")
        return

    console.print(f"Found {len(old_sessions)} sessions older than {days} days")

    if not force:
        confirm = typer.confirm("Delete these sessions?")
        if not confirm:
            console.print("[yellow]Cancelled[/]")
            return

    for session_id in old_sessions:
        manager.delete_session(session_id)
        console.print(f"  Deleted: {session_id}")

    console.print(f"[green]Cleaned {len(old_sessions)} sessions[/]")


@app.command("export")
def session_export(
    session_id: str = typer.Argument(..., help="Session ID to export"),
    output: str = typer.Option(None, "--output", "-o", help="Output file path"),
):
    """Export a session to JSON."""
    import json
    from jagabaya.core.session import SessionManager

    manager = SessionManager()
    session = manager.load_session(session_id)

    if not session:
        console.print(f"[red]Session '{session_id}' not found[/]")
        raise typer.Exit(1)

    data = session.model_dump(mode="json")
    content = json.dumps(data, indent=2, default=str)

    if output:
        output_path = Path(output)
        with open(output_path, "w") as f:
            f.write(content)
        console.print(f"[green]Exported to: {output_path}[/]")
    else:
        console.print(content)
