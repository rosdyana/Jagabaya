"""
Rich panels for Jagabaya CLI.

Provides styled panels for displaying various types of information.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree
from rich.console import Group

if TYPE_CHECKING:
    from jagabaya.models.findings import Finding
    from jagabaya.models.session import SessionState, SessionResult
    from jagabaya.models.tools import ToolResult


def create_scan_config_panel(
    target: str,
    scope: list[str] | None = None,
    blacklist: list[str] | None = None,
    safe_mode: bool = True,
    model: str = "",
    max_steps: int = 100,
) -> Panel:
    """
    Create a panel displaying scan configuration.
    
    Args:
        target: Primary target
        scope: In-scope targets
        blacklist: Out-of-scope targets
        safe_mode: Whether safe mode is enabled
        model: LLM model being used
        max_steps: Maximum steps
    
    Returns:
        Rich Panel with configuration info
    """
    content = []
    
    # Target info
    content.append(Text.from_markup(f"[bold]Target:[/] [cyan]{target}[/]"))
    
    # Scope
    if scope:
        scope_text = ", ".join(scope[:5])
        if len(scope) > 5:
            scope_text += f" (+{len(scope) - 5} more)"
        content.append(Text.from_markup(f"[bold]Scope:[/] {scope_text}"))
    
    # Blacklist
    if blacklist:
        blacklist_text = ", ".join(blacklist[:5])
        if len(blacklist) > 5:
            blacklist_text += f" (+{len(blacklist) - 5} more)"
        content.append(Text.from_markup(f"[bold]Blacklist:[/] {blacklist_text}"))
    
    # Options
    safe_mode_text = "[green]Enabled[/]" if safe_mode else "[red]Disabled[/]"
    content.append(Text.from_markup(f"[bold]Safe Mode:[/] {safe_mode_text}"))
    
    if model:
        content.append(Text.from_markup(f"[bold]Model:[/] {model}"))
    
    content.append(Text.from_markup(f"[bold]Max Steps:[/] {max_steps}"))
    
    return Panel(
        Group(*content),
        title="[bold blue]Scan Configuration[/]",
        border_style="blue",
    )


def create_findings_panel(
    findings: list["Finding"],
    title: str = "Findings",
    max_display: int = 10,
) -> Panel:
    """
    Create a panel displaying security findings.
    
    Args:
        findings: List of findings to display
        title: Panel title
        max_display: Maximum findings to show
    
    Returns:
        Rich Panel with findings
    """
    if not findings:
        return Panel(
            Text("No findings yet", style="dim"),
            title=f"[bold]{title}[/]",
            border_style="dim",
        )
    
    # Create table
    table = Table(show_header=True, header_style="bold", box=None)
    table.add_column("Sev", width=6)
    table.add_column("Title", overflow="ellipsis")
    table.add_column("Target", width=25, overflow="ellipsis")
    table.add_column("Tool", width=12)
    
    # Color mapping
    severity_styles = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }
    
    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        findings,
        key=lambda f: severity_order.get(f.severity.value, 5),
    )
    
    # Add rows
    for finding in sorted_findings[:max_display]:
        sev = finding.severity.value
        style = severity_styles.get(sev, "white")
        
        target_str = finding.target
        if finding.port:
            target_str += f":{finding.port}"
        
        table.add_row(
            Text(sev.upper()[:4], style=style),
            finding.title[:50],
            target_str[:25],
            finding.tool[:12],
        )
    
    if len(findings) > max_display:
        table.add_row(
            "",
            Text(f"... and {len(findings) - max_display} more", style="dim"),
            "",
            "",
        )
    
    # Summary line
    summary = _create_findings_summary_text(findings)
    
    return Panel(
        Group(table, Text(), summary),
        title=f"[bold]{title}[/] ({len(findings)} total)",
        border_style="yellow",
    )


def create_tool_result_panel(
    result: "ToolResult",
    show_output: bool = False,
    max_output_lines: int = 10,
) -> Panel:
    """
    Create a panel displaying tool execution result.
    
    Args:
        result: Tool execution result
        show_output: Whether to show raw output
        max_output_lines: Maximum output lines to display
    
    Returns:
        Rich Panel with tool result
    """
    content = []
    
    # Status
    if result.success:
        status = Text.from_markup("[green]Success[/]")
    else:
        status = Text.from_markup(f"[red]Failed[/]: {result.error_message or 'Unknown error'}")
    
    content.append(Text.from_markup(f"[bold]Status:[/] ") + status)
    content.append(Text.from_markup(f"[bold]Target:[/] {result.target}"))
    content.append(Text.from_markup(f"[bold]Duration:[/] {result.duration:.1f}s"))
    
    if result.exit_code is not None:
        content.append(Text.from_markup(f"[bold]Exit Code:[/] {result.exit_code}"))
    
    # Parsed data summary
    if result.parsed_data:
        data = result.parsed_data
        if isinstance(data, dict):
            content.append(Text())
            content.append(Text("Parsed Results:", style="bold"))
            for key, value in list(data.items())[:5]:
                if isinstance(value, list):
                    content.append(Text(f"  {key}: {len(value)} items", style="dim"))
                elif isinstance(value, dict):
                    content.append(Text(f"  {key}: {len(value)} keys", style="dim"))
                else:
                    content.append(Text(f"  {key}: {str(value)[:50]}", style="dim"))
    
    # Raw output (optional)
    if show_output and result.raw_output:
        content.append(Text())
        content.append(Text("Output:", style="bold"))
        lines = result.raw_output.split("\n")[:max_output_lines]
        for line in lines:
            content.append(Text(f"  {line[:100]}", style="dim"))
        if len(result.raw_output.split("\n")) > max_output_lines:
            content.append(Text(f"  ... (truncated)", style="dim italic"))
    
    # Border color based on status
    border_style = "green" if result.success else "red"
    
    return Panel(
        Group(*content),
        title=f"[bold]{result.tool}[/]",
        border_style=border_style,
    )


def create_session_panel(
    session: "SessionState | SessionResult",
    detailed: bool = False,
) -> Panel:
    """
    Create a panel displaying session information.
    
    Args:
        session: Session state or result
        detailed: Show detailed information
    
    Returns:
        Rich Panel with session info
    """
    content = []
    
    # Basic info
    content.append(Text.from_markup(f"[bold]Session ID:[/] {session.session_id}"))
    content.append(Text.from_markup(f"[bold]Target:[/] [cyan]{session.target}[/]"))
    
    # Timing
    if hasattr(session, "started_at"):
        started = session.started_at.strftime("%Y-%m-%d %H:%M:%S")
        content.append(Text.from_markup(f"[bold]Started:[/] {started}"))
    
    if hasattr(session, "completed_at") and session.completed_at:
        completed = session.completed_at.strftime("%Y-%m-%d %H:%M:%S")
        content.append(Text.from_markup(f"[bold]Completed:[/] {completed}"))
    
    # Phase (for SessionState)
    if hasattr(session, "current_phase"):
        content.append(Text.from_markup(
            f"[bold]Phase:[/] {session.current_phase.value}"
        ))
    
    # Status (for SessionResult)
    if hasattr(session, "status"):
        status_color = "green" if session.status == "completed" else "red"
        content.append(Text.from_markup(
            f"[bold]Status:[/] [{status_color}]{session.status}[/]"
        ))
    
    # Findings summary
    content.append(Text())
    if hasattr(session, "findings_summary"):
        summary = session.findings_summary
        content.append(Text.from_markup(
            f"[bold]Findings:[/] "
            f"[red]{summary.critical}C[/] "
            f"[red]{summary.high}H[/] "
            f"[yellow]{summary.medium}M[/] "
            f"[blue]{summary.low}L[/] "
            f"[dim]{summary.info}I[/]"
        ))
    elif hasattr(session, "findings"):
        summary = _count_findings_by_severity(session.findings)
        content.append(Text.from_markup(
            f"[bold]Findings:[/] "
            f"[red]{summary.get('critical', 0)}C[/] "
            f"[red]{summary.get('high', 0)}H[/] "
            f"[yellow]{summary.get('medium', 0)}M[/] "
            f"[blue]{summary.get('low', 0)}L[/] "
            f"[dim]{summary.get('info', 0)}I[/]"
        ))
    
    # Stats
    if detailed:
        content.append(Text())
        if hasattr(session, "tool_executions"):
            content.append(Text.from_markup(
                f"[bold]Tools Run:[/] {len(session.tool_executions)}"
            ))
        if hasattr(session, "ai_decisions"):
            content.append(Text.from_markup(
                f"[bold]AI Decisions:[/] {len(session.ai_decisions)}"
            ))
        if hasattr(session, "total_tokens"):
            content.append(Text.from_markup(
                f"[bold]Tokens Used:[/] {session.total_tokens:,}"
            ))
        if hasattr(session, "total_cost"):
            content.append(Text.from_markup(
                f"[bold]Est. Cost:[/] ${session.total_cost:.4f}"
            ))
    
    return Panel(
        Group(*content),
        title="[bold blue]Session Info[/]",
        border_style="blue",
    )


def create_tools_table(
    tools: dict[str, dict],
    show_unavailable: bool = True,
) -> Table:
    """
    Create a table displaying available tools.
    
    Args:
        tools: Dict of tool name -> tool info
        show_unavailable: Whether to show unavailable tools
    
    Returns:
        Rich Table with tool information
    """
    table = Table(show_header=True, header_style="bold")
    table.add_column("Tool", style="cyan")
    table.add_column("Category")
    table.add_column("Status", width=10)
    table.add_column("Description")
    
    for name, info in sorted(tools.items()):
        is_available = info.get("is_available", False)
        
        if not is_available and not show_unavailable:
            continue
        
        status = "[green]Ready[/]" if is_available else "[red]Missing[/]"
        category = info.get("category", "other")
        description = info.get("description", "")[:50]
        
        table.add_row(name, category, status, description)
    
    return table


def _create_findings_summary_text(findings: list["Finding"]) -> Text:
    """Create a summary text for findings."""
    counts = _count_findings_by_severity(findings)
    
    text = Text("Summary: ")
    parts = []
    
    if counts.get("critical", 0):
        parts.append(f"[bold red]{counts['critical']} Critical[/]")
    if counts.get("high", 0):
        parts.append(f"[red]{counts['high']} High[/]")
    if counts.get("medium", 0):
        parts.append(f"[yellow]{counts['medium']} Medium[/]")
    if counts.get("low", 0):
        parts.append(f"[blue]{counts['low']} Low[/]")
    if counts.get("info", 0):
        parts.append(f"[dim]{counts['info']} Info[/]")
    
    return Text.from_markup("Summary: " + " | ".join(parts))


def _count_findings_by_severity(findings: list["Finding"]) -> dict[str, int]:
    """Count findings by severity level."""
    counts: dict[str, int] = {}
    for finding in findings:
        sev = finding.severity.value
        counts[sev] = counts.get(sev, 0) + 1
    return counts
