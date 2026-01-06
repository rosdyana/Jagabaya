"""
Progress tracking for Jagabaya CLI.

Provides live-updating progress displays using Rich.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
from typing import Generator

from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from jagabaya.models.findings import Finding


class ScanProgress:
    """
    Real-time progress tracker for security scans.
    
    Provides a live-updating display showing:
    - Current stage and progress
    - Recent AI actions
    - Findings summary
    - Tool execution status
    
    Example:
        >>> progress = ScanProgress(console)
        >>> with progress.live():
        ...     progress.update("Reconnaissance", 0.25)
        ...     progress.add_finding(finding)
        ...     progress.add_action("Running nmap", "nmap", "Port scanning")
    """
    
    def __init__(
        self,
        console: Console | None = None,
        max_actions: int = 5,
        max_findings: int = 8,
    ):
        """
        Initialize the progress tracker.
        
        Args:
            console: Rich console to use (creates new if not provided)
            max_actions: Maximum recent actions to display
            max_findings: Maximum recent findings to display
        """
        self.console = console or Console()
        self.max_actions = max_actions
        self.max_findings = max_findings
        
        # State
        self._stage: str = "Initializing"
        self._progress: float = 0.0
        self._started_at: datetime = datetime.now()
        
        # Recent items
        self._actions: list[dict] = []
        self._findings: list[Finding] = []
        self._findings_count: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        
        # Current tool
        self._current_tool: str | None = None
        self._tool_target: str | None = None
        
        # Live display
        self._live: Live | None = None
        
        # Progress bar
        self._progress_bar = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=self.console,
            transient=True,
        )
        self._task_id = self._progress_bar.add_task("Scanning...", total=100)
    
    @contextmanager
    def live(self) -> Generator[None, None, None]:
        """
        Context manager for live display.
        
        Example:
            >>> with progress.live():
            ...     # Progress updates happen in real-time
            ...     progress.update("Scanning", 0.5)
        """
        self._started_at = datetime.now()
        
        with Live(
            self._render(),
            console=self.console,
            refresh_per_second=4,
            transient=False,
        ) as live:
            self._live = live
            try:
                yield
            finally:
                self._live = None
    
    def update(self, stage: str, progress: float) -> None:
        """
        Update the current stage and progress.
        
        Args:
            stage: Current stage name (e.g., "Reconnaissance", "Scanning")
            progress: Progress percentage (0.0 to 1.0)
        """
        self._stage = stage
        self._progress = min(1.0, max(0.0, progress))
        self._progress_bar.update(self._task_id, completed=self._progress * 100)
        self._refresh()
    
    def add_finding(self, finding: Finding) -> None:
        """
        Add a new finding to the display.
        
        Args:
            finding: The security finding to add
        """
        self._findings.append(finding)
        
        # Update counts
        severity = finding.severity.value
        self._findings_count[severity] = self._findings_count.get(severity, 0) + 1
        
        # Keep only recent findings
        if len(self._findings) > self.max_findings:
            self._findings = self._findings[-self.max_findings:]
        
        self._refresh()
    
    def add_action(
        self,
        action: str,
        tool: str | None = None,
        reasoning: str = "",
    ) -> None:
        """
        Add an AI action to the display.
        
        Args:
            action: Action description
            tool: Tool being used (if any)
            reasoning: AI reasoning for this action
        """
        self._actions.append({
            "action": action,
            "tool": tool,
            "reasoning": reasoning,
            "timestamp": datetime.now(),
        })
        
        # Keep only recent actions
        if len(self._actions) > self.max_actions:
            self._actions = self._actions[-self.max_actions:]
        
        self._current_tool = tool
        self._refresh()
    
    def set_current_tool(self, tool: str, target: str) -> None:
        """
        Set the currently executing tool.
        
        Args:
            tool: Tool name
            target: Target being scanned
        """
        self._current_tool = tool
        self._tool_target = target
        self._refresh()
    
    def clear_current_tool(self) -> None:
        """Clear the current tool indicator."""
        self._current_tool = None
        self._tool_target = None
        self._refresh()
    
    def _refresh(self) -> None:
        """Refresh the live display if active."""
        if self._live:
            self._live.update(self._render())
    
    def _render(self) -> Panel:
        """Render the progress display."""
        # Create the layout
        content = []
        
        # Progress section
        progress_text = Text()
        progress_text.append(f"Stage: ", style="dim")
        progress_text.append(self._stage, style="bold cyan")
        progress_text.append(f"  ({self._progress * 100:.0f}%)", style="dim")
        
        elapsed = datetime.now() - self._started_at
        elapsed_str = self._format_elapsed(elapsed.total_seconds())
        progress_text.append(f"  |  Elapsed: ", style="dim")
        progress_text.append(elapsed_str, style="yellow")
        
        content.append(progress_text)
        content.append(Text())  # Spacer
        
        # Findings summary
        findings_text = self._render_findings_summary()
        content.append(findings_text)
        content.append(Text())  # Spacer
        
        # Current tool
        if self._current_tool:
            tool_text = Text()
            tool_text.append("Running: ", style="dim")
            tool_text.append(self._current_tool, style="bold magenta")
            if self._tool_target:
                tool_text.append(f" on {self._tool_target}", style="dim")
            content.append(tool_text)
            content.append(Text())  # Spacer
        
        # Recent actions
        if self._actions:
            actions_text = Text("Recent Actions:\n", style="bold")
            for action_info in reversed(self._actions[-3:]):
                action_time = action_info["timestamp"].strftime("%H:%M:%S")
                actions_text.append(f"  [{action_time}] ", style="dim")
                if action_info.get("tool"):
                    actions_text.append(f"[{action_info['tool']}] ", style="magenta")
                actions_text.append(f"{action_info['action']}\n")
            content.append(actions_text)
        
        # Recent findings
        if self._findings:
            content.append(Text())  # Spacer
            findings_list = Text("Recent Findings:\n", style="bold")
            for finding in reversed(self._findings[-3:]):
                severity_color = self._severity_color(finding.severity.value)
                findings_list.append(f"  [{finding.severity.value.upper()}] ", style=severity_color)
                findings_list.append(f"{finding.title[:50]}\n")
            content.append(findings_list)
        
        # Combine into panel
        return Panel(
            Group(*content),
            title="[bold blue]Jagabaya Scan Progress[/]",
            border_style="blue",
        )
    
    def _render_findings_summary(self) -> Text:
        """Render findings count summary."""
        text = Text()
        text.append("Findings: ", style="bold")
        
        parts = []
        if self._findings_count["critical"]:
            parts.append(f"[bold red]{self._findings_count['critical']} Critical[/]")
        if self._findings_count["high"]:
            parts.append(f"[red]{self._findings_count['high']} High[/]")
        if self._findings_count["medium"]:
            parts.append(f"[yellow]{self._findings_count['medium']} Medium[/]")
        if self._findings_count["low"]:
            parts.append(f"[blue]{self._findings_count['low']} Low[/]")
        if self._findings_count["info"]:
            parts.append(f"[dim]{self._findings_count['info']} Info[/]")
        
        if parts:
            return Text.from_markup("Findings: " + "  ".join(parts))
        else:
            return Text("Findings: None yet", style="dim")
    
    def _severity_color(self, severity: str) -> str:
        """Get Rich color for severity level."""
        colors = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }
        return colors.get(severity.lower(), "white")
    
    def _format_elapsed(self, seconds: float) -> str:
        """Format elapsed time."""
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            minutes = int(seconds // 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            return f"{hours}h {minutes}m"
    
    @property
    def findings_count(self) -> dict[str, int]:
        """Get the current findings count by severity."""
        return self._findings_count.copy()
    
    @property
    def total_findings(self) -> int:
        """Get total number of findings."""
        return sum(self._findings_count.values())
