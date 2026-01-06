"""
Console utilities for Jagabaya CLI.

Provides styled console output, banner display, and formatting utilities.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.style import Style
from rich.theme import Theme

from jagabaya import __version__


# Custom theme for Jagabaya
JAGABAYA_THEME = Theme({
    "info": "dim cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "target": "bold cyan",
    "tool": "bold magenta",
    "phase": "bold blue",
})

# Global console instance
console = Console(theme=JAGABAYA_THEME)


# ASCII art banner
BANNER = r"""
       __                  __                      
      / /___ _____ _____ _/ /_  ____ ___  ______ _
 __  / / __ `/ __ `/ __ `/ __ \/ __ `/ / / / __ `/
/ /_/ / /_/ / /_/ / /_/ / /_/ / /_/ / /_/ / /_/ / 
\____/\__,_/\__, /\__,_/_.___/\__,_/\__, /\__,_/  
           /____/                  /____/          
"""

TAGLINE = "AI-Powered Penetration Testing CLI"


def show_banner() -> None:
    """Display the Jagabaya ASCII art banner."""
    # Create styled banner
    banner_text = Text(BANNER, style="bold blue")
    
    # Create info line
    version_text = Text()
    version_text.append("v", style="dim")
    version_text.append(__version__, style="bold cyan")
    version_text.append(" | ", style="dim")
    version_text.append(TAGLINE, style="italic")
    
    console.print(banner_text)
    console.print(version_text, justify="center")
    console.print()


def show_scan_progress(
    target: str,
    phase: str,
    step: int,
    total_steps: int,
    findings_count: dict[str, int],
) -> None:
    """
    Display scan progress summary.
    
    Args:
        target: Current target
        phase: Current phase name
        step: Current step number
        total_steps: Maximum steps
        findings_count: Dict of severity -> count
    """
    progress_pct = (step / total_steps) * 100 if total_steps > 0 else 0
    
    # Create progress text
    text = Text()
    text.append(f"Target: ", style="dim")
    text.append(target, style="target")
    text.append(f"  |  Phase: ", style="dim")
    text.append(phase, style="phase")
    text.append(f"  |  Step: ", style="dim")
    text.append(f"{step}/{total_steps}", style="bold")
    text.append(f" ({progress_pct:.0f}%)", style="dim")
    
    # Add findings summary
    if any(findings_count.values()):
        text.append("  |  Findings: ", style="dim")
        parts = []
        if findings_count.get("critical", 0):
            parts.append(f"[critical]{findings_count['critical']}C[/]")
        if findings_count.get("high", 0):
            parts.append(f"[high]{findings_count['high']}H[/]")
        if findings_count.get("medium", 0):
            parts.append(f"[medium]{findings_count['medium']}M[/]")
        if findings_count.get("low", 0):
            parts.append(f"[low]{findings_count['low']}L[/]")
        console.print(text, end="")
        console.print(" ".join(parts))
    else:
        console.print(text)


def print_error(message: str, prefix: str = "Error") -> None:
    """Print an error message."""
    console.print(f"[error]{prefix}:[/] {message}")


def print_warning(message: str, prefix: str = "Warning") -> None:
    """Print a warning message."""
    console.print(f"[warning]{prefix}:[/] {message}")


def print_success(message: str, prefix: str = "Success") -> None:
    """Print a success message."""
    console.print(f"[success]{prefix}:[/] {message}")


def print_info(message: str, prefix: str = "Info") -> None:
    """Print an info message."""
    console.print(f"[info]{prefix}:[/] {message}")


def format_severity(severity: str) -> str:
    """Format severity with appropriate color."""
    colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }
    color = colors.get(severity.lower(), "white")
    return f"[{color}]{severity.upper()}[/{color}]"


def format_duration(seconds: float) -> str:
    """Format duration in human-readable form."""
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


def format_count(count: int, singular: str, plural: str | None = None) -> str:
    """Format a count with singular/plural label."""
    plural = plural or f"{singular}s"
    label = singular if count == 1 else plural
    return f"{count} {label}"
