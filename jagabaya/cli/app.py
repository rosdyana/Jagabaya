"""
Main CLI application.

This module defines the main Typer application and entry point.
"""

from __future__ import annotations

import asyncio
import os
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from jagabaya import __version__
from jagabaya.cli.commands import scan, tools, config, report, session

# Create the main app
app = typer.Typer(
    name="jagabaya",
    help="AI-Powered Penetration Testing CLI",
    add_completion=True,
    rich_markup_mode="rich",
    no_args_is_help=True,
)

# Add sub-commands
app.add_typer(scan.app, name="scan", help="Run security scans")
app.add_typer(tools.app, name="tools", help="Manage security tools")
app.add_typer(config.app, name="config", help="Configuration management")
app.add_typer(report.app, name="report", help="Generate reports")
app.add_typer(session.app, name="session", help="Session management")

console = Console()


def version_callback(value: bool):
    """Show version and exit."""
    if value:
        console.print(f"[bold blue]Jagabaya[/] v{__version__}")
        raise typer.Exit()


# Global state for CLI options
class CLIState:
    """Global CLI state for options like quiet, debug, color."""

    quiet: bool = False
    debug: bool = False
    no_color: bool = False


cli_state = CLIState()


@app.callback()
def main_callback(
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        help="Show version and exit",
        callback=version_callback,
        is_eager=True,
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress non-essential output",
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        help="Enable debug output",
    ),
    no_color: bool = typer.Option(
        False,
        "--no-color",
        help="Disable colored output",
    ),
):
    """
    Jagabaya - AI-Powered Penetration Testing CLI

    An autonomous security assessment tool that uses AI to plan and execute
    penetration tests, analyze results, and generate reports.

    Global Options:
        --quiet, -q    Suppress non-essential output
        --debug        Enable debug logging
        --no-color     Disable colored output
    """
    cli_state.quiet = quiet
    cli_state.debug = debug
    cli_state.no_color = no_color

    # Set environment variable for no-color (used by Rich)
    if no_color:
        os.environ["NO_COLOR"] = "1"

    # Set debug logging level
    if debug:
        import logging

        logging.basicConfig(level=logging.DEBUG)


def get_console() -> Console:
    """Get a console instance with current CLI state applied."""
    return Console(
        quiet=cli_state.quiet,
        force_terminal=not cli_state.no_color if not cli_state.no_color else None,
        no_color=cli_state.no_color,
    )


@app.command()
def run(
    target: str = typer.Argument(..., help="Target to scan (domain, IP, or URL)"),
    scope: Optional[list[str]] = typer.Option(
        None,
        "--scope",
        "-s",
        help="Additional in-scope targets",
    ),
    blacklist: Optional[list[str]] = typer.Option(
        None,
        "--blacklist",
        "-b",
        help="Out-of-scope targets",
    ),
    max_steps: int = typer.Option(
        100,
        "--max-steps",
        "-n",
        help="Maximum number of steps",
    ),
    safe_mode: bool = typer.Option(
        True,
        "--safe-mode/--no-safe-mode",
        help="Enable safe mode (no exploitation)",
    ),
    output_dir: str = typer.Option(
        "./jagabaya_output",
        "--output-dir",
        "-o",
        help="Output directory for results",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-V",
        help="Enable verbose output",
    ),
    model: str = typer.Option(
        None,
        "--model",
        "-m",
        help="LLM model to use (e.g., gpt-4o, claude-3-5-sonnet)",
    ),
    provider: str = typer.Option(
        None,
        "--provider",
        "-p",
        help="LLM provider (openai, anthropic, google, etc.)",
    ),
):
    """
    Run an autonomous penetration test.

    This command starts an AI-driven security assessment of the target.
    The AI will plan and execute various security tests, analyze results,
    and report findings.

    Example:
        jagabaya run example.com
        jagabaya run example.com --scope "*.example.com"
        jagabaya run 192.168.1.0/24 --no-safe-mode
    """
    from jagabaya.cli.ui.console import show_banner, show_scan_progress
    from jagabaya.cli.commands.scan import run_scan

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
            model=model,
            provider=provider,
        )
    )


@app.command()
def init(
    config_file: str = typer.Option(
        "jagabaya.yaml",
        "--config",
        "-c",
        help="Configuration file path",
    ),
):
    """
    Initialize Jagabaya configuration.

    Creates a default configuration file and checks for required tools.
    """
    from jagabaya.cli.commands.config import init_config

    init_config(config_file)


@app.command()
def quick(
    target: str = typer.Argument(..., help="Target to scan"),
    scan_type: str = typer.Option(
        "recon",
        "--type",
        "-t",
        help="Quick scan type (recon, web, network, full)",
    ),
):
    """
    Run a quick pre-defined scan workflow.

    Quick scans run a predefined set of tools without AI planning.

    Scan types:
    - recon: Subdomain enumeration and basic reconnaissance
    - web: Web vulnerability scanning
    - network: Port scanning and service enumeration
    - full: Complete assessment (all phases)
    """
    from jagabaya.cli.commands.scan import run_quick_scan

    asyncio.run(run_quick_scan(target, scan_type))


def main():
    """Main entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
