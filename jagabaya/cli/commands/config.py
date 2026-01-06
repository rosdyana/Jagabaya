"""
Configuration commands for Jagabaya CLI.
"""

from __future__ import annotations

import os
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

app = typer.Typer(help="Configuration management")
console = Console()


@app.command("show")
def config_show():
    """Show current configuration."""
    from jagabaya.models.config import JagabayaConfig

    try:
        config = JagabayaConfig.load()

        console.print(
            Panel.fit(
                f"[bold]LLM Configuration:[/]\n"
                f"  Provider: {config.llm.provider}\n"
                f"  Model: {config.llm.model}\n"
                f"  Temperature: {config.llm.temperature}\n"
                f"  Max Tokens: {config.llm.max_tokens}\n"
                f"  API Key: {'Set' if config.llm.api_key else '[red]Not Set[/]'}\n"
                f"\n[bold]Scan Configuration:[/]\n"
                f"  Safe Mode: {config.scan.safe_mode}\n"
                f"  Stealth Mode: {config.scan.stealth_mode}\n"
                f"  Tool Timeout: {config.scan.tool_timeout}s\n"
                f"  Max Concurrent: {config.scan.max_concurrent_tools}\n"
                f"\n[bold]Output Configuration:[/]\n"
                f"  Output Dir: {config.output.output_dir}\n"
                f"  Report Format: {config.output.report_format}",
                title="[bold blue]Jagabaya Configuration[/]",
            )
        )
    except Exception as e:
        console.print(f"[red]Error loading config: {e}[/]")


@app.command("init")
def config_init(
    config_file: str = typer.Option(
        "jagabaya.yaml",
        "--output",
        "-o",
        help="Output file path",
    ),
):
    """Initialize a new configuration file."""
    init_config(config_file)


def init_config(config_file: str) -> None:
    """Create a new configuration file."""
    import yaml

    default_config = {
        "llm": {
            "provider": "openai",
            "model": "gpt-4o",
            "temperature": 0.1,
            "max_tokens": 4096,
            # Note: API key should be set via environment variable
        },
        "scan": {
            "safe_mode": True,
            "stealth_mode": False,
            "tool_timeout": 300,
            "max_concurrent_tools": 3,
            "rate_limit": 10,
        },
        "scope": {
            "default_scope": [],
            "default_blacklist": [],
            "respect_robots_txt": True,
        },
        "output": {
            "output_dir": "./jagabaya_output",
            "report_format": "markdown",
            "save_raw_output": True,
        },
    }

    config_path = Path(config_file)

    if config_path.exists():
        overwrite = typer.confirm(f"{config_file} already exists. Overwrite?")
        if not overwrite:
            console.print("[yellow]Cancelled[/]")
            return

    with open(config_path, "w") as f:
        yaml.dump(default_config, f, default_flow_style=False, sort_keys=False)

    console.print(f"[green]Configuration saved to {config_file}[/]")
    console.print("\n[bold]Next steps:[/]")
    console.print("1. Set your API key:")
    console.print("   [dim]export OPENAI_API_KEY=your-key-here[/]")
    console.print("   [dim]# or ANTHROPIC_API_KEY, GOOGLE_API_KEY, etc.[/]")
    console.print("\n2. Run a scan:")
    console.print("   [dim]jagabaya run example.com[/]")


@app.command("set")
def config_set(
    key: str = typer.Argument(..., help="Configuration key (e.g., llm.model)"),
    value: str = typer.Argument(..., help="Value to set"),
):
    """Set a configuration value."""
    import yaml

    config_file = Path("jagabaya.yaml")

    if not config_file.exists():
        console.print("[yellow]No config file found. Creating one...[/]")
        init_config("jagabaya.yaml")

    with open(config_file) as f:
        config = yaml.safe_load(f) or {}

    # Parse the key path
    keys = key.split(".")
    current = config

    for k in keys[:-1]:
        if k not in current:
            current[k] = {}
        current = current[k]

    # Try to parse value as appropriate type
    try:
        if value.lower() == "true":
            value = True
        elif value.lower() == "false":
            value = False
        elif value.isdigit():
            value = int(value)
        elif value.replace(".", "").isdigit():
            value = float(value)
    except:
        pass

    current[keys[-1]] = value

    with open(config_file, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    console.print(f"[green]Set {key} = {value}[/]")


@app.command("get")
def config_get(
    key: str = typer.Argument(..., help="Configuration key"),
):
    """Get a configuration value."""
    import yaml

    config_file = Path("jagabaya.yaml")

    if not config_file.exists():
        console.print("[red]No config file found. Run 'jagabaya config init' first.[/]")
        raise typer.Exit(1)

    with open(config_file) as f:
        config = yaml.safe_load(f) or {}

    # Parse the key path
    keys = key.split(".")
    current = config

    try:
        for k in keys:
            current = current[k]
        console.print(f"{key} = {current}")
    except KeyError:
        console.print(f"[red]Key '{key}' not found[/]")


@app.command("env")
def config_env():
    """Show environment variables used by Jagabaya."""
    env_vars = [
        ("OPENAI_API_KEY", "OpenAI API key"),
        ("ANTHROPIC_API_KEY", "Anthropic API key"),
        ("GOOGLE_API_KEY", "Google API key"),
        ("AZURE_API_KEY", "Azure OpenAI API key"),
        ("AZURE_API_BASE", "Azure API base URL"),
        ("GROQ_API_KEY", "Groq API key"),
        ("TOGETHER_API_KEY", "Together AI API key"),
        ("MISTRAL_API_KEY", "Mistral API key"),
        ("OLLAMA_API_BASE", "Ollama API base URL"),
        ("JAGABAYA_CONFIG", "Path to config file"),
        ("JAGABAYA_OUTPUT_DIR", "Output directory"),
    ]

    table = Table(title="Environment Variables")
    table.add_column("Variable", style="bold")
    table.add_column("Description")
    table.add_column("Status")

    for var, desc in env_vars:
        value = os.environ.get(var)
        if value:
            # Mask sensitive values
            if "KEY" in var:
                status = f"[green]Set[/] ({value[:8]}...)"
            else:
                status = f"[green]{value}[/]"
        else:
            status = "[dim]Not set[/]"

        table.add_row(var, desc, status)

    console.print(table)
