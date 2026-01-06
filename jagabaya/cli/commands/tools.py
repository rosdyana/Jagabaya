"""
Tools management commands for Jagabaya CLI.
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Manage security tools")
console = Console()


@app.command("list")
def tools_list(
    available_only: bool = typer.Option(
        False,
        "--available",
        "-a",
        help="Show only available tools",
    ),
    category: str = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter by category",
    ),
):
    """List all security tools."""
    from jagabaya.tools.registry import ToolRegistry
    
    registry = ToolRegistry()
    registry.register_all()
    
    tools = registry.list_tools()
    
    # Filter by category
    if category:
        tools = {
            name: info for name, info in tools.items()
            if info.category.value == category.lower()
        }
    
    # Filter by availability
    if available_only:
        tools = {
            name: info for name, info in tools.items()
            if info.is_available
        }
    
    # Create table
    table = Table(title="Security Tools", show_header=True)
    table.add_column("Name", style="bold")
    table.add_column("Category")
    table.add_column("Status")
    table.add_column("Description")
    
    for name, info in sorted(tools.items()):
        status = "[green]Available[/]" if info.is_available else "[red]Not Installed[/]"
        table.add_row(
            name,
            info.category.value,
            status,
            info.description[:50] + "..." if len(info.description) > 50 else info.description,
        )
    
    console.print(table)
    
    # Summary
    total = len(tools)
    available = sum(1 for t in tools.values() if t.is_available)
    console.print(f"\n[dim]Total: {total} | Available: {available}[/]")


@app.command("check")
def tools_check():
    """Check which tools are installed and available."""
    from jagabaya.tools.registry import ToolRegistry
    
    registry = ToolRegistry()
    registry.register_all()
    
    console.print("[bold]Checking tool availability...[/]\n")
    
    tools = registry.list_tools()
    
    available = []
    missing = []
    
    for name, info in sorted(tools.items()):
        if info.is_available:
            version = info.version or "unknown version"
            console.print(f"  [green][/] {name} ({version})")
            available.append(name)
        else:
            console.print(f"  [red][/] {name}")
            missing.append((name, info.install_command))
    
    console.print(f"\n[bold]Summary:[/] {len(available)}/{len(tools)} tools available")
    
    if missing:
        console.print("\n[bold yellow]Missing tools can be installed with:[/]")
        for name, install_cmd in missing[:5]:
            if install_cmd:
                console.print(f"  {name}: [dim]{install_cmd}[/]")


@app.command("info")
def tools_info(
    tool_name: str = typer.Argument(..., help="Tool name"),
):
    """Show detailed information about a tool."""
    from jagabaya.tools.registry import ToolRegistry
    from rich.panel import Panel
    
    registry = ToolRegistry()
    registry.register_all()
    
    tool = registry.get_tool(tool_name)
    
    if not tool:
        console.print(f"[red]Tool '{tool_name}' not found[/]")
        raise typer.Exit(1)
    
    info = tool.get_info()
    
    status = "[green]Available[/]" if info.is_available else "[red]Not Installed[/]"
    
    content = f"""
[bold]Name:[/] {info.name}
[bold]Category:[/] {info.category.value}
[bold]Binary:[/] {info.binary}
[bold]Status:[/] {status}
[bold]Version:[/] {info.version or 'N/A'}

[bold]Description:[/]
{info.description}

[bold]Homepage:[/] {info.homepage or 'N/A'}
[bold]Install:[/] {info.install_command or 'N/A'}
"""
    
    console.print(Panel(content, title=f"[bold]{tool_name}[/]"))


@app.command("run")
def tools_run(
    tool_name: str = typer.Argument(..., help="Tool name"),
    target: str = typer.Argument(..., help="Target"),
    timeout: int = typer.Option(300, "--timeout", "-t"),
):
    """Run a single tool manually."""
    import asyncio
    from jagabaya.tools.registry import ToolRegistry
    
    registry = ToolRegistry()
    registry.register_all()
    
    tool = registry.get_tool(tool_name)
    
    if not tool:
        console.print(f"[red]Tool '{tool_name}' not found[/]")
        raise typer.Exit(1)
    
    if not tool.is_available:
        console.print(f"[red]Tool '{tool_name}' is not installed[/]")
        raise typer.Exit(1)
    
    console.print(f"[bold]Running {tool_name} on {target}...[/]")
    
    async def run():
        result = await tool.execute(target, timeout=timeout)
        return result
    
    result = asyncio.run(run())
    
    if result.success:
        console.print(f"[green]Completed in {result.duration:.1f}s[/]")
        console.print("\n[bold]Output:[/]")
        console.print(result.raw_output[:2000])
        if len(result.raw_output) > 2000:
            console.print(f"[dim]... ({len(result.raw_output) - 2000} more characters)[/]")
    else:
        console.print(f"[red]Failed: {result.error_message}[/]")


@app.command("categories")
def tools_categories():
    """List tool categories."""
    from jagabaya.models.tools import ToolCategory
    
    console.print("[bold]Tool Categories:[/]\n")
    
    for cat in ToolCategory:
        console.print(f"  {cat.value}")
