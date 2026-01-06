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
    # Registry uses lazy initialization, no need to call register_all

    tools = {name: tool.get_info() for name, tool in registry.get_all().items()}

    # Filter by category
    if category:
        tools = {
            name: info for name, info in tools.items() if info.category.value == category.lower()
        }

    # Filter by availability
    if available_only:
        tools = {name: info for name, info in tools.items() if info.is_available}

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
    # Registry uses lazy initialization

    console.print("[bold]Checking tool availability...[/]\n")

    tools = {name: tool.get_info() for name, tool in registry.get_all().items()}

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
    # Registry uses lazy initialization

    tool = registry.get(tool_name)

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
[bold]Version:[/] {info.version or "N/A"}

[bold]Description:[/]
{info.description}

[bold]Homepage:[/] {info.homepage or "N/A"}
[bold]Install:[/] {info.install_command or "N/A"}
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
    # Registry uses lazy initialization

    tool = registry.get(tool_name)

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


def _detect_platform() -> dict[str, str | bool]:
    """Detect the current platform and available package managers."""
    import platform
    import shutil

    system = platform.system().lower()

    result = {
        "system": system,
        "is_windows": system == "windows",
        "is_linux": system == "linux",
        "is_macos": system == "darwin",
        "has_apt": shutil.which("apt") is not None or shutil.which("apt-get") is not None,
        "has_brew": shutil.which("brew") is not None,
        "has_choco": shutil.which("choco") is not None,
        "has_winget": shutil.which("winget") is not None,
        "has_scoop": shutil.which("scoop") is not None,
        "has_go": shutil.which("go") is not None,
        "has_pip": shutil.which("pip") is not None or shutil.which("pip3") is not None,
        "has_gem": shutil.which("gem") is not None,
        "has_cargo": shutil.which("cargo") is not None,
        "has_npm": shutil.which("npm") is not None,
    }

    return result


def _parse_install_command(install_cmd: str, platform_info: dict) -> list[str]:
    """
    Parse the install command string and return platform-appropriate commands.

    Handles formats like:
    - "apt install nmap / brew install nmap"
    - "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    - "pip install sslyze"
    """
    if not install_cmd:
        return []

    commands = []

    # Split by " / " to get alternatives
    alternatives = [cmd.strip() for cmd in install_cmd.split(" / ")]

    for alt in alternatives:
        # Check if this command is available on the current platform
        if alt.startswith("apt ") or alt.startswith("apt-get "):
            if platform_info["has_apt"]:
                # Add sudo for apt commands on Linux
                commands.append(f"sudo {alt}")
        elif alt.startswith("brew "):
            if platform_info["has_brew"]:
                commands.append(alt)
        elif alt.startswith("choco "):
            if platform_info["has_choco"]:
                # Choco might need admin on Windows
                commands.append(alt)
        elif alt.startswith("winget "):
            if platform_info["has_winget"]:
                commands.append(alt)
        elif alt.startswith("scoop "):
            if platform_info["has_scoop"]:
                commands.append(alt)
        elif alt.startswith("go install "):
            if platform_info["has_go"]:
                commands.append(alt)
        elif alt.startswith("pip install ") or alt.startswith("pip3 install "):
            if platform_info["has_pip"]:
                # Normalize to pip
                cmd = alt.replace("pip3 install", "pip install")
                commands.append(cmd)
        elif alt.startswith("gem install "):
            if platform_info["has_gem"]:
                commands.append(alt)
        elif alt.startswith("cargo install "):
            if platform_info["has_cargo"]:
                commands.append(alt)
        elif alt.startswith("npm install "):
            if platform_info["has_npm"]:
                commands.append(f"npm install -g {alt.replace('npm install ', '')}")
        elif alt.startswith("git clone "):
            # Git clone is generally available everywhere
            commands.append(alt)

    return commands


def _get_windows_install_alternatives(tool_name: str) -> list[str]:
    """Get Windows-specific install alternatives for common tools."""
    # Windows alternatives using choco, winget, or scoop
    windows_packages = {
        "nmap": ["choco install nmap", "winget install nmap", "scoop install nmap"],
        "masscan": ["choco install masscan"],
        "nikto": ["choco install nikto"],
        "sqlmap": ["pip install sqlmap", "choco install sqlmap"],
        "whatweb": [],  # Ruby-based, complex on Windows
        "testssl": ["git clone https://github.com/drwetter/testssl.sh"],
        "wpscan": ["gem install wpscan"],
    }
    return windows_packages.get(tool_name, [])


@app.command("install")
def tools_install(
    tool_name: str = typer.Argument(
        None,
        help="Tool name to install (omit for all missing tools)",
    ),
    all_tools: bool = typer.Option(
        False,
        "--all",
        "-a",
        help="Install all missing tools",
    ),
    category: str = typer.Option(
        None,
        "--category",
        "-c",
        help="Install all missing tools in a category",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Actually run the install commands (without this flag, only shows commands)",
    ),
    skip_unavailable: bool = typer.Option(
        True,
        "--skip-unavailable/--no-skip-unavailable",
        help="Skip tools that can't be installed on this platform",
    ),
):
    """
    Install security tools.

    By default, this command shows the install commands without running them.
    Use --force to actually execute the installation.

    Examples:
        jagabaya tools install nmap              # Show install command for nmap
        jagabaya tools install nmap --force      # Actually install nmap
        jagabaya tools install --all             # Show commands for all missing tools
        jagabaya tools install --all --force     # Install all missing tools
        jagabaya tools install -c recon --force  # Install all recon tools
    """
    import subprocess
    from jagabaya.tools.registry import ToolRegistry

    registry = ToolRegistry()
    platform_info = _detect_platform()

    # Show platform info
    console.print("[bold]Platform Detection:[/]")
    console.print(f"  System: {platform_info['system']}")
    pkg_managers = []
    if platform_info["has_apt"]:
        pkg_managers.append("apt")
    if platform_info["has_brew"]:
        pkg_managers.append("brew")
    if platform_info["has_choco"]:
        pkg_managers.append("choco")
    if platform_info["has_winget"]:
        pkg_managers.append("winget")
    if platform_info["has_scoop"]:
        pkg_managers.append("scoop")
    if platform_info["has_go"]:
        pkg_managers.append("go")
    if platform_info["has_pip"]:
        pkg_managers.append("pip")
    if platform_info["has_gem"]:
        pkg_managers.append("gem")
    if platform_info["has_cargo"]:
        pkg_managers.append("cargo")
    console.print(f"  Package managers: {', '.join(pkg_managers) or 'None detected'}\n")

    # Determine which tools to install
    tools_to_install = []

    if tool_name:
        # Single tool
        tool = registry.get(tool_name)
        if not tool:
            console.print(f"[red]Tool '{tool_name}' not found[/]")
            raise typer.Exit(1)
        if tool.is_available:
            console.print(f"[green]Tool '{tool_name}' is already installed[/]")
            return
        tools_to_install.append((tool_name, tool))
    elif all_tools or category:
        # Multiple tools
        all_tools_dict = registry.get_all()
        for name, tool in all_tools_dict.items():
            if tool.is_available:
                continue  # Skip already installed
            if category:
                info = tool.get_info()
                if info.category.value != category.lower():
                    continue
            tools_to_install.append((name, tool))
    else:
        console.print("[yellow]Specify a tool name, --all, or --category[/]")
        console.print("\nExamples:")
        console.print("  jagabaya tools install nmap")
        console.print("  jagabaya tools install --all")
        console.print("  jagabaya tools install --category recon")
        raise typer.Exit(1)

    if not tools_to_install:
        console.print("[green]All specified tools are already installed![/]")
        return

    console.print(f"[bold]Tools to install: {len(tools_to_install)}[/]\n")

    # Process each tool
    install_plan = []
    skipped = []

    for name, tool in tools_to_install:
        info = tool.get_info()
        install_cmd = info.install_command

        if not install_cmd:
            skipped.append((name, "No install command defined"))
            continue

        # Parse and get platform-appropriate commands
        commands = _parse_install_command(install_cmd, platform_info)

        # Try Windows alternatives if no commands found
        if not commands and platform_info["is_windows"]:
            win_alts = _get_windows_install_alternatives(name)
            for alt in win_alts:
                commands.extend(_parse_install_command(alt, platform_info))

        if not commands:
            if skip_unavailable:
                skipped.append((name, f"No compatible package manager (needs: {install_cmd})"))
                continue
            else:
                # Show the original command even if we can't run it
                commands = [install_cmd.split(" / ")[0]]

        install_plan.append((name, commands[0], info.category.value))

    # Show install plan
    if install_plan:
        table = Table(title="Installation Plan", show_header=True)
        table.add_column("Tool", style="bold")
        table.add_column("Category")
        table.add_column("Command")

        for name, cmd, cat in install_plan:
            table.add_row(name, cat, f"[dim]{cmd}[/]")

        console.print(table)

    # Show skipped tools
    if skipped:
        console.print(f"\n[yellow]Skipped {len(skipped)} tools:[/]")
        for name, reason in skipped:
            console.print(f"  [dim]{name}: {reason}[/]")

    # Execute if --force
    if force and install_plan:
        console.print("\n[bold]Installing tools...[/]\n")

        success_count = 0
        fail_count = 0

        for name, cmd, _ in install_plan:
            console.print(f"[bold blue]Installing {name}...[/]")
            console.print(f"  [dim]$ {cmd}[/]")

            try:
                # Run the install command
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=600,  # 10 minute timeout
                )

                if result.returncode == 0:
                    console.print(f"  [green]Success[/]")
                    success_count += 1
                else:
                    console.print(f"  [red]Failed (exit code {result.returncode})[/]")
                    if result.stderr:
                        console.print(f"  [dim]{result.stderr[:200]}[/]")
                    fail_count += 1

            except subprocess.TimeoutExpired:
                console.print(f"  [red]Timeout (exceeded 10 minutes)[/]")
                fail_count += 1
            except Exception as e:
                console.print(f"  [red]Error: {e}[/]")
                fail_count += 1

        console.print(
            f"\n[bold]Installation complete:[/] {success_count} succeeded, {fail_count} failed"
        )

    elif not force and install_plan:
        console.print("\n[yellow]Dry run mode. Use --force to actually install.[/]")
        console.print("Example: [dim]jagabaya tools install --all --force[/]")
