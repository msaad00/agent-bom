"""Inventory, validation, location, and shell completion commands."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from agent_bom.cli._common import BANNER, _make_console
from agent_bom.discovery import discover_all
from agent_bom.models import AIBOMReport
from agent_bom.output import print_agent_tree, print_summary
from agent_bom.parsers import extract_packages


@click.command()
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to specific MCP config file")
@click.option("--project", "-p", type=click.Path(exists=True), help="Project directory to scan")
@click.option("--transitive", is_flag=True, help="Resolve transitive dependencies for npx/uvx packages")
@click.option("--max-depth", type=int, default=3, help="Maximum depth for transitive dependency resolution")
@click.option("--quiet", "-q", is_flag=True, help="Suppress all output except results")
def inventory(config: Optional[str], project: Optional[str], transitive: bool, max_depth: int, quiet: bool):
    """Show discovered agents and MCP servers (no vulnerability scan)."""
    con = _make_console(quiet=quiet)

    import agent_bom.output as _out

    _out.console = con

    con.print(BANNER, style="bold blue")

    if config:
        config_path = Path(config)
        try:
            config_data = json.loads(config_path.read_text())
            from agent_bom.discovery import parse_mcp_config
            from agent_bom.models import Agent, AgentType

            servers = parse_mcp_config(config_data, str(config_path))
            agents = (
                [
                    Agent(
                        name=f"custom:{config_path.stem}",
                        agent_type=AgentType.CUSTOM,
                        config_path=str(config_path),
                        mcp_servers=servers,
                    )
                ]
                if servers
                else []
            )
        except Exception as e:
            con.print(f"[red]Error parsing config: {e}[/red]")
            sys.exit(1)
    else:
        agents = discover_all(project_dir=project)

    if not agents:
        con.print("\n[yellow]No MCP configurations found.[/yellow]")
        sys.exit(0)

    con.print("\n[bold blue]Extracting package dependencies...[/bold blue]\n")
    if transitive:
        con.print(f"  [cyan]Transitive resolution enabled (max depth: {max_depth})[/cyan]\n")

    for agent in agents:
        for server in agent.mcp_servers:
            if server.security_blocked:
                continue  # Don't extract from security-blocked servers
            server.packages = extract_packages(server, resolve_transitive=transitive, max_depth=max_depth)

    report = AIBOMReport(agents=agents)
    print_summary(report)
    print_agent_tree(report)


@click.command()
@click.argument("inventory_file", type=click.Path(exists=True))
def validate(inventory_file: str):
    """Validate an inventory file against the agent-bom schema.

    \b
    Exit codes:
      0  Valid — inventory matches the schema
      1  Invalid — schema violations found
    """
    console = Console()
    console.print(BANNER, style="bold blue")

    try:
        import jsonschema
    except ImportError:
        console.print("[red]jsonschema not installed. Run: pip install jsonschema[/red]")
        sys.exit(1)

    _initial_schema = Path(__file__).parent.parent.parent / "schemas" / "inventory.schema.json"
    schema_path: Path | None = _initial_schema
    if not _initial_schema.exists():
        # Fallback: look relative to installed package
        import importlib.resources

        try:
            schema_path = Path(str(importlib.resources.files("agent_bom"))) / ".." / ".." / "schemas" / "inventory.schema.json"
        except Exception:
            schema_path = None

    if not schema_path or not schema_path.exists():
        console.print("[red]Schema file not found. Run from the agent-bom repo root.[/red]")
        sys.exit(1)

    with open(schema_path) as f:
        schema = json.load(f)

    with open(inventory_file) as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            console.print(f"[red]JSON parse error: {e}[/red]")
            sys.exit(1)

    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))

    if not errors:
        agents = data.get("agents", [])
        total_servers = sum(len(a.get("mcp_servers", [])) for a in agents)
        total_packages = sum(len(s.get("packages", [])) for a in agents for s in a.get("mcp_servers", []))
        console.print(f"\n  [green]✓ Valid[/green] — {len(agents)} agent(s), {total_servers} server(s), {total_packages} package(s)")
        console.print(f"\n  [dim]Scan with:[/dim] agent-bom scan --inventory {inventory_file}")
    else:
        console.print(f"\n  [red]✗ Invalid — {len(errors)} error(s):[/red]\n")
        for err in errors:
            path = " → ".join(str(p) for p in err.path) or "(root)"
            console.print(f"  [red]•[/red] [bold]{path}[/bold]: {err.message}")
        console.print()
        sys.exit(1)


@click.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON for machine consumption")
def where(as_json: bool):
    """Show where agent-bom looks for MCP configurations.

    Lists every config path that would be checked during auto-discovery,
    grouped by MCP client. Paths that exist on your system are marked with ✓.

    Use --json for machine-readable output (useful for auditing).
    """
    import shutil

    from agent_bom.discovery import (
        AGENT_BINARIES,
        COMPOSE_FILE_NAMES,
        CONFIG_LOCATIONS,
        PROJECT_CONFIG_FILES,
        expand_path,
        get_all_discovery_paths,
        get_platform,
    )

    current_platform = get_platform()

    if as_json:
        import json as _json

        entries = []
        for client, path in get_all_discovery_paths(current_platform):
            expanded = str(expand_path(path)) if not path.startswith(".") else path
            entries.append(
                {
                    "client": client,
                    "path": path,
                    "expanded": expanded,
                    "exists": expand_path(path).exists() if not path.startswith(".") else Path(path).exists(),
                }
            )
        click.echo(_json.dumps({"platform": current_platform, "paths": entries}, indent=2))
        return

    console = Console()
    console.print(BANNER, style="bold blue")
    console.print("\n[bold]MCP Client Configuration Locations[/bold]\n")

    total_paths = 0
    found_paths = 0

    for agent_type, platforms in CONFIG_LOCATIONS.items():
        paths = platforms.get(current_platform, [])
        binary = AGENT_BINARIES.get(agent_type)
        binary_status = ""
        if binary:
            if shutil.which(binary):
                binary_status = f" [green](binary: {binary} found)[/green]"
            else:
                binary_status = f" [dim](binary: {binary} not found)[/dim]"

        console.print(f"\n  [bold cyan]{agent_type.value}[/bold cyan]{binary_status}")
        if paths:
            for p in paths:
                total_paths += 1
                expanded_path = expand_path(p)
                mark = "✓" if expanded_path.exists() else "✗"
                style = "green" if expanded_path.exists() else "dim"
                if expanded_path.exists():
                    found_paths += 1
                console.print(f"    [{style}]{mark} {expanded_path}[/{style}]")
        else:
            console.print(f"    [dim]  (CLI-based discovery via {binary or 'N/A'})[/dim]")

    # Docker MCP Toolkit paths
    console.print("\n  [bold cyan]Docker MCP Toolkit[/bold cyan]")
    for dp in ["~/.docker/mcp/registry.yaml", "~/.docker/mcp/catalogs/docker-mcp.yaml"]:
        total_paths += 1
        expanded_path = expand_path(dp)
        mark = "✓" if expanded_path.exists() else "✗"
        style = "green" if expanded_path.exists() else "dim"
        if expanded_path.exists():
            found_paths += 1
        console.print(f"    [{style}]{mark} {expanded_path}[/{style}]")

    console.print("\n  [bold cyan]Project-level configs[/bold cyan]  [dim](relative to CWD)[/dim]")
    for config_name in PROJECT_CONFIG_FILES:
        total_paths += 1
        file_exists = Path(config_name).exists()
        mark = "✓" if file_exists else "✗"
        style = "green" if file_exists else "dim"
        if file_exists:
            found_paths += 1
        console.print(f"    [{style}]{mark} ./{config_name}[/{style}]")

    console.print("\n  [bold cyan]Docker Compose files[/bold cyan]  [dim](relative to CWD)[/dim]")
    for cf in COMPOSE_FILE_NAMES:
        total_paths += 1
        file_exists = Path(cf).exists()
        mark = "✓" if file_exists else "✗"
        style = "green" if file_exists else "dim"
        if file_exists:
            found_paths += 1
        console.print(f"    [{style}]{mark} ./{cf}[/{style}]")

    console.print(f"\n  [bold]Total:[/bold] {total_paths} paths checked, {found_paths} found on this system")


@click.command("completions")
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]))
def completions_cmd(shell: str):
    """Print shell completion script.

    \b
    Setup:
      bash:  eval "$(agent-bom completions bash)"
      zsh:   eval "$(agent-bom completions zsh)"
      fish:  agent-bom completions fish | source

    \b
    Permanent setup (bash):
      agent-bom completions bash >> ~/.bashrc

    Permanent setup (zsh):
      agent-bom completions zsh >> ~/.zshrc
    """
    import os as _os
    import subprocess as _sp

    env = {**_os.environ, "_AGENT_BOM_COMPLETE": f"{shell}_source"}
    try:
        result = _sp.run(["agent-bom"], env=env, capture_output=True, text=True)
        click.echo(result.stdout, nl=False)
    except Exception:  # noqa: BLE001
        # Fallback: print activation instructions
        if shell == "bash":
            click.echo('eval "$(_AGENT_BOM_COMPLETE=bash_source agent-bom)"')
        elif shell == "zsh":
            click.echo('eval "$(_AGENT_BOM_COMPLETE=zsh_source agent-bom)"')
        elif shell == "fish":
            click.echo("eval (env _AGENT_BOM_COMPLETE=fish_source agent-bom)")
