"""CLI entry point for agent-bom."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from agent_bom import __version__
from agent_bom.discovery import discover_all
from agent_bom.models import AIBOMReport
from agent_bom.output import (
    export_cyclonedx,
    export_json,
    print_agent_tree,
    print_blast_radius,
    print_summary,
)
from agent_bom.parsers import extract_packages
from agent_bom.resolver import resolve_all_versions_sync
from agent_bom.scanners import scan_agents_sync

console = Console()

BANNER = r"""
   ___                    __     ____  ____  __  ___
  / _ | ___ ____ ___  ___/ /_   / __ )/ __ \/  |/  /
 / __ |/ _ `/ -_) _ \/ __/_  / / __  / / / / /|_/ /
/_/ |_/\_, /\__/_//_/\__/ /_/ /____/\____/_/  /_/
      /___/
  AI Bill of Materials for Agents & MCP Servers
"""


@click.group()
@click.version_option(version=__version__, prog_name="agent-bom")
def main():
    """agent-bom: Generate AI Bill of Materials for AI agents and MCP servers.

    Maps the full trust chain from agent → MCP server → packages → vulnerabilities,
    with blast radius analysis showing which agents are affected when a package is compromised.
    """
    pass


@main.command()
@click.option("--project", "-p", type=click.Path(exists=True), help="Project directory to scan")
@click.option("--config-dir", type=click.Path(exists=True), help="Custom agent config directory to scan")
@click.option("--inventory", type=click.Path(exists=True), help="Manual inventory JSON file")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["console", "json", "cyclonedx"]),
    default="console",
    help="Output format (default: console)",
)
@click.option("--no-scan", is_flag=True, help="Skip vulnerability scanning (inventory only)")
@click.option("--no-tree", is_flag=True, help="Skip dependency tree output")
@click.option("--transitive", is_flag=True, help="Resolve transitive dependencies for npx/uvx packages")
@click.option("--max-depth", type=int, default=3, help="Maximum depth for transitive dependency resolution (default: 3)")
@click.option("--enrich", is_flag=True, help="Enrich vulnerabilities with NVD, EPSS, and CISA KEV data")
@click.option("--nvd-api-key", envvar="NVD_API_KEY", help="NVD API key for higher rate limits (or set NVD_API_KEY env var)")
def scan(
    project: Optional[str],
    config_dir: Optional[str],
    inventory: Optional[str],
    output: Optional[str],
    output_format: str,
    no_scan: bool,
    no_tree: bool,
    transitive: bool,
    max_depth: int,
    enrich: bool,
    nvd_api_key: Optional[str],
):
    """Discover agents, extract dependencies, scan for vulnerabilities."""
    console.print(BANNER, style="bold blue")

    # Step 1: Discovery
    if inventory:
        # Load from manual inventory JSON
        console.print(f"\n[bold blue]📋 Loading inventory from {inventory}...[/bold blue]\n")
        from agent_bom.models import Agent, AgentType, MCPServer, TransportType
        with open(inventory) as f:
            inventory_data = json.load(f)

        # Parse agents from inventory JSON
        agents = []
        for agent_data in inventory_data.get("agents", []):
            # Parse MCP servers
            mcp_servers = []
            for server_data in agent_data.get("mcp_servers", []):
                server = MCPServer(
                    name=server_data.get("name", ""),
                    command=server_data.get("command", ""),
                    args=server_data.get("args", []),
                    env=server_data.get("env", {}),
                    transport=TransportType(server_data.get("transport", "stdio")),
                    url=server_data.get("url"),
                    config_path=agent_data.get("config_path"),
                    working_dir=server_data.get("working_dir"),
                )
                mcp_servers.append(server)

            # Create agent with proper field names
            agent = Agent(
                name=agent_data.get("name", "unknown"),
                agent_type=AgentType(agent_data.get("agent_type", agent_data.get("type", "custom"))),
                config_path=agent_data.get("config_path", inventory),
                mcp_servers=mcp_servers,
                version=agent_data.get("version"),
            )
            agents.append(agent)

        console.print(f"  [green]✓[/green] Loaded {len(agents)} agent(s) from inventory")
    elif config_dir:
        # Scan custom config directory
        console.print(f"\n[bold blue]🔍 Scanning custom config directory: {config_dir}...[/bold blue]\n")
        agents = discover_all(project_dir=config_dir)
    else:
        # Auto-discovery + optional project
        agents = discover_all(project_dir=project)

    if not agents:
        console.print("\n[yellow]No MCP configurations found. Nothing to scan.[/yellow]")
        console.print("\nTips:")
        console.print("  • Make sure you have Claude Desktop, Cursor, or another MCP client configured")
        console.print("  • Use --project to scan a specific project directory")
        console.print("  • Use --config-dir to scan a custom agent config directory")
        console.print("  • Use --inventory to load a manual inventory JSON file")
        sys.exit(0)

    # Step 2: Extract packages
    console.print("\n[bold blue]📦 Extracting package dependencies...[/bold blue]\n")
    if transitive:
        console.print(f"  [cyan]Transitive dependency resolution enabled (max depth: {max_depth})[/cyan]\n")

    total_packages = 0
    for agent in agents:
        for server in agent.mcp_servers:
            server.packages = extract_packages(server, resolve_transitive=transitive, max_depth=max_depth)
            total_packages += len(server.packages)
            if server.packages:
                # Count direct vs transitive
                direct_count = sum(1 for p in server.packages if p.is_direct)
                transitive_count = len(server.packages) - direct_count
                transitive_str = f" ({transitive_count} transitive)" if transitive_count > 0 else ""
                console.print(
                    f"  [green]✓[/green] {server.name}: {len(server.packages)} package(s) "
                    f"({server.packages[0].ecosystem}){transitive_str}"
                )
            else:
                console.print(f"  [dim]  {server.name}: no local packages found (may be remote/npx)[/dim]")

    console.print(f"\n  [bold]Extracted {total_packages} total packages.[/bold]")

    # Step 3: Resolve 'latest' and 'unknown' versions
    all_packages = [p for a in agents for s in a.mcp_servers for p in s.packages]
    unresolved = [p for p in all_packages if p.version in ("latest", "unknown", "")]
    if unresolved:
        console.print(f"\n[bold blue]🔄 Resolving {len(unresolved)} package version(s) from registries...[/bold blue]\n")
        resolved = resolve_all_versions_sync(all_packages)
        console.print(f"\n  [bold]Resolved {resolved}/{len(unresolved)} package version(s).[/bold]")


    # Step 4: Vulnerability scan
    blast_radii = []
    if not no_scan and total_packages > 0:
        blast_radii = scan_agents_sync(agents, enable_enrichment=enrich, nvd_api_key=nvd_api_key)
    # Build report
    report = AIBOMReport(
        agents=agents,
        blast_radii=blast_radii,
    )
    # Step 5: Output
    if output_format == "console" and not output:
        print_summary(report)
        if not no_tree:
            print_agent_tree(report)
        print_blast_radius(report)
    elif output_format == "json":
        out_path = output or "agent-bom-report.json"
        export_json(report, out_path)
        print_summary(report)
    elif output_format == "cyclonedx":
        out_path = output or "agent-bom.cdx.json"
        export_cyclonedx(report, out_path)
        print_summary(report)
    elif output:
        # Console format but with file output
        if output.endswith(".cdx.json"):
            export_cyclonedx(report, output)
        else:
            export_json(report, output)
        print_summary(report)


@main.command()
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to specific MCP config file")
@click.option("--project", "-p", type=click.Path(exists=True), help="Project directory to scan")
@click.option("--transitive", is_flag=True, help="Resolve transitive dependencies for npx/uvx packages")
@click.option("--max-depth", type=int, default=3, help="Maximum depth for transitive dependency resolution (default: 3)")
def inventory(config: Optional[str], project: Optional[str], transitive: bool, max_depth: int):
    """Show discovered agents and MCP servers (no vulnerability scan)."""
    console.print(BANNER, style="bold blue")

    if config:
        # Parse specific config file
        config_path = Path(config)
        try:
            config_data = json.loads(config_path.read_text())
            from agent_bom.discovery import parse_mcp_config
            from agent_bom.models import Agent, AgentType

            servers = parse_mcp_config(config_data, str(config_path))
            agents = [Agent(
                name=f"custom:{config_path.stem}",
                agent_type=AgentType.CUSTOM,
                config_path=str(config_path),
                mcp_servers=servers,
            )] if servers else []
        except Exception as e:
            console.print(f"[red]Error parsing config: {e}[/red]")
            sys.exit(1)
    else:
        agents = discover_all(project_dir=project)

    if not agents:
        console.print("\n[yellow]No MCP configurations found.[/yellow]")
        sys.exit(0)

    # Extract packages
    console.print("\n[bold blue]📦 Extracting package dependencies...[/bold blue]\n")
    if transitive:
        console.print(f"  [cyan]Transitive dependency resolution enabled (max depth: {max_depth})[/cyan]\n")

    for agent in agents:
        for server in agent.mcp_servers:
            server.packages = extract_packages(server, resolve_transitive=transitive, max_depth=max_depth)

    report = AIBOMReport(agents=agents)
    print_summary(report)
    print_agent_tree(report)


@main.command()
def where():
    """Show where agent-bom looks for MCP configurations."""
    console.print(BANNER, style="bold blue")
    console.print("\n[bold]MCP Client Configuration Locations[/bold]\n")

    from agent_bom.discovery import CONFIG_LOCATIONS, PROJECT_CONFIG_FILES, expand_path, get_platform

    current_platform = get_platform()

    for agent_type, platforms in CONFIG_LOCATIONS.items():
        paths = platforms.get(current_platform, [])
        console.print(f"\n  [bold cyan]{agent_type.value}[/bold cyan]")
        for p in paths:
            expanded = expand_path(p)
            exists = "✓" if expanded.exists() else "✗"
            style = "green" if expanded.exists() else "dim"
            console.print(f"    [{style}]{exists} {expanded}[/{style}]")

    console.print("\n  [bold cyan]Project-level configs[/bold cyan]")
    for config_name in PROJECT_CONFIG_FILES:
        console.print(f"    [dim]  ./{config_name}[/dim]")


if __name__ == "__main__":
    main()
