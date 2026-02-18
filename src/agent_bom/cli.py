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
    export_sarif,
    print_agent_tree,
    print_blast_radius,
    print_summary,
    to_cyclonedx,
    to_json,
    to_sarif,
)
from agent_bom.parsers import extract_packages
from agent_bom.resolver import resolve_all_versions_sync
from agent_bom.scanners import scan_agents_sync

BANNER = r"""
   ___                    __     ____  ____  __  ___
  / _ | ___ ____ ___  ___/ /_   / __ )/ __ \/  |/  /
 / __ |/ _ `/ -_) _ \/ __/_  / / __  / / / / /|_/ /
/_/ |_/\_, /\__/_//_/\__/ /_/ /____/\____/_/  /_/
      /___/
  AI Bill of Materials for Agents & MCP Servers
"""

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}


def _make_console(quiet: bool = False, output_format: str = "console") -> Console:
    """Create a Console that routes output correctly.

    - quiet mode: suppress all output
    - json/cyclonedx format: route to stderr (keep stdout clean for piping)
    - console format: normal stdout
    """
    if quiet:
        return Console(stderr=True, quiet=True)
    if output_format != "console":
        return Console(stderr=True)
    return Console()


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
@click.option("--output", "-o", type=str, help="Output file path (use '-' for stdout)")
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["console", "json", "cyclonedx", "sarif", "text"]),
    default="console",
    help="Output format",
)
@click.option("--no-scan", is_flag=True, help="Skip vulnerability scanning (inventory only)")
@click.option("--no-tree", is_flag=True, help="Skip dependency tree output")
@click.option("--transitive", is_flag=True, help="Resolve transitive dependencies for npx/uvx packages")
@click.option("--max-depth", type=int, default=3, help="Maximum depth for transitive dependency resolution")
@click.option("--enrich", is_flag=True, help="Enrich vulnerabilities with NVD, EPSS, and CISA KEV data")
@click.option("--nvd-api-key", envvar="NVD_API_KEY", help="NVD API key for higher rate limits")
@click.option("--quiet", "-q", is_flag=True, help="Suppress all output except results (for scripting)")
@click.option(
    "--fail-on-severity",
    type=click.Choice(["critical", "high", "medium", "low"]),
    help="Exit 1 if vulnerabilities of this severity or higher are found",
)
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
    quiet: bool,
    fail_on_severity: Optional[str],
):
    """Discover agents, extract dependencies, scan for vulnerabilities.

    \b
    Exit codes:
      0  Clean — no vulnerabilities at or above threshold
      1  Fail — vulnerabilities found at or above --fail-on-severity
    """
    # Route console output based on flags
    is_stdout = output == "-"
    con = _make_console(quiet=quiet or is_stdout, output_format=output_format)

    # Also set the output module's console so print_summary etc. route correctly
    import agent_bom.output as _out
    _out.console = con

    con.print(BANNER, style="bold blue")

    # Step 1: Discovery
    if inventory:
        con.print(f"\n[bold blue]Loading inventory from {inventory}...[/bold blue]\n")
        from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType
        with open(inventory) as f:
            inventory_data = json.load(f)

        agents = []
        for agent_data in inventory_data.get("agents", []):
            mcp_servers = []
            for server_data in agent_data.get("mcp_servers", []):
                # Parse pre-populated tools (e.g. from Snowflake/cloud inventory)
                tools = []
                for tool_data in server_data.get("tools", []):
                    if isinstance(tool_data, str):
                        tools.append(MCPTool(name=tool_data, description=""))
                    elif isinstance(tool_data, dict):
                        tools.append(MCPTool(
                            name=tool_data.get("name", ""),
                            description=tool_data.get("description", ""),
                            input_schema=tool_data.get("input_schema"),
                        ))

                # Parse pre-known packages (e.g. from cloud asset scan)
                packages = []
                for pkg_data in server_data.get("packages", []):
                    if isinstance(pkg_data, str):
                        # Accept "name@version" shorthand
                        if "@" in pkg_data:
                            name, version = pkg_data.rsplit("@", 1)
                        else:
                            name, version = pkg_data, "unknown"
                        packages.append(Package(name=name, version=version, ecosystem="unknown"))
                    elif isinstance(pkg_data, dict):
                        packages.append(Package(
                            name=pkg_data.get("name", ""),
                            version=pkg_data.get("version", "unknown"),
                            ecosystem=pkg_data.get("ecosystem", "unknown"),
                            purl=pkg_data.get("purl"),
                        ))

                server = MCPServer(
                    name=server_data.get("name", ""),
                    command=server_data.get("command", ""),
                    args=server_data.get("args", []),
                    env=server_data.get("env", {}),
                    transport=TransportType(server_data.get("transport", "stdio")),
                    url=server_data.get("url"),
                    config_path=agent_data.get("config_path"),
                    working_dir=server_data.get("working_dir"),
                    tools=tools,
                    packages=packages,
                )
                mcp_servers.append(server)

            agent = Agent(
                name=agent_data.get("name", "unknown"),
                agent_type=AgentType(agent_data.get("agent_type", agent_data.get("type", "custom"))),
                config_path=agent_data.get("config_path", inventory),
                mcp_servers=mcp_servers,
                version=agent_data.get("version"),
                source=agent_data.get("source", inventory_data.get("source")),
            )
            agents.append(agent)

        con.print(f"  [green]✓[/green] Loaded {len(agents)} agent(s) from inventory")
    elif config_dir:
        con.print(f"\n[bold blue]Scanning config directory: {config_dir}...[/bold blue]\n")
        agents = discover_all(project_dir=config_dir)
    else:
        agents = discover_all(project_dir=project)

    if not agents:
        con.print("\n[yellow]No MCP configurations found.[/yellow]")
        con.print("  Use --project, --config-dir, or --inventory to specify a target.")
        sys.exit(0)

    # Step 2: Extract packages
    con.print("\n[bold blue]Extracting package dependencies...[/bold blue]\n")
    if transitive:
        con.print(f"  [cyan]Transitive resolution enabled (max depth: {max_depth})[/cyan]\n")

    total_packages = 0
    for agent in agents:
        for server in agent.mcp_servers:
            # Keep pre-populated packages from inventory, merge with discovered ones
            pre_populated = list(server.packages)
            discovered = extract_packages(server, resolve_transitive=transitive, max_depth=max_depth)

            # Merge: discovered packages + any pre-populated that weren't already found
            discovered_names = {(p.name, p.ecosystem) for p in discovered}
            merged = discovered + [p for p in pre_populated if (p.name, p.ecosystem) not in discovered_names]
            server.packages = merged

            total_packages += len(server.packages)
            if server.packages:
                direct_count = sum(1 for p in server.packages if p.is_direct)
                transitive_count = len(server.packages) - direct_count
                transitive_str = f" ({transitive_count} transitive)" if transitive_count > 0 else ""
                pre_str = f" ({len(pre_populated)} from inventory)" if pre_populated else ""
                con.print(
                    f"  [green]✓[/green] {server.name}: {len(server.packages)} package(s) "
                    f"({server.packages[0].ecosystem}){transitive_str}{pre_str}"
                )
            else:
                con.print(f"  [dim]  {server.name}: no local packages found[/dim]")

    con.print(f"\n  [bold]{total_packages} total packages.[/bold]")

    # Step 3: Resolve unknown versions
    all_packages = [p for a in agents for s in a.mcp_servers for p in s.packages]
    unresolved = [p for p in all_packages if p.version in ("latest", "unknown", "")]
    if unresolved:
        con.print(f"\n[bold blue]Resolving {len(unresolved)} package version(s)...[/bold blue]\n")
        resolved = resolve_all_versions_sync(all_packages)
        con.print(f"\n  [bold]Resolved {resolved}/{len(unresolved)} version(s).[/bold]")

    # Step 4: Vulnerability scan
    blast_radii = []
    if not no_scan and total_packages > 0:
        blast_radii = scan_agents_sync(agents, enable_enrichment=enrich, nvd_api_key=nvd_api_key)

    # Build report
    report = AIBOMReport(agents=agents, blast_radii=blast_radii)

    # Step 5: Output
    if is_stdout:
        # Pipe mode: write clean output to stdout
        if output_format == "cyclonedx":
            sys.stdout.write(json.dumps(to_cyclonedx(report), indent=2))
        elif output_format == "sarif":
            sys.stdout.write(json.dumps(to_sarif(report), indent=2))
        else:
            sys.stdout.write(json.dumps(to_json(report), indent=2))
        sys.stdout.write("\n")
    elif output_format == "console" and not output:
        print_summary(report)
        if not no_tree:
            print_agent_tree(report)
        print_blast_radius(report)
    elif output_format == "text" and not output:
        _print_text(report, blast_radii)
    elif output_format == "json":
        out_path = output or "agent-bom-report.json"
        export_json(report, out_path)
        con.print(f"\n  [green]✓[/green] JSON report: {out_path}")
    elif output_format == "cyclonedx":
        out_path = output or "agent-bom.cdx.json"
        export_cyclonedx(report, out_path)
        con.print(f"\n  [green]✓[/green] CycloneDX BOM: {out_path}")
    elif output_format == "sarif":
        out_path = output or "agent-bom.sarif"
        export_sarif(report, out_path)
        con.print(f"\n  [green]✓[/green] SARIF report: {out_path}")
    elif output_format == "text" and output:
        Path(output).write_text(_format_text(report, blast_radii))
        con.print(f"\n  [green]✓[/green] Text report: {output}")
    elif output:
        if output.endswith(".cdx.json"):
            export_cyclonedx(report, output)
        elif output.endswith(".sarif"):
            export_sarif(report, output)
        else:
            export_json(report, output)
        con.print(f"\n  [green]✓[/green] Report: {output}")

    # Step 6: Exit code based on severity
    if fail_on_severity and blast_radii:
        threshold = SEVERITY_ORDER.get(fail_on_severity, 0)
        for br in blast_radii:
            sev = br.vulnerability.severity.value.lower()
            if SEVERITY_ORDER.get(sev, 0) >= threshold:
                if not quiet:
                    con.print(
                        f"\n  [red]Exiting with code 1: found {sev} vulnerability "
                        f"({br.vulnerability.id})[/red]"
                    )
                sys.exit(1)


def _format_text(report: AIBOMReport, blast_radii: list) -> str:
    """Plain text output for piping to grep/awk."""
    lines = []
    lines.append(f"agent-bom {report.tool_version}")
    lines.append(f"agents={report.total_agents} servers={report.total_servers} "
                 f"packages={report.total_packages} vulnerabilities={report.total_vulnerabilities}")
    lines.append("")

    for agent in report.agents:
        for server in agent.mcp_servers:
            for pkg in server.packages:
                lines.append(f"{agent.name}\t{server.name}\t{pkg.ecosystem}\t{pkg.name}\t{pkg.version}")

    if blast_radii:
        lines.append("")
        lines.append("VULN_ID\tSEVERITY\tPACKAGE\tFIX\tAGENTS\tCREDENTIALS")
        for br in blast_radii:
            v = br.vulnerability
            lines.append(
                f"{v.id}\t{v.severity.value}\t{br.package.name}@{br.package.version}\t"
                f"{v.fixed_version or '-'}\t{len(br.affected_agents)}\t{len(br.exposed_credentials)}"
            )

    return "\n".join(lines) + "\n"


def _print_text(report: AIBOMReport, blast_radii: list) -> None:
    """Print plain text to stdout."""
    sys.stdout.write(_format_text(report, blast_radii))


@main.command()
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
            agents = [Agent(
                name=f"custom:{config_path.stem}",
                agent_type=AgentType.CUSTOM,
                config_path=str(config_path),
                mcp_servers=servers,
            )] if servers else []
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
            server.packages = extract_packages(server, resolve_transitive=transitive, max_depth=max_depth)

    report = AIBOMReport(agents=agents)
    print_summary(report)
    print_agent_tree(report)


@main.command()
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

    schema_path = Path(__file__).parent.parent.parent / "schemas" / "inventory.schema.json"
    if not schema_path.exists():
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
        total_packages = sum(
            len(s.get("packages", []))
            for a in agents
            for s in a.get("mcp_servers", [])
        )
        console.print(f"\n  [green]✓ Valid[/green] — {len(agents)} agent(s), {total_servers} server(s), {total_packages} package(s)")
        console.print(f"\n  [dim]Scan with:[/dim] agent-bom scan --inventory {inventory_file}")
    else:
        console.print(f"\n  [red]✗ Invalid — {len(errors)} error(s):[/red]\n")
        for err in errors:
            path = " → ".join(str(p) for p in err.path) or "(root)"
            console.print(f"  [red]•[/red] [bold]{path}[/bold]: {err.message}")
        console.print()
        sys.exit(1)


@main.command()
def where():
    """Show where agent-bom looks for MCP configurations."""
    console = Console()
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
