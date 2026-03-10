"""Analysis commands — analytics, graph, dashboard, introspect."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console


@click.command("analytics")
@click.argument("query_type", type=click.Choice(["trends", "posture", "events", "top-cves"]))
@click.option("--days", default=30, type=int, help="Lookback window in days (default: 30)")
@click.option("--hours", default=24, type=int, help="Lookback window in hours for events (default: 24)")
@click.option("--agent", default=None, help="Filter by agent name")
@click.option("--limit", "top_limit", default=20, type=int, help="Limit for top-cves (default: 20)")
@click.option("--clickhouse-url", default=None, envvar="AGENT_BOM_CLICKHOUSE_URL", metavar="URL", help="ClickHouse HTTP URL")
def analytics_cmd(query_type, days, hours, agent, top_limit, clickhouse_url):
    """Query vulnerability trends, posture history, and runtime events from ClickHouse.

    \b
    Usage:
      agent-bom analytics trends [--days 30] [--agent NAME]
      agent-bom analytics posture [--days 90] [--agent NAME]
      agent-bom analytics events [--hours 24]
      agent-bom analytics top-cves [--limit 20]
    """
    from rich.table import Table

    from agent_bom.api.clickhouse_store import ClickHouseAnalyticsStore

    console = Console()

    if not clickhouse_url:
        console.print("[red]ClickHouse URL required.[/red] Set --clickhouse-url or AGENT_BOM_CLICKHOUSE_URL env var.")
        sys.exit(1)

    try:
        store = ClickHouseAnalyticsStore(url=clickhouse_url)
    except Exception as exc:
        console.print(f"[red]ClickHouse connection error:[/red] {exc}")
        sys.exit(1)

    if query_type == "trends":
        rows = store.query_vuln_trends(days=days, agent=agent)
        table = Table(title=f"Vulnerability Trends (last {days} days)")
        table.add_column("Day", style="cyan")
        table.add_column("Severity", style="yellow")
        table.add_column("Count", style="bold")
        for r in rows:
            table.add_row(str(r.get("day", "")), r.get("severity", ""), str(r.get("cnt", 0)))
        console.print(table)

    elif query_type == "posture":
        rows = store.query_posture_history(agent=agent, days=days)
        table = Table(title=f"Posture History (last {days} days)")
        table.add_column("Day", style="cyan")
        table.add_column("Agent", style="blue")
        table.add_column("Grade", style="bold")
        table.add_column("Risk Score", style="yellow")
        table.add_column("Compliance", style="green")
        for r in rows:
            table.add_row(
                str(r.get("day", "")),
                r.get("agent_name", ""),
                r.get("posture_grade", ""),
                str(r.get("risk_score", "")),
                str(r.get("compliance_score", "")),
            )
        console.print(table)

    elif query_type == "events":
        rows = store.query_event_summary(hours=hours)
        table = Table(title=f"Runtime Events (last {hours} hours)")
        table.add_column("Event Type", style="cyan")
        table.add_column("Severity", style="yellow")
        table.add_column("Count", style="bold")
        for r in rows:
            table.add_row(r.get("event_type", ""), r.get("severity", ""), str(r.get("cnt", 0)))
        console.print(table)

    elif query_type == "top-cves":
        rows = store.query_top_cves(limit=top_limit)
        table = Table(title=f"Top {top_limit} CVEs")
        table.add_column("CVE ID", style="cyan")
        table.add_column("Count", style="bold")
        table.add_column("Max CVSS", style="red")
        for r in rows:
            table.add_row(r.get("cve_id", ""), str(r.get("cnt", 0)), str(r.get("max_cvss", "")))
        console.print(table)

    if not rows:
        console.print("[dim]No data found. Run scans with --clickhouse-url to populate analytics.[/dim]")


@click.command("graph")
@click.argument("scan_file", type=click.Path(exists=True))
@click.option(
    "--format", "-f", "fmt", type=click.Choice(["json", "dot", "mermaid"]), default="json", show_default=True, help="Output format."
)
@click.option("--output", "-o", "output_path", default=None, help="Write to file instead of stdout.")
def graph_cmd(scan_file: str, fmt: str, output_path: Optional[str]) -> None:
    """Export the transitive dependency graph from a saved JSON scan report.

    \b
    SCAN_FILE  Path to a JSON file produced by: agent-bom scan --format json

    \b
    Examples:
        agent-bom scan --format json --output report.json
        agent-bom graph report.json --format dot --output deps.dot
        dot -Tsvg deps.dot -o deps.svg

        agent-bom graph report.json --format mermaid

    Closes #292.
    """
    from rich.console import Console as _Console

    from agent_bom.output.graph_export import load_graph_from_scan, to_dot, to_json, to_mermaid

    _con = _Console()

    try:
        graph = load_graph_from_scan(scan_file)
    except (ValueError, KeyError) as exc:
        _con.print(f"[red]Error loading scan file:[/red] {exc}")
        raise SystemExit(1) from exc

    if fmt == "dot":
        output = to_dot(graph)
    elif fmt == "mermaid":
        output = to_mermaid(graph)
    else:
        output = json.dumps(to_json(graph), indent=2)

    if output_path:
        Path(output_path).write_text(output)
        _con.print(f"[green]Graph exported[/green] ({graph.node_count()} nodes, {graph.edge_count()} edges) → {output_path}")
    else:
        click.echo(output)


@click.command("dashboard")
@click.option("--report", type=click.Path(exists=True), default=None, help="Path to agent-bom JSON report file.")
@click.option("--port", default=8501, show_default=True, help="Streamlit server port.")
def dashboard_cmd(report: Optional[str], port: int):
    """Launch the interactive Streamlit dashboard.

    \b
    Requires:  pip install 'agent-bom[dashboard]'

    \b
    Usage:
      agent-bom dashboard                        # Upload or live-scan from UI
      agent-bom dashboard --report scan.json     # Pre-load a report
      agent-bom scan -f json -o r.json && agent-bom dashboard --report r.json
    """
    import shutil
    import subprocess

    if not shutil.which("streamlit"):
        click.echo("Error: streamlit not found. Install with: pip install 'agent-bom[dashboard]'", err=True)
        sys.exit(1)

    app_path = Path(__file__).parent.parent.parent / "dashboard" / "app.py"
    if not app_path.exists():
        # Fallback: installed package location
        import importlib.resources

        try:
            ref = importlib.resources.files("dashboard") / "app.py"
            app_path = Path(str(ref))
        except (ModuleNotFoundError, TypeError):
            click.echo("Error: dashboard/app.py not found. Run from the agent-bom repo root.", err=True)
            sys.exit(1)

    cmd = ["streamlit", "run", str(app_path), "--server.port", str(port)]
    if report:
        cmd += ["--", "--report", report]

    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        pass
    except subprocess.CalledProcessError as exc:
        click.echo(f"Dashboard exited with code {exc.returncode}", err=True)
        sys.exit(exc.returncode)


@click.command("introspect")
@click.option("--command", "server_command", default=None, help="MCP server command to introspect (e.g. 'npx @mcp/server-filesystem /')")
@click.option("--url", "server_url", default=None, help="MCP server SSE/HTTP URL to introspect")
@click.option("--timeout", "timeout", default=10.0, show_default=True, type=float, help="Connection timeout per server (seconds)")
@click.option("--all", "introspect_all", is_flag=True, help="Introspect all discovered MCP servers (auto-discovery)")
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(exists=True),
    default=None,
    help="JSON baseline of expected tools — report drift against it",
)
@click.option("--format", "output_format", type=click.Choice(["console", "json"]), default="console", show_default=True)
@click.option("--no-color", is_flag=True, help="Disable ANSI color output")
def introspect_cmd(server_command, server_url, timeout, introspect_all, baseline_path, output_format, no_color):
    """Connect to live MCP servers and show their actual tools and resources.

    \b
    Read-only — only calls initialize, tools/list, resources/list.
    Never calls tools/call.  Detects drift against config-declared tools.

    \b
    Usage:
      agent-bom introspect --command "npx @mcp/server-filesystem /"
      agent-bom introspect --url http://localhost:8080/sse
      agent-bom introspect --all                           # all discovered servers
      agent-bom introspect --all --baseline baseline.json  # drift report
      agent-bom introspect --all --format json             # machine-readable

    \b
    Requires: pip install 'agent-bom[mcp-server]'  (for MCP SDK)
    """
    import json as _json

    from rich.table import Table

    from agent_bom.mcp_introspect import introspect_servers_sync

    con = Console(no_color=no_color)

    if not server_command and not server_url and not introspect_all:
        con.print("[red]Error:[/red] Provide --command, --url, or --all")
        sys.exit(1)

    # Build server list
    if introspect_all:
        from agent_bom.discovery import discover_all

        con.print("[dim]Discovering MCP servers...[/dim]", highlight=False)
        agents = discover_all()
        servers = [s for a in agents for s in a.mcp_servers]
        if not servers:
            con.print("[yellow]No MCP servers discovered.[/yellow]")
            sys.exit(0)
    else:
        from agent_bom.models import MCPServer, TransportType

        if server_command:
            parts = server_command.split()
            srv = MCPServer(
                name=parts[0],
                command=parts[0],
                args=parts[1:],
                transport=TransportType.STDIO,
            )
        else:
            srv = MCPServer(
                name=server_url or "server",
                url=server_url,
                transport=TransportType.SSE,
            )
        servers = [srv]

    # Load baseline if provided
    baseline: dict[str, list[str]] = {}
    if baseline_path:
        try:
            baseline = _json.loads(Path(baseline_path).read_text())
        except Exception as e:  # noqa: BLE001
            con.print(f"[yellow]Warning: could not load baseline: {e}[/yellow]")

    # Introspect
    try:
        results = introspect_servers_sync(servers, timeout=timeout)
    except ImportError:
        con.print("[red]MCP SDK not installed.[/red] Run: pip install 'agent-bom[mcp-server]'")
        sys.exit(1)

    if output_format == "json":
        output = []
        for r in results:
            entry = {
                "server": r.server_name,
                "success": r.success,
                "tools": [t.name for t in r.runtime_tools],
                "resources": [res.name for res in r.runtime_resources],
                "error": r.error,
            }
            if baseline:
                expected = baseline.get(r.server_name, [])
                entry["drift_added"] = [t for t in entry["tools"] if t not in expected]
                entry["drift_removed"] = [t for t in expected if t not in entry["tools"]]
            output.append(entry)
        click.echo(_json.dumps(output, indent=2))
        sys.exit(0)

    # Console output
    any_drift = False
    for r in results:
        status = "[green]✓[/green]" if r.success else "[red]✗[/red]"
        con.print(f"\n{status} [bold]{r.server_name}[/bold]", highlight=False)
        if not r.success:
            con.print(f"  [red]{r.error}[/red]")
            continue

        if r.protocol_version:
            con.print(f"  Protocol: {r.protocol_version}")

        if r.runtime_tools:
            tbl = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
            tbl.add_column("Tool")
            tbl.add_column("Description")
            for t in r.runtime_tools:
                desc = (t.description or "")[:80]
                expected_tools = baseline.get(r.server_name, [])
                marker = ""
                if expected_tools and t.name not in expected_tools:
                    marker = " [yellow](NEW)[/yellow]"
                    any_drift = True
                tbl.add_row(f"  {t.name}{marker}", desc)
            con.print(tbl)
        else:
            con.print("  [dim]No tools[/dim]")

        if r.runtime_resources:
            con.print(f"  Resources: {', '.join(res.name for res in r.runtime_resources)}")

        if baseline:
            expected_tools = baseline.get(r.server_name, [])
            removed = [t for t in expected_tools if t not in {x.name for x in r.runtime_tools}]
            if removed:
                con.print(f"  [red]Removed tools: {', '.join(removed)}[/red]")
                any_drift = True

    if any_drift:
        con.print("\n[yellow]⚠ Drift detected — tools differ from baseline.[/yellow]")
        sys.exit(1)
