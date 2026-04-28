"""Posture summary rendering for the scan command."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.panel import Panel


def render_posture_summary(agents: list[Any], blast_radii: list[Any]) -> None:
    """Render the compact --posture panel."""
    total_vulns = len(blast_radii)
    crit = sum(1 for br in blast_radii if br.vulnerability.severity.value == "critical")
    high = sum(1 for br in blast_radii if br.vulnerability.severity.value == "high")
    agent_names = [a.name for a in agents]
    agent_list_str = ", ".join(agent_names[:3]) + (f" +{len(agent_names) - 3}" if len(agent_names) > 3 else "")
    agent_count = len(agents)
    server_count = sum(len(a.mcp_servers) for a in agents)
    credential_server_count = sum(
        1
        for agent in agents
        for server in agent.mcp_servers
        if any(
            value
            for key, value in (getattr(server, "env", None) or {}).items()
            if any(keyword in key.upper() for keyword in ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"))
        )
    )
    floating = sum(
        1 for agent in agents for server in agent.mcp_servers if any("@latest" in str(arg) for arg in (getattr(server, "args", None) or []))
    )
    unverified = sum(1 for agent in agents for server in agent.mcp_servers if not getattr(server, "verified", False))
    credential_names = sorted({cred for br in blast_radii for cred in (br.exposed_credentials or [])})
    tool_names = sorted({tool.name for br in blast_radii for tool in (br.exposed_tools or []) if getattr(tool, "name", None)})
    fixable = sum(1 for br in blast_radii if getattr(br.vulnerability, "fixed_version", None))
    top_blast_radii = sorted(blast_radii, key=lambda br: br.risk_score or 0.0, reverse=True)
    top_str = ""
    if top_blast_radii:
        top = top_blast_radii[0]
        package_name = top.package.name if top.package else "unknown"
        vuln_id = top.vulnerability.id if top.vulnerability else "unknown"
        top_str = f"{package_name}@{top.package.version} ({vuln_id})" if top.package else vuln_id
        fixed_version = getattr(top.vulnerability, "fixed_version", None)
        action = (
            f"Upgrade {package_name} to {fixed_version} to clear {total_vulns} vuln(s)"
            if fixed_version and package_name != "unknown"
            else "Review findings with agent-bom agents"
        )
    else:
        action = "No vulnerabilities found — supply chain looks clean"

    lines = [
        f"[bold]Agents:[/bold]   {agent_count} configured ({agent_list_str})",
        f"[bold]Servers:[/bold]  {server_count} MCP servers ({credential_server_count} with credentials)",
    ]
    if total_vulns:
        lines.append(f"[bold]Risk:[/bold]     {total_vulns} vuln(s) ({crit} critical, {high} high)")
        lines.append(
            "  [bold]Blast:[/bold]    "
            f"{len({agent.name for br in blast_radii for agent in (br.affected_agents or [])})} agents · "
            f"{len(credential_names)} creds · {len(tool_names)} tools reachable"
        )
        lines.append(f"[bold]Fixes:[/bold]    {fixable} finding(s) have an upgrade path")
        if top_str:
            lines.append(f"[bold]Top:[/bold]      {top_str}")
    else:
        lines.append("[bold]Risk:[/bold]     No vulnerabilities found")
    lines.append(f"[bold]Trust:[/bold]    {floating} server(s) floating on @latest, {unverified} unverified")
    lines.append(f"[bold]Action:[/bold]   {action}")

    console = Console()
    console.print()
    console.print(
        Panel.fit(
            "\n".join(lines),
            title="[bold]agent-bom posture[/bold]",
            border_style="cyan",
            padding=(1, 2),
        )
    )
