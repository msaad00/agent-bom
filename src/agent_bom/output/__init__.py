"""Output formatters for AI-BOM reports."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional
from uuid import uuid4

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from agent_bom.models import AIBOMReport, Agent, BlastRadius, Severity

console = Console()

# ─── Console Output ─────────────────────────────────────────────────────────


def print_summary(report: AIBOMReport) -> None:
    """Print a summary of the AI-BOM report to console."""
    console.print("\n")
    console.print(Panel.fit(
        f"[bold]AI-BOM Report[/bold]\n"
        f"Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"agent-bom v{report.tool_version}",
        border_style="blue",
    ))

    # Summary stats
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("Agents discovered", str(report.total_agents))
    table.add_row("MCP servers", str(report.total_servers))
    table.add_row("Total packages", str(report.total_packages))
    table.add_row("Vulnerabilities", str(report.total_vulnerabilities))
    table.add_row("Critical findings", str(len(report.critical_vulns)))
    console.print(table)


def print_agent_tree(report: AIBOMReport) -> None:
    """Print the agent → server → package dependency tree."""
    console.print("\n[bold blue]📊 AI-BOM Dependency Tree[/bold blue]\n")

    for agent in report.agents:
        agent_tree = Tree(
            f"[bold]{agent.name}[/bold] ({agent.agent_type.value})"
            f" - {agent.config_path}"
        )

        for server in agent.mcp_servers:
            vuln_count = server.total_vulnerabilities
            vuln_indicator = f" [red]⚠ {vuln_count} vuln(s)[/red]" if vuln_count else ""
            cred_indicator = f" [yellow]🔑 {len(server.credential_names)} cred(s)[/yellow]" if server.has_credentials else ""

            server_branch = agent_tree.add(
                f"[bold cyan]{server.name}[/bold cyan] "
                f"({server.command} {' '.join(server.args[:2])})"
                f"{vuln_indicator}{cred_indicator}"
            )

            if server.tools:
                tools_branch = server_branch.add(f"[dim]Tools ({len(server.tools)})[/dim]")
                for tool in server.tools[:10]:  # Limit display
                    tools_branch.add(f"[dim]{tool.name}[/dim]")
                if len(server.tools) > 10:
                    tools_branch.add(f"[dim]...and {len(server.tools) - 10} more[/dim]")

            if server.packages:
                # Separate direct and transitive packages
                direct_pkgs = [p for p in server.packages if p.is_direct]
                transitive_pkgs = [p for p in server.packages if not p.is_direct]

                pkg_branch = server_branch.add(
                    f"Packages ({len(server.packages)}) - "
                    f"{len(direct_pkgs)} direct, {len(transitive_pkgs)} transitive"
                )

                # Show direct packages first
                for pkg in direct_pkgs:
                    vuln_str = ""
                    if pkg.has_vulnerabilities:
                        vuln_str = f" [red]({len(pkg.vulnerabilities)} vuln(s) - {pkg.max_severity.value})[/red]"
                    pkg_branch.add(
                        f"{pkg.name}@{pkg.version} [{pkg.ecosystem}]{vuln_str}"
                    )

                # Show transitive packages grouped by depth (limit display)
                if transitive_pkgs:
                    transitive_branch = pkg_branch.add(f"[dim]Transitive ({len(transitive_pkgs)})[/dim]")
                    for pkg in transitive_pkgs[:20]:  # Limit to 20 for readability
                        vuln_str = ""
                        if pkg.has_vulnerabilities:
                            vuln_str = f" [red]({len(pkg.vulnerabilities)} vuln(s))[/red]"
                        indent = "  " * pkg.dependency_depth
                        parent_str = f" ← {pkg.parent_package}" if pkg.parent_package else ""
                        transitive_branch.add(
                            f"[dim]{indent}{pkg.name}@{pkg.version}{parent_str}{vuln_str}[/dim]"
                        )
                    if len(transitive_pkgs) > 20:
                        transitive_branch.add(f"[dim]...and {len(transitive_pkgs) - 20} more[/dim]")

            if server.has_credentials:
                cred_branch = server_branch.add("[yellow]Credentials[/yellow]")
                for cred in server.credential_names:
                    cred_branch.add(f"[yellow]{cred}[/yellow]")

        console.print(agent_tree)
        console.print()


def print_blast_radius(report: AIBOMReport) -> None:
    """Print blast radius analysis for vulnerabilities."""
    if not report.blast_radii:
        return

    console.print("\n[bold red]💥 Blast Radius Analysis[/bold red]\n")

    table = Table(title="Vulnerability Impact Chain")
    table.add_column("Risk", justify="center", width=6)
    table.add_column("Vuln ID", width=20)
    table.add_column("Package", width=25)
    table.add_column("Severity", width=10)
    table.add_column("Agents", width=8, justify="center")
    table.add_column("Servers", width=8, justify="center")
    table.add_column("Creds", width=8, justify="center")
    table.add_column("Fix", width=15)

    severity_colors = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "dim",
    }

    for br in report.blast_radii[:25]:  # Top 25
        sev_style = severity_colors.get(br.vulnerability.severity, "white")
        risk_bar = "█" * int(br.risk_score) + "░" * (10 - int(br.risk_score))
        fix = br.vulnerability.fixed_version or "—"

        # EPSS score display
        epss_display = "—"
        if br.vulnerability.epss_score is not None:
            epss_pct = int(br.vulnerability.epss_score * 100)
            epss_style = "red bold" if epss_pct >= 70 else "yellow" if epss_pct >= 30 else "dim"
            epss_display = f"[{epss_style}]{epss_pct}%[/{epss_style}]"

        # KEV indicator
        kev_display = "[red bold]🔥[/red bold]" if br.vulnerability.is_kev else "—"

        table.add_row(
            f"[{sev_style}]{br.risk_score:.1f}[/{sev_style}]",
            br.vulnerability.id,
            f"{br.package.name}@{br.package.version}",
            f"[{sev_style}]{br.vulnerability.severity.value}[/{sev_style}]",
            epss_display,
            kev_display,
            str(len(br.affected_agents)),
            str(len(br.exposed_credentials)),
            fix,
        )

    console.print(table)

    if len(report.blast_radii) > 25:
        console.print(f"\n  [dim]...and {len(report.blast_radii) - 25} more findings. "
                       f"Use --output to export full report.[/dim]")


# ─── JSON Output ────────────────────────────────────────────────────────────


def to_json(report: AIBOMReport) -> dict:
    """Convert report to JSON-serializable dict."""
    return {
        "ai_bom_version": "0.1.0",
        "generated_at": report.generated_at.isoformat(),
        "summary": {
            "total_agents": report.total_agents,
            "total_mcp_servers": report.total_servers,
            "total_packages": report.total_packages,
            "total_vulnerabilities": report.total_vulnerabilities,
            "critical_findings": len(report.critical_vulns),
        },
        "agents": [
            {
                "name": agent.name,
                "type": agent.agent_type.value,
                "config_path": agent.config_path,
                "mcp_servers": [
                    {
                        "name": server.name,
                        "command": server.command,
                        "args": server.args,
                        "transport": server.transport.value,
                        "url": server.url,
                        "has_credentials": server.has_credentials,
                        "credential_env_vars": server.credential_names,
                        "tools": [
                            {"name": t.name, "description": t.description}
                            for t in server.tools
                        ],
                        "packages": [
                            {
                                "name": pkg.name,
                                "version": pkg.version,
                                "ecosystem": pkg.ecosystem,
                                "purl": pkg.purl,
                                "is_direct": pkg.is_direct,
                                "parent_package": pkg.parent_package,
                                "dependency_depth": pkg.dependency_depth,
                                "resolved_from_registry": pkg.resolved_from_registry,
                                "vulnerabilities": [
                                    {
                                        "id": v.id,
                                        "summary": v.summary,
                                        "severity": v.severity.value,
                                        "cvss_score": v.cvss_score,
                                        "fixed_version": v.fixed_version,
                                        "references": v.references,
                                    }
                                    for v in pkg.vulnerabilities
                                ],
                            }
                            for pkg in server.packages
                        ],
                    }
                    for server in agent.mcp_servers
                ],
            }
            for agent in report.agents
        ],
        "blast_radius": [
            {
                "risk_score": br.risk_score,
                "vulnerability_id": br.vulnerability.id,
                "severity": br.vulnerability.severity.value,
                "package": f"{br.package.name}@{br.package.version}",
                "ecosystem": br.package.ecosystem,
                "affected_agents": [a.name for a in br.affected_agents],
                "affected_servers": [s.name for s in br.affected_servers],
                "exposed_credentials": br.exposed_credentials,
                "exposed_tools": [t.name for t in br.exposed_tools],
                "fixed_version": br.vulnerability.fixed_version,
            }
            for br in report.blast_radii
        ],
    }


def export_json(report: AIBOMReport, output_path: str) -> None:
    """Export report as JSON."""
    data = to_json(report)
    Path(output_path).write_text(json.dumps(data, indent=2))
    console.print(f"\n  [green]✓[/green] JSON report saved to {output_path}")


# ─── CycloneDX Output ──────────────────────────────────────────────────────


def export_cyclonedx(report: AIBOMReport, output_path: str) -> None:
    """Export report in CycloneDX 1.6 JSON format."""
    components = []
    vulnerabilities_cdx = []
    dependencies = []

    comp_id = 0
    bom_ref_map = {}

    # Add agents as top-level components
    for agent in report.agents:
        agent_ref = f"agent-{agent.name}"
        agent_deps = []

        components.append({
            "type": "application",
            "bom-ref": agent_ref,
            "name": agent.name,
            "version": agent.version or "unknown",
            "description": f"AI Agent ({agent.agent_type.value})",
            "properties": [
                {"name": "agent-bom:type", "value": "ai-agent"},
                {"name": "agent-bom:config-path", "value": agent.config_path},
            ],
        })

        for server in agent.mcp_servers:
            server_ref = f"mcp-server-{server.name}-{comp_id}"
            comp_id += 1
            server_deps = []

            server_props = [
                {"name": "agent-bom:type", "value": "mcp-server"},
                {"name": "agent-bom:command", "value": server.command},
                {"name": "agent-bom:transport", "value": server.transport.value},
            ]
            if server.has_credentials:
                server_props.append({
                    "name": "agent-bom:has-credentials", "value": "true"
                })

            components.append({
                "type": "application",
                "bom-ref": server_ref,
                "name": server.name,
                "description": f"MCP Server ({server.transport.value})",
                "properties": server_props,
            })
            agent_deps.append(server_ref)

            for pkg in server.packages:
                pkg_ref = f"pkg-{pkg.ecosystem}-{pkg.name}-{pkg.version}-{comp_id}"
                comp_id += 1

                pkg_properties = [
                    {"name": "agent-bom:ecosystem", "value": pkg.ecosystem},
                    {"name": "agent-bom:is-direct", "value": str(pkg.is_direct).lower()},
                    {"name": "agent-bom:dependency-depth", "value": str(pkg.dependency_depth)},
                    {"name": "agent-bom:resolved-from-registry", "value": str(pkg.resolved_from_registry).lower()},
                ]
                if pkg.parent_package:
                    pkg_properties.append({
                        "name": "agent-bom:parent-package", "value": pkg.parent_package
                    })

                components.append({
                    "type": "library",
                    "bom-ref": pkg_ref,
                    "name": pkg.name,
                    "version": pkg.version,
                    "purl": pkg.purl,
                    "properties": pkg_properties,
                })
                server_deps.append(pkg_ref)
                bom_ref_map[f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"] = pkg_ref

                # Add vulnerabilities
                for vuln in pkg.vulnerabilities:
                    vuln_entry = {
                        "id": vuln.id,
                        "description": vuln.summary,
                        "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vuln.id}"},
                        "ratings": [],
                        "affects": [{"ref": pkg_ref}],
                    }
                    if vuln.cvss_score:
                        vuln_entry["ratings"].append({
                            "score": vuln.cvss_score,
                            "severity": vuln.severity.value,
                            "method": "CVSSv3",
                        })
                    else:
                        vuln_entry["ratings"].append({
                            "severity": vuln.severity.value,
                        })
                    if vuln.fixed_version:
                        vuln_entry["recommendation"] = f"Upgrade to {vuln.fixed_version}"
                    vulnerabilities_cdx.append(vuln_entry)

            dependencies.append({"ref": server_ref, "dependsOn": server_deps})
        dependencies.append({"ref": agent_ref, "dependsOn": agent_deps})

    cdx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": report.generated_at.isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "agent-bom",
                        "version": report.tool_version,
                        "description": "AI Bill of Materials generator for AI agents and MCP servers",
                    }
                ]
            },
            "properties": [
                {"name": "agent-bom:total-agents", "value": str(report.total_agents)},
                {"name": "agent-bom:total-mcp-servers", "value": str(report.total_servers)},
                {"name": "agent-bom:total-vulnerabilities", "value": str(report.total_vulnerabilities)},
            ],
        },
        "components": components,
        "dependencies": dependencies,
    }

    if vulnerabilities_cdx:
        cdx["vulnerabilities"] = vulnerabilities_cdx

    Path(output_path).write_text(json.dumps(cdx, indent=2))
    console.print(f"\n  [green]✓[/green] CycloneDX BOM saved to {output_path}")
