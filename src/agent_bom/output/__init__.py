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

from agent_bom.models import Agent, AIBOMReport, BlastRadius, Severity

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
    table.add_column("EPSS", width=6, justify="center")
    table.add_column("KEV", width=4, justify="center")
    table.add_column("Agents", width=7, justify="center")
    table.add_column("Creds", width=6, justify="center")
    table.add_column("Fix", width=15)

    severity_colors = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "dim",
    }

    for br in report.blast_radii[:25]:  # Top 25
        sev_style = severity_colors.get(br.vulnerability.severity, "white")
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


# ─── Remediation Plan ───────────────────────────────────────────────────────


def build_remediation_plan(blast_radii: list[BlastRadius]) -> list[dict]:
    """Group blast radii into a prioritized remediation plan.

    Returns items sorted by impact: each item = one upgrade action that clears
    N vulns across M agents and frees exposed credentials.
    """
    from collections import defaultdict

    groups: dict[tuple, dict] = defaultdict(lambda: {
        "package": "", "ecosystem": "", "current": "", "fix": None,
        "vulns": [], "agents": set(), "creds": set(), "tools": set(),
        "max_severity": Severity.NONE, "has_kev": False, "ai_risk": False,
    })
    severity_order = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1, Severity.NONE: 0}

    for br in blast_radii:
        key = (br.package.name, br.package.ecosystem, br.package.version, br.vulnerability.fixed_version)
        g = groups[key]
        g["package"] = br.package.name
        g["ecosystem"] = br.package.ecosystem
        g["current"] = br.package.version
        g["fix"] = br.vulnerability.fixed_version
        g["vulns"].append(br.vulnerability.id)
        for a in br.affected_agents:
            g["agents"].add(a.name)
        g["creds"].update(br.exposed_credentials)
        g["tools"].update(t.name for t in br.exposed_tools)
        if severity_order.get(br.vulnerability.severity, 0) > severity_order.get(g["max_severity"], 0):
            g["max_severity"] = br.vulnerability.severity
        if br.vulnerability.is_kev:
            g["has_kev"] = True
        if br.ai_risk_context:
            g["ai_risk"] = True

    plan = []
    for g in groups.values():
        g["vulns"] = list(set(g["vulns"]))
        g["agents"] = list(g["agents"])
        g["creds"] = list(g["creds"])
        g["tools"] = list(g["tools"])
        g["impact"] = (
            len(g["agents"]) * 10 + len(g["creds"]) * 3 + len(g["vulns"])
            + (5 if g["has_kev"] else 0) + (3 if g["ai_risk"] else 0)
        )
        plan.append(g)

    plan.sort(key=lambda x: x["impact"], reverse=True)
    return plan


def print_remediation_plan(blast_radii: list[BlastRadius]) -> None:
    """Print a prioritized remediation plan to the console."""
    if not blast_radii:
        return

    plan = build_remediation_plan(blast_radii)
    fixable = [p for p in plan if p["fix"]]
    unfixable = [p for p in plan if not p["fix"]]

    console.print("\n[bold green]🔧 Remediation Plan[/bold green]\n")

    sev_style = {
        Severity.CRITICAL: "red bold", Severity.HIGH: "red",
        Severity.MEDIUM: "yellow", Severity.LOW: "dim", Severity.NONE: "white",
    }

    if fixable:
        console.print(f"  [bold]{len(fixable)} fixable upgrade(s) — ordered by blast radius impact:[/bold]\n")
        for i, item in enumerate(fixable, 1):
            sev = item["max_severity"]
            style = sev_style.get(sev, "white")
            kev_flag = " [red bold][KEV][/red bold]" if item["has_kev"] else ""
            ai_flag = " [magenta][AI-RISK][/magenta]" if item["ai_risk"] else ""
            console.print(
                f"  [{style}]{i}. upgrade {item['package']}[/{style}]  "
                f"[dim]{item['current']}[/dim] → [green bold]{item['fix']}[/green bold]"
                f"{kev_flag}{ai_flag}"
            )
            impact_parts = [f"clears {len(item['vulns'])} vuln(s)", f"{len(item['agents'])} agent(s) protected"]
            if item["creds"]:
                impact_parts.append(f"frees {len(item['creds'])} credential(s): {', '.join(item['creds'][:3])}")
            if item["tools"]:
                impact_parts.append(f"removes attacker access to {len(item['tools'])} tool(s)")
            console.print(f"     [dim]{'  •  '.join(impact_parts)}[/dim]\n")

    if unfixable:
        console.print(f"  [dim yellow]⚠ {len(unfixable)} package(s) have no fix yet — monitor upstream for patches:[/dim yellow]")
        for item in unfixable[:10]:
            console.print(f"    [dim]• {item['package']}@{item['current']} ({', '.join(item['vulns'][:3])})[/dim]")
        console.print()


# ─── JSON Output ────────────────────────────────────────────────────────────


def to_json(report: AIBOMReport) -> dict:
    """Convert report to JSON-serializable dict."""
    return {
        "ai_bom_version": report.tool_version,
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
                "source": agent.source,
                "mcp_servers": [
                    {
                        "name": server.name,
                        "command": server.command,
                        "args": server.args,
                        "transport": server.transport.value,
                        "url": server.url,
                        "mcp_version": server.mcp_version,
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
                                        "epss_score": v.epss_score,
                                        "epss_percentile": v.epss_percentile,
                                        "is_kev": v.is_kev,
                                        "kev_date_added": v.kev_date_added,
                                        "cwe_ids": v.cwe_ids,
                                        "fixed_version": v.fixed_version,
                                        "references": v.references,
                                        "nvd_published": v.nvd_published,
                                        "nvd_modified": v.nvd_modified,
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
                "cvss_score": br.vulnerability.cvss_score,
                "epss_score": br.vulnerability.epss_score,
                "is_kev": br.vulnerability.is_kev,
                "package": f"{br.package.name}@{br.package.version}",
                "ecosystem": br.package.ecosystem,
                "affected_agents": [a.name for a in br.affected_agents],
                "affected_servers": [s.name for s in br.affected_servers],
                "exposed_credentials": br.exposed_credentials,
                "exposed_tools": [t.name for t in br.exposed_tools],
                "fixed_version": br.vulnerability.fixed_version,
                "ai_risk_context": br.ai_risk_context,
            }
            for br in report.blast_radii
        ],
    }


def export_json(report: AIBOMReport, output_path: str) -> None:
    """Export report as JSON file."""
    data = to_json(report)
    Path(output_path).write_text(json.dumps(data, indent=2))


# ─── CycloneDX Output ──────────────────────────────────────────────────────


def to_cyclonedx(report: AIBOMReport) -> dict:
    """Build CycloneDX 1.6 dict from report."""
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

    return cdx


def export_cyclonedx(report: AIBOMReport, output_path: str) -> None:
    """Export report as CycloneDX 1.6 JSON file."""
    cdx = to_cyclonedx(report)
    Path(output_path).write_text(json.dumps(cdx, indent=2))


# ─── SARIF Output ──────────────────────────────────────────────────────────

_SARIF_SEVERITY_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.NONE: "none",
}


def to_sarif(report: AIBOMReport) -> dict:
    """Convert report to SARIF 2.1.0 dict for GitHub Security tab."""
    rules = []
    results = []
    seen_rule_ids: set[str] = set()

    for br in report.blast_radii:
        vuln = br.vulnerability
        rule_id = vuln.id
        level = _SARIF_SEVERITY_MAP.get(vuln.severity, "warning")

        if rule_id not in seen_rule_ids:
            seen_rule_ids.add(rule_id)
            rule: dict = {
                "id": rule_id,
                "shortDescription": {"text": f"{vuln.severity.value.upper()}: {vuln.id} in {br.package.name}@{br.package.version}"},
                "fullDescription": {"text": vuln.summary or f"Vulnerability {vuln.id}"},
                "helpUri": f"https://osv.dev/vulnerability/{vuln.id}",
                "defaultConfiguration": {"level": level},
            }
            if vuln.cwe_ids:
                rule["properties"] = {"tags": vuln.cwe_ids}
            rules.append(rule)

        affected = ", ".join(a.name for a in br.affected_agents)
        message_text = (
            f"{vuln.id} ({vuln.severity.value}) in {br.package.name}@{br.package.version}. "
            f"Affects agents: {affected}."
        )
        if vuln.fixed_version:
            message_text += f" Fix: upgrade to {vuln.fixed_version}."

        config_path = br.affected_agents[0].config_path if br.affected_agents else "unknown"

        result = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": config_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                    },
                }
            ],
        }
        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-bom",
                        "version": report.tool_version,
                        "informationUri": "https://github.com/agent-bom/agent-bom",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def export_sarif(report: AIBOMReport, output_path: str) -> None:
    """Export report as SARIF 2.1.0 JSON file."""
    data = to_sarif(report)
    Path(output_path).write_text(json.dumps(data, indent=2))
