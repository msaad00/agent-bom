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
    table.add_column("OWASP", width=18)
    table.add_column("ATLAS", width=22)
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

        owasp_display = "[dim]" + " ".join(br.owasp_tags) + "[/dim]" if br.owasp_tags else "—"
        atlas_display = "[dim]" + " ".join(br.atlas_tags) + "[/dim]" if br.atlas_tags else "—"

        table.add_row(
            f"[{sev_style}]{br.risk_score:.1f}[/{sev_style}]",
            br.vulnerability.id,
            f"{br.package.name}@{br.package.version}",
            f"[{sev_style}]{br.vulnerability.severity.value}[/{sev_style}]",
            epss_display,
            kev_display,
            str(len(br.affected_agents)),
            str(len(br.exposed_credentials)),
            owasp_display,
            atlas_display,
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
                "owasp_tags": br.owasp_tags,
                "atlas_tags": br.atlas_tags,
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

        result: dict = {
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
        if br.owasp_tags or br.atlas_tags:
            result["properties"] = {
                "owasp_tags": br.owasp_tags,
                "atlas_tags": br.atlas_tags,
                "blast_score": br.risk_score,
                "exposed_credentials": br.exposed_credentials,
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


# ─── Diff Output ─────────────────────────────────────────────────────────────


def print_diff(diff: dict) -> None:
    """Print a human-readable diff between two scan reports."""
    summary = diff["summary"]
    baseline_ts = diff["baseline_generated_at"]
    current_ts = diff["current_generated_at"]

    console.print(f"\n[bold blue]📊 Scan Diff[/bold blue]  "
                  f"[dim]{baseline_ts}[/dim] → [dim]{current_ts}[/dim]\n")

    parts = []
    if summary["new_findings"]:
        parts.append(f"[red bold]+{summary['new_findings']} new[/red bold]")
    if summary["resolved_findings"]:
        parts.append(f"[green bold]-{summary['resolved_findings']} resolved[/green bold]")
    if summary["unchanged_findings"]:
        parts.append(f"[dim]{summary['unchanged_findings']} unchanged[/dim]")
    if summary["new_packages"]:
        parts.append(f"[yellow]{summary['new_packages']} new package(s)[/yellow]")
    if summary["removed_packages"]:
        parts.append(f"[dim]{summary['removed_packages']} removed package(s)[/dim]")

    if parts:
        console.print("  " + "  •  ".join(parts) + "\n")
    else:
        console.print("  [green]No changes since baseline.[/green]\n")
        return

    severity_styles = {
        "CRITICAL": "red bold", "HIGH": "red",
        "MEDIUM": "yellow", "LOW": "dim",
    }

    if diff["new"]:
        console.print(f"  [red bold]New findings ({len(diff['new'])}):[/red bold]")
        for br in diff["new"][:20]:
            sev = br.get("severity", "UNKNOWN")
            style = severity_styles.get(sev, "white")
            kev = " [red bold][KEV][/red bold]" if br.get("is_kev") else ""
            ai = " [magenta][AI-RISK][/magenta]" if br.get("ai_risk_context") else ""
            fix = f" → fix: {br['fixed_version']}" if br.get("fixed_version") else " (no fix)"
            console.print(
                f"    [+] [{style}]{br.get('vulnerability_id', '?')}[/{style}]  "
                f"{br.get('package', '?')}  [{sev}]{kev}{ai}[dim]{fix}[/dim]"
            )
        if len(diff["new"]) > 20:
            console.print(f"    [dim]...and {len(diff['new']) - 20} more[/dim]")
        console.print()

    if diff["resolved"]:
        console.print(f"  [green]Resolved findings ({len(diff['resolved'])}):[/green]")
        for br in diff["resolved"][:10]:
            console.print(
                f"    [-] [dim]{br.get('vulnerability_id', '?')}  "
                f"{br.get('package', '?')}[/dim]"
            )
        console.print()

    if diff["new_packages"]:
        console.print(f"  [yellow]New packages added ({len(diff['new_packages'])}):[/yellow]")
        for pkg in diff["new_packages"][:10]:
            console.print(f"    [+] [dim]{pkg}[/dim]")
        console.print()

    if diff["removed_packages"]:
        console.print(f"  [dim]Packages removed ({len(diff['removed_packages'])}):[/dim]")
        for pkg in diff["removed_packages"][:10]:
            console.print(f"    [-] [dim]{pkg}[/dim]")
        console.print()


# ─── Policy Output ──────────────────────────────────────────────────────────


def print_policy_results(policy_result: dict) -> None:
    """Print policy evaluation results to console."""
    name = policy_result["policy_name"]
    failures = policy_result["failures"]
    warnings = policy_result["warnings"]
    passed = policy_result["passed"]

    status = "[green]PASS[/green]" if passed else "[red bold]FAIL[/red bold]"
    console.print(f"\n[bold]📋 Policy: {name}[/bold]  {status}\n")

    if warnings:
        console.print(f"  [yellow]⚠ {len(warnings)} warning(s):[/yellow]")
        for v in warnings[:10]:
            console.print(
                f"    [yellow]WARN[/yellow]  [{v['rule_id']}]  "
                f"{v['vulnerability_id']}  {v['package']}  [{v['severity']}]"
            )
            console.print(f"           [dim]{v['rule_description']}[/dim]")
        console.print()

    if failures:
        console.print(f"  [red bold]✗ {len(failures)} failure(s):[/red bold]")
        for v in failures[:10]:
            kev = " [red bold][KEV][/red bold]" if v.get("is_kev") else ""
            ai = " [magenta][AI-RISK][/magenta]" if v.get("ai_risk_context") else ""
            console.print(
                f"    [red bold]FAIL[/red bold]  [{v['rule_id']}]  "
                f"{v['vulnerability_id']}  {v['package']}  [{v['severity']}]{kev}{ai}"
            )
            console.print(f"           [dim]{v['rule_description']}[/dim]")
        if len(failures) > 10:
            console.print(f"    [dim]...and {len(failures) - 10} more failures[/dim]")
        console.print()

    if passed and not warnings:
        console.print("  [green]✓ All policy rules passed.[/green]\n")


# ─── Severity Chart ─────────────────────────────────────────────────────────


def print_severity_chart(report: AIBOMReport) -> None:
    """Print an ASCII severity distribution bar chart."""
    if not report.blast_radii:
        return

    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for br in report.blast_radii:
        sev = br.vulnerability.severity.value.upper()
        if sev in counts:
            counts[sev] += 1

    total = sum(counts.values())
    if total == 0:
        return

    console.print("\n[bold]Severity Distribution[/bold]")
    max_count = max(counts.values()) or 1
    bar_width = 30
    styles = {
        "CRITICAL": "red bold",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "dim",
    }

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = counts[sev]
        bar_len = int(bar_width * count / max_count) if count else 0
        bar = "█" * bar_len
        style = styles[sev]
        pct = int(100 * count / total) if total else 0
        console.print(
            f"  [{style}]{sev:8}[/{style}]  "
            f"[{style}]{bar:<{bar_width}}[/{style}]  "
            f"[dim]{count:3} ({pct}%)[/dim]"
        )
    console.print()


# ─── SPDX 3.0 Output ────────────────────────────────────────────────────────


def to_spdx(report: AIBOMReport) -> dict:
    """Build an SPDX 3.0 (JSON-LD) dict from report.

    Follows the SPDX 3.0 AI BOM profile where applicable:
    - Each agent becomes an /AI element
    - Each package becomes a /Package element
    - Vulnerabilities become /security/VulnAssessmentRelationship elements
    - Dependency edges become DEPENDS_ON relationships
    """
    from datetime import timezone

    spdx_id_counter = [0]

    def _next_id(prefix: str = "SPDXRef") -> str:
        spdx_id_counter[0] += 1
        return f"{prefix}-{spdx_id_counter[0]}"

    elements = []
    relationships = []
    document_id = _next_id("SPDXRef-DOCUMENT")

    # Document / CreationInfo
    creation_info = {
        "specVersion": "3.0.0",
        "created": report.generated_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if report.generated_at.tzinfo
        else report.generated_at.strftime("%Y-%m-%dT%H:%M:%SZ") + "Z",
        "createdBy": [
            {
                "type": "Tool",
                "name": f"agent-bom {report.tool_version}",
                "externalIdentifier": [
                    {
                        "type": "PackageURL",
                        "identifier": f"pkg:pypi/agent-bom@{report.tool_version}",
                    }
                ],
            }
        ],
    }

    pkg_ref_map: dict[str, str] = {}  # ecosystem:name@version → spdxId

    for agent in report.agents:
        agent_id = _next_id("SPDXRef-Agent")

        agent_element = {
            "type": "ai_bom/Agent",
            "spdxId": agent_id,
            "name": agent.name,
            "primaryPurpose": "APPLICATION",
            "description": f"AI Agent ({agent.agent_type.value})",
        }
        if agent.config_path:
            agent_element["comment"] = f"config_path: {agent.config_path}"
        if agent.source:
            agent_element["originatedBy"] = agent.source
        elements.append(agent_element)

        for server in agent.mcp_servers:
            server_id = _next_id("SPDXRef-MCPServer")

            server_element = {
                "type": "SOFTWARE_PACKAGE",
                "spdxId": server_id,
                "name": server.name,
                "primaryPurpose": "APPLICATION",
                "description": f"MCP Server ({server.transport.value})",
            }
            if server.mcp_version:
                server_element["versionInfo"] = server.mcp_version
            elements.append(server_element)

            relationships.append({
                "type": "Relationship",
                "spdxId": _next_id("SPDXRef-Rel"),
                "relationshipType": "CONTAINS",
                "from": agent_id,
                "to": [server_id],
            })

            for pkg in server.packages:
                pkg_key = f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"
                if pkg_key not in pkg_ref_map:
                    pkg_id = _next_id("SPDXRef-Pkg")
                    pkg_ref_map[pkg_key] = pkg_id

                    pkg_element = {
                        "type": "SOFTWARE_PACKAGE",
                        "spdxId": pkg_id,
                        "name": pkg.name,
                        "versionInfo": pkg.version,
                        "primaryPurpose": "LIBRARY",
                    }
                    if pkg.purl:
                        pkg_element["externalIdentifier"] = [
                            {"type": "PackageURL", "identifier": pkg.purl}
                        ]
                    elements.append(pkg_element)

                pkg_id = pkg_ref_map[pkg_key]
                relationships.append({
                    "type": "Relationship",
                    "spdxId": _next_id("SPDXRef-Rel"),
                    "relationshipType": "DEPENDS_ON",
                    "from": server_id,
                    "to": [pkg_id],
                })

                # Security relationships for each vulnerability
                for vuln in pkg.vulnerabilities:
                    vuln_element_id = _next_id("SPDXRef-Vuln")
                    vuln_element = {
                        "type": "security/Vulnerability",
                        "spdxId": vuln_element_id,
                        "name": vuln.id,
                        "description": vuln.summary or "",
                        "externalIdentifier": [{"type": "cve", "identifier": vuln.id}]
                        if vuln.id.startswith("CVE-")
                        else [],
                    }
                    if vuln.cvss_score is not None:
                        vuln_element["assessedElement"] = pkg_id
                        vuln_element["score"] = {
                            "method": "CVSS_3",
                            "score": vuln.cvss_score,
                            "severity": vuln.severity.value,
                        }
                    elements.append(vuln_element)

                    assessment_id = _next_id("SPDXRef-VulnAssessment")
                    assessment = {
                        "type": "security/VulnAssessmentRelationship",
                        "spdxId": assessment_id,
                        "relationshipType": "AFFECTS",
                        "from": vuln_element_id,
                        "to": [pkg_id],
                        "severity": vuln.severity.value,
                    }
                    if vuln.fixed_version:
                        assessment["remediation"] = f"Upgrade to {vuln.fixed_version}"
                    if vuln.is_kev:
                        assessment["comment"] = "CISA KEV: actively exploited in the wild"
                    relationships.append(assessment)

    return {
        "spdxVersion": "SPDX-3.0",
        "dataLicense": "CC0-1.0",
        "SPDXID": document_id,
        "name": f"agent-bom-{report.generated_at.strftime('%Y%m%d-%H%M%S')}",
        "creationInfo": creation_info,
        "elements": elements,
        "relationships": relationships,
        "comment": (
            f"AI Bill of Materials generated by agent-bom {report.tool_version}. "
            f"Covers {report.total_agents} agent(s), {report.total_servers} MCP server(s), "
            f"{report.total_packages} package(s), {report.total_vulnerabilities} vulnerability/ies."
        ),
    }


def export_spdx(report: AIBOMReport, output_path: str) -> None:
    """Export report as SPDX 3.0 JSON-LD file."""
    data = to_spdx(report)
    Path(output_path).write_text(json.dumps(data, indent=2))


def to_html(report: AIBOMReport, blast_radii: list | None = None) -> str:
    """Generate a self-contained HTML report string."""
    from agent_bom.output.html import to_html as _to_html
    return _to_html(report, blast_radii or [])


def export_html(report: AIBOMReport, output_path: str, blast_radii: list | None = None) -> None:
    """Export report as a self-contained HTML file."""
    from agent_bom.output.html import export_html as _export_html
    _export_html(report, output_path, blast_radii or [])


# ─── Prometheus Output ───────────────────────────────────────────────────────


def to_prometheus(report: AIBOMReport, blast_radii: list | None = None) -> str:
    """Generate Prometheus text exposition format string."""
    from agent_bom.output.prometheus import to_prometheus as _to_prometheus
    return _to_prometheus(report, blast_radii or [])


def export_prometheus(
    report: AIBOMReport, output_path: str, blast_radii: list | None = None
) -> None:
    """Write Prometheus metrics to a .prom file."""
    from agent_bom.output.prometheus import export_prometheus as _export_prometheus
    _export_prometheus(report, output_path, blast_radii or [])


def push_to_gateway(
    gateway_url: str,
    report: AIBOMReport,
    blast_radii: list | None = None,
    job: str = "agent-bom",
    instance: str | None = None,
) -> None:
    """Push scan metrics to a Prometheus Pushgateway."""
    from agent_bom.output.prometheus import push_to_gateway as _push
    _push(gateway_url, report, blast_radii or [], job=job, instance=instance)


def push_otlp(
    endpoint: str,
    report: AIBOMReport,
    blast_radii: list | None = None,
) -> None:
    """Export metrics via OpenTelemetry OTLP/HTTP (requires agent-bom[otel])."""
    from agent_bom.output.prometheus import push_otlp as _push_otlp
    _push_otlp(endpoint, report, blast_radii or [])
