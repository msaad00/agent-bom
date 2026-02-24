"""Output formatters for AI-BOM reports."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional
from uuid import uuid4

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.tree import Tree

from agent_bom.models import Agent, AgentStatus, AIBOMReport, BlastRadius, Severity

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


def print_posture_summary(report: AIBOMReport) -> None:
    """Print a high-level security posture summary with ecosystem and credential aggregation."""
    from collections import Counter

    # Aggregate agent status counts
    configured = sum(1 for a in report.agents if a.status == AgentStatus.CONFIGURED)
    not_configured = sum(1 for a in report.agents if a.status == AgentStatus.INSTALLED_NOT_CONFIGURED)

    # Aggregate ecosystem breakdown
    ecosystem_pkgs: Counter[str] = Counter()
    ecosystem_servers: Counter[str] = Counter()
    seen_pkgs: set[str] = set()
    for agent in report.agents:
        for server in agent.mcp_servers:
            server_ecosystems: set[str] = set()
            for pkg in server.packages:
                pkg_key = f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"
                if pkg_key not in seen_pkgs:
                    seen_pkgs.add(pkg_key)
                    ecosystem_pkgs[pkg.ecosystem] += 1
                server_ecosystems.add(pkg.ecosystem)
            for eco in server_ecosystems:
                ecosystem_servers[eco] += 1

    # Aggregate credentials across agents
    cred_map: dict[str, list[str]] = {}  # cred_name → [agent names]
    total_cred_servers = 0
    for agent in report.agents:
        for server in agent.mcp_servers:
            if server.has_credentials:
                total_cred_servers += 1
                for cred in server.credential_names:
                    cred_map.setdefault(cred, []).append(f"{agent.name}/{server.name}")

    # Vulnerability severity breakdown
    sev_counts: Counter[str] = Counter()
    for br in report.blast_radii:
        sev_counts[br.vulnerability.severity.value.upper()] += 1

    # Posture headline
    if report.total_vulnerabilities == 0:
        posture = "[bold green]CLEAN[/bold green]"
        border_style = "green"
    elif sev_counts.get("CRITICAL", 0) > 0:
        parts = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if sev_counts.get(sev, 0) > 0:
                parts.append(f"{sev_counts[sev]} {sev}")
        posture = "[bold red]" + ", ".join(parts) + "[/bold red]"
        border_style = "red"
    else:
        parts = []
        for sev in ("HIGH", "MEDIUM", "LOW"):
            if sev_counts.get(sev, 0) > 0:
                parts.append(f"{sev_counts[sev]} {sev}")
        posture = "[bold yellow]" + ", ".join(parts) + "[/bold yellow]"
        border_style = "yellow"

    # Build the panel content
    lines: list[str] = []
    lines.append(f"  [bold]SECURITY POSTURE:[/bold]  {posture}")
    lines.append("")

    # Agent summary
    agent_parts = [f"{report.total_agents}"]
    if configured:
        agent_parts.append(f"{configured} configured")
    if not_configured:
        agent_parts.append(f"{not_configured} installed-not-configured")
    lines.append(f"  [bold]Agents[/bold]           {', '.join(agent_parts)}")

    # Server summary
    configured_agents = [a for a in report.agents if a.status == AgentStatus.CONFIGURED]
    hosting_agents = sum(1 for a in configured_agents if a.mcp_servers)
    lines.append(f"  [bold]MCP Servers[/bold]       {report.total_servers} across {hosting_agents} agent(s)")

    # Package summary with ecosystem breakdown
    unique_pkgs = len(seen_pkgs)
    if ecosystem_pkgs:
        eco_parts = [f"{eco}: {count}" for eco, count in ecosystem_pkgs.most_common()]
        lines.append(f"  [bold]Packages[/bold]          {unique_pkgs} unique ({', '.join(eco_parts)})")
    else:
        lines.append(f"  [bold]Packages[/bold]          {unique_pkgs} unique")

    # Credential exposure
    if cred_map:
        lines.append(f"  [bold yellow]Credentials[/bold yellow]       {total_cred_servers} server(s) with credentials exposed")
        cred_names = list(cred_map.keys())
        if len(cred_names) <= 4:
            lines.append(f"                    [yellow]{', '.join(cred_names)}[/yellow]")
        else:
            lines.append(f"                    [yellow]{', '.join(cred_names[:4])}[/yellow]")
            lines.append(f"                    [dim]+{len(cred_names) - 4} more[/dim]")
    else:
        lines.append("  [bold]Credentials[/bold]       None detected")

    # Privilege summary
    elevated_servers = sum(
        1 for a in report.agents for s in a.mcp_servers
        if s.permission_profile and s.permission_profile.is_elevated
    )
    if elevated_servers:
        lines.append(f"  [bold red]Privileges[/bold red]        {elevated_servers} server(s) with elevated privileges")
    else:
        lines.append("  [bold]Privileges[/bold]        None elevated")

    # Vulnerability count
    lines.append(f"  [bold]Vulnerabilities[/bold]   {report.total_vulnerabilities}")

    # Ecosystem breakdown section
    if ecosystem_pkgs:
        lines.append("")
        lines.append("  [bold]Ecosystem Breakdown[/bold]")
        for eco, count in ecosystem_pkgs.most_common():
            srv_count = ecosystem_servers.get(eco, 0)
            pkg_label = "package" if count == 1 else "packages"
            srv_label = "server instance" if srv_count == 1 else "server instances"
            lines.append(f"    {eco:<10} {count} {pkg_label} across {srv_count} {srv_label}")

    # Credential exposure detail
    if cred_map:
        lines.append("")
        lines.append("  [bold]Credential Exposure[/bold]")
        for cred, locations in sorted(cred_map.items()):
            loc_str = ", ".join(locations[:3])
            if len(locations) > 3:
                loc_str += f" +{len(locations) - 3}"
            lines.append(f"    [yellow]{cred}[/yellow]  [dim]({loc_str})[/dim]")

    # Top impacted packages (when vulns exist)
    if report.blast_radii:
        lines.append("")
        lines.append("  [bold]Top Impacted Packages[/bold]")
        # Group vulns by package
        pkg_vulns: dict[str, dict] = {}
        for br in report.blast_radii:
            key = f"{br.package.name}@{br.package.version}"
            if key not in pkg_vulns:
                pkg_vulns[key] = {"eco": br.package.ecosystem, "sevs": Counter(), "agents": set(), "kev": False}
            pkg_vulns[key]["sevs"][br.vulnerability.severity.value.upper()] += 1
            for a in br.affected_agents:
                pkg_vulns[key]["agents"].add(a.name)
            if br.vulnerability.is_kev:
                pkg_vulns[key]["kev"] = True

        # Sort by total vuln count descending
        sorted_pkgs = sorted(pkg_vulns.items(), key=lambda x: sum(x[1]["sevs"].values()), reverse=True)
        for pkg_name, info in sorted_pkgs[:5]:
            sev_parts = []
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if info["sevs"].get(sev, 0) > 0:
                    sev_parts.append(f"{info['sevs'][sev]} {sev.lower()}")
            kev_flag = ", [red bold]CISA KEV[/red bold]" if info["kev"] else ""
            agents_str = ", ".join(sorted(info["agents"]))
            lines.append(
                f"    {pkg_name} ({info['eco']})    "
                f"{', '.join(sev_parts)}{kev_flag} — affects {agents_str}"
            )

    content = "\n".join(lines)
    console.print(Panel(content, border_style=border_style, padding=(1, 1)))


def print_agent_tree(report: AIBOMReport) -> None:
    """Print the agent → server → package dependency tree."""
    console.print()
    console.print(Rule("AI-BOM Dependency Tree", style="blue"))
    console.print()

    for agent in report.agents:
        status_str = ""
        if agent.status == AgentStatus.INSTALLED_NOT_CONFIGURED:
            status_str = " [yellow][installed, not configured][/yellow]"
        # Compute summary stats
        total_servers = len(agent.mcp_servers)
        total_pkgs = sum(len(s.packages) for s in agent.mcp_servers)
        total_creds = sum(len(s.credential_names) for s in agent.mcp_servers)
        stats_parts = [f"{total_servers} server{'s' if total_servers != 1 else ''}"]
        stats_parts.append(f"{total_pkgs} package{'s' if total_pkgs != 1 else ''}")
        if total_creds:
            stats_parts.append(f"{total_creds} credential{'s' if total_creds != 1 else ''}")

        agent_tree = Tree(
            f"\U0001f916 Agent: [bold]{agent.name}[/bold] ({agent.agent_type.value})"
            f"{status_str}"
        )
        agent_tree.add(f"[dim]{agent.config_path}[/dim]")
        sep = " \u00b7 "
        agent_tree.add(f"[dim]{sep.join(stats_parts)}[/dim]")

        for server in agent.mcp_servers:
            vuln_count = server.total_vulnerabilities
            vuln_indicator = f" [red]⚠ {vuln_count} vuln(s)[/red]" if vuln_count else ""
            cred_indicator = f" [yellow]🔑 {len(server.credential_names)} cred(s)[/yellow]" if server.has_credentials else ""

            priv_indicator = ""
            if server.permission_profile and server.permission_profile.is_elevated:
                plevel = server.permission_profile.privilege_level
                if plevel == "critical":
                    priv_indicator = " [red bold]🛡 PRIVILEGED[/red bold]"
                elif plevel == "high":
                    priv_indicator = " [red]🛡 root/shell[/red]"
                elif plevel == "medium":
                    priv_indicator = " [yellow]🛡 elevated[/yellow]"

            server_branch = agent_tree.add(
                f"\U0001f50c MCP Server: [bold cyan]{server.name}[/bold cyan] "
                f"({server.command} {' '.join(server.args[:2])})"
                f"{vuln_indicator}{cred_indicator}{priv_indicator}"
            )

            if server.tools:
                tools_branch = server_branch.add(f"[dim]\U0001f527 Tools ({len(server.tools)})[/dim]")
                for tool in server.tools[:10]:  # Limit display
                    tools_branch.add(f"[dim]{tool.name}[/dim]")
                if len(server.tools) > 10:
                    tools_branch.add(f"[dim]...and {len(server.tools) - 10} more[/dim]")

            if server.packages:
                # Separate direct and transitive packages
                direct_pkgs = [p for p in server.packages if p.is_direct]
                transitive_pkgs = [p for p in server.packages if not p.is_direct]

                pkg_branch = server_branch.add(
                    f"\U0001f4e6 Packages ({len(server.packages)}) \u2014 "
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
                cred_branch = server_branch.add("[yellow]\U0001f511 Credentials[/yellow]")
                for cred in server.credential_names:
                    cred_branch.add(f"[yellow]{cred}[/yellow]")

        console.print(agent_tree)
        console.print()


def print_blast_radius(report: AIBOMReport) -> None:
    """Print blast radius analysis for vulnerabilities."""
    if not report.blast_radii:
        return

    console.print()
    console.print(Rule("Blast Radius Analysis", style="red"))
    console.print()

    table = Table(title="Vulnerability Impact Chain", expand=True, padding=(0, 1))
    table.add_column("Risk", justify="center", no_wrap=True)
    table.add_column("Vulnerability", no_wrap=True, ratio=3)
    table.add_column("Severity", no_wrap=True)
    table.add_column("EPSS", justify="center", no_wrap=True)
    table.add_column("KEV", justify="center", no_wrap=True)
    table.add_column("Blast", justify="center", no_wrap=True)
    table.add_column("Threats", ratio=3)
    table.add_column("Fix", ratio=2)

    severity_colors = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "dim",
    }

    for br in report.blast_radii[:25]:  # Top 25
        sev_style = severity_colors.get(br.vulnerability.severity, "white")
        if br.vulnerability.fixed_version:
            fix = f"[green]✓ {br.vulnerability.fixed_version}[/green]"
        else:
            fix = "[red dim]No fix[/red dim]"

        # EPSS score display
        epss_display = "—"
        if br.vulnerability.epss_score is not None:
            epss_pct = int(br.vulnerability.epss_score * 100)
            epss_style = "red bold" if epss_pct >= 70 else "yellow" if epss_pct >= 30 else "dim"
            epss_display = f"[{epss_style}]{epss_pct}%[/{epss_style}]"

        # KEV indicator
        kev_display = "[red bold]🔥[/red bold]" if br.vulnerability.is_kev else "—"

        # Blast column: agents/creds compact
        blast_parts = []
        n_agents = len(br.affected_agents)
        n_creds = len(br.exposed_credentials)
        if n_agents:
            blast_parts.append(f"{n_agents}A")
        if n_creds:
            blast_parts.append(f"[yellow]{n_creds}C[/yellow]")
        blast_display = "/".join(blast_parts) if blast_parts else "—"

        # Vulnerability: ID + package on two lines
        vuln_display = (
            f"{br.vulnerability.id}\n"
            f"[dim]{br.package.name}@{br.package.version}[/dim]"
        )

        # Threats column: actual framework tag IDs per finding
        threat_lines = []
        if br.owasp_tags:
            tags = sorted(br.owasp_tags)[:3]
            extra = f" +{len(br.owasp_tags) - 3}" if len(br.owasp_tags) > 3 else ""
            threat_lines.append(f"[purple]{' '.join(tags)}{extra}[/purple]")
        if br.atlas_tags:
            tags = sorted(br.atlas_tags)[:3]
            extra = f" +{len(br.atlas_tags) - 3}" if len(br.atlas_tags) > 3 else ""
            threat_lines.append(f"[cyan]{' '.join(tags)}{extra}[/cyan]")
        if br.nist_ai_rmf_tags:
            tags = sorted(br.nist_ai_rmf_tags)[:3]
            extra = f" +{len(br.nist_ai_rmf_tags) - 3}" if len(br.nist_ai_rmf_tags) > 3 else ""
            threat_lines.append(f"[green]{' '.join(tags)}{extra}[/green]")
        threats_display = "\n".join(threat_lines) if threat_lines else "—"

        table.add_row(
            f"[{sev_style}]{br.risk_score:.1f}[/{sev_style}]",
            vuln_display,
            f"[{sev_style} reverse] {br.vulnerability.severity.value.upper()} [/{sev_style} reverse]",
            epss_display,
            kev_display,
            blast_display,
            threats_display,
            fix,
        )

    console.print(table)

    if len(report.blast_radii) > 25:
        console.print(f"\n  [dim]...and {len(report.blast_radii) - 25} more findings. "
                       f"Use --output to export full report.[/dim]")

    # Verification sources — one link per unique CVE
    seen_ids: set[str] = set()
    sources: list[tuple[str, str]] = []
    for br in report.blast_radii:
        vid = br.vulnerability.id
        if vid in seen_ids:
            continue
        seen_ids.add(vid)
        if br.vulnerability.references:
            sources.append((vid, br.vulnerability.references[0]))
        elif vid.startswith("CVE-"):
            sources.append((vid, f"https://osv.dev/vulnerability/{vid}"))
        elif vid.startswith("GHSA-"):
            sources.append((vid, f"https://github.com/advisories/{vid}"))
    if sources:
        console.print("\n[bold]Verification Sources[/bold]")
        for vid, url in sources[:15]:
            console.print(f"  [dim]{vid}[/dim]  →  [link={url}]{url}[/link]")
        if len(sources) > 15:
            console.print(f"  [dim]...and {len(sources) - 15} more (see JSON output for full list)[/dim]")


def print_attack_flow_tree(report: AIBOMReport) -> None:
    """Print per-CVE blast radius chains as Rich Trees."""
    if not report.blast_radii:
        return

    console.print()
    console.print(Rule("Attack Flow Chains", style="red"))
    console.print()

    severity_styles = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "dim",
    }

    for br in sorted(report.blast_radii, key=lambda b: b.risk_score, reverse=True)[:15]:
        sev = br.vulnerability.severity
        sev_style = severity_styles.get(sev, "white")

        # Root: CVE line
        root_parts = [f"[{sev_style}]{br.vulnerability.id}[/{sev_style}]"]
        root_parts.append(f"[{sev_style}]\\[{sev.value}][/{sev_style}]")
        if br.vulnerability.cvss_score is not None:
            root_parts.append(f"CVSS {br.vulnerability.cvss_score:.1f}")
        if br.vulnerability.epss_score is not None:
            pct = int(br.vulnerability.epss_score * 100)
            root_parts.append(f"EPSS {pct}%")
        if br.vulnerability.is_kev:
            root_parts.append("[red bold]🔥 KEV[/red bold]")

        cve_tree = Tree(" · ".join(root_parts))

        # Package node
        pkg_label = f"{br.package.name}@{br.package.version} ({br.package.ecosystem})"
        pkg_branch = cve_tree.add(f"[dim]{pkg_label}[/dim]")

        # Server branches
        for server in br.affected_servers:
            srv_branch = pkg_branch.add(f"\U0001f50c [bold cyan]{server.name}[/bold cyan] [dim](MCP Server)[/dim]")

            # Agents
            for agent in br.affected_agents:
                srv_branch.add(f"\U0001f916 [green]{agent.name}[/green] [dim](Agent)[/dim]")

            # Credentials
            for cred in br.exposed_credentials:
                srv_branch.add(f"[yellow]🔑 {cred}[/yellow]")

            # Tools (compact, max 5 per line)
            if br.exposed_tools:
                tool_names = [t.name for t in br.exposed_tools[:5]]
                extra = f" +{len(br.exposed_tools) - 5}" if len(br.exposed_tools) > 5 else ""
                srv_branch.add(f"[dim]🔧 {', '.join(tool_names)}{extra}[/dim]")

        # If no servers, still show agents/creds/tools under package
        if not br.affected_servers:
            for agent in br.affected_agents:
                pkg_branch.add(f"\U0001f916 [green]{agent.name}[/green] [dim](Agent)[/dim]")
            for cred in br.exposed_credentials:
                pkg_branch.add(f"[yellow]🔑 {cred}[/yellow]")
            if br.exposed_tools:
                tool_names = [t.name for t in br.exposed_tools[:5]]
                extra = f" +{len(br.exposed_tools) - 5}" if len(br.exposed_tools) > 5 else ""
                pkg_branch.add(f"[dim]🔧 {', '.join(tool_names)}{extra}[/dim]")

        console.print(cve_tree)

    remaining = len(report.blast_radii) - 15
    if remaining > 0:
        console.print(f"\n  [dim]...and {remaining} more findings. Use --output to export full report.[/dim]")
    console.print()


def print_threat_frameworks(report: AIBOMReport) -> None:
    """Print aggregated threat framework coverage — OWASP LLM Top 10 + MITRE ATLAS + NIST AI RMF."""
    from collections import Counter

    from agent_bom.atlas import ATLAS_TECHNIQUES
    from agent_bom.nist_ai_rmf import NIST_AI_RMF
    from agent_bom.owasp import OWASP_LLM_TOP10

    if not report.blast_radii:
        return

    # Aggregate tag counts
    owasp_counts: Counter[str] = Counter()
    atlas_counts: Counter[str] = Counter()
    nist_counts: Counter[str] = Counter()
    for br in report.blast_radii:
        for tag in br.owasp_tags:
            owasp_counts[tag] += 1
        for tag in br.atlas_tags:
            atlas_counts[tag] += 1
        for tag in br.nist_ai_rmf_tags:
            nist_counts[tag] += 1

    if not owasp_counts and not atlas_counts and not nist_counts:
        return

    console.print()
    console.print(Rule("Threat Framework Coverage", style="bold"))
    console.print()

    # OWASP table
    if owasp_counts:
        owasp_table = Table(title="OWASP LLM Top 10", title_style="bold purple", border_style="dim")
        owasp_table.add_column("Code", width=7, style="bold purple")
        owasp_table.add_column("Category", width=36)
        owasp_table.add_column("Findings", width=9, justify="right")
        owasp_table.add_column("", width=20)

        for code in sorted(OWASP_LLM_TOP10.keys()):
            count = owasp_counts.get(code, 0)
            name = OWASP_LLM_TOP10[code]
            if count > 0:
                bar_len = min(count, 16)
                bar = "[red]" + "█" * bar_len + "[/red]"
                owasp_table.add_row(code, name, f"[bold]{count}[/bold]", bar)
            else:
                owasp_table.add_row(f"[dim]{code}[/dim]", f"[dim]{name}[/dim]", "[dim]—[/dim]", "")

        console.print(owasp_table)

    # ATLAS table
    if atlas_counts:
        atlas_table = Table(title="MITRE ATLAS", title_style="bold cyan", border_style="dim")
        atlas_table.add_column("Technique", width=12, style="bold cyan")
        atlas_table.add_column("Name", width=38)
        atlas_table.add_column("Findings", width=9, justify="right")
        atlas_table.add_column("", width=20)

        for code in sorted(ATLAS_TECHNIQUES.keys()):
            count = atlas_counts.get(code, 0)
            name = ATLAS_TECHNIQUES[code]
            if count > 0:
                bar_len = min(count, 16)
                bar = "[red]" + "█" * bar_len + "[/red]"
                atlas_table.add_row(code, name, f"[bold]{count}[/bold]", bar)
            else:
                atlas_table.add_row(f"[dim]{code}[/dim]", f"[dim]{name}[/dim]", "[dim]—[/dim]", "")

        console.print(atlas_table)

    # NIST AI RMF table
    if nist_counts:
        nist_table = Table(title="NIST AI RMF 1.0", title_style="bold green", border_style="dim")
        nist_table.add_column("Subcategory", width=14, style="bold green")
        nist_table.add_column("Description", width=46)
        nist_table.add_column("Findings", width=9, justify="right")
        nist_table.add_column("", width=20)

        for sid in sorted(NIST_AI_RMF.keys()):
            count = nist_counts.get(sid, 0)
            name = NIST_AI_RMF[sid]
            if count > 0:
                bar_len = min(count, 16)
                bar = "[red]" + "█" * bar_len + "[/red]"
                nist_table.add_row(sid, name, f"[bold]{count}[/bold]", bar)
            else:
                nist_table.add_row(f"[dim]{sid}[/dim]", f"[dim]{name}[/dim]", "[dim]—[/dim]", "")

        console.print(nist_table)
    console.print()


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
        "owasp": set(), "atlas": set(), "nist": set(),
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
        g["owasp"].update(br.owasp_tags)
        g["atlas"].update(br.atlas_tags)
        g["nist"].update(br.nist_ai_rmf_tags)
        if severity_order.get(br.vulnerability.severity, 0) > severity_order.get(g["max_severity"], 0):
            g["max_severity"] = br.vulnerability.severity
        if br.vulnerability.is_kev:
            g["has_kev"] = True
        if br.ai_risk_context:
            g["ai_risk"] = True

    plan = []
    for g in groups.values():
        g["vulns"] = list(set(g["vulns"]))
        g["agents"] = sorted(g["agents"])
        g["creds"] = sorted(g["creds"])
        g["tools"] = sorted(g["tools"])
        g["owasp"] = sorted(g["owasp"])
        g["atlas"] = sorted(g["atlas"])
        g["nist"] = sorted(g["nist"])
        g["impact"] = (
            len(g["agents"]) * 10 + len(g["creds"]) * 3 + len(g["vulns"])
            + (5 if g["has_kev"] else 0) + (3 if g["ai_risk"] else 0)
        )
        plan.append(g)

    plan.sort(key=lambda x: x["impact"], reverse=True)
    return plan


def print_remediation_plan(report: AIBOMReport) -> None:
    """Print a prioritized remediation plan with named assets and risk narrative."""
    if not report.blast_radii:
        return

    plan = build_remediation_plan(report.blast_radii)
    fixable = [p for p in plan if p["fix"]]
    unfixable = [p for p in plan if not p["fix"]]

    # Totals for percentage calculations
    total_agents = report.total_agents or 1
    all_creds: set[str] = set()
    all_tools: set[str] = set()
    for br in report.blast_radii:
        all_creds.update(br.exposed_credentials)
        all_tools.update(t.name for t in br.exposed_tools)
    total_creds = len(all_creds) or 1
    total_tools = len(all_tools) or 1

    console.print()
    console.print(Rule("Remediation Plan", style="green"))
    console.print()

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

            # Header: upgrade package version → fix
            console.print(
                f"  [{style}]{i}. upgrade {item['package']}[/{style}]  "
                f"[dim]{item['current']}[/dim] → [green bold]{item['fix']}[/green bold]"
                f"{kev_flag}{ai_flag}"
            )

            # Impact line with counts
            n_vulns = len(item["vulns"])
            n_agents = len(item["agents"])
            n_creds = len(item["creds"])
            n_tools = len(item["tools"])

            impact_parts = [f"clears {n_vulns} vuln(s)"]
            impact_parts.append(f"{n_agents} agent(s) protected ({_pct(n_agents, total_agents)})")
            if item["creds"]:
                impact_parts.append(f"frees {n_creds} credential(s) ({_pct(n_creds, total_creds)})")
            if item["tools"]:
                impact_parts.append(f"secures {n_tools} tool(s) ({_pct(n_tools, total_tools)})")
            console.print(f"     [dim]{'  •  '.join(impact_parts)}[/dim]")

            # Named assets
            if item["agents"]:
                console.print(f"     [dim]agents:[/dim]  {', '.join(item['agents'])}")
            if item["creds"]:
                console.print(f"     [dim]credentials:[/dim]  [yellow]{', '.join(item['creds'])}[/yellow]")
            if item["tools"]:
                console.print(f"     [dim]tools:[/dim]  {', '.join(item['tools'][:8])}"
                              + (f" +{len(item['tools']) - 8} more" if len(item["tools"]) > 8 else ""))

            # Threat framework tags
            tags = []
            if item["owasp"]:
                tags.append("[purple]" + " ".join(item["owasp"]) + "[/purple]")
            if item["atlas"]:
                tags.append("[cyan]" + " ".join(item["atlas"]) + "[/cyan]")
            if item["nist"]:
                tags.append("[green]" + " ".join(item["nist"]) + "[/green]")
            if tags:
                console.print(f"     [dim]mitigates:[/dim]  {' '.join(tags)}")

            # Risk narrative — what happens if NOT fixed
            console.print(f"     [dim red]⚠ if not fixed:[/dim red] "
                          f"[dim]attacker exploiting {item['vulns'][0]} can reach "
                          f"{'[yellow]' + ', '.join(item['creds'][:2]) + '[/yellow]' if item['creds'] else 'no credentials'} "
                          f"via {', '.join(item['agents'][:2])}"
                          f"{' through ' + ', '.join(item['tools'][:3]) if item['tools'] else ''}[/dim]")
            console.print()

    if unfixable:
        console.print(f"  [dim yellow]⚠ {len(unfixable)} package(s) have no fix yet — monitor upstream for patches:[/dim yellow]")
        for item in unfixable[:10]:
            agents_str = f" ({', '.join(item['agents'][:3])})" if item["agents"] else ""
            console.print(f"    [dim]• {item['package']}@{item['current']} — {', '.join(item['vulns'][:3])}{agents_str}[/dim]")
        console.print()


def print_export_hint(report: AIBOMReport) -> None:
    """Print an AI-BOM identity footer with threat framework badge, explore links, and export hints."""
    from collections import Counter

    from agent_bom.atlas import ATLAS_TECHNIQUES
    from agent_bom.nist_ai_rmf import NIST_AI_RMF
    from agent_bom.owasp import OWASP_LLM_TOP10

    lines: list[str] = []

    # ── Threat Framework Coverage Badge ──
    owasp_hit: set[str] = set()
    atlas_hit: set[str] = set()
    nist_hit: set[str] = set()
    for br in report.blast_radii:
        owasp_hit.update(br.owasp_tags)
        atlas_hit.update(br.atlas_tags)
        nist_hit.update(br.nist_ai_rmf_tags)

    owasp_total = len(OWASP_LLM_TOP10)
    atlas_total = len(ATLAS_TECHNIQUES)
    nist_total = len(NIST_AI_RMF)

    if report.blast_radii:
        lines.append("[bold]AI Threat Framework Coverage[/bold]")
        lines.append("")

        # OWASP bar
        owasp_pct = int(len(owasp_hit) / owasp_total * 100) if owasp_total else 0
        owasp_bar = _coverage_bar(len(owasp_hit), owasp_total, "purple")
        lines.append(f"  [bold purple]OWASP LLM Top 10[/bold purple]  {owasp_bar}  [purple]{len(owasp_hit)}/{owasp_total}[/purple] ({owasp_pct}%)")

        # ATLAS bar
        atlas_pct = int(len(atlas_hit) / atlas_total * 100) if atlas_total else 0
        atlas_bar = _coverage_bar(len(atlas_hit), atlas_total, "cyan")
        lines.append(f"  [bold cyan]MITRE ATLAS      [/bold cyan]  {atlas_bar}  [cyan]{len(atlas_hit)}/{atlas_total}[/cyan] ({atlas_pct}%)")

        # NIST bar
        nist_pct = int(len(nist_hit) / nist_total * 100) if nist_total else 0
        nist_bar = _coverage_bar(len(nist_hit), nist_total, "green")
        lines.append(f"  [bold green]NIST AI RMF 1.0  [/bold green]  {nist_bar}  [green]{len(nist_hit)}/{nist_total}[/green] ({nist_pct}%)")

        lines.append("")

    # ── Identity ──
    lines.append("[bold]AI Bill of Materials (AI-BOM)[/bold]")
    lines.append(
        f"[dim]{report.total_agents} agents · {report.total_servers} MCP servers · "
        f"{report.total_packages} packages · {report.total_vulnerabilities} vulnerabilities[/dim]"
    )
    lines.append("")

    # ── Explore ──
    lines.append("[bold]Explore & Analyze[/bold]")
    lines.append("  [green]agent-bom serve[/green]                              [dim]Interactive dashboard (graphs, detail pages)[/dim]")
    lines.append("  [green]agent-bom scan -f html -o report.html[/green]        [dim]Self-contained HTML report[/dim]")
    lines.append("  [green]agent-bom api[/green]                                [dim]REST API for CI/CD integration[/dim]")
    lines.append("")

    # ── Runtime ──
    lines.append("[bold]Runtime Security[/bold]")
    lines.append("  [green]agent-bom proxy -- npx @mcp/server ...[/green]       [dim]Intercept & audit MCP tool calls[/dim]")
    lines.append("  [green]agent-bom watch --webhook <url>[/green]              [dim]Continuous config monitoring + alerts[/dim]")
    lines.append("  [green]agent-bom scan --remediate fix.md[/green]            [dim]Generate actionable fix commands[/dim]")
    lines.append("")

    # ── Export ──
    lines.append("[bold]Export AI-BOM[/bold]")
    lines.append("  [green]agent-bom scan -f cyclonedx -o ai-bom.cdx.json[/green]   [dim]CycloneDX 1.6[/dim]")
    lines.append("  [green]agent-bom scan -f spdx -o ai-bom.spdx.json[/green]       [dim]SPDX 3.0[/dim]")
    lines.append("  [green]agent-bom scan -f sarif -o results.sarif[/green]         [dim]GitHub Security tab[/dim]")
    lines.append("  [green]agent-bom scan -f json -o ai-bom.json[/green]            [dim]Full AI-BOM JSON[/dim]")

    console.print()
    console.print(Panel("\n".join(lines), border_style="blue", padding=(1, 2)))


def _coverage_bar(hit: int, total: int, color: str, width: int = 20) -> str:
    """Build a colored coverage bar like [████████░░░░░░░░░░░░]."""
    filled = int(width * hit / total) if total else 0
    empty = width - filled
    return f"[{color}]{'█' * filled}[/{color}][dim]{'░' * empty}[/dim]"


def _pct(part: int, total: int) -> str:
    """Format a percentage string."""
    return f"{round(part / total * 100)}%" if total > 0 else "—"


def _build_remediation_json(report: AIBOMReport) -> list[dict]:
    """Build JSON-serializable remediation plan with named assets and percentages."""
    plan = build_remediation_plan(report.blast_radii)
    total_agents = report.total_agents or 1

    all_creds: set[str] = set()
    all_tools: set[str] = set()
    for br in report.blast_radii:
        all_creds.update(br.exposed_credentials)
        all_tools.update(t.name for t in br.exposed_tools)
    total_creds = len(all_creds) or 1
    total_tools = len(all_tools) or 1

    result = []
    for item in plan:
        n_agents = len(item["agents"])
        n_creds = len(item["creds"])
        n_tools = len(item["tools"])
        result.append({
            "package": item["package"],
            "ecosystem": item["ecosystem"],
            "current_version": item["current"],
            "fixed_version": item["fix"],
            "severity": item["max_severity"].value,
            "is_kev": item["has_kev"],
            "impact_score": item["impact"],
            "vulnerabilities": item["vulns"],
            "affected_agents": item["agents"],
            "agents_pct": round(n_agents / total_agents * 100),
            "exposed_credentials": item["creds"],
            "credentials_pct": round(n_creds / total_creds * 100) if n_creds else 0,
            "reachable_tools": item["tools"],
            "tools_pct": round(n_tools / total_tools * 100) if n_tools else 0,
            "owasp_tags": item["owasp"],
            "atlas_tags": item["atlas"],
            "nist_ai_rmf_tags": item["nist"],
            "risk_narrative": _risk_narrative(item),
        })
    return result


def _risk_narrative(item: dict) -> str:
    """Build plain-text risk narrative for a remediation item."""
    vuln_id = item["vulns"][0] if item["vulns"] else "this vulnerability"
    agents = ", ".join(item["agents"][:3]) or "affected agents"
    creds = ", ".join(item["creds"][:3])
    tools = ", ".join(item["tools"][:3])

    parts = [f"If not remediated, an attacker exploiting {vuln_id}"]
    if creds:
        parts.append(f"can exfiltrate {creds}")
    parts.append(f"via {agents}")
    if tools:
        parts.append(f"through {tools}")
    return " ".join(parts) + "."


# ─── JSON Output ────────────────────────────────────────────────────────────


def _build_framework_summary(blast_radii: list[BlastRadius]) -> dict:
    """Aggregate OWASP + ATLAS tag coverage across all blast radius findings."""
    from collections import Counter

    from agent_bom.atlas import ATLAS_TECHNIQUES
    from agent_bom.nist_ai_rmf import NIST_AI_RMF
    from agent_bom.owasp import OWASP_LLM_TOP10

    owasp_counts: Counter[str] = Counter()
    atlas_counts: Counter[str] = Counter()
    nist_counts: Counter[str] = Counter()
    for br in blast_radii:
        for tag in br.owasp_tags:
            owasp_counts[tag] += 1
        for tag in br.atlas_tags:
            atlas_counts[tag] += 1
        for tag in br.nist_ai_rmf_tags:
            nist_counts[tag] += 1

    return {
        "owasp_llm_top10": [
            {
                "code": code,
                "name": OWASP_LLM_TOP10[code],
                "findings": owasp_counts.get(code, 0),
                "triggered": code in owasp_counts,
            }
            for code in sorted(OWASP_LLM_TOP10.keys())
        ],
        "mitre_atlas": [
            {
                "technique_id": tid,
                "name": ATLAS_TECHNIQUES[tid],
                "findings": atlas_counts.get(tid, 0),
                "triggered": tid in atlas_counts,
            }
            for tid in sorted(ATLAS_TECHNIQUES.keys())
        ],
        "nist_ai_rmf": [
            {
                "subcategory_id": sid,
                "name": NIST_AI_RMF[sid],
                "findings": nist_counts.get(sid, 0),
                "triggered": sid in nist_counts,
            }
            for sid in sorted(NIST_AI_RMF.keys())
        ],
        "total_owasp_triggered": sum(1 for c in owasp_counts if owasp_counts[c] > 0),
        "total_atlas_triggered": sum(1 for c in atlas_counts if atlas_counts[c] > 0),
        "total_nist_triggered": sum(1 for c in nist_counts if nist_counts[c] > 0),
    }


def to_json(report: AIBOMReport) -> dict:
    """Convert report to JSON-serializable dict."""
    result = {
        "document_type": "AI-BOM",
        "spec_version": "1.0",
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
                "status": agent.status.value,
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
                        "permission_profile": (
                            {
                                "runs_as_root": server.permission_profile.runs_as_root,
                                "container_privileged": server.permission_profile.container_privileged,
                                "privilege_level": server.permission_profile.privilege_level,
                                "tool_permissions": server.permission_profile.tool_permissions,
                                "capabilities": server.permission_profile.capabilities,
                                "network_access": server.permission_profile.network_access,
                                "filesystem_write": server.permission_profile.filesystem_write,
                                "shell_access": server.permission_profile.shell_access,
                            }
                            if server.permission_profile else None
                        ),
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
                "ai_summary": br.ai_summary,
                "owasp_tags": br.owasp_tags,
                "atlas_tags": br.atlas_tags,
                "nist_ai_rmf_tags": br.nist_ai_rmf_tags,
            }
            for br in report.blast_radii
        ],
        "threat_framework_summary": _build_framework_summary(report.blast_radii),
        "remediation_plan": _build_remediation_json(report),
    }

    # AI enrichment fields (only when present)
    if report.executive_summary:
        result["executive_summary"] = report.executive_summary
    if report.ai_threat_chains:
        result["ai_threat_chains"] = report.ai_threat_chains
    if report.mcp_config_analysis:
        result["mcp_config_analysis"] = report.mcp_config_analysis

    # Skill security audit (only when skill files were scanned)
    if report.skill_audit_data:
        result["skill_audit"] = report.skill_audit_data

    # Trust assessment (only when skill files were scanned)
    if report.trust_assessment_data:
        result["trust_assessment"] = report.trust_assessment_data

    if report.prompt_scan_data:
        result["prompt_scan"] = report.prompt_scan_data

    if report.model_files:
        result["model_files"] = report.model_files

    return result


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
                {"name": "agent-bom:status", "value": agent.status.value},
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
        if br.owasp_tags or br.atlas_tags or br.nist_ai_rmf_tags:
            result["properties"] = {
                "owasp_tags": br.owasp_tags,
                "atlas_tags": br.atlas_tags,
                "nist_ai_rmf_tags": br.nist_ai_rmf_tags,
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
                        "informationUri": "https://github.com/msaad00/agent-bom",
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

    console.print()
    console.print(Rule("Severity Distribution", style="bold"))
    console.print()
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
            agent_element["comment"] = f"config_path: {agent.config_path}, status: {agent.status.value}"
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


# ─── Badge Output (shields.io endpoint format) ───────────────────────────


def to_badge(report: AIBOMReport) -> dict:
    """Generate a shields.io endpoint badge JSON from scan results.

    The output follows the shields.io endpoint schema:
    https://shields.io/badges/endpoint-badge

    Use with: https://img.shields.io/endpoint?url=<badge-json-url>
    """
    # Collect all vulnerabilities from agents → servers → packages
    all_vulns = []
    for agent in report.agents:
        for server in agent.mcp_servers:
            for pkg in server.packages:
                all_vulns.extend(pkg.vulnerabilities)
    critical = len([v for v in all_vulns if v.severity == Severity.CRITICAL])
    high = len([v for v in all_vulns if v.severity == Severity.HIGH])
    total = len(all_vulns)

    if critical > 0:
        color = "critical"
        message = f"{critical} critical, {high} high"
    elif high > 0:
        color = "orange"
        message = f"{high} high, {total} total"
    elif total > 0:
        color = "yellow"
        message = f"{total} findings"
    else:
        color = "brightgreen"
        message = "clean"

    return {
        "schemaVersion": 1,
        "label": "agent-bom",
        "message": message,
        "color": color,
        "namedLogo": "shield",
    }


def export_badge(report: AIBOMReport, output_path: str) -> None:
    """Export shields.io endpoint badge JSON to file."""
    data = to_badge(report)
    Path(output_path).write_text(json.dumps(data, indent=2))
