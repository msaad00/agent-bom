"""Output formatters for AI-BOM reports."""

from __future__ import annotations

from collections.abc import Sequence

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.tree import Tree

from agent_bom.graph.severity import SEVERITY_THRESHOLD_LABELS, severity_rank, severity_worst_first_rank
from agent_bom.models import AgentStatus, AIBOMReport, Severity
from agent_bom.output.compact import _coverage_bar, _pct
from agent_bom.output.finding_views import (
    active_cve_findings,
    cve_findings,
    finding_references,
    finding_severity,
    is_actionable_finding,
    is_package_malicious,
    package_ecosystem,
    package_name,
    package_version,
)
from agent_bom.security import sanitize_command_args

console = Console()


def safe_emoji(emoji: str, fallback: str = "*") -> str:
    """Return ``emoji`` only when the active stdout encoding can render it.

    On terminals/locales whose encoding cannot encode the glyph (for example a
    ``cp1252``/``ascii`` Windows console or a stripped CI locale) a raw emoji
    prints as a mojibake box or raises ``UnicodeEncodeError`` mid-line. Fall
    back to a plain ASCII marker so the line stays readable everywhere.
    """
    import sys

    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        emoji.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return fallback
    return emoji


# ─── Centralized severity styling ────────────────────────────────────────────

SEVERITY_BADGES: dict[Severity, str] = {
    Severity.CRITICAL: "white on red",
    Severity.HIGH: "white on #e67e22",
    Severity.MEDIUM: "black on yellow",
    Severity.LOW: "white on #555555",
    Severity.UNKNOWN: "black on white",
}

SEVERITY_TEXT: dict[Severity, str] = {
    Severity.CRITICAL: "red bold",
    Severity.HIGH: "#e67e22 bold",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "dim",
}


def _sev_badge(severity: Severity) -> str:
    """Render a severity badge with background color: ` CRIT `, ` HIGH `, etc."""
    style = SEVERITY_BADGES.get(severity, "white")
    labels = {
        Severity.CRITICAL: " CRIT ",
        Severity.HIGH: " HIGH ",
        Severity.MEDIUM: " MED  ",
        Severity.LOW: " LOW  ",
        Severity.UNKNOWN: " ADV  ",
    }
    label = labels.get(severity, f" {severity.value.upper()} ")
    return f"[{style}]{label}[/{style}]"


def _console() -> Console:
    """Resolve the shared output console from the compatibility barrel."""
    from agent_bom import output as output_mod

    return output_mod.console


# ─── Console Output ─────────────────────────────────────────────────────────


def print_summary(report: AIBOMReport) -> None:
    """Print a summary of the AI-BOM report to console."""
    _console().print("\n")
    _console().print(
        Panel.fit(
            f"[bold]AI-BOM Report[/bold]\n"
            f"Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            f"agent-bom v{report.tool_version}",
            border_style="blue",
        )
    )

    # Summary stats
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("Agents discovered", str(report.total_agents))
    table.add_row("MCP servers", str(report.total_servers))
    table.add_row("Total packages", str(report.total_packages))
    table.add_row("Vulnerabilities", str(report.total_vulnerabilities))
    table.add_row("Critical findings", str(len(report.critical_vulns)))

    # AI inventory stats (if scan was run)
    ai_inv = getattr(report, "ai_inventory_data", None)
    if ai_inv and ai_inv.get("total_components", 0) > 0:
        table.add_row("AI components", str(ai_inv["total_components"]))
        shadow = ai_inv.get("shadow_ai_count", 0)
        if shadow:
            table.add_row("Shadow AI", f"[yellow]{shadow}[/yellow]")
        depr = ai_inv.get("deprecated_models_count", 0)
        if depr:
            table.add_row("Deprecated models", str(depr))
        keys = ai_inv.get("api_keys_count", 0)
        if keys:
            table.add_row("Hardcoded API keys", f"[red]{keys}[/red]")

    project_inv = getattr(report, "project_inventory_data", None)
    if project_inv:
        table.add_row("Project manifests", str(project_inv.get("manifest_files", 0)))
        table.add_row("Lockfiles", str(project_inv.get("lockfiles", 0)))
        table.add_row(
            "Project inventory",
            (
                f"{project_inv.get('package_count', 0)} packages "
                f"({project_inv.get('direct_packages', 0)} direct / {project_inv.get('transitive_packages', 0)} transitive)"
            ),
        )
        lockfile_backed_packages = project_inv.get("lockfile_backed_packages", project_inv.get("package_count", 0))
        declaration_only_packages = project_inv.get("declaration_only_packages", 0)
        advisory_depth_pct = project_inv.get("advisory_depth_pct")
        advisory_depth = f"{lockfile_backed_packages} lockfile-backed / {declaration_only_packages} declaration-only"
        if advisory_depth_pct is not None:
            advisory_depth += f" ({advisory_depth_pct}% lockfile-backed)"
        table.add_row("Advisory depth", advisory_depth)

    model_sc = getattr(report, "model_supply_chain_data", None)
    if model_sc:
        table.add_row(
            "Model artifacts",
            (
                f"{model_sc.get('model_files', 0)} file(s), "
                f"{model_sc.get('manifest_files', 0)} manifest(s), "
                f"{model_sc.get('provenance_checks', 0)} provenance check(s)"
            ),
        )
        table.add_row(
            "Model integrity",
            (
                f"{model_sc.get('signed_files', 0)} signed, "
                f"{model_sc.get('hash_verification', {}).get('verified', 0)} hash-verified, "
                f"{model_sc.get('hash_verification', {}).get('tampered', 0)} tampered"
            ),
        )
        model_lineage = model_sc.get("manifests_with_repo_id", 0) + model_sc.get("adapter_lineage_refs", 0)
        if model_lineage:
            table.add_row(
                "Model lineage",
                (f"{model_sc.get('sharded_bundles', 0)} sharded bundle(s), {model_lineage} lineage ref(s)"),
            )
        model_flags = model_sc.get("files_with_security_flags", 0) + model_sc.get("provenance_with_security_flags", 0)
        model_flags += model_sc.get("manifests_with_security_flags", 0)
        if model_flags:
            table.add_row("Model risk flags", f"[yellow]{model_flags}[/yellow]")

    perf = report.scan_performance_data or {}
    osv = perf.get("osv") or {}
    registry = perf.get("registry") or {}
    advisory = perf.get("advisory_coverage") or {}
    if osv and _osv_lookup_count(osv) > 0:
        hit_rate = osv.get("cache_hit_rate_pct")
        osv_label = f"{osv.get('cache_hits', 0)} hit / {osv.get('cache_misses', 0)} miss"
        if hit_rate is not None:
            osv_label += f" ({hit_rate}% hit rate)"
        table.add_row("OSV cache", osv_label)
    if registry and _registry_lookup_count(registry) > 0:
        reg_label = f"{registry.get('cache_hits', 0)} hit / {registry.get('cache_misses', 0)} miss"
        reg_rate = registry.get("cache_hit_rate_pct")
        if reg_rate is not None:
            reg_label += f" ({reg_rate}% hit rate)"
        table.add_row("Registry cache", reg_label)
    if advisory:
        primary = advisory.get("primary_sources", {})
        enriched = advisory.get("records_with_enrichment", 0)
        primary_bits = [f"{source} {count}" for source, count in primary.items() if count]
        advisory_label = ", ".join(primary_bits) if primary_bits else "no advisory sources attributed"
        if enriched:
            advisory_label += f" · {enriched} enriched"
        table.add_row("Threat intel", advisory_label)

    _console().print(table)

    coverage_warnings = getattr(report, "coverage_warnings", None) or []
    if coverage_warnings:

        def _coverage_line(w: dict) -> str:
            if w.get("reason") == "manifest_parse_error":
                return (
                    f"[bold yellow]⚠ {w.get('release', '?')}[/bold yellow] — "
                    f"{w.get('detail') or 'manifest failed to parse; ecosystem not scanned'}"
                )
            return (
                f"[bold yellow]⚠ {w.get('release', '?')}[/bold yellow] — "
                f"{w.get('package_count', 0)} package(s) present, "
                f"{w.get('advisory_rows', 0)} advisory row(s) in the data source"
            )

        lines = [_coverage_line(w) for w in coverage_warnings]
        body = "\n".join(lines) + (
            "\n\n[dim]Vulnerability coverage for the release(s) above is incomplete — likely "
            "end-of-life and no longer carried by the data source. Results may UNDER-report; a "
            "low or zero count is NOT a clean bill of health.[/dim]"
        )
        _console().print(
            Panel.fit(
                body,
                title="[bold red]Incomplete vulnerability coverage[/bold red]",
                border_style="red",
            )
        )


def print_scan_performance_summary(report: AIBOMReport) -> None:
    """Print a compact cache/performance summary when available."""
    perf = report.scan_performance_data or {}
    osv = perf.get("osv") or {}
    registry = perf.get("registry") or {}
    advisory = perf.get("advisory_coverage") or {}
    if not osv and not registry and not advisory:
        return

    lines: list[str] = []
    if osv and _osv_lookup_count(osv) > 0:
        osv_line = (
            f"OSV cache {osv.get('cache_hits', 0)} hit / {osv.get('cache_misses', 0)} miss"
            f" · {osv.get('packages_queried', 0)} package lookup(s)"
        )
        hit_rate = osv.get("cache_hit_rate_pct")
        if hit_rate is not None:
            osv_line += f" · {hit_rate}% hit rate"
        if osv.get("lookup_errors", 0):
            osv_line += f" · {osv.get('lookup_errors', 0)} lookup error(s)"
        lines.append(osv_line)
    if registry and _registry_lookup_count(registry) > 0:
        reg_line = (
            f"Registry cache {registry.get('cache_hits', 0)} hit / {registry.get('cache_misses', 0)} miss"
            f" · {registry.get('network_requests', 0)} network request(s)"
        )
        reg_rate = registry.get("cache_hit_rate_pct")
        if reg_rate is not None:
            reg_line += f" · {reg_rate}% hit rate"
        if registry.get("npm_rate_limit_short_circuits", 0):
            reg_line += f" · {registry.get('npm_rate_limit_short_circuits', 0)} npm cooldown skip(s)"
        lines.append(reg_line)
    if advisory:
        primary = advisory.get("primary_sources", {})
        enrich = advisory.get("enrichment_sources", {})
        primary_line = ", ".join(f"{source} {count}" for source, count in primary.items() if count) or "no primary sources"
        enrich_line = ", ".join(f"{source} {count}" for source, count in enrich.items() if count) or "no enrichment"
        lines.append(
            f"Threat intel {primary_line} · {enrich_line} · {advisory.get('records_with_multiple_sources', 0)} multi-source record(s)"
        )
    if not lines:
        return
    _console().print("\n[dim]Cache & lookup reuse[/dim]")
    for line in lines:
        _console().print(f"  [dim]{line}[/dim]")


def _osv_lookup_count(osv: dict) -> int:
    """Return online OSV lookups represented by a performance payload."""
    return int(osv.get("packages_queried") or osv.get("cache_hits", 0) + osv.get("cache_misses", 0) or 0)


def _registry_lookup_count(registry: dict) -> int:
    """Return registry lookups represented by a performance payload."""
    return int(registry.get("network_requests") or registry.get("cache_hits", 0) + registry.get("cache_misses", 0) or 0)


def print_posture_summary(report: AIBOMReport) -> None:
    """Print a high-level security posture summary with ecosystem and credential aggregation."""
    from collections import Counter

    from agent_bom.evidence.scan_run import ScanOutcome, effective_scan_run

    coverage = report.scan_performance_data or {}
    scan_run = effective_scan_run(report)
    coverage_incomplete = coverage.get("coverage_state") == "incomplete" or scan_run.outcome is not ScanOutcome.COMPLETE

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

    # Vulnerability severity breakdown (excluding VEX-suppressed)
    from agent_bom.finding import FindingType

    sev_counts: Counter[str] = Counter()
    all_cve = cve_findings(report)
    active_findings = active_cve_findings(report)
    vex_suppressed_count = len(all_cve) - len(active_findings)
    for finding in active_findings:
        sev_counts[finding_severity(finding).value.upper()] += 1

    # Non-CVE policy/security findings (cloud CIS FAILs, MCP blocklist, toxic
    # combinations, governance) drive the headline too. A cloud scan with HIGH
    # CIS failures must NOT read CLEAN just because no package CVEs were found —
    # these findings already flow into to_findings() and --fail-on-severity.
    policy_findings = [finding for finding in report.to_findings() if finding.finding_type != FindingType.CVE]
    for finding in policy_findings:
        sev_counts[str(finding.severity).upper()] += 1

    # Posture headline
    if scan_run.outcome is ScanOutcome.FAILED:
        posture = "[bold red]SCAN FAILED[/bold red]"
        border_style = "red"
    elif coverage_incomplete:
        posture = "[bold yellow]PARTIAL COVERAGE[/bold yellow]"
        border_style = "yellow"
    elif report.total_vulnerabilities == 0 and not policy_findings:
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
    if coverage_incomplete:
        reason = str(coverage.get("coverage_reason") or "scan coverage incomplete")
        lines.append(f"  [yellow]Coverage[/yellow]          {reason}")
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
    elevated_servers = sum(1 for a in report.agents for s in a.mcp_servers if s.permission_profile and s.permission_profile.is_elevated)
    if elevated_servers:
        lines.append(f"  [bold red]Privileges[/bold red]        {elevated_servers} server(s) with elevated privileges")
    else:
        lines.append("  [bold]Privileges[/bold]        None elevated")

    # Vulnerability count
    vuln_label = str(report.total_vulnerabilities)
    if vex_suppressed_count:
        vuln_label += f" ({vex_suppressed_count} suppressed by VEX)"
    lines.append(f"  [bold]Vulnerabilities[/bold]   {vuln_label}")

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
    if cve_findings(report):
        lines.append("")
        lines.append("  [bold]Top Impacted Packages[/bold]")
        # Group vulns by package
        pkg_vulns: dict[str, dict] = {}
        for finding in all_cve:
            key = f"{package_name(finding)}@{package_version(finding)}"
            if key not in pkg_vulns:
                pkg_vulns[key] = {"eco": package_ecosystem(finding), "sevs": Counter(), "agents": set(), "kev": False}
            pkg_vulns[key]["sevs"][finding_severity(finding).value.upper()] += 1
            pkg_vulns[key]["agents"].update(finding.affected_agents)
            if finding.is_kev:
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
            lines.append(f"    {pkg_name} ({info['eco']})    {', '.join(sev_parts)}{kev_flag} — affects {agents_str}")

    # AI inventory summary (when scan was run)
    ai_inv = getattr(report, "ai_inventory_data", None)
    if ai_inv and ai_inv.get("total_components", 0) > 0:
        lines.append("")
        lines.append("  [bold]AI Component Inventory[/bold]")
        lines.append(f"    Components: {ai_inv['total_components']}  \u00b7  Files scanned: {ai_inv.get('files_scanned', 0)}")
        sdks = ai_inv.get("unique_sdks", [])
        models = ai_inv.get("unique_models", [])
        if sdks:
            sdk_str = ", ".join(sdks[:6]) + (f" +{len(sdks) - 6}" if len(sdks) > 6 else "")
            lines.append(f"    SDKs: [cyan]{sdk_str}[/cyan]")
        if models:
            model_str = ", ".join(models[:6]) + (f" +{len(models) - 6}" if len(models) > 6 else "")
            lines.append(f"    Models: [cyan]{model_str}[/cyan]")
        shadow = ai_inv.get("shadow_ai_count", 0)
        depr = ai_inv.get("deprecated_models_count", 0)
        keys = ai_inv.get("api_keys_count", 0)
        risk_parts = []
        if keys:
            risk_parts.append(f"[red]{keys} hardcoded key(s)[/red]")
        if shadow:
            risk_parts.append(f"[yellow]{shadow} shadow AI[/yellow]")
        if depr:
            risk_parts.append(f"{depr} deprecated model(s)")
        if risk_parts:
            risk_str = " \u00b7 ".join(risk_parts)
            lines.append(f"    Risks: {risk_str}")
        else:
            lines.append("    Risks: [green]none[/green]")

    content = "\n".join(lines)
    _console().print(Panel(content, border_style=border_style, padding=(1, 1)))


def print_agent_tree(report: AIBOMReport) -> None:
    """Print the agent → server → package dependency tree."""
    _console().print()
    _console().print(Rule("AI-BOM Dependency Tree", style="blue"))
    _console().print()

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

        agent_tree = Tree(f"\U0001f916 Agent: [bold]{agent.name}[/bold] ({agent.agent_type.value}){status_str}")
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

            registry_indicator = " [green]✓ registry[/green]" if server.registry_verified else " [dim]unknown registry[/dim]"

            server_args = sanitize_command_args(server.args[:2])
            server_branch = agent_tree.add(
                f"\U0001f50c MCP Server: [bold cyan]{server.name}[/bold cyan] "
                f"({server.command} {' '.join(server_args)})"
                f"{vuln_indicator}{cred_indicator}{priv_indicator}{registry_indicator}"
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
                    f"\U0001f4e6 Packages ({len(server.packages)}) \u2014 {len(direct_pkgs)} direct, {len(transitive_pkgs)} transitive"
                )

                # Show direct packages first
                for pkg in direct_pkgs:
                    vuln_str = ""
                    if pkg.has_vulnerabilities:
                        vuln_str = f" [red]({len(pkg.vulnerabilities)} vuln(s) - {pkg.max_severity.value})[/red]"
                    sc_str = ""
                    if pkg.scorecard_score is not None:
                        sc_color = "green" if pkg.scorecard_score >= 7.0 else "yellow" if pkg.scorecard_score >= 4.0 else "red"
                        sc_str = f" [{sc_color}]SC:{pkg.scorecard_score:.1f}[/{sc_color}]"
                    pkg_branch.add(f"{pkg.name}@{pkg.version} [{pkg.ecosystem}]{sc_str}{vuln_str}")

                # Show transitive packages grouped by depth (limit display)
                if transitive_pkgs:
                    transitive_branch = pkg_branch.add(f"[dim]Transitive ({len(transitive_pkgs)})[/dim]")
                    for pkg in transitive_pkgs[:20]:  # Limit to 20 for readability
                        vuln_str = ""
                        if pkg.has_vulnerabilities:
                            vuln_str = f" [red]({len(pkg.vulnerabilities)} vuln(s))[/red]"
                        indent = "  " * pkg.dependency_depth
                        parent_str = f" ← {pkg.parent_package}" if pkg.parent_package else ""
                        transitive_branch.add(f"[dim]{indent}{pkg.name}@{pkg.version}{parent_str}{vuln_str}[/dim]")
                    if len(transitive_pkgs) > 20:
                        transitive_branch.add(f"[dim]...and {len(transitive_pkgs) - 20} more[/dim]")

            if server.has_credentials:
                cred_branch = server_branch.add("[yellow]\U0001f511 Credentials[/yellow]")
                for cred in server.credential_names:
                    cred_branch.add(f"[yellow]{cred}[/yellow]")

        _console().print(agent_tree)
        _console().print()


def print_blast_radius(report: AIBOMReport, fixable_only: bool = False) -> None:
    """Print blast radius analysis for vulnerabilities."""
    all_cve = cve_findings(report)
    if not all_cve:
        return

    _console().print()
    _console().print(Rule("Blast Radius Analysis", style="red"))
    _console().print()

    table = Table(title="Vulnerability Impact Chain", expand=True, padding=(0, 1))
    table.add_column("Risk", justify="center", no_wrap=True)
    table.add_column("Vulnerability", no_wrap=True, ratio=3)
    table.add_column("Severity", no_wrap=True)
    table.add_column("EPSS", justify="center", no_wrap=True)
    table.add_column("KEV", justify="center", no_wrap=True)
    table.add_column("Blast", justify="center", no_wrap=True)
    table.add_column("Threats", ratio=3)
    table.add_column("Fix", ratio=2)

    # Filter to actionable findings only — UNKNOWN severity transitive
    # deps with no creds/tools are noise. Users see all with --verbose.
    actionable = [finding for finding in all_cve if is_actionable_finding(finding)]
    # --fixable-only: keep only entries that have a fix available
    if fixable_only:
        actionable = [finding for finding in actionable if finding.fixed_version]
    if not actionable:
        _console().print("  [green]✓ No actionable findings (all transitive/low-severity noise).[/green]")
        if len(all_cve) > 0:
            _console().print(f"  [dim]{len(all_cve)} low-priority findings hidden. Use --verbose to see all.[/dim]")
        return

    for finding in actionable[:25]:  # Top 25 actionable
        sev = finding_severity(finding)
        sev_style = SEVERITY_TEXT.get(sev, "white")
        if finding.fixed_version:
            fix = f"[green]✓ {finding.fixed_version}[/green]"
        else:
            fix = "[red dim]No fix[/red dim]"

        # EPSS score display
        epss_display = "—"
        if finding.epss_score is not None:
            epss_pct = int(finding.epss_score * 100)
            epss_style = "red bold" if epss_pct >= 70 else "yellow" if epss_pct >= 30 else "dim"
            epss_display = f"[{epss_style}]{epss_pct}%[/{epss_style}]"

        # KEV indicator
        kev_display = "[red bold]🔥[/red bold]" if finding.is_kev else "—"

        # Malicious package indicator
        if is_package_malicious(finding):
            kev_display += " [red bold]☠[/red bold]"

        # Blast column: agents/creds compact
        blast_parts = []
        n_agents = len(finding.affected_agents)
        n_creds = len(finding.exposed_credentials)
        if n_agents:
            blast_parts.append(f"{n_agents}A")
        if n_creds:
            blast_parts.append(f"[yellow]{n_creds}C[/yellow]")
        blast_display = "/".join(blast_parts) if blast_parts else "—"

        # Vulnerability: ID + package on two lines
        vuln_id = finding.cve_id or finding.id
        vuln_display = f"{vuln_id}\n[dim]{package_name(finding)}@{package_version(finding)}[/dim]"

        # Threats column: actual framework tag IDs per finding
        threat_lines = []
        if finding.owasp_tags:
            tags = sorted(finding.owasp_tags)[:3]
            extra = f" +{len(finding.owasp_tags) - 3}" if len(finding.owasp_tags) > 3 else ""
            threat_lines.append(f"[purple]{' '.join(tags)}{extra}[/purple]")
        if finding.atlas_tags:
            tags = sorted(finding.atlas_tags)[:3]
            extra = f" +{len(finding.atlas_tags) - 3}" if len(finding.atlas_tags) > 3 else ""
            threat_lines.append(f"[cyan]{' '.join(tags)}{extra}[/cyan]")
        if finding.attack_tags:
            tags = sorted(finding.attack_tags)[:3]
            extra = f" +{len(finding.attack_tags) - 3}" if len(finding.attack_tags) > 3 else ""
            threat_lines.append(f"[red]{' '.join(tags)}{extra}[/red]")
        if finding.nist_ai_rmf_tags:
            tags = sorted(finding.nist_ai_rmf_tags)[:3]
            extra = f" +{len(finding.nist_ai_rmf_tags) - 3}" if len(finding.nist_ai_rmf_tags) > 3 else ""
            threat_lines.append(f"[green]{' '.join(tags)}{extra}[/green]")
        if finding.owasp_mcp_tags:
            tags = sorted(finding.owasp_mcp_tags)[:3]
            extra = f" +{len(finding.owasp_mcp_tags) - 3}" if len(finding.owasp_mcp_tags) > 3 else ""
            threat_lines.append(f"[yellow]{' '.join(tags)}{extra}[/yellow]")
        if finding.owasp_agentic_tags:
            tags = sorted(finding.owasp_agentic_tags)[:3]
            extra = f" +{len(finding.owasp_agentic_tags) - 3}" if len(finding.owasp_agentic_tags) > 3 else ""
            threat_lines.append(f"[magenta]{' '.join(tags)}{extra}[/magenta]")
        if finding.eu_ai_act_tags:
            tags = sorted(finding.eu_ai_act_tags)[:3]
            extra = f" +{len(finding.eu_ai_act_tags) - 3}" if len(finding.eu_ai_act_tags) > 3 else ""
            threat_lines.append(f"[blue]{' '.join(tags)}{extra}[/blue]")
        if finding.nist_csf_tags:
            tags = sorted(finding.nist_csf_tags)[:3]
            extra = f" +{len(finding.nist_csf_tags) - 3}" if len(finding.nist_csf_tags) > 3 else ""
            threat_lines.append(f"[bright_green]{' '.join(tags)}{extra}[/bright_green]")
        if finding.iso_27001_tags:
            tags = sorted(finding.iso_27001_tags)[:3]
            extra = f" +{len(finding.iso_27001_tags) - 3}" if len(finding.iso_27001_tags) > 3 else ""
            threat_lines.append(f"[bright_cyan]{' '.join(tags)}{extra}[/bright_cyan]")
        if finding.soc2_tags:
            tags = sorted(finding.soc2_tags)[:3]
            extra = f" +{len(finding.soc2_tags) - 3}" if len(finding.soc2_tags) > 3 else ""
            threat_lines.append(f"[bright_yellow]{' '.join(tags)}{extra}[/bright_yellow]")
        if finding.cis_tags:
            tags = sorted(finding.cis_tags)[:3]
            extra = f" +{len(finding.cis_tags) - 3}" if len(finding.cis_tags) > 3 else ""
            threat_lines.append(f"[bright_magenta]{' '.join(tags)}{extra}[/bright_magenta]")
        threats_display = "\n".join(threat_lines) if threat_lines else "—"

        table.add_row(
            f"[{sev_style}]{finding.risk_score:.1f}[/{sev_style}]",
            vuln_display,
            _sev_badge(sev),
            epss_display,
            kev_display,
            blast_display,
            threats_display,
            fix,
        )

    _console().print(table)

    if len(all_cve) > 25:
        _console().print(f"\n  [dim]...and {len(all_cve) - 25} more findings. Use --output to export full report.[/dim]")

    # Verification sources — one link per unique CVE
    seen_ids: set[str] = set()
    sources: list[tuple[str, str]] = []
    for finding in all_cve:
        vid = finding.cve_id or finding.id
        if vid in seen_ids:
            continue
        seen_ids.add(vid)
        refs = finding_references(finding)
        if refs:
            sources.append((vid, refs[0]))
        elif vid.startswith("CVE-"):
            sources.append((vid, f"https://osv.dev/vulnerability/{vid}"))
        elif vid.startswith("GHSA-"):
            sources.append((vid, f"https://github.com/advisories/{vid}"))
    if sources:
        _console().print("\n[bold]Verification Sources[/bold]")
        for vid, url in sources[:15]:
            _console().print(f"  [dim]{vid}[/dim]  →  [link={url}]{url}[/link]")
        if len(sources) > 15:
            _console().print(f"  [dim]...and {len(sources) - 15} more (see JSON output for full list)[/dim]")


def print_attack_flow_tree(report: AIBOMReport) -> None:
    """Print per-CVE blast radius chains as Rich Trees."""
    all_cve = cve_findings(report)
    if not all_cve:
        return

    _console().print()
    _console().print(Rule("Attack Flow Chains", style="red"))
    _console().print()

    severity_styles = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "#e67e22 bold",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "dim",
    }

    for finding in sorted(all_cve, key=lambda item: item.risk_score, reverse=True)[:15]:
        sev = finding_severity(finding)
        sev_style = severity_styles.get(sev, "white")
        vuln_id = finding.cve_id or finding.id

        # Root: CVE line
        root_parts = [f"[{sev_style}]{vuln_id}[/{sev_style}]"]
        root_parts.append(f"[{sev_style}]\\[{sev.value}][/{sev_style}]")
        if finding.cvss_score is not None:
            root_parts.append(f"CVSS {finding.cvss_score:.1f}")
        if finding.epss_score is not None:
            pct = int(finding.epss_score * 100)
            root_parts.append(f"EPSS {pct}%")
        if finding.is_kev:
            root_parts.append("[red bold]🔥 KEV[/red bold]")

        cve_tree = Tree(" · ".join(root_parts))

        # Package node
        pkg_label = f"{package_name(finding)}@{package_version(finding)} ({package_ecosystem(finding)})"
        pkg_branch = cve_tree.add(f"[dim]{pkg_label}[/dim]")

        # Server branches
        for server_name in finding.affected_servers:
            srv_branch = pkg_branch.add(f"\U0001f50c [bold cyan]{server_name}[/bold cyan] [dim](MCP Server)[/dim]")

            # Agents
            for agent_name in finding.affected_agents:
                srv_branch.add(f"\U0001f916 [green]{agent_name}[/green] [dim](Agent)[/dim]")

            # Credentials
            for cred in finding.exposed_credentials:
                srv_branch.add(f"[yellow]🔑 {cred}[/yellow]")

            # Tools (compact, max 5 per line)
            if finding.exposed_tools:
                tool_names = finding.exposed_tools[:5]
                extra = f" +{len(finding.exposed_tools) - 5}" if len(finding.exposed_tools) > 5 else ""
                srv_branch.add(f"[dim]🔧 {', '.join(tool_names)}{extra}[/dim]")

        # If no servers, still show agents/creds/tools under package
        if not finding.affected_servers:
            for agent_name in finding.affected_agents:
                pkg_branch.add(f"\U0001f916 [green]{agent_name}[/green] [dim](Agent)[/dim]")
            for cred in finding.exposed_credentials:
                pkg_branch.add(f"[yellow]🔑 {cred}[/yellow]")
            if finding.exposed_tools:
                tool_names = finding.exposed_tools[:5]
                extra = f" +{len(finding.exposed_tools) - 5}" if len(finding.exposed_tools) > 5 else ""
                pkg_branch.add(f"[dim]🔧 {', '.join(tool_names)}{extra}[/dim]")

        _console().print(cve_tree)

    remaining = len(all_cve) - 15
    if remaining > 0:
        _console().print(f"\n  [dim]...and {remaining} more findings. Use --output to export full report.[/dim]")
    _console().print()


def print_threat_frameworks(report: AIBOMReport) -> None:
    """Print aggregated threat framework coverage — OWASP LLM Top 10 + MITRE ATT&CK + MITRE ATLAS + NIST AI RMF."""
    from collections import Counter

    from agent_bom.atlas import ATLAS_TECHNIQUES
    from agent_bom.mitre_attack import ATTACK_TECHNIQUES
    from agent_bom.nist_ai_rmf import NIST_AI_RMF
    from agent_bom.owasp import OWASP_LLM_TOP10

    if not cve_findings(report):
        return

    # Aggregate tag counts
    owasp_counts: Counter[str] = Counter()
    atlas_counts: Counter[str] = Counter()
    attack_counts: Counter[str] = Counter()
    nist_counts: Counter[str] = Counter()
    owasp_mcp_counts: Counter[str] = Counter()
    owasp_agentic_counts: Counter[str] = Counter()
    eu_ai_act_counts: Counter[str] = Counter()
    nist_csf_counts: Counter[str] = Counter()
    iso_27001_counts: Counter[str] = Counter()
    soc2_counts: Counter[str] = Counter()
    cis_counts: Counter[str] = Counter()
    for finding in cve_findings(report):
        for tag in finding.owasp_tags:
            owasp_counts[tag] += 1
        for tag in finding.atlas_tags:
            atlas_counts[tag] += 1
        for tag in finding.attack_tags:
            attack_counts[tag] += 1
        for tag in finding.nist_ai_rmf_tags:
            nist_counts[tag] += 1
        for tag in finding.owasp_mcp_tags:
            owasp_mcp_counts[tag] += 1
        for tag in finding.owasp_agentic_tags:
            owasp_agentic_counts[tag] += 1
        for tag in finding.eu_ai_act_tags:
            eu_ai_act_counts[tag] += 1
        for tag in finding.nist_csf_tags:
            nist_csf_counts[tag] += 1
        for tag in finding.iso_27001_tags:
            iso_27001_counts[tag] += 1
        for tag in finding.soc2_tags:
            soc2_counts[tag] += 1
        for tag in finding.cis_tags:
            cis_counts[tag] += 1

    if (
        not owasp_counts
        and not atlas_counts
        and not attack_counts
        and not nist_counts
        and not owasp_mcp_counts
        and not owasp_agentic_counts
        and not eu_ai_act_counts
        and not nist_csf_counts
        and not iso_27001_counts
        and not soc2_counts
        and not cis_counts
    ):
        return

    _console().print()
    _console().print(Rule("Threat Framework Coverage", style="bold"))
    _console().print()

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

        _console().print(owasp_table)

    # MITRE ATT&CK Enterprise table (CVE blast radius mappings)
    if attack_counts:
        attack_table = Table(title="MITRE ATT&CK Enterprise", title_style="bold red", border_style="dim")
        attack_table.add_column("Technique", width=12, style="bold red")
        attack_table.add_column("Name", width=44)
        attack_table.add_column("Findings", width=9, justify="right")
        attack_table.add_column("", width=20)

        for code in sorted(attack_counts.keys()):
            count = attack_counts[code]
            name = ATTACK_TECHNIQUES.get(code, "Unknown")
            bar_len = min(count, 16)
            bar = "[red]" + "█" * bar_len + "[/red]"
            attack_table.add_row(code, name, f"[bold]{count}[/bold]", bar)

        _console().print(attack_table)

    # ATLAS table
    if atlas_counts:
        atlas_table = Table(title="MITRE ATLAS (AI/ML)", title_style="bold cyan", border_style="dim")
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

        _console().print(atlas_table)

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

        _console().print(nist_table)

    # OWASP MCP Top 10 table
    if owasp_mcp_counts:
        from agent_bom.owasp_mcp import OWASP_MCP_TOP10

        mcp_table = Table(title="OWASP MCP Top 10", title_style="bold yellow", border_style="dim")
        mcp_table.add_column("Code", width=7, style="bold yellow")
        mcp_table.add_column("Risk", width=42)
        mcp_table.add_column("Findings", width=9, justify="right")
        mcp_table.add_column("", width=20)

        for code in sorted(OWASP_MCP_TOP10.keys()):
            count = owasp_mcp_counts.get(code, 0)
            name = OWASP_MCP_TOP10[code]
            if count > 0:
                bar_len = min(count, 16)
                bar = "[red]" + "█" * bar_len + "[/red]"
                mcp_table.add_row(code, name, f"[bold]{count}[/bold]", bar)
            else:
                mcp_table.add_row(f"[dim]{code}[/dim]", f"[dim]{name}[/dim]", "[dim]—[/dim]", "")

        _console().print(mcp_table)

    # OWASP Agentic Top 10 table
    if owasp_agentic_counts:
        from agent_bom.owasp_agentic import OWASP_AGENTIC_TOP10

        agentic_table = Table(title="OWASP Agentic Top 10", title_style="bold magenta", border_style="dim")
        agentic_table.add_column("Code", width=7, style="bold magenta")
        agentic_table.add_column("Risk", width=42)
        agentic_table.add_column("Findings", width=9, justify="right")
        agentic_table.add_column("", width=20)

        for code in sorted(OWASP_AGENTIC_TOP10.keys()):
            count = owasp_agentic_counts.get(code, 0)
            name = OWASP_AGENTIC_TOP10[code]
            if count > 0:
                bar_len = min(count, 16)
                bar = "[red]" + "█" * bar_len + "[/red]"
                agentic_table.add_row(code, name, f"[bold]{count}[/bold]", bar)
            else:
                agentic_table.add_row(f"[dim]{code}[/dim]", f"[dim]{name}[/dim]", "[dim]—[/dim]", "")

        _console().print(agentic_table)

    # EU AI Act table
    if eu_ai_act_counts:
        from agent_bom.eu_ai_act import EU_AI_ACT

        eu_table = Table(title="EU AI Act", title_style="bold blue", border_style="dim")
        eu_table.add_column("Article", width=9, style="bold blue")
        eu_table.add_column("Description", width=42)
        eu_table.add_column("Findings", width=9, justify="right")
        eu_table.add_column("", width=20)

        for code in sorted(EU_AI_ACT.keys()):
            count = eu_ai_act_counts.get(code, 0)
            name = EU_AI_ACT[code]
            if count > 0:
                bar_len = min(count, 16)
                bar = "[red]" + "█" * bar_len + "[/red]"
                eu_table.add_row(code, name, f"[bold]{count}[/bold]", bar)
            else:
                eu_table.add_row(f"[dim]{code}[/dim]", f"[dim]{name}[/dim]", "[dim]—[/dim]", "")

        _console().print(eu_table)

    # NIST CSF 2.0 table
    if nist_csf_counts:
        from agent_bom.nist_csf import NIST_CSF

        csf_table = Table(title="NIST CSF 2.0", title_style="bold bright_green", border_style="dim")
        csf_table.add_column("Category", width=12, style="bold bright_green")
        csf_table.add_column("Description", width=42)
        csf_table.add_column("Findings", width=9, justify="right")
        csf_table.add_column("", width=20)

        for code in sorted(NIST_CSF.keys()):
            count = nist_csf_counts.get(code, 0)
            name = NIST_CSF[code]
            if count > 0:
                bar_len = min(count, 16)
                bar = "[red]" + "\u2588" * bar_len + "[/red]"
                csf_table.add_row(code, name, f"[bold]{count}[/bold]", bar)
            else:
                csf_table.add_row(f"[dim]{code}[/dim]", f"[dim]{name}[/dim]", "[dim]\u2014[/dim]", "")

        _console().print(csf_table)

    # ISO 27001:2022 table
    if iso_27001_counts:
        from agent_bom.iso_27001 import ISO_27001

        iso_table = Table(title="ISO 27001:2022", title_style="bold bright_cyan", border_style="dim")
        iso_table.add_column("Control", width=9, style="bold bright_cyan")
        iso_table.add_column("Description", width=42)
        iso_table.add_column("Findings", width=9, justify="right")
        iso_table.add_column("", width=20)

        for code in sorted(ISO_27001.keys()):
            count = iso_27001_counts.get(code, 0)
            name = ISO_27001[code]
            if count > 0:
                bar_len = min(count, 16)
                bar = "[red]" + "\u2588" * bar_len + "[/red]"
                iso_table.add_row(code, name, f"[bold]{count}[/bold]", bar)
            else:
                iso_table.add_row(f"[dim]{code}[/dim]", f"[dim]{name}[/dim]", "[dim]\u2014[/dim]", "")

        _console().print(iso_table)

    # SOC 2 TSC table
    if soc2_counts:
        from agent_bom.soc2 import SOC2_TSC

        soc2_table = Table(title="SOC 2 TSC", title_style="bold bright_yellow", border_style="dim")
        soc2_table.add_column("Criteria", width=9, style="bold bright_yellow")
        soc2_table.add_column("Description", width=42)
        soc2_table.add_column("Findings", width=9, justify="right")
        soc2_table.add_column("", width=20)

        for code in sorted(SOC2_TSC.keys()):
            count = soc2_counts.get(code, 0)
            name = SOC2_TSC[code]
            if count > 0:
                bar_len = min(count, 16)
                bar = "[red]" + "\u2588" * bar_len + "[/red]"
                soc2_table.add_row(code, name, f"[bold]{count}[/bold]", bar)
            else:
                soc2_table.add_row(f"[dim]{code}[/dim]", f"[dim]{name}[/dim]", "[dim]\u2014[/dim]", "")

        _console().print(soc2_table)

    # CIS Controls v8 table
    if cis_counts:
        from agent_bom.cis_controls import CIS_CONTROLS

        cis_table = Table(title="CIS Controls v8", title_style="bold bright_magenta", border_style="dim")
        cis_table.add_column("Safeguard", width=12, style="bold bright_magenta")
        cis_table.add_column("Description", width=42)
        cis_table.add_column("Findings", width=9, justify="right")
        cis_table.add_column("", width=20)

        for code in sorted(CIS_CONTROLS.keys()):
            count = cis_counts.get(code, 0)
            name = CIS_CONTROLS[code]
            if count > 0:
                bar_len = min(count, 16)
                bar = "[red]" + "\u2588" * bar_len + "[/red]"
                cis_table.add_row(code, name, f"[bold]{count}[/bold]", bar)
            else:
                cis_table.add_row(f"[dim]{code}[/dim]", f"[dim]{name}[/dim]", "[dim]\u2014[/dim]", "")

        _console().print(cis_table)
    _console().print()


# ─── Remediation Plan ───────────────────────────────────────────────────────


def build_remediation_plan(blast_radii: Sequence[object]) -> list[dict]:
    """Group CVE findings into a prioritized remediation plan.

    Accepts legacy ``BlastRadius`` rows or unified ``Finding`` CVE rows. When
    passed BlastRadius objects, they are projected through ``blast_radius_to_finding``
    before grouping.

    Returns items sorted by grouped blast-radius risk: each item = one upgrade action that clears
    N vulns across M agents and frees exposed credentials.
    """
    from collections import defaultdict

    from agent_bom.finding import Asset, Finding, FindingSource, FindingType, blast_radius_to_finding
    from agent_bom.remediation_commands import build_fix_command, build_remove_command, build_verify_command

    if not blast_radii:
        return []

    def _is_mock_value(value: object) -> bool:
        return type(value).__module__ == "unittest.mock"

    def _attr(obj: object, name: str, default: object = None) -> object:
        return getattr(obj, name, default)

    def _text(value: object, default: str = "") -> str:
        if value is None or _is_mock_value(value):
            return default
        raw = getattr(value, "value", value)
        if raw is None or _is_mock_value(raw):
            return default
        return str(raw)

    def _names(values: object) -> list[str]:
        if not values or _is_mock_value(values):
            return []
        names: list[str] = []
        iterable = values if isinstance(values, list | tuple | set) else []
        for item in iterable:
            name = _text(_attr(item, "name", item))
            if name:
                names.append(name)
        return names

    def _list_text(values: object) -> list[str]:
        if not values or _is_mock_value(values):
            return []
        if not isinstance(values, list | tuple | set):
            return []
        return [_text(item) for item in values if _text(item)]

    def _float(value: object, default: float = 0.0) -> float:
        if value is None or _is_mock_value(value):
            return default
        try:
            return float(str(value))
        except (TypeError, ValueError):
            return default

    def _blast_radius_like_to_finding(item: object) -> Finding:
        if isinstance(item, Finding):
            return item
        try:
            return blast_radius_to_finding(item)
        except TypeError:
            # Some legacy CLI tests and plugin adapters still pass BlastRadius-like
            # objects instead of the dataclass. Keep remediation tolerant while the
            # formatter migration converges on the unified Finding stream.
            vuln = _attr(item, "vulnerability")
            pkg = _attr(item, "package")
            package = _text(_attr(pkg, "name"), "unknown-package")
            version = _text(_attr(pkg, "version"))
            ecosystem = _text(_attr(pkg, "ecosystem"))
            vuln_id = _text(_attr(vuln, "id"), "UNKNOWN")
            severity = _text(_attr(vuln, "severity"), "unknown").lower()
            fixed_version = _text(_attr(vuln, "fixed_version")) or None
            references = _list_text(_attr(vuln, "references", []))
            identifier = f"pkg:{ecosystem}/{package}@{version}" if ecosystem and package and version else None
            return Finding(
                finding_type=FindingType.CVE,
                source=FindingSource.SBOM,
                asset=Asset(name=package, asset_type="package", identifier=identifier),
                severity=severity,
                title=f"{vuln_id} in {package}",
                cve_id=vuln_id,
                fixed_version=fixed_version,
                is_kev=bool(_attr(vuln, "is_kev", False)),
                evidence={
                    "package_name": package,
                    "package_version": version,
                    "ecosystem": ecosystem,
                    "references": references,
                },
                affected_agents=_names(_attr(item, "affected_agents", [])),
                affected_servers=_names(_attr(item, "affected_servers", [])),
                exposed_credentials=_list_text(_attr(item, "exposed_credentials", [])),
                exposed_tools=_list_text(_attr(item, "exposed_tools", [])),
                owasp_tags=_list_text(_attr(item, "owasp_tags", [])),
                atlas_tags=_list_text(_attr(item, "atlas_tags", [])),
                nist_ai_rmf_tags=_list_text(_attr(item, "nist_ai_rmf_tags", [])),
                owasp_mcp_tags=_list_text(_attr(item, "owasp_mcp_tags", [])),
                owasp_agentic_tags=_list_text(_attr(item, "owasp_agentic_tags", [])),
                eu_ai_act_tags=_list_text(_attr(item, "eu_ai_act_tags", [])),
                nist_csf_tags=_list_text(_attr(item, "nist_csf_tags", [])),
                iso_27001_tags=_list_text(_attr(item, "iso_27001_tags", [])),
                soc2_tags=_list_text(_attr(item, "soc2_tags", [])),
                cis_tags=_list_text(_attr(item, "cis_tags", [])),
                risk_score=_float(_attr(item, "risk_score", 0.0)),
                ai_risk_context=_text(_attr(item, "ai_risk_context")) or None,
            )

    findings = [_blast_radius_like_to_finding(item) for item in blast_radii]

    groups: dict[tuple, dict] = defaultdict(
        lambda: {
            "package": "",
            "ecosystem": "",
            "current": "",
            "fix": None,
            "reason": None,
            "command": None,
            "verify_command": None,
            "vulns": [],
            "agents": set(),
            "creds": set(),
            "tools": set(),
            "owasp": set(),
            "atlas": set(),
            "nist": set(),
            "owasp_mcp": set(),
            "owasp_agentic": set(),
            "eu_ai_act": set(),
            "nist_csf": set(),
            "iso_27001": set(),
            "soc2": set(),
            "cis": set(),
            "max_severity": Severity.NONE,
            "critical_count": 0,
            "high_count": 0,
            "has_kev": False,
            "ai_risk": False,
            "max_risk_score": 0.0,
            "references": set(),
            "suppressed_prerelease_fixes": set(),
            "is_malicious": False,
        }
    )
    severity_order = {sev: severity_rank(sev.value) for sev in Severity}
    priority_order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}

    def _ranking_reasons(group: dict) -> list[str]:
        reasons: list[str] = []
        if group["has_kev"]:
            reasons.append("actively exploited")
        if group["creds"]:
            cred_count = len(group["creds"])
            reasons.append(f"{cred_count} exposed credential{'s' if cred_count != 1 else ''}")
        if group["tools"]:
            tool_count = len(group["tools"])
            reasons.append(f"{tool_count} reachable tool{'s' if tool_count != 1 else ''}")
        if group["agents"]:
            agent_count = len(group["agents"])
            reasons.append(f"{agent_count} affected agent{'s' if agent_count != 1 else ''}")
        if group["max_risk_score"]:
            reasons.append(f"blast radius risk {group['max_risk_score']:.1f}/10")
        return reasons

    def _ranking_rationale(group: dict) -> str:
        reasons = group["ranking_reasons"]
        if not reasons:
            return f"Prioritized as {group['priority']} based on grouped remediation impact."
        if len(reasons) == 1:
            detail = reasons[0]
        else:
            detail = ", ".join(reasons[:-1]) + f", and {reasons[-1]}"
        return f"Prioritized as {group['priority']} because {detail}."

    for finding in findings:
        pkg_name = package_name(finding)
        ecosystem = package_ecosystem(finding)
        current = package_version(finding)
        key = (pkg_name, ecosystem, current)
        g = groups[key]
        g["package"] = pkg_name
        g["ecosystem"] = ecosystem
        g["current"] = current
        # Only accept fixed_version values that are real forward upgrades for
        # the package ecosystem; this avoids downgrade/canary suggestions from
        # multi-branch or pre-release advisories.
        fv = finding.fixed_version
        if fv:
            from agent_bom.version_utils import compare_versions, is_prerelease_version

            if is_prerelease_version(fv, ecosystem):
                g["suppressed_prerelease_fixes"].add(fv)
            elif compare_versions(current, fv, ecosystem):
                if g["fix"] is None or compare_versions(g["fix"], fv, ecosystem):
                    g["fix"] = fv
        vuln_id = finding.cve_id or finding.id
        g["vulns"].append(vuln_id)
        g["agents"].update(finding.affected_agents)
        g["creds"].update(finding.exposed_credentials)
        g["tools"].update(finding.exposed_tools)
        g["owasp"].update(finding.owasp_tags)
        g["atlas"].update(finding.atlas_tags)
        g["nist"].update(finding.nist_ai_rmf_tags)
        g["owasp_mcp"].update(finding.owasp_mcp_tags)
        g["owasp_agentic"].update(finding.owasp_agentic_tags)
        g["eu_ai_act"].update(finding.eu_ai_act_tags)
        g["nist_csf"].update(finding.nist_csf_tags)
        g["iso_27001"].update(finding.iso_27001_tags)
        g["soc2"].update(finding.soc2_tags)
        g["cis"].update(finding.cis_tags)
        for ref in finding_references(finding):
            g["references"].add(ref)
        sev = finding_severity(finding)
        if severity_order.get(sev, 0) > severity_order.get(g["max_severity"], 0):
            g["max_severity"] = sev
        if sev == Severity.CRITICAL:
            g["critical_count"] += 1
        elif sev == Severity.HIGH:
            g["high_count"] += 1
        if finding.is_kev:
            g["has_kev"] = True
        if finding.ai_risk_context:
            g["ai_risk"] = True
        g["max_risk_score"] = max(g["max_risk_score"], finding.risk_score)
        if getattr(finding, "is_malicious", False) or bool((finding.evidence or {}).get("package_is_malicious")):
            g["is_malicious"] = True

    plan = []
    for g in groups.values():
        g["vulns"] = sorted(set(g["vulns"]))
        g["agents"] = sorted(g["agents"])
        g["creds"] = sorted(g["creds"])
        g["tools"] = sorted(g["tools"])
        g["owasp"] = sorted(g["owasp"])
        g["atlas"] = sorted(g["atlas"])
        g["nist"] = sorted(g["nist"])
        g["owasp_mcp"] = sorted(g["owasp_mcp"])
        g["owasp_agentic"] = sorted(g["owasp_agentic"])
        g["eu_ai_act"] = sorted(g["eu_ai_act"])
        g["nist_csf"] = sorted(g["nist_csf"])
        g["iso_27001"] = sorted(g["iso_27001"])
        g["soc2"] = sorted(g["soc2"])
        g["cis"] = sorted(g["cis"])
        g["references"] = sorted(g["references"])
        g["suppressed_prerelease_fixes"] = sorted(g["suppressed_prerelease_fixes"])
        # Use the highest grouped blast-radius risk score so remediation stays
        # anchored to the canonical vulnerability risk model instead of a
        # separate package-level heuristic.
        g["impact"] = round(g["max_risk_score"], 1)
        if g["has_kev"] or g["critical_count"] >= 3:
            g["priority"] = "P1"
        elif g["critical_count"] > 0 or (g["high_count"] > 0 and g["creds"]):
            g["priority"] = "P2"
        elif g["high_count"] > 0:
            g["priority"] = "P3"
        else:
            g["priority"] = "P4"

        if g["is_malicious"]:
            action = f"Remove {g['package']} from all environments immediately"
            g["fix"] = None
            g["command"] = build_remove_command(g["ecosystem"], g["package"])
            g["verify_command"] = None
            g["reason"] = "known malicious package"
        elif g["fix"]:
            action = f"Upgrade {g['package']} to {g['fix']}"
            g["command"] = build_fix_command(g["ecosystem"], g["package"], g["fix"])
            g["verify_command"] = build_verify_command(g["ecosystem"], g["package"], g["fix"])
        else:
            action = f"Monitor {g['package']} upstream and isolate exposed surface"
            g["command"] = None
            g["verify_command"] = None
            if g["suppressed_prerelease_fixes"]:
                g["reason"] = "prerelease fix suppressed by default"
                action = f"Wait for a stable {g['package']} release; prerelease fix exists but is suppressed by default"
        g["credential_count"] = len(g["creds"])
        g["tool_count"] = len(g["tools"])
        g["agent_count"] = len(g["agents"])
        g["ranking_reasons"] = _ranking_reasons(g)
        g["ranking_rationale"] = _ranking_rationale(g)
        g["ranking_score"] = round(
            g["impact"]
            + (1.5 if g["has_kev"] else 0.0)
            + min(g["credential_count"] * 0.5, 2.0)
            + min(g["tool_count"] * 0.2, 1.0)
            + min(g["agent_count"] * 0.15, 0.75)
            + (0.25 if g["ai_risk"] else 0.0),
            2,
        )
        if g["creds"]:
            action += "; rotate exposed credentials"
        if g["tools"]:
            action += "; review reachable tool permissions"
        if g["has_kev"]:
            action += "; expedite patching due to active exploitation"
        g["action"] = action
        plan.append(g)

    plan.sort(
        key=lambda x: (
            priority_order.get(x["priority"], 99),
            -x["ranking_score"],
            -x["impact"],
            -x["credential_count"],
            -x["tool_count"],
            -x["agent_count"],
            x["package"],
        )
    )
    return plan


def print_remediation_plan(report: AIBOMReport) -> None:
    """Print a prioritized remediation plan with named assets and risk narrative."""
    try:
        all_cve: Sequence[object] = cve_findings(report)
    except TypeError:
        all_cve = list(getattr(report, "blast_radii", []) or [])
    if not all_cve:
        return

    plan = build_remediation_plan(all_cve)
    # A malicious package sets fix=None to signal REMOVAL (not a version bump),
    # so it must be pulled out of the fix-based buckets. Without this it lands in
    # the "no fix yet — monitor upstream for patches" bucket, which tells the user
    # to keep a known-malicious dependency and wait — the opposite of the
    # required "remove immediately" action.
    malicious = [p for p in plan if p.get("is_malicious")]
    fixable = [p for p in plan if p["fix"] and not p.get("is_malicious")]
    unfixable = [p for p in plan if not p["fix"] and not p.get("is_malicious")]

    # Totals for percentage calculations
    total_agents = report.total_agents or 1
    all_creds: set[str] = set()
    all_tools: set[str] = set()
    for finding in all_cve:
        all_creds.update(getattr(finding, "exposed_credentials", []) or [])
        all_tools.update(getattr(finding, "exposed_tools", []) or [])
    total_creds = len(all_creds) or 1
    total_tools = len(all_tools) or 1

    _console().print()
    _console().print(Rule("Remediation Plan", style="green"))
    _console().print()

    sev_style = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "#e67e22 bold",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "dim",
        Severity.NONE: "white",
    }

    if malicious:
        _console().print(
            f"  [red bold]☠ {len(malicious)} MALICIOUS package(s) — remove immediately (do not wait for a patch):[/red bold]\n"
        )
        for item in malicious:
            reason = item.get("reason") or "known malicious package"
            _console().print(
                f"    [white on red] MALICIOUS [/white on red] "
                f"[red bold]Remove {item['package']}@{item['current']}[/red bold] [dim]({reason})[/dim]"
            )
            if item.get("command"):
                _console().print(f"      [dim]$ {item['command']}[/dim]")
            if item["agents"]:
                _console().print(f"      [dim]agents:[/dim]  {', '.join(item['agents'][:3])}")
        _console().print()

    if fixable:
        _console().print(f"  [bold]{len(fixable)} fixable upgrade(s) — ordered by grouped blast-radius risk:[/bold]\n")
        for i, item in enumerate(fixable, 1):
            sev = item["max_severity"]
            style = sev_style.get(sev, "white")
            kev_flag = " [red bold][KEV][/red bold]" if item["has_kev"] else ""
            ai_flag = " [magenta][AI-RISK][/magenta]" if item["ai_risk"] else ""

            # Header: upgrade package version → fix
            _console().print(
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
            _console().print(f"     [dim]{'  •  '.join(impact_parts)}[/dim]")

            # Named assets
            if item["agents"]:
                _console().print(f"     [dim]agents:[/dim]  {', '.join(item['agents'])}")
            if item["creds"]:
                _console().print(f"     [dim]credentials:[/dim]  [yellow]{', '.join(item['creds'])}[/yellow]")
            if item["tools"]:
                _console().print(
                    f"     [dim]tools:[/dim]  {', '.join(item['tools'][:8])}"
                    + (f" +{len(item['tools']) - 8} more" if len(item["tools"]) > 8 else "")
                )

            # Threat framework tags
            tags = []
            if item["owasp"]:
                tags.append("[purple]" + " ".join(item["owasp"]) + "[/purple]")
            if item["atlas"]:
                tags.append("[cyan]" + " ".join(item["atlas"]) + "[/cyan]")
            if item["nist"]:
                tags.append("[green]" + " ".join(item["nist"]) + "[/green]")
            if tags:
                _console().print(f"     [dim]mitigates:[/dim]  {' '.join(tags)}")

            # Risk narrative — what happens if NOT fixed. Suppress the
            # credential-reach clause entirely when the fix frees no
            # credentials, so it never reads "can reach no credentials".
            via = f" via {', '.join(item['agents'][:2])}" if item["agents"] else ""
            through = f" through {', '.join(item['tools'][:3])}" if item["tools"] else ""
            if item["creds"]:
                reach = f"can reach [yellow]{', '.join(item['creds'][:2])}[/yellow]{via}{through}"
            elif item["agents"] or item["tools"]:
                reach = f"widens the attack surface{via}{through}"
            else:
                reach = "widens the attack surface on this dependency"
            _console().print(f"     [dim red]⚠ if not fixed:[/dim red] [dim]attacker exploiting {item['vulns'][0]} {reach}[/dim]")
            _console().print()

    if unfixable:
        _console().print(f"  [dim yellow]⚠ {len(unfixable)} package(s) have no fix yet — monitor upstream for patches:[/dim yellow]")
        for item in unfixable[:10]:
            agents_str = f" ({', '.join(item['agents'][:3])})" if item["agents"] else ""
            _console().print(f"    [dim]• {item['package']}@{item['current']} — {', '.join(item['vulns'][:3])}{agents_str}[/dim]")
        _console().print()


_CIS_CLOUD_BUNDLES: tuple[tuple[str, str, str], ...] = (
    ("aws", "AWS", "cis_benchmark_data"),
    ("azure", "Azure", "azure_cis_benchmark_data"),
    ("gcp", "GCP", "gcp_cis_benchmark_data"),
    ("snowflake", "Snowflake", "snowflake_cis_benchmark_data"),
    ("databricks", "Databricks", "databricks_cis_benchmark_data"),
)

_SEV_LABEL: dict[str, str] = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}
_SEV_TABLE_STYLE: dict[str, str] = {
    "critical": "white on red",
    "high": "white on #e67e22",
    "medium": "black on yellow",
    "low": "white on #555555",
}


def _cis_sev(check: dict) -> str:
    """Normalize a check's severity to a known lowercase band."""
    sev = str(check.get("severity") or "").lower()
    return sev if sev in SEVERITY_THRESHOLD_LABELS else "low"


def _cis_check_sort_key(check: dict) -> tuple[int, int, str, str]:
    """Deterministic ordering: severity, remediation priority, section, id."""
    rem = check.get("remediation") or {}
    priority = rem.get("priority")
    if not isinstance(priority, int):
        priority = 3
    return (
        severity_worst_first_rank(check.get("severity")),
        priority,
        str(check.get("cis_section") or "~"),
        str(check.get("check_id") or ""),
    )


def _cis_evidence(check: dict) -> str:
    """Best available evidence string: prefer affected resource IDs."""
    resources = check.get("resource_ids") or []
    if resources:
        shown = ", ".join(str(r) for r in resources[:4])
        if len(resources) > 4:
            shown += f" (+{len(resources) - 4} more)"
        return shown
    return str(check.get("evidence") or "").strip()


def _cis_remediation_line(check: dict) -> str:
    """Resolve the single 'what to do' line for a failed check."""
    rem = check.get("remediation") or {}
    fix_cli = rem.get("fix_cli")
    if fix_cli:
        return str(fix_cli)
    fix_console = rem.get("fix_console")
    if fix_console:
        return f"→ {fix_console}"
    recommendation = str(check.get("recommendation") or "").strip()
    if recommendation:
        return recommendation
    return ""


def print_cis_findings(report: AIBOMReport, *, show_passed: bool = False) -> None:
    """Render CIS benchmark results as a prioritized, grouped FAILED plan.

    Built for large result sets (60+ checks) where a flat table is
    unreadable. For each cloud with benchmark data:

      - A posture header: pass-rate band, passed/evaluated counts, and a
        verdict driven by the highest failing severity.
      - PASS checks are collapsed into a single ``N passed`` summary line
        by default; pass ``show_passed=True`` to list them.
      - FAILED checks lead, grouped by severity (CRITICAL first) then by
        CIS section/domain, each showing a severity badge, check id +
        title, the affected resources (evidence), and a recommendation /
        remediation command (the 'what to do' line).

    Ordering is deterministic so the same report renders identically
    across runs. Emits nothing when no CIS data is present.
    """
    con = _console()
    raw_bundles = [(cloud, label, getattr(report, attr, None)) for cloud, label, attr in _CIS_CLOUD_BUNDLES]
    bundles = [(c, lbl, b) for c, lbl, b in raw_bundles if b and b.get("checks")]
    if not bundles:
        return

    con.print()
    con.print(Rule("Cloud Security Posture", style="bold bright_magenta"))

    for _cloud, label, bundle in bundles:
        checks = bundle.get("checks") or []
        failed = [c for c in checks if str(c.get("status")) == "fail"]
        passed = [c for c in checks if str(c.get("status")) == "pass"]
        errored = [c for c in checks if str(c.get("status")) == "error"]
        actionable = failed + errored
        evaluated = len(failed) + len(passed)
        pass_rate = bundle.get("pass_rate")
        if not isinstance(pass_rate, (int, float)):
            pass_rate = (len(passed) / evaluated * 100) if evaluated else 0.0

        band = "green" if pass_rate >= 90 else "yellow" if pass_rate >= 70 else "red"

        # Verdict driven by the worst failing severity.
        if errored and not failed:
            verdict = "[bold red]ERROR[/bold red]"
        elif errored:
            verdict = "[bold yellow]INCOMPLETE[/bold yellow]"
        elif not failed:
            verdict = "[bold green]PASS[/bold green]"
        else:
            worst_check = min(failed, key=lambda c: severity_worst_first_rank(c.get("severity")))
            worst_band = _SEV_LABEL.get(_cis_sev(worst_check), "LOW")
            vstyle = {"CRITICAL": "red bold", "HIGH": "#e67e22 bold", "MEDIUM": "yellow", "LOW": "dim"}[worst_band]
            verdict = f"[{vstyle}]{worst_band} GAPS[/{vstyle}]"

        con.print()
        con.print(
            f"  [bold]{label}[/bold]  {verdict}   "
            f"[{band}]{pass_rate:.0f}% pass[/{band}]  "
            f"[dim]({len(passed)}/{evaluated} checks"
            + (f", {len(failed)} failed" if failed else "")
            + (f", {len(errored)} errored" if errored else "")
            + ")[/dim]"
        )

        if not actionable:
            con.print(f"    [green]{safe_emoji('✓', 'OK')}[/green] [dim]no failed checks[/dim]")
            if show_passed and passed:
                _print_cis_passed(con, passed)
            continue

        # Top risks: the highest-priority failing check ids, for the header.
        top = sorted(actionable, key=_cis_check_sort_key)[:3]
        top_str = ", ".join(str(c.get("check_id") or "?") for c in top)
        con.print(f"    [dim]top risks:[/dim] {top_str}")

        # Group failed checks by severity, then by CIS section.
        for sev in ("critical", "high", "medium", "low"):
            sev_actionable = [c for c in actionable if _cis_sev(c) == sev]
            if not sev_actionable:
                continue
            badge_style = _SEV_TABLE_STYLE[sev]
            failed_n = sum(1 for c in sev_actionable if c.get("status") == "fail")
            error_n = len(sev_actionable) - failed_n
            summary = ", ".join(
                part for part in (f"{failed_n} failed" if failed_n else "", f"{error_n} unevaluable" if error_n else "") if part
            )
            con.print(f"\n    [{badge_style}] {_SEV_LABEL[sev]} [/{badge_style}] [dim]{summary}[/dim]")

            # Group within severity by section for readability.
            sections: dict[str, list[dict]] = {}
            for c in sorted(sev_actionable, key=_cis_check_sort_key):
                sections.setdefault(str(c.get("cis_section") or "Other"), []).append(c)

            for section in sorted(sections):
                con.print(f"      [bold dim]{section}[/bold dim]")
                for check in sections[section]:
                    rem = check.get("remediation") or {}
                    review = f" [yellow]{safe_emoji('↺', '(review)')} review[/yellow]" if rem.get("requires_human_review") else ""
                    title = str(check.get("title") or "").rstrip(".")
                    con.print(f"        [bold]{check.get('check_id', '')}[/bold]  {title}{review}")
                    evidence = _cis_evidence(check)
                    if evidence:
                        con.print(f"          [dim]evidence:[/dim] {evidence}")
                    fix = _cis_remediation_line(check)
                    if fix:
                        con.print(f"          [cyan]fix:[/cyan] {fix}")

        # Collapsed PASS summary (expandable).
        if passed:
            if show_passed:
                _print_cis_passed(con, passed)
            else:
                con.print(f"\n    [green]{safe_emoji('✓', 'OK')}[/green] [dim]{len(passed)} passed (use --show-passed to list)[/dim]")

    con.print()


def _print_cis_passed(con: Console, passed: list[dict]) -> None:
    """List passed checks compactly, sorted by check id (deterministic)."""
    con.print(f"\n    [green]Passed ({len(passed)}):[/green]")
    for check in sorted(passed, key=lambda c: str(c.get("check_id") or "")):
        title = str(check.get("title") or "").rstrip(".")
        con.print(f"      [green]{safe_emoji('✓', 'OK')}[/green] [dim]{check.get('check_id', '')}  {title}[/dim]")


def print_export_hint(report: AIBOMReport) -> None:
    """Print an AI-BOM identity footer with threat framework badge, explore links, and export hints."""

    from agent_bom.atlas import ATLAS_TECHNIQUES
    from agent_bom.mitre_attack import ATTACK_TECHNIQUES
    from agent_bom.nist_ai_rmf import NIST_AI_RMF
    from agent_bom.owasp import OWASP_LLM_TOP10

    lines: list[str] = []

    # ── Threat Framework Coverage Badge ──
    owasp_hit: set[str] = set()
    atlas_hit: set[str] = set()
    attack_hit: set[str] = set()
    nist_hit: set[str] = set()
    owasp_mcp_hit: set[str] = set()
    owasp_agentic_hit: set[str] = set()
    eu_ai_act_hit: set[str] = set()
    nist_csf_hit: set[str] = set()
    iso_27001_hit: set[str] = set()
    soc2_hit: set[str] = set()
    cis_hit: set[str] = set()
    for br in cve_findings(report):
        owasp_hit.update(br.owasp_tags)
        atlas_hit.update(br.atlas_tags)
        attack_hit.update(br.attack_tags)
        nist_hit.update(br.nist_ai_rmf_tags)
        owasp_mcp_hit.update(br.owasp_mcp_tags)
        owasp_agentic_hit.update(br.owasp_agentic_tags)
        eu_ai_act_hit.update(br.eu_ai_act_tags)
        nist_csf_hit.update(br.nist_csf_tags)
        iso_27001_hit.update(br.iso_27001_tags)
        soc2_hit.update(br.soc2_tags)
        cis_hit.update(br.cis_tags)

    from agent_bom.cis_controls import CIS_CONTROLS as _CIS_CONTROLS
    from agent_bom.eu_ai_act import EU_AI_ACT as _EU_AI_ACT
    from agent_bom.iso_27001 import ISO_27001 as _ISO_27001
    from agent_bom.nist_csf import NIST_CSF as _NIST_CSF
    from agent_bom.owasp_agentic import OWASP_AGENTIC_TOP10 as _OWASP_AGENTIC
    from agent_bom.owasp_mcp import OWASP_MCP_TOP10
    from agent_bom.soc2 import SOC2_TSC as _SOC2_TSC

    owasp_total = len(OWASP_LLM_TOP10)
    atlas_total = len(ATLAS_TECHNIQUES)
    attack_total = len(ATTACK_TECHNIQUES)
    nist_total = len(NIST_AI_RMF)
    owasp_mcp_total = len(OWASP_MCP_TOP10)
    owasp_agentic_total = len(_OWASP_AGENTIC)
    eu_ai_act_total = len(_EU_AI_ACT)
    nist_csf_total = len(_NIST_CSF)
    iso_27001_total = len(_ISO_27001)
    soc2_total = len(_SOC2_TSC)
    cis_total = len(_CIS_CONTROLS)

    if cve_findings(report):
        lines.append("[bold]AI Threat Framework Coverage[/bold]")
        lines.append("")

        # OWASP bar
        owasp_pct = int(len(owasp_hit) / owasp_total * 100) if owasp_total else 0
        owasp_bar = _coverage_bar(len(owasp_hit), owasp_total, "purple")
        lines.append(
            f"  [bold purple]OWASP LLM Top 10[/bold purple]  {owasp_bar}  [purple]{len(owasp_hit)}/{owasp_total}[/purple] ({owasp_pct}%)"
        )

        # ATT&CK Enterprise bar
        attack_pct = int(len(attack_hit) / attack_total * 100) if attack_total else 0
        attack_bar = _coverage_bar(len(attack_hit), attack_total, "red")
        lines.append(f"  [bold red]MITRE ATT&CK     [/bold red]  {attack_bar}  [red]{len(attack_hit)}/{attack_total}[/red] ({attack_pct}%)")

        # ATLAS bar
        atlas_pct = int(len(atlas_hit) / atlas_total * 100) if atlas_total else 0
        atlas_bar = _coverage_bar(len(atlas_hit), atlas_total, "cyan")
        lines.append(f"  [bold cyan]MITRE ATLAS      [/bold cyan]  {atlas_bar}  [cyan]{len(atlas_hit)}/{atlas_total}[/cyan] ({atlas_pct}%)")

        # NIST bar
        nist_pct = int(len(nist_hit) / nist_total * 100) if nist_total else 0
        nist_bar = _coverage_bar(len(nist_hit), nist_total, "green")
        lines.append(f"  [bold green]NIST AI RMF 1.0  [/bold green]  {nist_bar}  [green]{len(nist_hit)}/{nist_total}[/green] ({nist_pct}%)")

        # OWASP MCP bar
        owasp_mcp_pct = int(len(owasp_mcp_hit) / owasp_mcp_total * 100) if owasp_mcp_total else 0
        owasp_mcp_bar = _coverage_bar(len(owasp_mcp_hit), owasp_mcp_total, "yellow")
        lines.append(
            f"  [bold yellow]OWASP MCP Top 10 [/bold yellow]  {owasp_mcp_bar}"
            f"  [yellow]{len(owasp_mcp_hit)}/{owasp_mcp_total}[/yellow] ({owasp_mcp_pct}%)"
        )

        # OWASP Agentic bar
        owasp_agentic_pct = int(len(owasp_agentic_hit) / owasp_agentic_total * 100) if owasp_agentic_total else 0
        owasp_agentic_bar = _coverage_bar(len(owasp_agentic_hit), owasp_agentic_total, "magenta")
        lines.append(
            f"  [bold magenta]OWASP Agentic T10[/bold magenta]  {owasp_agentic_bar}"
            f"  [magenta]{len(owasp_agentic_hit)}/{owasp_agentic_total}[/magenta] ({owasp_agentic_pct}%)"
        )

        # EU AI Act bar
        eu_ai_act_pct = int(len(eu_ai_act_hit) / eu_ai_act_total * 100) if eu_ai_act_total else 0
        eu_ai_act_bar = _coverage_bar(len(eu_ai_act_hit), eu_ai_act_total, "blue")
        lines.append(
            f"  [bold blue]EU AI Act         [/bold blue]  {eu_ai_act_bar}"
            f"  [blue]{len(eu_ai_act_hit)}/{eu_ai_act_total}[/blue] ({eu_ai_act_pct}%)"
        )

        # NIST CSF 2.0 bar
        nist_csf_pct = int(len(nist_csf_hit) / nist_csf_total * 100) if nist_csf_total else 0
        nist_csf_bar = _coverage_bar(len(nist_csf_hit), nist_csf_total, "bright_green")
        lines.append(
            f"  [bold bright_green]NIST CSF 2.0      [/bold bright_green]  {nist_csf_bar}"
            f"  [bright_green]{len(nist_csf_hit)}/{nist_csf_total}[/bright_green] ({nist_csf_pct}%)"
        )

        # ISO 27001:2022 bar
        iso_27001_pct = int(len(iso_27001_hit) / iso_27001_total * 100) if iso_27001_total else 0
        iso_27001_bar = _coverage_bar(len(iso_27001_hit), iso_27001_total, "bright_cyan")
        lines.append(
            f"  [bold bright_cyan]ISO 27001:2022    [/bold bright_cyan]  {iso_27001_bar}"
            f"  [bright_cyan]{len(iso_27001_hit)}/{iso_27001_total}[/bright_cyan] ({iso_27001_pct}%)"
        )

        # SOC 2 TSC bar
        soc2_pct = int(len(soc2_hit) / soc2_total * 100) if soc2_total else 0
        soc2_bar = _coverage_bar(len(soc2_hit), soc2_total, "bright_yellow")
        lines.append(
            f"  [bold bright_yellow]SOC 2 TSC         [/bold bright_yellow]  {soc2_bar}"
            f"  [bright_yellow]{len(soc2_hit)}/{soc2_total}[/bright_yellow] ({soc2_pct}%)"
        )

        # CIS Controls v8 bar
        cis_pct = int(len(cis_hit) / cis_total * 100) if cis_total else 0
        cis_bar = _coverage_bar(len(cis_hit), cis_total, "bright_magenta")
        lines.append(
            f"  [bold bright_magenta]CIS Controls v8   [/bold bright_magenta]  {cis_bar}"
            f"  [bright_magenta]{len(cis_hit)}/{cis_total}[/bright_magenta] ({cis_pct}%)"
        )

        lines.append("")

    # ── Summary ──
    vuln_color = "red" if report.total_vulnerabilities > 0 else "green"
    lines.append("[bold]AI Infrastructure Security Report[/bold]")
    lines.append(
        f"  [dim]{report.total_agents} agents · {report.total_servers} MCP servers · "
        f"{report.total_packages} packages ·[/dim] "
        f"[bold {vuln_color}]{report.total_vulnerabilities} vulnerabilities[/bold {vuln_color}]"
    )
    lines.append("")

    # ── Contextual next steps ──
    lines.append("[bold]Next steps[/bold]")
    if report.total_vulnerabilities > 0:
        lines.append("  [green]agent-bom scan --remediate fix.md[/green]               [dim]Generate fix commands[/dim]")
        lines.append("  [green]agent-bom scan -f sarif -o results.sarif[/green]        [dim]Upload to GitHub Security[/dim]")
    if report.total_servers > 0:
        lines.append("  [green]agent-bom runtime proxy -- npx @mcp/server ...[/green]  [dim]Enforce MCP traffic[/dim]")
    lines.append("  [green]agent-bom scan -f html -o report.html[/green]           [dim]Interactive HTML report[/dim]")
    lines.append("  [green]agent-bom scan -f pdf -o report.pdf[/green]             [dim]Audit-ready PDF export[/dim]")
    lines.append("")

    # ── Export (compact) ──
    lines.append("[bold]Export[/bold]")
    lines.append("  [green]-f[/green] json · cyclonedx · spdx · sarif · html · pdf · junit   [dim]19 formats[/dim]")

    _console().print()
    _console().print(Panel("\n".join(lines), border_style="blue", padding=(1, 2)))


# The compact output family moved to agent_bom/output/compact.py as Phase 1a
# of the #1522 monolith split. Re-exported at the bottom of this file for
# backward compatibility.


# ─── Diff Output ─────────────────────────────────────────────────────────────


def print_diff(diff: dict, *, quiet: bool = False) -> None:
    """Print a human-readable diff between two scan reports."""
    summary = diff["summary"]
    baseline_ts = diff["baseline_generated_at"]
    current_ts = diff["current_generated_at"]

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
    inventory_diff = diff.get("inventory_diff", {})
    inv_summary = inventory_diff.get("summary", {}) if isinstance(inventory_diff, dict) else {}
    if inv_summary.get("new_servers"):
        parts.append(f"[cyan]{inv_summary['new_servers']} new server(s)[/cyan]")
    if inv_summary.get("removed_servers"):
        parts.append(f"[dim]{inv_summary['removed_servers']} removed server(s)[/dim]")
    if inv_summary.get("changed_servers"):
        parts.append(f"[magenta]{inv_summary['changed_servers']} changed server fingerprint(s)[/magenta]")
    if inv_summary.get("changed_tools"):
        parts.append(f"[magenta]{inv_summary['changed_tools']} changed tool(s)[/magenta]")
    if inv_summary.get("changed_resources"):
        parts.append(f"[magenta]{inv_summary['changed_resources']} changed resource(s)[/magenta]")
    if inv_summary.get("new_tools"):
        parts.append(f"[cyan]{inv_summary['new_tools']} new tool(s)[/cyan]")
    if inv_summary.get("new_resources"):
        parts.append(f"[cyan]{inv_summary['new_resources']} new resource(s)[/cyan]")
    if inv_summary.get("new_relationships"):
        parts.append(f"[cyan]{inv_summary['new_relationships']} new relationship(s)[/cyan]")
    if inv_summary.get("removed_relationships"):
        parts.append(f"[dim]{inv_summary['removed_relationships']} removed relationship(s)[/dim]")

    if quiet:
        if parts:
            _console().print("  •  ".join(parts))
        else:
            _console().print("No changes since baseline.")
        return

    _console().print(f"\n[bold blue]📊 Scan Diff[/bold blue]  [dim]{baseline_ts}[/dim] → [dim]{current_ts}[/dim]\n")

    if parts:
        _console().print("  " + "  •  ".join(parts) + "\n")
    else:
        _console().print("  [green]No changes since baseline.[/green]\n")
        return

    severity_styles = {
        "CRITICAL": "red bold",
        "HIGH": "#e67e22 bold",
        "MEDIUM": "yellow",
        "LOW": "dim",
    }

    if diff["new"]:
        _console().print(f"  [red bold]New findings ({len(diff['new'])}):[/red bold]")
        for br in diff["new"][:20]:
            sev = br.get("severity", "UNKNOWN")
            style = severity_styles.get(sev, "white")
            kev = " [red bold][KEV][/red bold]" if br.get("is_kev") else ""
            ai = " [magenta][AI-RISK][/magenta]" if br.get("ai_risk_context") else ""
            fix = f" → fix: {br['fixed_version']}" if br.get("fixed_version") else " (no fix)"
            _console().print(
                f"    [+] [{style}]{br.get('vulnerability_id', '?')}[/{style}]  {br.get('package', '?')}  [{sev}]{kev}{ai}[dim]{fix}[/dim]"
            )
        if len(diff["new"]) > 20:
            _console().print(f"    [dim]...and {len(diff['new']) - 20} more[/dim]")
        _console().print()

    if diff["resolved"]:
        _console().print(f"  [green]Resolved findings ({len(diff['resolved'])}):[/green]")
        for br in diff["resolved"][:10]:
            _console().print(f"    [-] [dim]{br.get('vulnerability_id', '?')}  {br.get('package', '?')}[/dim]")
        _console().print()

    if diff["new_packages"]:
        _console().print(f"  [yellow]New packages added ({len(diff['new_packages'])}):[/yellow]")
        for pkg in diff["new_packages"][:10]:
            _console().print(f"    [+] [dim]{pkg}[/dim]")
        _console().print()

    if diff["removed_packages"]:
        _console().print(f"  [dim]Packages removed ({len(diff['removed_packages'])}):[/dim]")
        for pkg in diff["removed_packages"][:10]:
            _console().print(f"    [-] [dim]{pkg}[/dim]")
        _console().print()

    if isinstance(inventory_diff, dict) and inventory_diff.get("changed_servers"):
        _console().print(f"  [magenta]Server fingerprint changes ({len(inventory_diff['changed_servers'])}):[/magenta]")
        for server in inventory_diff["changed_servers"][:10]:
            _console().print(f"    [~] [dim]{server.get('name') or server.get('id')}[/dim]")
        _console().print()

    if isinstance(inventory_diff, dict) and inventory_diff.get("changed_tools"):
        _console().print(f"  [magenta]Changed tools ({len(inventory_diff['changed_tools'])}):[/magenta]")
        for tool in inventory_diff["changed_tools"][:10]:
            _console().print(f"    [~] [dim]{tool.get('name') or tool.get('id')}[/dim]")
        _console().print()

    if isinstance(inventory_diff, dict) and inventory_diff.get("changed_resources"):
        _console().print(f"  [magenta]Changed resources ({len(inventory_diff['changed_resources'])}):[/magenta]")
        for resource in inventory_diff["changed_resources"][:10]:
            _console().print(f"    [~] [dim]{resource.get('uri') or resource.get('id')}[/dim]")
        _console().print()

    if isinstance(inventory_diff, dict) and inventory_diff.get("new_tools"):
        _console().print(f"  [cyan]New tools ({len(inventory_diff['new_tools'])}):[/cyan]")
        for tool in inventory_diff["new_tools"][:10]:
            _console().print(f"    [+] [dim]{tool.get('name') or tool.get('id')}[/dim]")
        _console().print()

    if isinstance(inventory_diff, dict) and inventory_diff.get("new_resources"):
        _console().print(f"  [cyan]New resources ({len(inventory_diff['new_resources'])}):[/cyan]")
        for resource in inventory_diff["new_resources"][:10]:
            _console().print(f"    [+] [dim]{resource.get('uri') or resource.get('id')}[/dim]")
        _console().print()

    if isinstance(inventory_diff, dict) and inventory_diff.get("new_relationships"):
        _console().print(f"  [cyan]New relationships ({len(inventory_diff['new_relationships'])}):[/cyan]")
        for relationship in inventory_diff["new_relationships"][:10]:
            _console().print(f"    [+] [dim]{relationship.get('from')} -[{relationship.get('type')}]-> {relationship.get('to')}[/dim]")
        _console().print()


# ─── Policy Output ──────────────────────────────────────────────────────────


def print_policy_results(policy_result: dict) -> None:
    """Print policy evaluation results to console."""
    name = policy_result["policy_name"]
    failures = policy_result["failures"]
    warnings = policy_result["warnings"]
    passed = policy_result["passed"]

    status = "[green]PASS[/green]" if passed else "[red bold]FAIL[/red bold]"
    _console().print(f"\n[bold]📋 Policy: {name}[/bold]  {status}\n")

    if warnings:
        _console().print(f"  [yellow]⚠ {len(warnings)} warning(s):[/yellow]")
        for v in warnings[:10]:
            _console().print(f"    [yellow]WARN[/yellow]  [{v['rule_id']}]  {v['vulnerability_id']}  {v['package']}  [{v['severity']}]")
            _console().print(f"           [dim]{v['rule_description']}[/dim]")
        _console().print()

    if failures:
        _console().print(f"  [red bold]✗ {len(failures)} failure(s):[/red bold]")
        for v in failures[:10]:
            kev = " [red bold][KEV][/red bold]" if v.get("is_kev") else ""
            ai = " [magenta][AI-RISK][/magenta]" if v.get("ai_risk_context") else ""
            _console().print(
                f"    [red bold]FAIL[/red bold]  [{v['rule_id']}]  {v['vulnerability_id']}  {v['package']}  [{v['severity']}]{kev}{ai}"
            )
            _console().print(f"           [dim]{v['rule_description']}[/dim]")
        if len(failures) > 10:
            _console().print(f"    [dim]...and {len(failures) - 10} more failures[/dim]")
        _console().print()

    if passed and not warnings:
        _console().print("  [green]✓ All policy rules passed.[/green]\n")


# ─── Severity Chart ─────────────────────────────────────────────────────────


def print_severity_chart(report: AIBOMReport) -> None:
    """Print an ASCII severity distribution bar chart."""
    all_cve = cve_findings(report)
    if not all_cve:
        return

    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in all_cve:
        sev = finding_severity(finding).value.upper()
        if sev in counts:
            counts[sev] += 1

    total = sum(counts.values())
    if total == 0:
        return

    _console().print()
    _console().print(Rule("Severity Distribution", style="bold"))
    _console().print()
    max_count = max(counts.values()) or 1
    bar_width = 30
    styles = {
        "CRITICAL": "red bold",
        "HIGH": "#e67e22 bold",
        "MEDIUM": "yellow",
        "LOW": "dim",
    }

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = counts[sev]
        bar_len = int(bar_width * count / max_count) if count else 0
        bar = "█" * bar_len
        style = styles[sev]
        pct = int(100 * count / total) if total else 0
        _console().print(f"  [{style}]{sev:8}[/{style}]  [{style}]{bar:<{bar_width}}[/{style}]  [dim]{count:3} ({pct}%)[/dim]")
    _console().print()
