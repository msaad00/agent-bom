"""Discovery stages for skill/instruction files: inventory, security audit, trust."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rich.panel import Panel
from rich.table import Table as RichTable

from agent_bom.cli.agents._discovery_state import DiscoveryRun
from agent_bom.models import Agent, AgentType
from agent_bom.models import MCPServer as _SkillSrv

_SEV_COLORS = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim"}
_SEV_ICONS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}


def _skill_provenance() -> dict[str, Any]:
    return {
        "source_type": "skill_invoked_pull",
        "observed_via": ["skill_invoked_pull"],
        "source": "skill-files",
        "collector": "skill_scanner",
        "confidence": "high",
    }


def _collect_skill_files(run: DiscoveryRun, discover_skill_files: Any) -> list[Path]:
    skill_file_list: list[Path] = []
    for sp in run.skill_paths:
        p = Path(sp)
        if p.is_dir():
            skill_file_list.extend(discover_skill_files(p))
        else:
            skill_file_list.append(p)
    explicit_target_scan = bool(run.sbom_file or run.images or run.image_tars or run.filesystem_paths)
    if not run.no_discover and not explicit_target_scan:
        # Auto-discover skill files in project directory
        search_dir = Path(run.project) if run.project else Path.cwd()
        auto_skills = discover_skill_files(search_dir)
        for sf in auto_skills:
            if sf not in skill_file_list:
                skill_file_list.append(sf)
    return skill_file_list


def _attach_skill_servers(run: DiscoveryRun, skill_result: Any, skill_file_list: list[Path]) -> None:
    skill_provenance = _skill_provenance()
    for server in skill_result.servers:
        for pkg in getattr(server, "packages", []) or []:
            if getattr(pkg, "discovery_provenance", None) is None:
                pkg.discovery_provenance = skill_provenance
    skill_agent = Agent(
        name="skill-files",
        agent_type=AgentType.CUSTOM,
        config_path=str(skill_file_list[0]),
        mcp_servers=skill_result.servers,
        source="skill-files",
        discovery_provenance=skill_provenance,
    )
    run.ctx.agents.append(skill_agent)
    run.con.print(f"  [green]✓[/green] Found {len(skill_result.servers)} MCP server(s) in skill files")


def _attach_skill_packages(run: DiscoveryRun, skill_result: Any, skill_file_list: list[Path]) -> None:
    skill_provenance = _skill_provenance()
    for pkg in skill_result.packages:
        if getattr(pkg, "discovery_provenance", None) is None:
            pkg.discovery_provenance = skill_provenance
    skill_server = _SkillSrv(name="skill-packages", command="(from skill files)", packages=skill_result.packages)
    skill_pkg_agent = Agent(
        name="skill-packages",
        agent_type=AgentType.CUSTOM,
        config_path=", ".join(str(p) for p in skill_file_list[:3]),
        mcp_servers=[skill_server],
        source="skill-files",
        discovery_provenance=skill_provenance,
    )
    run.ctx.agents.append(skill_pkg_agent)
    run.con.print(f"  [green]✓[/green] Found {len(skill_result.packages)} package(s) referenced in skill files")


def _skill_audit_data(skill_audit: Any) -> dict[str, Any]:
    return {
        "findings": [
            {
                "severity": f.severity,
                "category": f.category,
                "title": f.title,
                "detail": f.detail,
                "source_file": f.source_file,
                "package": f.package,
                "server": f.server,
                "recommendation": f.recommendation,
                "context": f.context,
                "ai_detected": f.ai_detected,
            }
            for f in skill_audit.findings
        ],
        "packages_checked": skill_audit.packages_checked,
        "servers_checked": skill_audit.servers_checked,
        "credentials_checked": skill_audit.credentials_checked,
        "passed": skill_audit.passed,
    }


def _audit_row(finding: Any) -> tuple[str, str, str, str]:
    style = _SEV_COLORS.get(finding.severity, "white")
    icon = _SEV_ICONS.get(finding.severity, "⚪")
    sev_cell = f"{icon} [{style}]{finding.severity.upper()}[/{style}]"
    cat_cell = f"[cyan]{finding.category}[/cyan]"
    detail_parts = [f"[bold]{finding.title}[/bold]"]
    detail_parts.append(f"[dim]{finding.detail}[/dim]")
    if finding.recommendation:
        detail_parts.append(f"[green]→ {finding.recommendation}[/green]")
    detail_cell = "\n".join(detail_parts)
    source_parts = []
    if finding.source_file:
        source_parts.append(Path(finding.source_file).name)
    if finding.package:
        source_parts.append(f"pkg:{finding.package}")
    if finding.server:
        source_parts.append(f"srv:{finding.server}")
    source_cell = "\n".join(source_parts) if source_parts else "—"
    return sev_cell, cat_cell, detail_cell, source_cell


def _print_skill_audit(run: DiscoveryRun, skill_audit: Any) -> None:
    audit_table = RichTable(
        title=f"Skill Security Audit — {len(skill_audit.findings)} finding(s)",
        expand=True,
        padding=(0, 1),
        title_style="bold yellow",
    )
    audit_table.add_column("Sev", justify="center", no_wrap=True, width=10)
    audit_table.add_column("Category", no_wrap=True, width=20)
    audit_table.add_column("Finding", ratio=3)
    audit_table.add_column("Source", ratio=2, style="dim")
    for finding in skill_audit.findings:
        audit_table.add_row(*_audit_row(finding))
    stats_line = (
        f"[dim]Checked: {skill_audit.packages_checked} pkg(s) · "
        f"{skill_audit.servers_checked} server(s) · "
        f"{skill_audit.credentials_checked} credential(s) · "
        f"{'[green]PASS[/green]' if skill_audit.passed else '[red]FAIL[/red]'}[/dim]"
    )
    run.con.print()
    run.con.print(Panel(audit_table, subtitle=stats_line, border_style="yellow"))


def _audit_skills(run: DiscoveryRun, skill_result: Any) -> None:
    """Step 1g3: skill security audit."""
    from agent_bom.parsers.skill_audit import audit_skill_result

    skill_audit = audit_skill_result(skill_result)
    run.skill_result = skill_result
    run.skill_audit = skill_audit
    run.ctx.skill_audit_data = _skill_audit_data(skill_audit)
    if skill_audit.findings:
        _print_skill_audit(run, skill_audit)


def _report_skill_result(run: DiscoveryRun, skill_result: Any, skill_file_list: list[Path]) -> None:
    con = run.con
    con.print(f"\n[bold blue]Scanning {len(skill_file_list)} skill file(s)...[/bold blue]\n")
    if run.verbose:
        for sf in skill_file_list:
            con.print(f"  [dim]•[/dim] {sf.name}  [dim]{sf.parent}[/dim]")
    if skill_result.servers:
        _attach_skill_servers(run, skill_result, skill_file_list)
    if skill_result.packages:
        _attach_skill_packages(run, skill_result, skill_file_list)
    if skill_result.credential_env_vars:
        con.print(f"  [yellow]⚠[/yellow] {len(skill_result.credential_env_vars)} credential env var(s) referenced in skill files")
    _audit_skills(run, skill_result)


def scan_skills(run: DiscoveryRun) -> None:
    """Step 1g2: skill file scanning (--skill + auto-discovery)."""
    if run.no_skill:
        return
    from agent_bom.parsers.skills import discover_skill_files, scan_skill_files

    skill_file_list = _collect_skill_files(run, discover_skill_files)
    if not skill_file_list:
        return
    skill_result = scan_skill_files(skill_file_list)
    # A successfully read instruction file is itself an auditable
    # security surface. Behavioral risks live in ``raw_content`` and
    # must not be gated on whether inventory extraction happened to
    # find a package, server, or credential reference.
    if skill_result.source_files:
        _report_skill_result(run, skill_result, skill_file_list)


def _print_trust_panel(run: DiscoveryRun, trust_result: Any, vstyle: str, levels: Any) -> None:
    level_icons = {
        levels.PASS: "[green]✓[/green]",
        levels.INFO: "[blue]ℹ[/blue]",
        levels.WARN: "[yellow]⚠[/yellow]",
        levels.FAIL: "[red]✗[/red]",
    }
    trust_table = RichTable(expand=True, padding=(0, 1), show_header=True)
    trust_table.add_column("", justify="center", no_wrap=True, width=3)
    trust_table.add_column("Category", no_wrap=True, width=24)
    trust_table.add_column("Summary", ratio=3)
    for cat in trust_result.categories:
        icon = level_icons.get(cat.level, "?")
        trust_table.add_row(icon, f"[bold]{cat.name}[/bold]", cat.summary)
    verdict_line = f"[{vstyle}]{trust_result.verdict.value.upper()}[/{vstyle}] ({trust_result.confidence.value} confidence)"
    run.con.print()
    run.con.print(
        Panel(
            trust_table,
            title=f"[bold]Trust Assessment — {Path(trust_result.source_file).name}[/bold]",
            subtitle=verdict_line,
            border_style=vstyle,
        )
    )
    if trust_result.recommendations:
        for rec in trust_result.recommendations:
            run.con.print(f"  [dim]→ {rec}[/dim]")


def _print_trust_line(run: DiscoveryRun, trust_result: Any, vstyle: str, levels: Any) -> None:
    fail_count = sum(1 for c in trust_result.categories if c.level == levels.FAIL)
    warn_count = sum(1 for c in trust_result.categories if c.level == levels.WARN)
    fname = Path(trust_result.source_file).name
    verdict_text = f"[{vstyle}]{trust_result.verdict.value.upper()}[/{vstyle}]"
    issues = []
    if fail_count:
        issues.append(f"[red]{fail_count} fail[/red]")
    if warn_count:
        issues.append(f"[yellow]{warn_count} warn[/yellow]")
    issues_str = f" ({', '.join(issues)})" if issues else ""
    run.con.print(f"  Trust: {fname} → {verdict_text}{issues_str}")


def assess_skill_trust(run: DiscoveryRun) -> None:
    """Step 1g4: trust assessment over the audited skill files."""
    if not (run.skill_result and run.skill_audit):
        return
    from agent_bom.parsers.trust_assessment import TrustLevel, Verdict, assess_trust

    trust_result = assess_trust(run.skill_result, run.skill_audit)
    run.ctx.trust_assessment_data = trust_result.to_dict()
    verdict_styles = {
        Verdict.BENIGN: "green",
        Verdict.SUSPICIOUS: "yellow",
        Verdict.MALICIOUS: "red bold",
    }
    vstyle = verdict_styles.get(trust_result.verdict, "white")
    if run.verbose:
        _print_trust_panel(run, trust_result, vstyle, TrustLevel)
    else:
        _print_trust_line(run, trust_result, vstyle, TrustLevel)


def publish_skill_objects(run: DiscoveryRun) -> None:
    """Preserve skill objects on the scan context for AI enrichment later."""
    run.ctx._skill_result_obj = run.skill_result
    run.ctx._skill_audit_obj = run.skill_audit
