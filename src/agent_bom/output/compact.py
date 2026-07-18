"""Compact terminal output — the default mode for CLI commands.

Split out of ``agent_bom.output.__init__`` as part of the monolith-split
work tracked in issue #1522. Zero behavior change: every function is
re-exported from ``agent_bom.output`` for backward compatibility and
existing call sites work unchanged.

The compact family keeps the default output to roughly one screen.
Verbose renderers live next to their concerns in
``agent_bom.output.__init__`` (scan summary, full blast-radius tree,
remediation plan, etc.).
"""

from __future__ import annotations

from pathlib import Path

from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from agent_bom.models import AgentStatus, AIBOMReport, Severity
from agent_bom.output.brand_tokens import lane_title

# The cross-cutting helpers (`console`, `_sev_badge`, `build_remediation_plan`)
# live in the package's __init__. Import lazily inside functions to avoid a
# circular import with the package-level re-exports at the bottom of __init__.


# ─── Helpers (local to the compact family) ──────────────────────────────────


def _coverage_bar(hit: int, total: int, color: str, width: int = 20) -> str:
    """Build a colored coverage bar like [████████░░░░░░░░░░░░]."""
    filled = int(width * hit / total) if total else 0
    empty = width - filled
    return f"[{color}]{'█' * filled}[/{color}][dim]{'░' * empty}[/dim]"


def _pct(part: int, total: int) -> str:
    """Format a percentage string."""
    return f"{round(part / total * 100)}%" if total > 0 else "—"


def _posture_grade_badge(grade: str) -> str:
    """Render a compact color badge for posture grade output."""
    grade = (grade or "?").upper()
    if grade == "A":
        style = "white on green"
    elif grade == "B":
        style = "black on bright_green"
    elif grade == "C":
        style = "black on yellow"
    elif grade == "D":
        style = "white on dark_orange3"
    else:
        style = "white on red"
    return f"[bold {style}] {grade} [/bold {style}]"


def _compact_detail(text: str, limit: int = 88) -> str:
    """Trim long explanatory detail so the default output stays one-screen friendly."""
    clean = " ".join(text.split())
    if len(clean) <= limit:
        return clean
    return clean[: limit - 1].rstrip() + "…"


def _page_window(total: int, limit: int, page: int) -> tuple[int, int, int]:
    """Return a bounded page window as (page, start, end)."""
    safe_limit = max(1, limit)
    total_pages = max(1, (total + safe_limit - 1) // safe_limit)
    safe_page = min(max(1, page), total_pages)
    start = (safe_page - 1) * safe_limit
    end = min(start + safe_limit, total)
    return safe_page, start, end


def _forward_fix_version(finding) -> str | None:
    """Return a fix version only when it is a forward upgrade for this package."""
    from agent_bom.finding import Finding
    from agent_bom.output.finding_views import package_ecosystem, package_version

    if isinstance(finding, Finding):
        fixed = finding.fixed_version
        if not fixed:
            return None
        current = package_version(finding)
        ecosystem = package_ecosystem(finding)
    else:
        fixed = getattr(getattr(finding, "vulnerability", None), "fixed_version", None)
        if not fixed:
            return None
        package = getattr(finding, "package", None)
        current = str(getattr(package, "version", "") or "")
        ecosystem = str(getattr(package, "ecosystem", "") or "")
    if current in ("", "unknown", "latest"):
        return str(fixed)
    try:
        from agent_bom.version_utils import compare_version_order

        order = compare_version_order(current, str(fixed), ecosystem)
    except Exception:  # noqa: BLE001
        order = None
    if order is not None and order >= 0:
        return None
    return str(fixed)


def _agent_display_name(agent) -> str:
    """Return a human-readable agent label for compact tables."""
    name = str(getattr(agent, "name", "") or "").strip()
    if not name.startswith("project:"):
        return name or "unknown-agent"

    config_path = str(getattr(agent, "config_path", "") or "").strip()
    project_name = name.removeprefix("project:").strip(":") or "project"
    if config_path:
        path = Path(config_path)
        if path.name and path.name != project_name:
            return f"{path.name} ({project_name})"
    return f"{project_name} (project)"


def _iter_cis_bundles(report: AIBOMReport):
    """Yield (cloud, bundle_dict) for every populated CIS benchmark bundle."""
    bundles = [
        ("aws", getattr(report, "cis_benchmark_data", None)),
        ("azure", getattr(report, "azure_cis_benchmark_data", None)),
        ("gcp", getattr(report, "gcp_cis_benchmark_data", None)),
        ("snowflake", getattr(report, "snowflake_cis_benchmark_data", None)),
    ]
    for cloud, bundle in bundles:
        if bundle and bundle.get("checks"):
            yield cloud, bundle


# ─── Compact Output (default mode) ───────────────────────────────────────────


def print_compact_summary(report: AIBOMReport, *, verbose: bool = False) -> None:
    """Compact summary — verdict-led posture in 2-4 lines.

    Default (``verbose=False``) leads with a severity-coloured one-liner
    verdict, follows with an inventory count line, and only mentions the
    posture grade / drivers / credentials when richer context exists,
    pointing the operator at ``--verbose`` for that detail.

    ``verbose=True`` re-renders the previous detailed panel form
    (posture grade, weak driver dimensions, credential list, privilege
    counts, AI inventory).
    """
    from collections import Counter

    from agent_bom.finding import FindingType
    from agent_bom.output import _sev_badge, console
    from agent_bom.output.finding_views import active_cve_findings, finding_severity
    from agent_bom.posture import compute_posture_scorecard

    sev_counts: Counter[str] = Counter()
    active_findings = active_cve_findings(report)
    for finding in active_findings:
        sev_counts[finding_severity(finding).value.upper()] += 1
    policy_findings = [finding for finding in report.to_findings() if finding.finding_type != FindingType.CVE]
    for finding in policy_findings:
        sev_counts[str(finding.severity).upper()] += 1

    scorecard = compute_posture_scorecard(report)
    coverage = report.scan_performance_data or {}
    coverage_incomplete = coverage.get("coverage_state") == "incomplete"
    high_risk_policy_count = sev_counts.get("CRITICAL", 0) + sev_counts.get("HIGH", 0)
    scorecard_summary = scorecard.summary
    if coverage_incomplete:
        scorecard_summary = "scan coverage incomplete"
    if high_risk_policy_count and not active_findings:
        scorecard_summary = f"{high_risk_policy_count} high-risk policy/security finding(s) present"
    preferred_driver_order = [
        "credential_hygiene",
        "vulnerability_posture",
        "active_exploitation",
        "configuration_quality",
        "supply_chain_quality",
        "compliance_coverage",
    ]
    weak_dimensions = [
        scorecard.dimensions[name]
        for name in preferred_driver_order
        if name in scorecard.dimensions and scorecard.dimensions[name].score < 90
    ][:2]
    if len(weak_dimensions) < 2:
        seen_names = {dim.name for dim in weak_dimensions}
        for dim in sorted(scorecard.dimensions.values(), key=lambda d: d.score):
            if dim.score >= 80 or dim.name in seen_names:
                continue
            weak_dimensions.append(dim)
            seen_names.add(dim.name)
            if len(weak_dimensions) >= 2:
                break

    if coverage_incomplete:
        posture = "[bold black on yellow] PARTIAL COVERAGE [/bold black on yellow]"
        border_style = "yellow"
    elif report.total_vulnerabilities == 0 and not active_findings and not policy_findings:
        posture = "[bold white on green] CLEAN [/bold white on green]"
        border_style = "green"
    else:
        badge_parts = []
        sev_map = [
            ("CRITICAL", Severity.CRITICAL),
            ("HIGH", Severity.HIGH),
            ("MEDIUM", Severity.MEDIUM),
            ("LOW", Severity.LOW),
        ]
        for sev_name, sev_enum in sev_map:
            if sev_counts.get(sev_name):
                badge_parts.append(f"{_sev_badge(sev_enum)} {sev_counts[sev_name]}")
        # UNKNOWN findings are still real advisories; they just lack finalized
        # severity scoring data and should not read like parser breakage.
        unknown_count = sev_counts.get("UNKNOWN", 0) + sev_counts.get("NONE", 0)
        if unknown_count:
            badge_parts.append(f"[dim]{unknown_count} advisory[/dim]")
        posture = "  ".join(badge_parts) if badge_parts else "[dim]advisory findings pending severity[/dim]"
        border_style = "red" if sev_counts.get("CRITICAL", 0) > 0 else "yellow"

    # Credential count
    cred_names: list[str] = []
    for a in report.agents:
        for s in a.mcp_servers:
            cred_names.extend(s.credential_names)
    cred_names = sorted(set(cred_names))

    # Privilege count
    elevated = sum(1 for a in report.agents for s in a.mcp_servers if s.permission_profile and s.permission_profile.is_elevated)

    # Direct vs transitive package counts
    all_pkgs = [p for a in report.agents for s in a.mcp_servers for p in s.packages]
    n_direct = sum(1 for p in all_pkgs if p.is_direct)
    n_transitive = len(all_pkgs) - n_direct
    pkg_detail = f" ({n_direct}D/{n_transitive}T)" if n_transitive else ""

    has_ai_inventory = bool(getattr(report, "ai_inventory_data", None) and (report.ai_inventory_data or {}).get("total_components", 0) > 0)
    has_more_context = bool(weak_dimensions or cred_names or elevated or has_ai_inventory or coverage_incomplete or scorecard.score < 90)

    inventory_line = (
        f"  [bold]{report.total_agents}[/bold] agents [dim]·[/dim] "
        f"[bold]{report.total_servers}[/bold] servers [dim]·[/dim] "
        f"[bold]{report.total_packages}[/bold][dim]{pkg_detail}[/dim] packages"
    )

    if not verbose:
        # Default verdict-led form: verdict + inventory + a compact posture
        # card + optional --verbose hint. The posture grade is now surfaced
        # inline so a normal scan reads a posture verdict in one screen.
        lines = [
            f"  [bold]Security posture:[/bold]  {posture}",
            inventory_line,
        ]
        if scorecard.score < 100 or high_risk_policy_count:
            grade_line = f"  [bold]Posture grade:[/bold]  {_posture_grade_badge(scorecard.grade)} {scorecard.score:.0f}/100"
            if scorecard_summary:
                grade_line += f"  [dim]{_compact_detail(scorecard_summary, limit=48)}[/dim]"
            lines.append(grade_line)
            if weak_dimensions:
                lines.append(f"  [dim]Top driver:[/dim] [yellow]{weak_dimensions[0].name}[/yellow]")
        if has_more_context:
            # The grade is shown above, so the hint covers the remaining detail.
            hint_bits: list[str] = []
            if weak_dimensions:
                hint_bits.append(f"{len(weak_dimensions)} weak driver(s)")
            if cred_names:
                hint_bits.append(f"{len(cred_names)} credential(s)")
            if elevated:
                hint_bits.append(f"{elevated} elevated server(s)")
            hint_text = " · ".join(hint_bits) if hint_bits else "drivers and credentials"
            lines.append("")
            lines.append(f"  [dim]→ Run with[/dim] [bold]--verbose[/bold] [dim]for[/dim] {hint_text}")

        console.print(
            Panel(
                "\n".join(lines),
                title=lane_title("scan", f"agent-bom v{report.tool_version}"),
                border_style=border_style,
                padding=(0, 1),
            )
        )
        return

    # Verbose form: full posture detail (the previous default rendering).
    lines = [
        f"  [bold]CONFIG POSTURE GRADE:[/bold]  {_posture_grade_badge(scorecard.grade)} "
        f"[bold]{scorecard.score:.1f}/100[/bold]  [dim]{scorecard_summary}[/dim]",
        f"  [bold]SECURITY POSTURE:[/bold]  {posture}",
        "",
        f"  Agents  [bold]{report.total_agents}[/bold]    "
        f"Servers  [bold]{report.total_servers}[/bold]    "
        f"Packages  [bold]{report.total_packages}[/bold][dim]{pkg_detail}[/dim]    "
        f"Vulns  [bold]{report.total_vulnerabilities}[/bold]    "
        f"Findings  [bold]{len(policy_findings)}[/bold]",
    ]
    if weak_dimensions:
        driver_parts = [f"[yellow]{dim.name}[/yellow]: {_compact_detail(dim.details, limit=54)}" for dim in weak_dimensions]
        lines.append(f"  [bold]Top Drivers:[/bold]  {' [dim]·[/dim] '.join(driver_parts)}")
    if cred_names:
        names = ", ".join(cred_names[:3])
        more = f" +{len(cred_names) - 3}" if len(cred_names) > 3 else ""
        lines.append(f"  [yellow]Credentials:[/yellow]  {names}{more}")
    if elevated:
        lines.append(f"  [red]Privileges:[/red]  {elevated} server(s) elevated")

    # AI inventory stats (if scan was run)
    ai_inv = getattr(report, "ai_inventory_data", None)
    if ai_inv and ai_inv.get("total_components", 0) > 0:
        ai_parts = [f"[bold]{ai_inv['total_components']}[/bold] components"]
        shadow = ai_inv.get("shadow_ai_count", 0)
        depr = ai_inv.get("deprecated_models_count", 0)
        keys = ai_inv.get("api_keys_count", 0)
        if keys:
            ai_parts.append(f"[red]{keys} hardcoded key(s)[/red]")
        if shadow:
            ai_parts.append(f"[yellow]{shadow} shadow AI[/yellow]")
        if depr:
            ai_parts.append(f"{depr} deprecated")
        sdks = ai_inv.get("unique_sdks", [])
        if sdks:
            sdk_str = ", ".join(sdks[:4]) + (f" +{len(sdks) - 4}" if len(sdks) > 4 else "")
            ai_parts.append(f"SDKs: [cyan]{sdk_str}[/cyan]")
        ai_str = " \u00b7 ".join(ai_parts)
        lines.append(f"  [bold]AI Inventory:[/bold]  {ai_str}")

    console.print(
        Panel(
            "\n".join(lines),
            title=lane_title("scan", f"agent-bom v{report.tool_version}"),
            border_style=border_style,
            padding=(0, 1),
        )
    )


def print_compact_agents(report: AIBOMReport) -> None:
    """One-line-per-agent table."""
    from agent_bom.output import console

    configured = [a for a in report.agents if a.status == AgentStatus.CONFIGURED]
    if not configured:
        return

    console.print()
    console.print(Rule(lane_title("discover", "Agents"), style="dim"))
    table = Table(box=None, padding=(0, 2), show_header=True, header_style="bold dim")
    table.add_column("Agent")
    table.add_column("Type", style="dim")
    table.add_column("Servers", justify="right")
    table.add_column("Pkgs", justify="right")
    table.add_column("Creds", justify="right")
    table.add_column("Vulns", justify="right")

    for a in configured:
        n_servers = len(a.mcp_servers)
        n_pkgs = sum(len(s.packages) for s in a.mcp_servers)
        n_creds = sum(len(s.credential_names) for s in a.mcp_servers)
        n_vulns = sum(s.total_vulnerabilities for s in a.mcp_servers)
        vuln_style = "red" if n_vulns > 0 else "dim"
        cred_style = "yellow" if n_creds > 0 else "dim"
        table.add_row(
            f"[bold]{_agent_display_name(a)}[/bold]",
            a.agent_type.value if hasattr(a.agent_type, "value") else str(a.agent_type),
            str(n_servers),
            str(n_pkgs),
            f"[{cred_style}]{n_creds}[/{cred_style}]",
            f"[{vuln_style}]{n_vulns}[/{vuln_style}]",
        )

    console.print(table)


def print_compact_blast_radius(report: AIBOMReport, limit: int = 10, fixable_only: bool = False, page: int = 1) -> None:
    """Show top N findings in a compact table.

    Context-aware: shows blast radius chain (agent → server → credential) only
    when MCP agent context is available. Falls back to a clean vuln table for
    scan types without agent context (image, check, iac, CI/CD).
    """
    from agent_bom.output import _sev_badge, console
    from agent_bom.output.finding_views import (
        active_cve_findings,
        cve_findings,
        exploit_likelihood_value,
        finding_severity,
        is_actionable_finding,
        is_package_direct,
        package_name,
        package_version,
    )

    active_findings = active_cve_findings(report)
    if not active_findings:
        return

    priority = [finding for finding in active_findings if is_actionable_finding(finding)]
    rest_count = len(active_findings) - len(priority)
    if fixable_only:
        priority = [finding for finding in priority if _forward_fix_version(finding)]
    if not priority:
        display_list = [finding for finding in active_findings if _forward_fix_version(finding)] if fixable_only else active_findings
    else:
        display_list = priority
    total = len(display_list)
    page, start, end = _page_window(total, limit, page)
    shown = display_list[start:end]

    # Detect if we have blast radius context (agents/servers/credentials)
    has_blast_context = any(finding.affected_agents and (finding.affected_servers or finding.exposed_credentials) for finding in shown)

    console.print()
    shown_n = len(shown)
    total_active = len(active_findings)
    total_pages = max(1, (total + max(1, limit) - 1) // max(1, limit))
    if total > limit:
        # Priority list truncated by --limit; tell the operator how many
        # additional priority rows aren't shown.
        suffix = ""
        if total_active > total:
            suffix = f" · {total_active - total} more below priority"
        title = f"Top Findings (page {page}/{total_pages} · {start + 1}-{end} of {total}{suffix})"
    elif total_active > shown_n:
        # Display list fits in --limit but priority filtering hid some
        # lower-severity rows further down. Tell the operator both numbers
        # so '+ N hidden' below the table doesn't look contradictory.
        title = f"Findings ({shown_n} of {total_active} shown · {total_active - shown_n} hidden)"
    else:
        title = f"Findings ({shown_n})"
    console.print(Rule(lane_title("analyze", title), style="dim"))

    # Context-aware table layout
    table = Table(expand=True, padding=(0, 1))
    table.add_column("Sev", no_wrap=True)
    table.add_column("Vulnerability", no_wrap=True, ratio=2)
    table.add_column("Package", ratio=2)
    if has_blast_context:
        table.add_column("Blast Radius", ratio=3, no_wrap=True)
    table.add_column("EPSS", justify="center", no_wrap=True)
    table.add_column("Fix", ratio=1)

    for finding in shown:
        forward_fix = _forward_fix_version(finding)
        fix = f"[green]{forward_fix}[/green]" if forward_fix else "[dim]no fix[/dim]"
        _exploit_level = exploit_likelihood_value(finding)
        if finding.is_kev:
            kev = " [red bold]KEV[/red bold]"
        elif _exploit_level == "likely_exploited":
            kev = " [#e67e22 bold]EXPL[/#e67e22 bold]"
        elif _exploit_level == "public_exploit":
            kev = " [yellow]PoC[/yellow]"
        else:
            kev = ""

        epss_display = "[dim]—[/dim]"
        if finding.epss_score is not None:
            epss_pct = int(finding.epss_score * 100)
            epss_style = "red bold" if epss_pct >= 70 else "yellow" if epss_pct >= 30 else "dim"
            epss_display = f"[{epss_style}]{epss_pct}%[/{epss_style}]"

        pkg_display = f"{package_name(finding)}@{package_version(finding)}" + ("" if is_package_direct(finding) else " [dim]T[/dim]")
        vuln_id = finding.cve_id or finding.id

        if has_blast_context:
            agent_names = list(finding.affected_agents)
            cred_names = list(finding.exposed_credentials)
            server_names = list(finding.affected_servers)
            chain_parts: list[str] = []
            if agent_names:
                name = agent_names[0][:16]
                chain_parts.append(f"[bold]{name}[/bold]")
                if len(agent_names) > 1:
                    chain_parts[-1] += f"+{len(agent_names) - 1}"
            if server_names:
                name = server_names[0][:16]
                chain_parts.append(f"{name}")
            if cred_names:
                name = cred_names[0][:20]
                chain_parts.append(f"[yellow]{name}[/yellow]")
                if len(cred_names) > 1:
                    chain_parts[-1] += f"+{len(cred_names) - 1}"
            blast_display = " → ".join(chain_parts) if chain_parts else "[dim]—[/dim]"
            table.add_row(
                _sev_badge(finding_severity(finding)),
                f"{vuln_id}{kev}",
                pkg_display,
                blast_display,
                epss_display,
                fix,
            )
        else:
            table.add_row(
                _sev_badge(finding_severity(finding)),
                f"{vuln_id}{kev}",
                pkg_display,
                epss_display,
                fix,
            )

    console.print(table)

    overflow = total - end
    hidden_before = start
    if overflow > 0 or hidden_before > 0 or rest_count > 0:
        parts = []
        if hidden_before > 0:
            parts.append(f"{hidden_before} earlier hidden")
        if overflow > 0:
            parts.append(f"{overflow} more critical/high")
        if rest_count > 0:
            parts.append(f"{rest_count} medium/low hidden")
        nav_hints = []
        if page < total_pages:
            nav_hints.append(f"--page {page + 1} next")
        if page > 1:
            nav_hints.append(f"--page {page - 1} previous")
        nav_hints.append("--verbose full list")
        console.print(f"  [dim]+ {' · '.join(parts)} — {' · '.join(nav_hints)}[/dim]")

    # Critical details section — show description and blast chain for CRIT/HIGH only
    critical_findings = [finding for finding in shown if finding_severity(finding) in (Severity.CRITICAL, Severity.HIGH)]
    if critical_findings:
        console.print()
        console.print(Rule(lane_title("analyze", "Critical Details"), style="dim"))
        sev_style_map = {Severity.CRITICAL: "red bold", Severity.HIGH: "#e67e22 bold"}
        for finding in critical_findings[:5]:
            sev = finding_severity(finding)
            style = sev_style_map.get(sev, "white")
            summary = finding.description or ""
            if len(summary) > 80:
                summary = summary[:77] + "..."
            sev_label = sev.value.upper()
            pkg_ref = f"{package_name(finding)}@{package_version(finding)}"
            vuln_id = finding.cve_id or finding.id
            console.print(f"\n  [{style}]{vuln_id}[/{style}] · {pkg_ref} · [{style}]{sev_label}[/{style}]")
            if summary:
                console.print(f"  {summary}")
            forward_fix = _forward_fix_version(finding)
            if forward_fix:
                console.print(f"  Fix: [green]upgrade to ≥ {forward_fix}[/green]")
            if has_blast_context and (finding.affected_agents or finding.exposed_credentials):
                agent_str = ", ".join(finding.affected_agents[:3])
                cred_str = ", ".join(finding.exposed_credentials[:3])
                blast_parts = []
                if agent_str:
                    blast_parts.append(agent_str)
                if finding.affected_servers:
                    blast_parts.append(", ".join(finding.affected_servers[:2]))
                if cred_str:
                    blast_parts.append(f"[yellow]{cred_str}[/yellow]")
                if blast_parts:
                    console.print(f"  Blast: {' → '.join(blast_parts)}")

    console.print()
    all_cve = cve_findings(report)
    fixable = sum(1 for finding in all_cve if _forward_fix_version(finding))
    kev_count = sum(1 for finding in all_cve if finding.is_kev)
    unknown_sev = sum(1 for finding in all_cve if finding_severity(finding) == Severity.NONE)
    hints = ["[dim]--verbose[/dim] full details", "[dim]-f html[/dim] interactive report"]
    if page < total_pages:
        hints.insert(0, f"[dim]--page {page + 1}[/dim] next findings")
    if fixable:
        hints.insert(0, f"[green]{fixable} fixable[/green]")
    if kev_count:
        hints.insert(0, f"[red]{kev_count} KEV[/red]")
    if unknown_sev > 0 and unknown_sev == len(all_cve):
        hints.insert(0, "[yellow]--enrich[/yellow] for severity scores")
    console.print(Rule(style="dim"))
    console.print(f"  {' · '.join(hints)}")


def print_compact_remediation(report: AIBOMReport, limit: int = 5, page: int = 1) -> None:
    """Top N remediation items, one-liner each."""
    from agent_bom.output import build_remediation_plan, console
    from agent_bom.output.finding_views import cve_findings

    cve_rows = cve_findings(report)
    if not cve_rows:
        return

    plan = build_remediation_plan(cve_rows)
    fixable = [p for p in plan if p["fix"]]
    if not fixable:
        return

    console.print()
    total = len(fixable)
    page, start, end = _page_window(total, limit, page)
    total_pages = max(1, (total + max(1, limit) - 1) // max(1, limit))
    if total > limit:
        title = f"Fix First (page {page}/{total_pages} · {start + 1}-{end} of {total})"
    else:
        title = f"Fix First ({total})"
    console.print(Rule(lane_title("protect", title), style="dim"))
    console.print("  [dim]Each item shows the impact radius, the primary action, and a verification command.[/dim]")
    console.print()

    sev_style = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "#e67e22 bold",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "dim",
        Severity.NONE: "white",
    }

    shown = fixable[start:end]
    for row_number, item in enumerate(shown, start + 1):
        style = sev_style.get(item["max_severity"], "white")
        kev = " [red]KEV[/red]" if item["has_kev"] else ""
        reach_parts = [f"{len(item['vulns'])} vuln(s)", f"{len(item['agents'])} agent(s)"]
        if item["creds"]:
            reach_parts.append(f"{len(item['creds'])} credential(s)")
        if item["tools"]:
            reach_parts.append(f"{len(item['tools'])} tool(s)")
        reach = ", ".join(reach_parts)
        console.print(
            f"  [{style}]{row_number}.[/{style}] "
            f"[bold]{item['package']}[/bold] [dim]{item['current']}[/dim] → [green]{item['fix']}[/green]{kev}"
        )
        console.print(f"     [bold]Priority:[/bold] {item['priority']} [dim]· clears {reach}[/dim]")
        console.print(f"     [bold]Action:[/bold] [dim]{_compact_detail(item['action'], limit=96)}[/dim]")
        if item.get("command"):
            console.print(f"     [bold cyan]Install:[/bold cyan] [cyan]$ {item['command']}[/cyan]")
        if item.get("verify_command"):
            console.print(
                f"     [bold dim cyan]Verify:[/bold dim cyan] [dim cyan]$ {item['verify_command']}[/dim cyan] [dim](verify)[/dim]"
            )
        if row_number < end:
            console.print()

    if total > limit:
        console.print()
        nav_hints = []
        if page < total_pages:
            nav_hints.append(f"--page {page + 1} next")
        if page > 1:
            nav_hints.append(f"--page {page - 1} previous")
        nav_hints.append("--verbose full plan")
        console.print(f"  [dim]... {total - end} more · {' · '.join(nav_hints)}[/dim]")
    console.print()


def print_compact_cis_posture(report: AIBOMReport, limit: int = 5) -> None:
    """Per-cloud CIS posture with top failing checks + remediation.

    Renders once per cloud that has a populated benchmark. For each
    cloud:
      - Header line with pass rate and failed-count (colored by
        pass-rate band).
      - Top ``limit`` failed checks, sorted by remediation priority
        (1 = fix first), each showing: check_id, title, guardrails
        tags, effort, ``fix_cli`` (when present) or the ``fix_console``
        path (when ``fix_cli`` is ``None``), and a ``review`` flag when
        ``requires_human_review`` is true.

    Respects the same compact/one-screen style as
    ``print_compact_blast_radius`` and ``print_compact_remediation``.
    """
    from agent_bom.output import console

    bundles = list(_iter_cis_bundles(report))
    if not bundles:
        return

    console.print()
    console.print(f"  {lane_title('govern', 'Cloud Security Posture')}")

    for cloud, bundle in bundles:
        checks = bundle.get("checks") or []
        failed = [c for c in checks if c.get("status") == "fail"]
        errored = [c for c in checks if c.get("status") == "error"]
        actionable = failed + errored
        total_eval = sum(1 for c in checks if c.get("status") in ("pass", "fail"))
        pass_rate = bundle.get("pass_rate", 0.0)

        band = "green" if pass_rate >= 90 else "yellow" if pass_rate >= 70 else "red"
        cloud_label = {"aws": "AWS", "azure": "Azure", "gcp": "GCP", "snowflake": "Snowflake"}.get(cloud, cloud)
        console.print(
            f"  [bold]{cloud_label}[/bold]  "
            f"[{band}]{pass_rate:.0f}%[/{band}] pass  "
            f"[dim]({bundle.get('passed', 0)}/{total_eval} checks, "
            f"{len(failed)} failed, {len(errored)} unevaluable)[/dim]"
        )

        if errored and not failed:
            console.print("    [red bold]ERROR[/red bold] [dim]benchmark evidence is incomplete[/dim]")
        if not actionable:
            console.print("    [green]✓[/green] [dim]no failed checks[/dim]")
            continue

        # Sort by remediation priority (1 = fix first), then severity.
        def _sort_key(c: dict) -> tuple[int, int]:
            from agent_bom.graph.severity import severity_worst_first_rank

            rem = c.get("remediation") or {}
            priority = rem.get("priority", 3)
            sev = c.get("severity") or ""
            return (priority, severity_worst_first_rank(sev))

        failed_sorted = sorted(actionable, key=_sort_key)
        shown = failed_sorted[:limit]
        sev_style = {"critical": "red bold", "high": "#e67e22 bold", "medium": "yellow", "low": "dim"}

        for i, check in enumerate(shown, 1):
            sev = (check.get("severity") or "").lower()
            style = sev_style.get(sev, "white")
            rem = check.get("remediation") or {}
            guardrails = rem.get("guardrails") or []
            guard_str = " · ".join(guardrails[:3])
            if len(guardrails) > 3:
                guard_str += f" · +{len(guardrails) - 3}"
            review_flag = " [yellow]↺ review[/yellow]" if rem.get("requires_human_review") else ""

            title = (check.get("title") or "").rstrip(".")
            console.print(
                f"    [{style}]{i}.[/{style}] [bold]{check.get('check_id', '')}[/bold] "
                f"{_compact_detail(title, limit=70)}{review_flag}  "
                f"[dim]P{rem.get('priority', 3)} · {rem.get('effort', 'manual')}[/dim]"
            )
            if guard_str:
                console.print(f"       [dim]{guard_str}[/dim]")
            if check.get("status") == "error" and check.get("evidence"):
                console.print(f"       [red]unevaluable:[/red] {_compact_detail(str(check['evidence']), limit=110)}")
            if rem.get("fix_cli"):
                console.print(f"       [cyan]{_compact_detail(rem['fix_cli'], limit=110)}[/cyan]")
            elif rem.get("fix_console"):
                console.print(f"       [dim]→ {_compact_detail(rem['fix_console'], limit=110)}[/dim]")

        if len(actionable) > limit:
            console.print(f"    [dim]... {len(actionable) - limit} more (use --verbose for full plan)[/dim]")

    console.print()


def print_compact_export_hint(report: AIBOMReport) -> None:
    """Single-line summary with key metrics."""
    from agent_bom.output import console

    vuln_color = "red" if report.total_vulnerabilities > 0 else "green"
    # Label this per-package CVE-instance total with an explicit scope so it
    # never reads as the same number as the scan-lane finding count or the
    # severity breakdown (they legitimately differ — see honest-counts).
    console.print(
        f"\n  [bold]{report.total_agents} agents[/bold] · "
        f"[bold]{report.total_servers} servers[/bold] · "
        f"[bold]{report.total_packages} packages[/bold] · "
        f"[bold {vuln_color}]{report.total_vulnerabilities} package CVEs[/bold {vuln_color}]"
    )


__all__ = [
    "print_compact_summary",
    "print_compact_agents",
    "print_compact_blast_radius",
    "print_compact_remediation",
    "print_compact_cis_posture",
    "print_compact_export_hint",
    # Helpers kept public for callers that already import them.
    "_coverage_bar",
    "_pct",
    "_posture_grade_badge",
    "_compact_detail",
    "_iter_cis_bundles",
]
