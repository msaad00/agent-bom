"""Discovery stages that scan for findings: prompt templates, browser extensions, IaC."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rich.panel import Panel
from rich.table import Table as RichTable

from agent_bom.cli.agents._discovery_state import DiscoveryRun

_SEV_COLORS = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim"}
_SEV_ICONS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}
_IAC_SEV_ICONS = {"critical": "\U0001f534", "high": "\U0001f7e0", "medium": "\U0001f7e1", "low": "⚪"}
_IAC_DISPLAY_LIMIT = 20


def _prompt_scan_data(prompt_result: Any) -> dict[str, Any]:
    return {
        "files_scanned": prompt_result.files_scanned,
        "prompt_files": prompt_result.prompt_files,
        "findings": [
            {
                "severity": f.severity,
                "category": f.category,
                "title": f.title,
                "detail": f.detail,
                "source_file": f.source_file,
                "line_number": f.line_number,
                "matched_text": f.matched_text,
                "recommendation": f.recommendation,
            }
            for f in prompt_result.findings
        ],
        "passed": prompt_result.passed,
    }


def _prompt_row(prompt_finding: Any) -> tuple[str, str, str, str]:
    style = _SEV_COLORS.get(prompt_finding.severity, "white")
    icon = _SEV_ICONS.get(prompt_finding.severity, "⚪")
    sev_cell = f"{icon} [{style}]{prompt_finding.severity.upper()}[/{style}]"
    cat_cell = f"[cyan]{prompt_finding.category}[/cyan]"
    detail_parts = [f"[bold]{prompt_finding.title}[/bold]"]
    detail_parts.append(f"[dim]{prompt_finding.detail}[/dim]")
    if prompt_finding.recommendation:
        detail_parts.append(f"[green]→ {prompt_finding.recommendation}[/green]")
    detail_cell = "\n".join(detail_parts)
    file_info = Path(prompt_finding.source_file).name
    if prompt_finding.line_number:
        file_info += f":{prompt_finding.line_number}"
    return sev_cell, cat_cell, detail_cell, file_info


def _print_prompt_findings(run: DiscoveryRun, prompt_result: Any) -> None:
    prompt_table = RichTable(
        title=f"Prompt Template Security Scan — {len(prompt_result.findings)} finding(s)",
        expand=True,
        padding=(0, 1),
        title_style="bold magenta",
    )
    prompt_table.add_column("Sev", justify="center", no_wrap=True, width=10)
    prompt_table.add_column("Category", no_wrap=True, width=20)
    prompt_table.add_column("Finding", ratio=3)
    prompt_table.add_column("File", ratio=2, style="dim")
    for prompt_finding in prompt_result.findings:
        prompt_table.add_row(*_prompt_row(prompt_finding))
    stats_line = (
        f"[dim]{prompt_result.files_scanned} file(s) scanned · {'[green]PASS[/green]' if prompt_result.passed else '[red]FAIL[/red]'}[/dim]"
    )
    run.con.print()
    run.con.print(Panel(prompt_table, subtitle=stats_line, border_style="magenta"))


def scan_prompt_templates(run: DiscoveryRun) -> None:
    """Step 1g3b: prompt template scanning (--scan-prompts)."""
    if not run.scan_prompts:
        return
    from agent_bom.parsers.prompt_scanner import scan_prompt_files

    con = run.con
    search_dir = Path(run.project) if run.project else Path.cwd()
    prompt_result = scan_prompt_files(root=search_dir)
    run.ctx.prompt_scan_data = _prompt_scan_data(prompt_result)
    if prompt_result.files_scanned <= 0:
        con.print(f"\n[dim]Prompt template scan: no supported prompt files found in {search_dir}[/dim]")
        return
    con.print(f"\n[bold blue]Scanned {prompt_result.files_scanned} prompt template file(s)...[/bold blue]\n")
    for pf in prompt_result.prompt_files:
        con.print(f"  [dim]•[/dim] {Path(pf).name}")
    if prompt_result.findings:
        _print_prompt_findings(run, prompt_result)
    else:
        con.print("  [green]✓[/green] No security issues found in prompt templates")


def _extension_row(ext: Any) -> tuple[str, str, str, str]:
    style = _SEV_COLORS.get(ext.risk_level, "white")
    icon = _SEV_ICONS.get(ext.risk_level, "⚪")
    risk_cell = f"{icon} [{style}]{ext.risk_level.upper()}[/{style}]"
    browser_cell = f"[cyan]{ext.browser}[/cyan]"
    name_cell = f"[bold]{ext.name}[/bold]\n[dim]{ext.version}[/dim]"
    findings_cell = "\n".join(f"[dim]• {r}[/dim]" for r in ext.risk_reasons[:4])
    if len(ext.risk_reasons) > 4:
        findings_cell += f"\n[dim]  (+{len(ext.risk_reasons) - 4} more)[/dim]"
    return risk_cell, browser_cell, name_cell, findings_cell


def _print_extensions(run: DiscoveryRun, br_exts: list[Any]) -> None:
    br_table = RichTable(
        title=f"Browser Extension Security Scan — {len(br_exts)} medium+ risk extension(s)",
        expand=True,
        padding=(0, 1),
        title_style="bold magenta",
    )
    br_table.add_column("Risk", justify="center", no_wrap=True, width=10)
    br_table.add_column("Browser", no_wrap=True, width=10)
    br_table.add_column("Extension", ratio=2)
    br_table.add_column("Findings", ratio=4)
    for ext in br_exts:
        br_table.add_row(*_extension_row(ext))
    crit_count = sum(1 for e in br_exts if e.risk_level == "critical")
    high_count = sum(1 for e in br_exts if e.risk_level == "high")
    stats = f"[dim]{crit_count} critical · {high_count} high · scan complete[/dim]"
    run.con.print(Panel(br_table, subtitle=stats, border_style="magenta"))


def scan_browser_extensions(run: DiscoveryRun) -> None:
    """Step 1g3c: browser extension scanning (--browser-extensions)."""
    if not run.browser_extensions:
        return
    from agent_bom.parsers.browser_extensions import discover_browser_extensions

    run.con.print("\n[bold blue]Scanning browser extensions...[/bold blue]\n")
    br_exts = discover_browser_extensions(include_low_risk=False)
    if br_exts:
        _print_extensions(run, br_exts)
    else:
        run.con.print("  [green]✓[/green] No medium+ risk browser extensions found")
    run.ctx._browser_ext_results = {
        "extensions": [e.to_dict() for e in br_exts],
        "total": len(br_exts),
        "critical_count": sum(1 for e in br_exts if e.risk_level == "critical"),
        "high_count": sum(1 for e in br_exts if e.risk_level == "high"),
    }


def iac_severity_summary(findings: list[Any]) -> str:
    by_sev: dict[str, int] = {}
    for iac_f in findings:
        by_sev[iac_f.severity] = by_sev.get(iac_f.severity, 0) + 1
    sev_parts = []
    for sev in ("critical", "high", "medium", "low"):
        if sev in by_sev:
            style = _SEV_COLORS.get(sev, "white")
            sev_parts.append(f"[{style}]{by_sev[sev]} {sev}[/{style}]")
    return ", ".join(sev_parts)


def _iac_row(iac_f: Any) -> tuple[str, str, str, str]:
    sev = iac_f.severity
    style = _SEV_COLORS.get(sev, "white")
    icon = _IAC_SEV_ICONS.get(sev, "⚪")
    sev_cell = f"{icon} [{style}]{sev.upper()}[/{style}]"
    rule_cell = f"[cyan]{iac_f.rule_id}[/cyan]"
    detail_parts = [f"[bold]{iac_f.title}[/bold]"]
    detail_parts.append(f"[dim]{iac_f.message}[/dim]")
    detail_cell = "\n".join(detail_parts)
    file_cell = f"{Path(iac_f.file_path).name}:{iac_f.line_number}"
    return sev_cell, rule_cell, detail_cell, file_cell


def print_iac_findings(run: DiscoveryRun, all_iac_findings: list[Any]) -> None:
    iac_table = RichTable(
        title=f"IaC Misconfigurations — {len(all_iac_findings)} finding(s)",
        expand=True,
        padding=(0, 1),
        title_style="bold cyan",
    )
    iac_table.add_column("Sev", justify="center", no_wrap=True, width=10)
    iac_table.add_column("Rule", no_wrap=True, width=12)
    iac_table.add_column("Finding", ratio=3)
    iac_table.add_column("File", ratio=2, style="dim")
    for iac_f in all_iac_findings[:_IAC_DISPLAY_LIMIT]:
        iac_table.add_row(*_iac_row(iac_f))
    if len(all_iac_findings) > _IAC_DISPLAY_LIMIT:
        iac_table.add_row("[dim]...[/dim]", "", f"[dim]+{len(all_iac_findings) - _IAC_DISPLAY_LIMIT} more[/dim]", "")
    crit = sum(1 for f in all_iac_findings if f.severity == "critical")
    high = sum(1 for f in all_iac_findings if f.severity == "high")
    stats = f"[dim]{crit} critical · {high} high · scan complete[/dim]"
    run.con.print()
    run.con.print(Panel(iac_table, subtitle=stats, border_style="cyan"))


def iac_findings_data(all_iac_findings: list[Any]) -> dict[str, Any]:
    return {
        "total": len(all_iac_findings),
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "title": f.title,
                "message": f.message,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "category": f.category,
                "compliance": f.compliance,
                "attack_techniques": f.attack_techniques,
                "remediation": f.remediation,
            }
            for f in all_iac_findings
        ],
    }
