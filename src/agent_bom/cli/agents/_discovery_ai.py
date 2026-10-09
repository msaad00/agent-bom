"""Discovery stage for AI component source scanning (--ai-inventory)."""

from __future__ import annotations

from typing import Any

from rich.panel import Panel as AiPanel
from rich.table import Table as AiTable

from agent_bom.cli.agents._discovery_state import DiscoveryRun
from agent_bom.models import Agent, AgentType, MCPServer, Package, ServerSurface

_SEV_COLORS = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim", "info": "dim"}
_SEV_ICONS = {"critical": "\U0001f534", "high": "\U0001f7e0", "medium": "\U0001f7e1", "low": "⚪", "info": "⚪"}
_DISPLAY_LIMIT = 15


def _manifest_package_names(run: DiscoveryRun) -> set[str]:
    # Collect manifest packages for shadow AI detection
    manifest_pkgs: set[str] = set()
    for ag in run.ctx.agents:
        for srv in ag.mcp_servers:
            for pkg in srv.packages:
                manifest_pkgs.add(pkg.name)
    return manifest_pkgs


def _component_row(comp: Any) -> tuple[str, str, str, str, str]:
    sev = comp.severity.value
    style = _SEV_COLORS.get(sev, "white")
    icon = _SEV_ICONS.get(sev, "⚪")
    sev_cell = f"{icon} [{style}]{sev.upper()}[/{style}]"
    type_label = comp.component_type.value.replace("_", " ")
    name_cell = f"[bold]{comp.name}[/bold]"
    if comp.is_shadow:
        name_cell += " [yellow](shadow)[/yellow]"
    if comp.deprecated_replacement:
        name_cell += f"\n[dim]→ {comp.deprecated_replacement}[/dim]"
    file_cell = f"[dim]{comp.file_path}:{comp.line_number}[/dim]"
    return sev_cell, type_label, name_cell, file_cell, f"[cyan]{comp.language}[/cyan]"


def _stats_subtitle(ai_report: Any) -> str:
    crit = sum(1 for c in ai_report.components if c.severity.value == "critical")
    high = sum(1 for c in ai_report.components if c.severity.value == "high")
    shadow = len(ai_report.shadow_ai)
    depr = len(ai_report.deprecated_models)
    keys = len(ai_report.api_keys)
    stats_parts = []
    if crit:
        stats_parts.append(f"[red bold]{crit} critical[/red bold]")
    if high:
        stats_parts.append(f"[red]{high} high[/red]")
    if shadow:
        stats_parts.append(f"[yellow]{shadow} shadow AI[/yellow]")
    if depr:
        stats_parts.append(f"{depr} deprecated")
    if keys:
        stats_parts.append(f"[red]{keys} hardcoded key(s)[/red]")
    return "[dim]" + " · ".join(stats_parts) + "[/dim]" if stats_parts else ""


def _print_actionable_table(run: DiscoveryRun, ai_report: Any, actionable: list[Any]) -> None:
    ai_table = AiTable(
        title=f"AI Component Inventory — {ai_report.total} components across {ai_report.files_scanned} files",
        expand=True,
        padding=(0, 1),
        title_style="bold cyan",
    )
    ai_table.add_column("Sev", justify="center", no_wrap=True, width=10)
    ai_table.add_column("Type", no_wrap=True, width=18)
    ai_table.add_column("Name", ratio=2)
    ai_table.add_column("File", ratio=2)
    ai_table.add_column("Lang", no_wrap=True, width=6)
    for comp in actionable[:_DISPLAY_LIMIT]:
        ai_table.add_row(*_component_row(comp))
    if len(actionable) > _DISPLAY_LIMIT:
        ai_table.add_row("[dim]...[/dim]", "", f"[dim]+{len(actionable) - _DISPLAY_LIMIT} more[/dim]", "", "")
    run.con.print(AiPanel(ai_table, subtitle=_stats_subtitle(ai_report), border_style="cyan"))


def _print_all_safe(run: DiscoveryRun, ai_report: Any) -> None:
    sdks = sorted(ai_report.unique_sdks)
    models = sorted(ai_report.unique_models)
    sdk_str = ", ".join(sdks[:5]) + (f" +{len(sdks) - 5}" if len(sdks) > 5 else "") if sdks else "none"
    model_str = ", ".join(models[:4]) + (f" +{len(models) - 4}" if len(models) > 4 else "") if models else "none"
    run.con.print(
        f"  [green]✓[/green] {ai_report.files_scanned} files scanned — "
        f"[bold]{ai_report.total}[/bold] components, [green]all safe[/green]\n"
        f"    SDKs: [cyan]{sdk_str}[/cyan]\n"
        f"    Models: [cyan]{model_str}[/cyan]"
    )


def _attach_sdk_packages(run: DiscoveryRun, ai_report: Any, first_path: Any) -> None:
    # Create synthetic packages for SDK components -> feed into CVE scanning
    ai_packages: list[Package] = []
    seen_pkgs: set[str] = set()
    for comp in ai_report.components:
        if comp.package_name and comp.ecosystem:
            pkg_key = f"{comp.ecosystem}:{comp.package_name}"
            if pkg_key not in seen_pkgs:
                seen_pkgs.add(pkg_key)
                ai_packages.append(Package(name=comp.package_name, version="latest", ecosystem=comp.ecosystem))
    if ai_packages:
        server = MCPServer(name="ai-inventory", surface=ServerSurface.AI_INVENTORY)
        server.packages = ai_packages
        ai_agent = Agent(
            name="ai-inventory",
            agent_type=AgentType.CUSTOM,
            config_path=str(first_path),
            source="ai-inventory",
            mcp_servers=[server],
        )
        run.ctx.agents.append(ai_agent)


def _component_record(c: Any) -> dict[str, Any]:
    return {
        "type": c.component_type.value,
        # Redact credential fragments — never persist key material in report data
        "name": "[REDACTED]" if c.component_type.value == "api_key" else c.name,
        "language": c.language,
        "file": c.file_path,
        "line": c.line_number,
        "severity": c.severity.value,
        "is_shadow": c.is_shadow,
        "package": c.package_name,
        "ecosystem": c.ecosystem,
        "description": c.description,
        "deprecated_replacement": c.deprecated_replacement,
    }


def _inventory_data(ai_report: Any) -> dict[str, Any]:
    return {
        "total_components": ai_report.total,
        "shadow_ai_count": len(ai_report.shadow_ai),
        "deprecated_models_count": len(ai_report.deprecated_models),
        "api_keys_count": len(ai_report.api_keys),
        "unique_sdks": sorted(ai_report.unique_sdks),
        "unique_models": sorted(ai_report.unique_models),
        "files_scanned": ai_report.files_scanned,
        "framework_agents": list(ai_report.framework_agents),
        "components": [_component_record(c) for c in ai_report.components],
    }


def scan_ai_inventory(run: DiscoveryRun) -> None:
    """Step 1d3b: AI component source scan (--ai-inventory)."""
    ai_inventory_paths = run.extra.get("ai_inventory_paths", ())
    if run.skill_only or not ai_inventory_paths:
        return
    from agent_bom.ai_components import scan_source

    manifest_pkgs = _manifest_package_names(run)
    run.con.print(f"\n[bold blue]Scanning {len(ai_inventory_paths)} path(s) for AI components...[/bold blue]\n")
    ai_report = scan_source(*ai_inventory_paths, manifest_packages=manifest_pkgs)

    # Rich table for AI component findings (show critical/high/medium first, limit display)
    actionable = [c for c in ai_report.components if c.severity.value in ("critical", "high", "medium")]
    if actionable:
        _print_actionable_table(run, ai_report, actionable)
    else:
        _print_all_safe(run, ai_report)
    _attach_sdk_packages(run, ai_report, ai_inventory_paths[0])
    run.ctx.ai_inventory_data = _inventory_data(ai_report)
