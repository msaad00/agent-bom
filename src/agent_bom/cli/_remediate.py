"""Standalone ``agent-bom remediate`` command.

Runs the scan pipeline, builds a prioritized remediation plan, and outputs
it in console, JSON, or Markdown format.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click

from agent_bom import __version__
from agent_bom.cli._common import _make_console, logger
from agent_bom.cli._scan_runner import ScanConfig, run_default_scan

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PRIORITY_RANK = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}


def _compute_blast_radius_score(blast_radii, package_name: str) -> float:
    """Compute max risk_score across blast radii matching the given package."""
    scores = [br.risk_score for br in blast_radii if br.package.name == package_name]
    return max(scores) if scores else 0.0


def _group_by_server(plan_items: list[dict], blast_radii) -> dict[str, list[dict]]:
    """Re-group plan items by MCP server name instead of package."""
    server_groups: dict[str, list[dict]] = {}
    for item in plan_items:
        # Find which servers are affected via blast radii
        servers_for_pkg: set[str] = set()
        for br in blast_radii:
            if br.package.name == item["package"]:
                for srv in br.affected_servers:
                    servers_for_pkg.add(srv.name)
        if not servers_for_pkg:
            servers_for_pkg = {"unknown"}
        for srv_name in sorted(servers_for_pkg):
            server_groups.setdefault(srv_name, []).append(item)
    return server_groups


def _render_markdown(plan_items: list[dict], blast_radii) -> str:
    """Render a PR-ready Markdown remediation report."""
    lines: list[str] = []
    lines.append("# Remediation Plan")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"agent-bom {__version__}")
    lines.append("")

    fixable = [p for p in plan_items if p.get("fix")]
    unfixable = [p for p in plan_items if not p.get("fix")]

    if fixable:
        lines.append(f"## Fixable ({len(fixable)} upgrade(s))")
        lines.append("")
        lines.append("| # | Priority | Package | Current | Fix | Vulns | Blast Radius Score |")
        lines.append("|---|----------|---------|---------|-----|-------|--------------------|")
        for i, item in enumerate(fixable, 1):
            br_score = item.get("blast_radius_score", 0.0)
            n_vulns = len(item.get("vulns", []))
            lines.append(
                f"| {i} | {item['priority']} | {item['package']} | {item['current']} | {item['fix']} | {n_vulns} | {br_score:.1f} |"
            )
        lines.append("")

        for i, item in enumerate(fixable, 1):
            lines.append(f"### {i}. {item['package']} {item['current']} -> {item['fix']}")
            lines.append("")
            lines.append(f"- **Priority**: {item['priority']}")
            lines.append(f"- **Ecosystem**: {item['ecosystem']}")
            lines.append(f"- **Vulnerabilities**: {', '.join(item['vulns'][:5])}")
            if item.get("agents"):
                lines.append(f"- **Affected agents**: {', '.join(item['agents'][:5])}")
            if item.get("command"):
                lines.append(f"- **Fix command**: `{item['command']}`")
            if item.get("verify_command"):
                lines.append(f"- **Verify command**: `{item['verify_command']}`")
            if item.get("references"):
                lines.append("- **Advisories**:")
                for ref in item["references"][:5]:
                    lines.append(f"  - {ref}")
            lines.append("")

    if unfixable:
        lines.append(f"## No Fix Available ({len(unfixable)} package(s))")
        lines.append("")
        for item in unfixable:
            lines.append(f"- **{item['package']}@{item['current']}** -- {', '.join(item['vulns'][:3])}")
            if item.get("agents"):
                lines.append(f"  - Agents: {', '.join(item['agents'][:3])}")
        lines.append("")

    return "\n".join(lines)


def _plan_to_json(plan_items: list[dict]) -> dict:
    """Build JSON-serialisable output following the json_fmt.py pattern."""
    from agent_bom.models import Severity

    items_out = []
    for item in plan_items:
        sev = item.get("max_severity", Severity.NONE)
        sev_str = sev.name.lower() if hasattr(sev, "name") else str(sev)
        items_out.append(
            {
                "package": item["package"],
                "ecosystem": item["ecosystem"],
                "current_version": item["current"],
                "fixed_version": item.get("fix"),
                "priority": item["priority"],
                "action": item.get("action", ""),
                "command": item.get("command"),
                "verify_command": item.get("verify_command"),
                "max_severity": sev_str,
                "blast_radius_score": item.get("blast_radius_score", 0.0),
                "impact": item.get("impact", 0),
                "vulnerabilities": item.get("vulns", []),
                "affected_agents": item.get("agents", []),
                "exposed_credentials": item.get("creds", []),
                "exposed_tools": item.get("tools", []),
                "references": item.get("references", []),
                "has_kev": item.get("has_kev", False),
                "ai_risk": item.get("ai_risk", False),
                "compliance_tags": {
                    "owasp": item.get("owasp", []),
                    "atlas": item.get("atlas", []),
                    "nist": item.get("nist", []),
                    "owasp_mcp": item.get("owasp_mcp", []),
                    "owasp_agentic": item.get("owasp_agentic", []),
                    "eu_ai_act": item.get("eu_ai_act", []),
                    "nist_csf": item.get("nist_csf", []),
                    "iso_27001": item.get("iso_27001", []),
                    "soc2": item.get("soc2", []),
                    "cis": item.get("cis", []),
                },
            }
        )

    return {
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "remediation_plan": items_out,
        "summary": {
            "total_items": len(items_out),
            "fixable": sum(1 for i in items_out if i["fixed_version"]),
            "unfixable": sum(1 for i in items_out if not i["fixed_version"]),
            "p1_count": sum(1 for i in items_out if i["priority"] == "P1"),
            "p2_count": sum(1 for i in items_out if i["priority"] == "P2"),
            "p3_count": sum(1 for i in items_out if i["priority"] == "P3"),
            "p4_count": sum(1 for i in items_out if i["priority"] == "P4"),
        },
    }


# ---------------------------------------------------------------------------
# Click command
# ---------------------------------------------------------------------------


@click.command("remediate")
@click.option("--demo", is_flag=True, help="Scan a curated demo environment with known-vulnerable packages.")
@click.option("--offline", is_flag=True, help="Use local vulnerability DB only (no network calls).")
@click.option("-p", "--project", type=click.Path(exists=True), default=None, help="Project directory to scan.")
@click.option("--server-group", is_flag=True, default=False, help="Group output by MCP server instead of by package.")
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["console", "json", "markdown"], case_sensitive=False),
    default="console",
    help="Output format.",
)
@click.option("-o", "--output", "output_path", type=click.Path(), default=None, help="Write output to a file.")
@click.option(
    "--priority",
    "min_priority",
    type=click.Choice(["P1", "P2", "P3", "P4"], case_sensitive=False),
    default=None,
    help="Filter to show only items at this priority or higher.",
)
@click.option("--fixable-only", is_flag=True, default=False, help="Hide items without a fix version.")
def remediate_cmd(
    demo: bool,
    offline: bool,
    project: Optional[str],
    server_group: bool,
    output_format: str,
    output_path: Optional[str],
    min_priority: Optional[str],
    fixable_only: bool,
) -> None:
    """Generate a prioritized remediation plan for discovered vulnerabilities.

    \b
    Runs a scan, then builds a remediation plan ordered by blast-radius impact.
    Each item includes fix commands, verification steps, and compliance tags.

    \b
    Examples:
      agent-bom remediate --demo                      demo remediation plan
      agent-bom remediate -p . -f json -o plan.json   JSON plan for current project
      agent-bom remediate --fixable-only --priority P2 show P1+P2 fixable items only
      agent-bom remediate --server-group               group by MCP server
    """
    from agent_bom.output import build_remediation_plan, print_remediation_plan

    con = _make_console(quiet=(output_format != "console"), output_format=output_format)

    # Run the scan pipeline
    try:
        result = run_default_scan(
            ScanConfig(project=project, demo=demo, offline=offline),
            con=con,
        )
        blast_radii, report = result.blast_radii, result.report
    except SystemExit:
        raise
    except Exception as exc:
        logger.error("Scan failed: %s", exc)
        raise SystemExit(1)

    if not blast_radii:
        if output_format == "json":
            empty_plan = _plan_to_json([])
            _out_str = json.dumps(empty_plan, indent=2)
            if output_path:
                Path(output_path).write_text(_out_str)
            else:
                click.echo(_out_str)
            return
        con.print("\n[green]No vulnerabilities found — no remediation needed.[/green]\n")
        return

    # Build the plan
    plan = build_remediation_plan(blast_radii)

    # Enrich with blast_radius_score
    for item in plan:
        item["blast_radius_score"] = _compute_blast_radius_score(blast_radii, item["package"])

    # Apply filters
    if min_priority:
        threshold = _PRIORITY_RANK.get(min_priority.upper(), 4)
        plan = [item for item in plan if _PRIORITY_RANK.get(item["priority"], 4) <= threshold]

    if fixable_only:
        plan = [item for item in plan if item.get("fix")]

    if not plan:
        if output_format == "json":
            empty_plan = _plan_to_json([])
            _out_str = json.dumps(empty_plan, indent=2)
            if output_path:
                Path(output_path).write_text(_out_str)
            else:
                click.echo(_out_str)
            return
        con.print("\n[dim]No remediation items match the current filters.[/dim]\n")
        return

    # Render output
    if output_format == "console":
        if server_group:
            groups = _group_by_server(plan, blast_radii)
            from rich.rule import Rule

            con.print()
            con.print(Rule("Remediation Plan (grouped by MCP server)", style="green"))
            con.print()
            for srv_name, items in groups.items():
                con.print(f"\n  [bold cyan]{srv_name}[/bold cyan]")
                for item in items:
                    fix_str = f"[green]{item['fix']}[/green]" if item.get("fix") else "[dim]no fix[/dim]"
                    kev = " [red][KEV][/red]" if item.get("has_kev") else ""
                    con.print(
                        f"    [{item['priority']}] {item['package']} "
                        f"[dim]{item['current']}[/dim] -> {fix_str}{kev}"
                        f"  ({len(item.get('vulns', []))} vuln(s))"
                    )
            con.print()
        else:
            # Use the existing print_remediation_plan for default console view
            print_remediation_plan(report)

    elif output_format == "json":
        if server_group:
            groups = _group_by_server(plan, blast_radii)
            json_out = _plan_to_json(plan)
            json_out["server_groups"] = {srv: [item["package"] for item in items] for srv, items in groups.items()}
        else:
            json_out = _plan_to_json(plan)
        _out_str = json.dumps(json_out, indent=2)
        if output_path:
            Path(output_path).write_text(_out_str)
            con_file = _make_console(quiet=False)
            con_file.print(f"[green]Remediation plan written[/green] -> {output_path}")
        else:
            click.echo(_out_str)

    elif output_format == "markdown":
        md = _render_markdown(plan, blast_radii)
        if output_path:
            Path(output_path).write_text(md)
            con_file = _make_console(quiet=False)
            con_file.print(f"[green]Remediation report written[/green] -> {output_path}")
        else:
            click.echo(md)
