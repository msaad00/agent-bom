"""Step 5: output rendering and format helpers."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any, Callable

from agent_bom.cli.scan._context import ScanContext
from agent_bom.models import AIBOMReport
from agent_bom.output import (
    export_badge,
    export_csv,
    export_cyclonedx,
    export_html,
    export_json,
    export_junit,
    export_markdown,
    export_prometheus,
    export_sarif,
    export_spdx,
    print_agent_tree,
    print_attack_flow_tree,
    print_blast_radius,
    print_compact_agents,
    print_compact_blast_radius,
    print_compact_export_hint,
    print_compact_remediation,
    print_compact_summary,
    print_export_hint,
    print_posture_summary,
    print_remediation_plan,
    print_severity_chart,
    print_summary,
    print_threat_frameworks,
    push_otlp,
    push_to_gateway,
    to_csv,
    to_cyclonedx,
    to_json,
    to_junit,
    to_markdown,
    to_prometheus,
    to_sarif,
    to_spdx,
)

_logger = logging.getLogger(__name__)


def _safe_export(fn: Callable, *args: Any, label: str = "report", path: str = "") -> bool:
    """Call an export function, catching file I/O errors gracefully."""
    try:
        fn(*args)
        return True
    except (PermissionError, OSError) as exc:
        _logger.error("Failed to write %s to %s: %s", label, path, exc)
        import click

        click.echo(f"Error: cannot write {label} to {path}: {exc}", err=True)
        return False


def render_output(
    ctx: ScanContext,
    *,
    output: Any,
    output_format: str,
    no_tree: bool,
    quiet: bool,
    no_color: bool,
    open_report: bool,
    compliance_export: Any,
    mermaid_mode: str,
    push_gateway: Any,
    otel_endpoint: Any,
    baseline: Any,
    delta_mode: bool,
    verbose: bool = False,
    **kwargs: Any,
) -> None:
    """Step 5: render report to console/file. Also Steps 5b, 5c, 5d."""
    con = ctx.con
    report = ctx.report
    blast_radii = ctx.blast_radii
    is_stdout = output == "-"

    if is_stdout:
        # Pipe mode: write clean output to stdout
        if output_format == "cyclonedx":
            sys.stdout.write(json.dumps(to_cyclonedx(report), indent=2))
        elif output_format == "sarif":
            sys.stdout.write(json.dumps(to_sarif(report), indent=2))
        elif output_format == "spdx":
            sys.stdout.write(json.dumps(to_spdx(report), indent=2))
        elif output_format == "html":
            from agent_bom.output import to_html

            sys.stdout.write(to_html(report, blast_radii))
        elif output_format == "prometheus":
            sys.stdout.write(to_prometheus(report, blast_radii))
        elif output_format == "graph":
            from agent_bom.output.graph import build_graph_elements

            elements = build_graph_elements(report, blast_radii)
            sys.stdout.write(json.dumps({"elements": elements, "format": "cytoscape"}, indent=2))
        elif output_format == "mermaid":
            if mermaid_mode == "attack-flow":
                from agent_bom.output.mermaid import to_mermaid

                sys.stdout.write(to_mermaid(report, blast_radii))
            elif mermaid_mode == "lifecycle":
                from agent_bom.output.mermaid import to_mermaid_lifecycle

                sys.stdout.write(to_mermaid_lifecycle(report, blast_radii))
            else:
                from agent_bom.output.mermaid import to_mermaid_supply_chain

                sys.stdout.write(to_mermaid_supply_chain(report))
        elif output_format == "svg":
            from agent_bom.output.svg import to_svg

            sys.stdout.write(to_svg(report, blast_radii))
        elif output_format == "junit":
            sys.stdout.write(to_junit(report, blast_radii))
        elif output_format == "csv":
            sys.stdout.write(to_csv(report, blast_radii))
        elif output_format == "markdown":
            sys.stdout.write(to_markdown(report, blast_radii))
        elif output_format == "graph-html":
            import click

            click.echo("Error: --format graph-html requires --output/-o (cannot write HTML to stdout)", err=True)
            sys.exit(2)
        else:
            sys.stdout.write(json.dumps(to_json(report), indent=2))
        sys.stdout.write("\n")
    elif output_format == "console" and not output:
        _skill_audit_obj = ctx._skill_audit_obj
        if verbose:
            # Full output (--verbose)
            print_summary(report)
            print_posture_summary(report)
            if not no_tree:
                print_agent_tree(report)
            print_severity_chart(report)
            print_blast_radius(report)
            if not no_tree:
                print_attack_flow_tree(report)
            print_threat_frameworks(report)
        else:
            # Compact output (default)
            print_compact_summary(report)
            print_compact_agents(report)
            print_compact_blast_radius(report)

        # AI enrichment output (both modes)
        if report.executive_summary:
            from rich.panel import Panel

            con.print("\n[bold]Executive Summary (AI-Generated)[/bold]")
            con.print(Panel.fit(report.executive_summary, border_style="cyan"))
        if report.ai_threat_chains:
            from rich.panel import Panel

            con.print("\n[bold]Threat Chain Analysis (AI-Generated)[/bold]")
            for chain in report.ai_threat_chains:
                con.print(Panel(chain, border_style="red dim"))
        # AI skill analysis output (if enriched)
        if _skill_audit_obj and _skill_audit_obj.ai_skill_summary:
            from rich.panel import Panel

            sev_colors = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim", "safe": "green"}
            risk = _skill_audit_obj.ai_overall_risk_level or "unknown"
            risk_style = sev_colors.get(risk, "white")
            con.print(f"\n[bold]Skill File AI Analysis[/bold]  [{risk_style}]\\[{risk.upper()}][/{risk_style}]")
            con.print(Panel.fit(_skill_audit_obj.ai_skill_summary, border_style="cyan"))

            # Show AI-adjusted findings
            adjusted = [sk_f for sk_f in _skill_audit_obj.findings if sk_f.ai_adjusted_severity]
            if adjusted:
                for sk_f in adjusted:
                    if sk_f.ai_adjusted_severity == "false_positive":
                        con.print(f"  [green]✓ FP[/green] {sk_f.title}")
                        con.print(f"    [dim]{sk_f.ai_analysis}[/dim]")
                    else:
                        con.print(f"  [yellow]↕ ADJ[/yellow] {sk_f.title}: {sk_f.severity} → {sk_f.ai_adjusted_severity}")
                        if sk_f.ai_analysis:
                            con.print(f"    [dim]{sk_f.ai_analysis}[/dim]")

            # Show AI-detected new findings
            ai_detected = [sk_f for sk_f in _skill_audit_obj.findings if sk_f.context == "ai_analysis"]
            if ai_detected:
                con.print(f"\n  [bold yellow]AI-Detected Threats ({len(ai_detected)})[/bold yellow]")
                for sk_f in ai_detected:
                    style = sev_colors.get(sk_f.severity, "white")
                    con.print(f"    [{style}]\\[{sk_f.severity.upper()}][/{style}] {sk_f.title}")
                    con.print(f"      [dim]{sk_f.detail}[/dim]")
                    if sk_f.recommendation:
                        con.print(f"      [green]→ {sk_f.recommendation}[/green]")

        if verbose:
            print_remediation_plan(report)
            print_export_hint(report)
        else:
            print_compact_remediation(report)
            print_compact_export_hint(report)
    elif output_format in ("text", "plain") and not output:
        _print_text(report, blast_radii)
    elif output_format == "json":
        out_path = output or "agent-bom-report.json"
        if _safe_export(export_json, report, out_path, label="JSON report", path=out_path):
            con.print(f"\n  [green]✓[/green] JSON report: {out_path}")
    elif output_format == "cyclonedx":
        out_path = output or "agent-bom.cdx.json"
        if _safe_export(export_cyclonedx, report, out_path, label="CycloneDX BOM", path=out_path):
            con.print(f"\n  [green]✓[/green] CycloneDX BOM: {out_path}")
    elif output_format == "sarif":
        out_path = output or "agent-bom.sarif"
        if _safe_export(export_sarif, report, out_path, label="SARIF report", path=out_path):
            con.print(f"\n  [green]✓[/green] SARIF report: {out_path}")
    elif output_format == "spdx":
        out_path = output or "agent-bom.spdx.json"
        if _safe_export(export_spdx, report, out_path, label="SPDX 3.0 BOM", path=out_path):
            con.print(f"\n  [green]✓[/green] SPDX 3.0 BOM: {out_path}")
    elif output_format == "junit":
        out_path = output or "agent-bom-results.xml"
        if _safe_export(export_junit, report, out_path, blast_radii, label="JUnit XML", path=out_path):
            con.print(f"\n  [green]✓[/green] JUnit XML: {out_path}")
    elif output_format == "csv":
        out_path = output or "agent-bom-results.csv"
        if _safe_export(export_csv, report, out_path, blast_radii, label="CSV report", path=out_path):
            con.print(f"\n  [green]✓[/green] CSV report: {out_path}")
    elif output_format == "markdown":
        out_path = output or "agent-bom-report.md"
        if _safe_export(export_markdown, report, out_path, blast_radii, label="Markdown report", path=out_path):
            con.print(f"\n  [green]✓[/green] Markdown report: {out_path}")
    elif output_format == "html":
        out_path = output or "agent-bom-report.html"
        if _safe_export(export_html, report, out_path, blast_radii, label="HTML report", path=out_path):
            con.print(f"\n  [green]✓[/green] HTML report: {out_path}")
        if open_report:
            import webbrowser

            con.print(f"  [green]✓[/green] Opening report in browser: {out_path}")
            webbrowser.open(f"file://{Path(out_path).resolve()}")
        else:
            con.print(f"  [dim]Open with:[/dim] open {out_path}")
    elif output_format == "prometheus":
        out_path = output or "agent-bom-metrics.prom"
        if _safe_export(export_prometheus, report, out_path, blast_radii, label="Prometheus metrics", path=out_path):
            con.print(f"\n  [green]✓[/green] Prometheus metrics: {out_path}")
        con.print("  [dim]Scrape with node_exporter textfile or push via --push-gateway[/dim]")
    elif output_format == "graph":
        from agent_bom.output.graph import build_graph_elements

        out_path = output or "agent-bom-graph.json"
        elements = build_graph_elements(report, blast_radii)
        Path(out_path).write_text(json.dumps({"elements": elements, "format": "cytoscape"}, indent=2))
        con.print(f"\n  [green]✓[/green] Graph JSON: {out_path}")
        con.print("  [dim]Cytoscape.js-compatible element list — open with Cytoscape desktop or any JS graph library[/dim]")
    elif output_format == "mermaid":
        out_path = output or "agent-bom-diagram.mmd"
        if mermaid_mode == "attack-flow":
            from agent_bom.output.mermaid import to_mermaid

            Path(out_path).write_text(to_mermaid(report, blast_radii))
        elif mermaid_mode == "lifecycle":
            from agent_bom.output.mermaid import to_mermaid_lifecycle

            Path(out_path).write_text(to_mermaid_lifecycle(report, blast_radii))
        else:
            from agent_bom.output.mermaid import to_mermaid_supply_chain

            Path(out_path).write_text(to_mermaid_supply_chain(report))
        con.print(f"\n  [green]✓[/green] Mermaid diagram ({mermaid_mode}): {out_path}")
        con.print("  [dim]Render with: mermaid-cli, GitHub markdown, or mermaid.live[/dim]")
    elif output_format == "svg":
        from agent_bom.output.svg import export_svg

        out_path = output or "agent-bom-supply-chain.svg"
        export_svg(report, blast_radii, out_path)
        con.print(f"\n  [green]✓[/green] SVG diagram: {out_path}")
        con.print("  [dim]Open in any browser or image viewer[/dim]")
    elif output_format == "graph-html":
        from agent_bom.output.graph import export_graph_html

        out_path = output or "agent-bom-graph.html"
        export_graph_html(report, blast_radii, out_path)
        con.print(f"\n  [green]✓[/green] Interactive graph: {out_path}")
        if open_report:
            import webbrowser

            con.print(f"  [green]✓[/green] Opening report in browser: {out_path}")
            webbrowser.open(f"file://{Path(out_path).resolve()}")
        else:
            con.print(f"  [dim]Open with:[/dim] open {out_path}")
    elif output_format == "badge":
        out_path = output or "agent-bom-badge.json"
        if _safe_export(export_badge, report, out_path, label="Badge JSON", path=out_path):
            con.print(f"\n  [green]✓[/green] Badge JSON: {out_path}")
            con.print("  [dim]Use with: https://img.shields.io/endpoint?url=<public-url-to-badge-json>[/dim]")
    elif output_format in ("text", "plain") and output:
        if _safe_export(Path(output).write_text, _format_text(report, blast_radii), label="Plain text report", path=output):
            con.print(f"\n  [green]✓[/green] Plain text report: {output}")
    elif output:
        # Auto-detect format from file extension
        _ext_fn: Callable = export_json  # default fallback
        _ext_args: tuple = (report, output)
        if output.endswith(".cdx.json"):
            _ext_fn, _ext_args = export_cyclonedx, (report, output)
        elif output.endswith(".sarif"):
            _ext_fn, _ext_args = export_sarif, (report, output)
        elif output.endswith(".spdx.json"):
            _ext_fn, _ext_args = export_spdx, (report, output)
        elif output.endswith(".html"):
            _ext_fn, _ext_args = export_html, (report, output, blast_radii)
        elif output.endswith(".xml"):
            _ext_fn, _ext_args = export_junit, (report, output, blast_radii)
        elif output.endswith(".csv"):
            _ext_fn, _ext_args = export_csv, (report, output, blast_radii)
        elif output.endswith(".md"):
            _ext_fn, _ext_args = export_markdown, (report, output, blast_radii)
        else:
            _ext_fn, _ext_args = export_json, (report, output)
        if _safe_export(_ext_fn, *_ext_args, label="Report", path=output):
            con.print(f"\n  [green]✓[/green] Report: {output}")

    # Step 5b: Push to Prometheus Pushgateway (if requested)
    if push_gateway:
        from agent_bom.output.prometheus import PushgatewayError

        try:
            push_to_gateway(push_gateway, report, blast_radii)
            con.print(f"\n  [green]✓[/green] Metrics pushed to Pushgateway: {push_gateway}")
        except PushgatewayError as e:
            con.print(f"\n  [yellow]⚠[/yellow] Pushgateway push failed: {e}")

    # Step 5c: OpenTelemetry OTLP export (if requested)
    if otel_endpoint:
        try:
            push_otlp(otel_endpoint, report, blast_radii)
            con.print(f"\n  [green]✓[/green] Metrics exported via OTLP: {otel_endpoint}")
        except ImportError as e:
            con.print(f"\n  [yellow]⚠[/yellow] OTel export skipped: {e}")
        except Exception as e:  # noqa: BLE001
            con.print(f"\n  [yellow]⚠[/yellow] OTLP export failed: {e}")

    # Step 5d: Compliance evidence export (if requested)
    if compliance_export:
        from agent_bom.output import export_compliance_bundle

        ce_path = output or f"compliance-{compliance_export}.zip"
        if not ce_path.endswith(".zip"):
            ce_path += ".zip"
        export_compliance_bundle(report, compliance_export, ce_path)
        con.print(f"\n  [green]✓[/green] Compliance bundle: {ce_path}")


def _format_text(report: AIBOMReport, blast_radii: list) -> str:
    """Plain text output for piping to grep/awk."""
    lines = []
    lines.append(f"agent-bom {report.tool_version}")
    lines.append(
        f"agents={report.total_agents} servers={report.total_servers} "
        f"packages={report.total_packages} vulnerabilities={report.total_vulnerabilities}"
    )
    lines.append("")

    for agent in report.agents:
        for server in agent.mcp_servers:
            for pkg in server.packages:
                lines.append(f"{agent.name}\t{server.name}\t{pkg.ecosystem}\t{pkg.name}\t{pkg.version}")

    if blast_radii:
        lines.append("")
        lines.append("VULN_ID\tSEVERITY\tPACKAGE\tFIX\tAGENTS\tCREDENTIALS")
        for br in blast_radii:
            v = br.vulnerability
            lines.append(
                f"{v.id}\t{v.severity.value}\t{br.package.name}@{br.package.version}\t"
                f"{v.fixed_version or '-'}\t{len(br.affected_agents)}\t{len(br.exposed_credentials)}"
            )

    return "\n".join(lines) + "\n"


def _print_text(report: AIBOMReport, blast_radii: list) -> None:
    """Print plain text to stdout."""
    sys.stdout.write(_format_text(report, blast_radii))
