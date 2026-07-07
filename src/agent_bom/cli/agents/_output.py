"""Step 5: output rendering and format helpers."""

from __future__ import annotations

import contextlib
import errno
import json
import sys
from pathlib import Path
from typing import Any, Iterator

import click

from agent_bom.cli._agent_mode import dumps_envelope, success_envelope
from agent_bom.cli._terminal_sections import print_scan_next_steps, print_section_divider
from agent_bom.cli.agents._cloud import render_cis_findings_from_context
from agent_bom.cli.agents._context import ScanContext
from agent_bom.models import AIBOMReport
from agent_bom.output import (
    export_badge,
    export_csv,
    export_cyclonedx,
    export_html,
    export_json,
    export_junit,
    export_markdown,
    export_parquet,
    export_pdf,
    export_prometheus,
    export_sarif,
    export_spdx,
    export_spdx2,
    print_agent_tree,
    print_attack_flow_tree,
    print_blast_radius,
    print_compact_agents,
    print_compact_blast_radius,
    print_compact_cis_posture,
    print_compact_export_hint,
    print_compact_remediation,
    print_compact_summary,
    print_export_hint,
    print_posture_summary,
    print_remediation_plan,
    print_scan_performance_summary,
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
    to_spdx2,
)

_FORMAT_OUTPUT_RULES: dict[str, tuple[str, tuple[str, ...]]] = {
    "json": ("agent-bom-report.json", (".json",)),
    "cyclonedx": ("agent-bom.cdx.json", (".cdx.json", ".json")),
    "sarif": ("agent-bom.sarif", (".sarif", ".sarif.json")),
    "spdx": ("agent-bom.spdx.json", (".spdx.json", ".json")),
    "spdx2": ("agent-bom.spdx2.json", (".spdx2.json", ".spdx.json", ".json")),
    "junit": ("agent-bom-results.xml", (".xml",)),
    "csv": ("agent-bom-results.csv", (".csv",)),
    "parquet": ("agent-bom-findings.parquet", (".parquet",)),
    "markdown": ("agent-bom-report.md", (".md", ".markdown")),
    "html": ("agent-bom-report.html", (".html", ".htm")),
    "pdf": ("agent-bom-report.pdf", (".pdf",)),
    "prometheus": ("agent-bom-metrics.prom", (".prom", ".txt")),
    "graph": ("agent-bom-graph.json", (".json",)),
    "mermaid": ("agent-bom-diagram.mmd", (".mmd", ".mermaid", ".md")),
    "svg": ("agent-bom-supply-chain.svg", (".svg",)),
    "graph-html": ("agent-bom-graph.html", (".html", ".htm")),
    "badge": ("agent-bom-badge.json", (".json",)),
    "plain": ("agent-bom-report.txt", (".txt", ".text", ".log")),
    "text": ("agent-bom-report.txt", (".txt", ".text", ".log")),
}


def _is_null_device(output: Any) -> bool:
    """Return True when ``output`` points at the platform null device."""
    import os

    if not output or output == "-":
        return False
    candidates = {os.devnull, "/dev/null"}
    try:
        return os.path.realpath(str(output)) in {os.path.realpath(c) for c in candidates}
    except OSError:
        return str(output) in candidates


def _resolve_output_path(output: Any, output_format: str) -> str:
    """Return an output path whose suffix matches the selected format."""
    default_name, allowed_suffixes = _FORMAT_OUTPUT_RULES[output_format]
    if not output:
        return default_name

    raw_path = str(output)
    # Null device is a discard sink: keep the path verbatim so the write lands on
    # /dev/null (which succeeds silently) rather than a suffixed sibling like
    # `/dev/null.json` that lives in an unwritable dir and would fail (#3643).
    if _is_null_device(raw_path):
        return raw_path
    lower_path = raw_path.lower()
    if any(lower_path.endswith(suffix) for suffix in allowed_suffixes):
        return raw_path

    path = Path(raw_path)
    if not path.suffix:
        default_suffix = "".join(Path(default_name).suffixes)
        return f"{raw_path}{default_suffix}"

    # Friendly short-form handling: a truncated final suffix like `.cdx` /
    # `.spdx` / `.spdx2` that becomes a valid multi-part suffix for this format
    # once `.json` is appended is accepted rather than hard-erroring. We match
    # the exact allowed multi-part suffix (e.g. `.cdx.json`), so unrelated
    # extensions like `.png` still error instead of silently gaining `.json`.
    short_form = f"{path.suffix.lower()}.json"
    if short_form in allowed_suffixes:
        aliased = f"{raw_path}.json"
        click.echo(
            f"--format {output_format}: '{raw_path}' looks like a short form for this format; writing to '{aliased}'.",
            err=True,
        )
        return aliased

    suffix_list = ", ".join(allowed_suffixes)
    click.echo(
        f"--format {output_format} cannot write to '{raw_path}' because the file extension does not match. Use one of: {suffix_list}.",
        err=True,
    )
    raise SystemExit(2)


def _stdout_serialization(
    report: AIBOMReport,
    blast_radii: list,
    output_format: str,
    *,
    exclude_unfixable: bool,
    offline_html: bool,
) -> str | None:
    """Best-effort serialize the report for stdout fallback when -o write fails.

    Returns ``None`` for formats that have no usable stdout representation
    (e.g. binary PDF), in which case the caller prints a skip message instead.
    """
    if output_format in ("json", "graph", "badge"):
        if output_format == "graph":
            from agent_bom.output.graph import build_graph_elements

            return json.dumps({"elements": build_graph_elements(report, blast_radii), "format": "cytoscape"}, indent=2)
        if output_format == "badge":
            from agent_bom.output.badge import to_badge

            return json.dumps(to_badge(report), indent=2)
        return json.dumps(to_json(report), indent=2)
    if output_format == "cyclonedx":
        return json.dumps(to_cyclonedx(report), indent=2)
    if output_format == "sarif":
        return json.dumps(to_sarif(report, exclude_unfixable=exclude_unfixable), indent=2)
    if output_format == "spdx":
        return json.dumps(to_spdx(report), indent=2)
    if output_format == "spdx2":
        return json.dumps(to_spdx2(report), indent=2)
    if output_format == "junit":
        return to_junit(report, blast_radii)
    if output_format == "csv":
        return to_csv(report, blast_radii)
    if output_format == "parquet":
        return None
    if output_format == "markdown":
        return to_markdown(report, blast_radii)
    if output_format == "prometheus":
        return to_prometheus(report, blast_radii)
    if output_format in ("html", "graph-html"):
        from agent_bom.output import to_html

        return to_html(report, blast_radii, offline_assets=offline_html)
    if output_format in ("text", "plain"):
        return _format_text(report, blast_radii)
    if output_format == "mermaid":
        from agent_bom.output.mermaid import to_mermaid_supply_chain

        return to_mermaid_supply_chain(report)
    if output_format == "svg":
        from agent_bom.output.svg import to_svg

        return to_svg(report, blast_radii)
    # pdf and any unknown/binary format have no stdout representation
    return None


@contextlib.contextmanager
def _enospc_report_fallback(
    con: Any,
    report: AIBOMReport,
    blast_radii: list,
    output_format: str,
    *,
    exclude_unfixable: bool,
    offline_html: bool,
) -> Iterator[None]:
    """Catch a full-disk (or any) failure writing the ``-o`` report.

    The scan has already done all the work and computed its findings; a failed
    report write must NOT crash with a traceback. On ``OSError`` we emit the
    report to stdout when the format allows (so results are never lost), or
    print a clear actionable skip message, then let the normal exit-code path
    run with the scan's real exit code.
    """
    try:
        yield
    except OSError as exc:
        is_full = exc.errno in (errno.ENOSPC, errno.EDQUOT)
        reason = "disk full" if is_full else (exc.strerror or str(exc))
        target = getattr(exc, "filename", None) or "the report file"
        serialized = _stdout_serialization(
            report,
            blast_radii,
            output_format,
            exclude_unfixable=exclude_unfixable,
            offline_html=offline_html,
        )
        if serialized is not None:
            con.print(f"\n  [yellow]⚠[/yellow] Could not write report to {target} ({reason}) — emitting results to stdout instead.")
            sys.stdout.write(serialized)
            if not serialized.endswith("\n"):
                sys.stdout.write("\n")
        else:
            con.print(
                f"\n  [yellow]⚠[/yellow] Could not write report to {target} ({reason}) — "
                f"results shown above. Free space, pass -o to a roomier path, or set "
                f"AGENT_BOM_STATE_DIR=/tmp/agent-bom."
            )


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
    exclude_unfixable: bool = False,
    fixable_only: bool = False,
    agent_mode: bool = False,
    agent_token_budget: int = 0,
    agent_mode_full: bool = False,
    offline_html: bool = False,
    **kwargs: Any,
) -> None:
    """Step 5: render report to console/file. Also Steps 5b, 5c, 5d."""
    con = ctx.con
    report = ctx.report
    blast_radii = ctx.blast_radii
    is_stdout = output == "-"
    compact_page = int(kwargs.get("page") or 1)

    def _emit_report() -> None:
        """All console/stdout/file emission for the report.

        Wrapped so a failed -o file write (e.g. ENOSPC) degrades to stdout
        instead of crashing after the scan already computed its findings.
        """
        if is_stdout:
            # Pipe mode: write clean output to stdout
            if output_format == "cyclonedx":
                sys.stdout.write(json.dumps(to_cyclonedx(report), indent=2))
            elif output_format == "sarif":
                sys.stdout.write(json.dumps(to_sarif(report, exclude_unfixable=exclude_unfixable), indent=2))
            elif output_format == "spdx":
                sys.stdout.write(json.dumps(to_spdx(report), indent=2))
            elif output_format == "spdx2":
                sys.stdout.write(json.dumps(to_spdx2(report), indent=2))
            elif output_format == "html":
                from agent_bom.output import to_html

                sys.stdout.write(to_html(report, blast_radii, offline_assets=offline_html))
            elif output_format == "pdf":
                click.echo("Error: --format pdf requires --output/-o (cannot write PDF to stdout)", err=True)
                sys.exit(2)
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
            elif output_format == "parquet":
                click.echo("Error: --format parquet requires --output/-o (binary Parquet)", err=True)
                sys.exit(2)
            elif output_format == "markdown":
                sys.stdout.write(to_markdown(report, blast_radii))
            elif output_format == "graph-html":
                click.echo("Error: --format graph-html requires --output/-o (cannot write HTML to stdout)", err=True)
                sys.exit(2)
            elif agent_mode:
                payload = success_envelope(
                    command="agents",
                    report_json=to_json(report),
                    exit_code=ctx.exit_code,
                    token_budget=agent_token_budget,
                    full=agent_mode_full,
                    output_path=output if isinstance(output, str) else None,
                )
                sys.stdout.write(dumps_envelope(payload))
            else:
                sys.stdout.write(json.dumps(to_json(report), indent=2))
            sys.stdout.write("\n")
        elif _is_null_device(output) and output_format in ("console", "text", "plain"):
            # `-o /dev/null` with a terminal-only format: discard silently rather
            # than falling through to extension inference (which exited 2 and
            # masked --fail-on-severity). The scan already ran; the policy exit
            # code stands (#3643).
            pass
        elif output_format == "console" and not output:
            _skill_audit_obj = ctx._skill_audit_obj
            if verbose:
                # Full output (--verbose)
                print_section_divider(con, "Report")
                print_summary(report)
                print_scan_performance_summary(report)
                print_posture_summary(report)
                if not no_tree:
                    print_agent_tree(report)
                print_severity_chart(report)
                print_blast_radius(report, fixable_only=fixable_only)
                if not no_tree:
                    print_attack_flow_tree(report)
                print_threat_frameworks(report)
            else:
                # Compact output (default) — verdict-led posture summary.
                print_section_divider(con, "Summary")
                print_compact_summary(report, verbose=verbose)
                print_compact_agents(report)
                print_section_divider(con, "Findings")
                print_compact_blast_radius(report, fixable_only=fixable_only, page=compact_page)

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
                print_section_divider(con, "Remediation")
                print_remediation_plan(report)
                print_section_divider(con, "CIS Posture")
                render_cis_findings_from_context(ctx)
                print_export_hint(report)
            else:
                print_section_divider(con, "Remediation")
                print_compact_remediation(report, page=compact_page)
                print_section_divider(con, "CIS Posture")
                print_compact_cis_posture(report)
                print_compact_export_hint(report)
            print_scan_next_steps(con, report, quiet=quiet)
        elif output_format in ("text", "plain") and not output:
            _print_text(report, blast_radii)
        elif output_format == "json":
            if output in (None, "", "-"):
                sys.stdout.write(json.dumps(to_json(report), indent=2))
                sys.stdout.write("\n")
            else:
                out_path = _resolve_output_path(output, output_format)
                export_json(report, out_path)
                con.print(f"\n  [green]✓[/green] JSON report: {out_path}")
        elif output_format == "cyclonedx":
            out_path = _resolve_output_path(output, output_format)
            export_cyclonedx(report, out_path)
            con.print(f"\n  [green]✓[/green] CycloneDX BOM: {out_path}")
        elif output_format == "sarif":
            out_path = _resolve_output_path(output, output_format)
            export_sarif(report, out_path, exclude_unfixable=exclude_unfixable)
            con.print(f"\n  [green]✓[/green] SARIF report: {out_path}")
            if not quiet:
                con.print("  [dim]SARIF includes enrichment context when available: CVSS/CWE, EPSS, and CISA KEV.[/dim]")
        elif output_format == "spdx":
            out_path = _resolve_output_path(output, output_format)
            export_spdx(report, out_path)
            con.print(f"\n  [green]✓[/green] SPDX 3.0 BOM: {out_path}")
        elif output_format == "spdx2":
            out_path = _resolve_output_path(output, output_format)
            export_spdx2(report, out_path)
            con.print(f"\n  [green]✓[/green] SPDX 2.3 BOM: {out_path}")
        elif output_format == "junit":
            out_path = _resolve_output_path(output, output_format)
            export_junit(report, out_path, blast_radii)
            con.print(f"\n  [green]✓[/green] JUnit XML: {out_path}")
        elif output_format == "csv":
            out_path = _resolve_output_path(output, output_format)
            export_csv(report, out_path, blast_radii)
            con.print(f"\n  [green]✓[/green] CSV report: {out_path}")
        elif output_format == "parquet":
            out_path = _resolve_output_path(output, output_format)
            export_parquet(report, out_path, blast_radii)
            con.print(f"\n  [green]✓[/green] Parquet findings: {out_path}")
        elif output_format == "markdown":
            out_path = _resolve_output_path(output, output_format)
            export_markdown(report, out_path, blast_radii)
            con.print(f"\n  [green]✓[/green] Markdown report: {out_path}")
        elif output_format == "html":
            out_path = _resolve_output_path(output, output_format)
            export_html(report, out_path, blast_radii, offline_assets=offline_html)
            con.print(f"\n  [green]✓[/green] HTML report: {out_path}")
            if open_report:
                import webbrowser

                con.print(f"  [green]✓[/green] Opening report in browser: {out_path}")
                webbrowser.open(f"file://{Path(out_path).resolve()}")
            else:
                con.print(f"  [dim]Open with:[/dim] open {out_path}")
        elif output_format == "pdf":
            out_path = _resolve_output_path(output, output_format)
            export_pdf(report, out_path, blast_radii)
            con.print(f"\n  [green]✓[/green] PDF report: {out_path}")
        elif output_format == "prometheus":
            out_path = _resolve_output_path(output, output_format)
            export_prometheus(report, out_path, blast_radii)
            con.print(f"\n  [green]✓[/green] Prometheus metrics: {out_path}")
            con.print("  [dim]Scrape with node_exporter textfile or push via --push-gateway[/dim]")
        elif output_format == "graph":
            from agent_bom.output.graph import build_graph_elements

            out_path = _resolve_output_path(output, output_format)
            elements = build_graph_elements(report, blast_radii)
            Path(out_path).write_text(json.dumps({"elements": elements, "format": "cytoscape"}, indent=2))
            con.print(f"\n  [green]✓[/green] Graph JSON: {out_path}")
            con.print("  [dim]Cytoscape.js-compatible element list — open with Cytoscape desktop or any JS graph library[/dim]")
        elif output_format == "mermaid":
            out_path = _resolve_output_path(output, output_format)
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

            out_path = _resolve_output_path(output, output_format)
            export_svg(report, blast_radii, out_path)
            con.print(f"\n  [green]✓[/green] SVG diagram: {out_path}")
            con.print("  [dim]Open in any browser or image viewer[/dim]")
        elif output_format == "graph-html":
            from agent_bom.output.graph import export_graph_html

            out_path = _resolve_output_path(output, output_format)
            export_graph_html(report, blast_radii, out_path, offline_assets=offline_html)
            con.print(f"\n  [green]✓[/green] Interactive graph: {out_path}")
            if open_report:
                import webbrowser

                con.print(f"  [green]✓[/green] Opening report in browser: {out_path}")
                webbrowser.open(f"file://{Path(out_path).resolve()}")
            else:
                con.print(f"  [dim]Open with:[/dim] open {out_path}")
        elif output_format == "badge":
            out_path = _resolve_output_path(output, output_format)
            export_badge(report, out_path)
            con.print(f"\n  [green]✓[/green] Badge JSON: {out_path}")
            con.print("  [dim]Use with: https://img.shields.io/endpoint?url=<public-url-to-badge-json>[/dim]")
        elif output_format in ("text", "plain") and output:
            out_path = _resolve_output_path(output, output_format)
            Path(out_path).write_text(_format_text(report, blast_radii))
            con.print(f"\n  [green]✓[/green] Plain text report: {out_path}")
        elif output:
            if output.endswith(".cdx.json"):
                export_cyclonedx(report, output)
            elif output.endswith(".json"):
                export_json(report, output)
            elif output.endswith(".sarif"):
                export_sarif(report, output, exclude_unfixable=exclude_unfixable)
            elif output.endswith(".spdx.json"):
                export_spdx(report, output)
            elif output.endswith(".html"):
                export_html(report, output, blast_radii, offline_assets=offline_html)
            elif output.endswith(".pdf"):
                export_pdf(report, output, blast_radii)
            elif output.endswith(".xml"):
                export_junit(report, output, blast_radii)
            elif output.endswith(".csv"):
                export_csv(report, output, blast_radii)
            elif output.endswith(".parquet"):
                export_parquet(report, output, blast_radii)
            elif output.endswith(".md"):
                export_markdown(report, output, blast_radii)
            else:
                click.echo(
                    f"Cannot infer output format from '{output}'. Use --format explicitly or choose a supported extension.",
                    err=True,
                )
                raise SystemExit(2)
            con.print(f"\n  [green]✓[/green] Report: {output}")

    with _enospc_report_fallback(
        con,
        report,
        blast_radii,
        output_format,
        exclude_unfixable=exclude_unfixable,
        offline_html=offline_html,
    ):
        _emit_report()

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
