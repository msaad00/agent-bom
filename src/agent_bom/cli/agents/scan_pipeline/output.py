"""Stage 11: finalize the canonical projection and render every output."""

from __future__ import annotations

import time as _time
from pathlib import Path
from typing import Any

from agent_bom.cli._common import logger
from agent_bom.cli.agents._output import render_output
from agent_bom.cli.agents._posture import render_posture_summary
from agent_bom.cli.agents.scan_pipeline.options import ScanOptions
from agent_bom.cli.agents.scan_pipeline.state import ScanState, StopScan
from agent_bom.output import print_diff


def _scan_cmd_to_json(report: Any) -> dict[str, Any]:
    """Project through ``scan_cmd.to_json`` so callers observing it see every projection."""
    from agent_bom.cli.agents import scan_cmd

    return scan_cmd.to_json(report)


def _finalize_report(opts: ScanOptions, st: ScanState) -> None:
    # Attach blast_radii and report to context for downstream phases
    st.ctx.blast_radii = st.blast_radii
    st.ctx.report = st.report

    st.current_report_json = _scan_cmd_to_json(st.report)

    # Step 4h: Delta mode must run before rendering so JSON/SARIF artifacts
    # and CI exit gates both reflect the same new-only finding set.
    if opts.delta_mode:
        from agent_bom.scan_delta import compute_delta, load_baseline

        _baseline_path = opts.baseline
        if not _baseline_path:
            from agent_bom.scan_delta import default_baseline_path

            _default_baseline = default_baseline_path()
            if _default_baseline.exists():
                _baseline_path = str(_default_baseline)
            else:
                logger.warning(
                    "Delta mode requested but no --baseline file specified and no auto-baseline found at %s. Skipping delta filter.",
                    _default_baseline,
                )

        if _baseline_path:
            try:
                _baseline_data = load_baseline(_baseline_path)
                _delta_result = compute_delta(st.current_report_json, _baseline_data)
                _delta_result.baseline_path = _baseline_path
                st.ctx.delta_result = _delta_result
                st.report.delta_data = {
                    "enabled": True,
                    "new_count": _delta_result.new_count,
                    "pre_existing_count": _delta_result.pre_existing_count,
                    "baseline_path": _baseline_path,
                }

                _new_keys = {(d.get("vulnerability_id", "").upper(), d.get("package", "")) for d in _delta_result.new_items}
                st.blast_radii = [
                    br for br in st.blast_radii if (br.vulnerability.id.upper(), f"{br.package.name}@{br.package.version}") in _new_keys
                ]
                st.report.blast_radii = st.blast_radii
                if st.report.findings:
                    from agent_bom.finding import FindingType

                    _new_cve_ids = {d.get("vulnerability_id", "").upper() for d in _delta_result.new_items}
                    st.report.findings = [
                        finding
                        for finding in st.report.findings
                        if finding.finding_type != FindingType.CVE or str(finding.cve_id or "").upper() in _new_cve_ids
                    ]
                st.ctx.blast_radii = st.blast_radii
                st.current_report_json = _scan_cmd_to_json(st.report)

                if not opts.quiet:
                    from rich.console import Console as _Console

                    _Console().print(f"\n[bold]Delta:[/bold] {_delta_result.summary_line()} (baseline: {_baseline_path})\n")
            except (FileNotFoundError, ValueError) as exc:
                logger.warning("Delta baseline error: %s — skipping delta filter", exc)

    st.ctx.report_json = st.current_report_json


def _print_totals_and_record(opts: ScanOptions, st: ScanState) -> None:
    if not opts.quiet:
        # Print only after late scanners, AI enrichment, and filters finalize
        # the report, so every machine surface shares these severity totals.
        _unified = st.report.to_findings()
        if _unified:
            _u_counts: dict[str, int] = {}
            for _uf in _unified:
                _u_sev = str(_uf.effective_severity() or "unknown").lower()
                _u_counts[_u_sev] = _u_counts.get(_u_sev, 0) + 1
            _u_order = ["critical", "high", "medium", "low", "unknown"]
            _u_color = {
                "critical": "red bold",
                "high": "red",
                "medium": "yellow",
                "low": "blue",
                "unknown": "dim",
            }
            _u_str = " · ".join(f"[{_u_color[s]}]{_u_counts[s]} {s}[/{_u_color[s]}]" for s in _u_order if s in _u_counts)
            st.con.print(f"  [red]⚠[/red] Findings — {_u_str} [dim](all finding categories)[/dim]")

    if not opts.save_report:
        try:
            from agent_bom.db.local_analytics import record_scan_report_best_effort

            record_scan_report_best_effort(st.current_report_json, source="cli")
        except Exception as exc:  # pragma: no cover - best-effort analytics must never break scans
            logger.debug("Local analytics persistence failed: %s", exc, exc_info=True)


def _render(opts: ScanOptions, st: ScanState) -> None:
    import agent_bom.output as _out
    import agent_bom.output.console_render as _console_render

    # Step 5: Output
    st.step_t0 = _time.monotonic()
    _posture_console_only = opts.posture and opts.output_format == "console" and not opts.output
    if not _posture_console_only and not opts.agent_mode:
        _render_con = st.report_con if opts.output_format == "console" and not opts.output else st.con
        st.ctx.con = _render_con
        _out.console = _render_con
        _console_render.console = _render_con
        try:
            render_output(
                st.ctx,
                output=opts.output,
                output_format=opts.output_format,
                no_tree=opts.no_tree,
                quiet=opts.quiet,
                no_color=opts.no_color,
                open_report=opts.open_report,
                offline_html=opts.offline_html,
                compliance_export=opts.compliance_export,
                mermaid_mode=opts.mermaid_mode,
                push_gateway=opts.push_gateway,
                otel_endpoint=opts.otel_endpoint,
                baseline=opts.baseline,
                delta_mode=opts.delta_mode,
                verbose=opts.verbose,
                exclude_unfixable=opts.exclude_unfixable,
                fixable_only=opts.fixable_only,
                agent_mode=opts.agent_mode,
                agent_token_budget=opts.agent_token_budget,
                agent_mode_full=opts.agent_mode_full,
                page=opts.page,
            )
        finally:
            st.ctx.con = st.con
            _out.console = st.con
            _console_render.console = st.con


def _record_adoption_and_nudge(opts: ScanOptions, st: ScanState) -> None:
    from agent_bom.db.adoption_events import record_scan_completion_best_effort

    _artifact_type = (
        opts.output_format if opts.output_format in {"json", "sarif", "cyclonedx", "spdx", "html", "markdown", "graph"} else None
    )
    _adoption_outcome = str((st.current_report_json.get("scan_run") or {}).get("outcome") or "complete")
    record_scan_completion_best_effort(outcome=_adoption_outcome, artifact_type=_artifact_type)

    # ── First-run nudge: offline scan with no local advisory data ─────────────
    # A clean install running `scan … --offline` with no synced advisory DB
    # reports "0 vulns / PARTIAL COVERAGE" — alarming and unexplained. Surface an
    # actionable line right under the summary so the empty result reads as a
    # setup gap, not a clean bill of health. Console output only (machine formats
    # stay clean) and never in demo mode, which ships a bundled advisory DB.
    if (
        opts.offline
        and not opts.demo
        and not opts.quiet
        and not opts.agent_mode
        and opts.output_format == "console"
        and not opts.output
        and st.vuln_freshness is not None
        and st.vuln_freshness.mode == "offline"
        and st.vuln_freshness.record_count == 0
    ):
        st.con.print("[yellow]No local advisory DB — run 'agent-bom db update' (or drop --offline). Coverage may be incomplete.[/yellow]")


def _render_posture(opts: ScanOptions, st: ScanState) -> None:
    # ── Posture summary mode (--posture) ──────────────────────────────────────
    if opts.posture:
        render_posture_summary(st.agents, st.blast_radii)
        raise StopScan


def _save_history(opts: ScanOptions, st: ScanState) -> None:
    # Step 6: Save report to history + asset tracking. History saving owns the
    # analytics write for ``--save`` scans; ordinary scans were mirrored once
    # above. This keeps one persisted run per CLI invocation.
    if opts.save_report:
        from agent_bom.history import save_report as _save

        saved_path = _save(st.current_report_json)
        st.con.print(f"\n  [green]✓[/green] Report saved to history: {saved_path}")

        try:
            from agent_bom.asset_tracker import AssetTracker

            tracker = AssetTracker()
            asset_diff = tracker.record_scan(st.current_report_json)
            summary = asset_diff["summary"]
            parts = []
            if summary["new_count"]:
                parts.append(f"[red]{summary['new_count']} new[/red]")
            if summary["resolved_count"]:
                parts.append(f"[green]{summary['resolved_count']} resolved[/green]")
            if summary["reopened_count"]:
                parts.append(f"[yellow]{summary['reopened_count']} reopened[/yellow]")
            if parts:
                st.con.print(f"  [green]✓[/green] Asset tracker: {', '.join(parts)} ({summary['total_open']} open)")
            else:
                st.con.print(f"  [green]✓[/green] Asset tracker: {summary['total_open']} open (no changes)")
            tracker.close()
        except Exception as exc:
            logger.debug("Asset tracking failed: %s", exc, exc_info=True)


def _diff_baseline(opts: ScanOptions, st: ScanState) -> None:
    # Step 7: Diff against baseline
    if opts.baseline:
        from agent_bom.history import diff_reports
        from agent_bom.scan_delta import load_baseline

        baseline_data = load_baseline(Path(opts.baseline))
        diff = diff_reports(baseline_data, st.current_report_json)
        print_diff(diff)

    st.ctx.step_timings["output"] = _time.monotonic() - st.step_t0


def _print_completion(opts: ScanOptions, st: ScanState) -> None:
    # Scan completion divider
    _elapsed = _time.monotonic() - st.scan_start
    if opts.output_format == "console" and not opts.output and not opts.quiet:
        from rich.rule import Rule

        from agent_bom.evidence.scan_run import ScanOutcome, effective_scan_run

        _execution_outcome = effective_scan_run(st.report).outcome
        _completion_label = {
            ScanOutcome.COMPLETE: "Scan Complete",
            ScanOutcome.PARTIAL: "Scan Partial",
            ScanOutcome.FAILED: "Scan Failed",
        }[_execution_outcome]
        _completion_style = {
            ScanOutcome.COMPLETE: "green" if not st.blast_radii else "yellow",
            ScanOutcome.PARTIAL: "yellow",
            ScanOutcome.FAILED: "red",
        }[_execution_outcome]
        st.con.print()
        st.con.print(Rule(f"{_completion_label} — {_elapsed:.1f}s", style=_completion_style))

        # Per-step timing breakdown
        _timings = st.ctx.step_timings
        _timing_parts = []
        for _step_name in ("db refresh", "discovery", "cloud", "extraction", "scanning", "output"):
            _t = _timings.get(_step_name, 0.0)
            if _t >= 0.1:
                _timing_parts.append(f"{_step_name}: {_t:.1f}s")
        if _timing_parts:
            _breakdown = " · ".join(_timing_parts)
            st.con.print(f"  [dim]{_breakdown}[/dim]")

        # Concise next-step hint (1-2 lines max)
        if st.blast_radii:
            _fixable = sum(1 for br in st.blast_radii if br.vulnerability.fixed_version)
            if _fixable:
                st.con.print(
                    f"\n  [green]→[/green] {_fixable} fixable — [bold]-f html[/bold] for full report · [bold]--verbose[/bold] for details"
                )
        elif (
            _execution_outcome is ScanOutcome.COMPLETE
            and not opts.no_scan
            and st.total_packages > 0
            and st.report.total_vulnerabilities == 0
            and not [f for f in st.report.to_findings() if f.finding_type.value != "CVE"]
        ):
            st.con.print("\n  [green]→[/green] no vulnerabilities found — supply chain looks clean")


def run_output(opts: ScanOptions, st: ScanState) -> None:
    """Finalize the canonical projection, render, persist and summarize."""
    _finalize_report(opts, st)
    _print_totals_and_record(opts, st)
    _render(opts, st)
    _record_adoption_and_nudge(opts, st)
    _render_posture(opts, st)
    _save_history(opts, st)
    _diff_baseline(opts, st)
    _print_completion(opts, st)
