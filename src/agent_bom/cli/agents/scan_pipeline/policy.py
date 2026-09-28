"""Stage 10: AI enrichment, remediation, suppression and reachability stamping."""

from __future__ import annotations

import time as _time
from pathlib import Path

import click

from agent_bom.cli.agents.scan_pipeline.options import ScanOptions
from agent_bom.cli.agents.scan_pipeline.state import ScanState


def _run_ai_enrichment(opts: ScanOptions, st: ScanState) -> None:
    # Step 4c: AI-powered enrichment (optional)
    _skill_result_obj = st.ctx._skill_result_obj
    _skill_audit_obj = st.ctx._skill_audit_obj
    if opts.ai_enrich:
        from agent_bom.ai_enrich import run_ai_enrichment_sync

        run_ai_enrichment_sync(
            st.report,
            model=opts.ai_model,
            skill_result=_skill_result_obj,
            skill_audit=_skill_audit_obj,
            deterministic=opts.ai_deterministic,
            gate_ai_findings=opts.ai_gate_findings,
        )

        if _skill_audit_obj:
            st.ctx.skill_audit_data = {
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
                        "ai_analysis": f.ai_analysis,
                        "ai_adjusted_severity": f.ai_adjusted_severity,
                        "ai_source": f.ai_source,
                        "ai_model": f.ai_model,
                        "ai_confidence": f.ai_confidence,
                        "ai_detected": f.ai_detected,
                    }
                    for f in _skill_audit_obj.findings
                ],
                "packages_checked": _skill_audit_obj.packages_checked,
                "servers_checked": _skill_audit_obj.servers_checked,
                "credentials_checked": _skill_audit_obj.credentials_checked,
                "passed": _skill_audit_obj.passed,
                "deterministic_passed": _skill_audit_obj.deterministic_passed,
                "ai_gate_enabled": _skill_audit_obj.ai_gate_enabled,
                "ai_skill_summary": _skill_audit_obj.ai_skill_summary,
                "ai_overall_risk_level": _skill_audit_obj.ai_overall_risk_level,
            }
            st.report.skill_audit_data = st.ctx.skill_audit_data
            from agent_bom.parsers.skill_audit import replace_skill_findings

            replace_skill_findings(st.report, st.ctx.skill_audit_data)


def _write_remediation(opts: ScanOptions, st: ScanState) -> None:
    # Step 4d: Generate remediation files (optional)
    if opts.remediate_path or opts.remediate_sh_path:
        from agent_bom.remediate import export_remediation_md, export_remediation_sh, generate_remediation

        remed_plan = generate_remediation(st.report, st.blast_radii)
        if opts.remediate_path:
            export_remediation_md(remed_plan, opts.remediate_path)
            st.con.print(f"\n  [green]✓[/green] Remediation plan: {opts.remediate_path}")
        if opts.remediate_sh_path:
            export_remediation_sh(remed_plan, opts.remediate_sh_path)
            st.con.print(f"\n  [green]✓[/green] Remediation script: {opts.remediate_sh_path}")


def _apply_fixes(opts: ScanOptions, st: ScanState) -> None:
    # Step 4e: Auto-apply fixes (optional)
    if opts.apply_fixes_flag or opts.apply_dry_run:
        from agent_bom.remediate import apply_fixes as _apply_fixes
        from agent_bom.remediate import generate_remediation as _gen_remed

        remed_plan = _gen_remed(st.report, st.blast_radii)
        if remed_plan.package_fixes:
            project_dirs: list[Path] = []
            for agent in st.agents:
                if agent.config_path:
                    agent_config_dir = Path(agent.config_path).parent
                    for candidate_dir in [agent_config_dir, agent_config_dir.parent, agent_config_dir.parent.parent]:
                        if (candidate_dir / "package.json").exists() or (candidate_dir / "requirements.txt").exists():
                            if candidate_dir not in project_dirs:
                                project_dirs.append(candidate_dir)
                            break
            cwd = Path.cwd()
            if cwd not in project_dirs and ((cwd / "package.json").exists() or (cwd / "requirements.txt").exists()):
                project_dirs.append(cwd)

            if project_dirs:
                ar = _apply_fixes(remed_plan, project_dirs, dry_run=opts.apply_dry_run)
                if ar.dry_run:
                    st.con.print("\n  [yellow]Dry run — no files modified[/yellow]")
                for fix in ar.applied:
                    st.con.print(f"  [green]✓[/green] {fix.package} {fix.current_version} → {fix.fixed_version} ({fix.ecosystem})")
                for fix in ar.skipped:
                    st.con.print(f"  [dim]  Skipped {fix.package} — no {fix.ecosystem} dependency file found[/dim]")
                if ar.backed_up:
                    st.con.print(f"\n  Backups: {', '.join(ar.backed_up)}")
            else:
                st.con.print("\n  [yellow]⚠ No project directories with dependency files found for --apply[/yellow]")
        else:
            st.con.print("\n  [green]✓[/green] No fixable vulnerabilities — nothing to apply")


def _correlate_runtime(opts: ScanOptions, st: ScanState) -> None:
    # Step 4f: Runtime ↔ scan correlation (optional)
    if opts.correlate_log and st.blast_radii:
        from agent_bom.runtime_correlation import correlate as _correlate_runtime

        try:
            _corr_report = _correlate_runtime(st.blast_radii, audit_log_path=opts.correlate_log)
            st.report.runtime_correlation = _corr_report.to_dict()
            if _corr_report.vulnerable_tools_called > 0:
                st.con.print(
                    f"\n  [red]⚠[/red] Runtime correlation: "
                    f"{_corr_report.vulnerable_tools_called} vulnerable tool(s) were actually called "
                    f"(out of {_corr_report.unique_tools_called} unique tools in audit log)"
                )
                for cf in _corr_report.correlated_findings[:5]:
                    st.con.print(
                        f"    [red]●[/red] {cf.vulnerability_id} → tool:{cf.tool_name} "
                        f"(called {cf.call_count}x, risk {cf.original_risk_score:.1f}→{cf.correlated_risk_score:.1f})"
                    )
            else:
                st.con.print(
                    f"\n  [green]✓[/green] Runtime correlation: "
                    f"no vulnerable tools were called ({_corr_report.unique_tools_called} tools in audit log)"
                )

            # Observe→enforce: propose gateway block rules for tools that are BOTH
            # confirmed-vulnerable and actively invoked. Default = propose only
            # (audit-mode policy = advisory warn); an enforce-mode policy is emitted
            # only under the explicit AGENT_BOM_ENFORCE_CORRELATED_BLOCKS opt-in.
            import os as _os

            from agent_bom.observe_enforce import propose_block_rules

            _enforce_optin = _os.environ.get("AGENT_BOM_ENFORCE_CORRELATED_BLOCKS", "").strip().lower() in (
                "1",
                "true",
                "yes",
                "on",
            )
            _oe = propose_block_rules(_corr_report, enforce=_enforce_optin)
            if isinstance(st.report.runtime_correlation, dict):
                st.report.runtime_correlation["observe_enforce"] = _oe.to_dict()
            if _oe.proposals:
                _mode_label = "ENFORCE (opt-in)" if _oe.enforced else "propose-only (audit)"
                st.con.print(f"\n  [yellow]⚑[/yellow] Observe→enforce: {len(_oe.proposals)} gateway block-rule proposal(s) [{_mode_label}]")
                for _p in _oe.proposals[:5]:
                    st.con.print(
                        f"    [yellow]▸[/yellow] block tool:{_p.tool_name} — {', '.join(_p.vulnerability_ids)} (called {_p.call_count}x)"
                    )
                if not _oe.enforced:
                    st.con.print(
                        "    [dim]Advisory only. Set AGENT_BOM_ENFORCE_CORRELATED_BLOCKS=1 to emit an "
                        "enforce-mode policy for review before import.[/dim]"
                    )
        except Exception as exc:  # noqa: BLE001
            st.con.print(f"\n  [yellow]⚠[/yellow] Runtime correlation failed: {type(exc).__name__}")


def _apply_ignores(opts: ScanOptions, st: ScanState) -> None:
    # Apply ignore/allowlist file (.agent-bom-ignore.yaml or --ignore-file)
    from agent_bom.ignores import apply_ignores, load_ignore_file

    try:
        _ignore_entries = st.validated_ignore_entries if st.validated_ignore_entries is not None else load_ignore_file(opts.ignore_file)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    if _ignore_entries:
        st.blast_radii, _suppressed = apply_ignores(st.blast_radii, _ignore_entries)
        if _suppressed and not opts.quiet:
            st.con.print(f"\n  [dim]Suppressed {_suppressed} finding(s) via ignore file[/dim]")
        # Rebuild report.blast_radii to reflect suppressions
        st.report.blast_radii = st.blast_radii

    # `--exclude-unfixable` drops vulnerabilities that have no available fix from
    # the report, the console/JSON output, and the --fail-on-severity gate. A
    # finding with no upstream fix cannot be remediated by an upgrade, so this is
    # the gate-level equivalent of an "ignore unfixed" policy. (SARIF export also
    # honours the flag independently via to_sarif().)
    if opts.exclude_unfixable:
        from agent_bom.ignores import drop_unfixable

        st.blast_radii, _dropped_unfixed = drop_unfixable(st.blast_radii)
        st.report.blast_radii = st.blast_radii
        if _dropped_unfixed and not opts.quiet:
            st.con.print(f"\n  [dim]Excluded {_dropped_unfixed} unfixable finding(s) (no upstream fix available)[/dim]")

    st.ctx.step_timings["scanning"] = _time.monotonic() - st.step_t0


def _stamp_reachability(opts: ScanOptions, st: ScanState) -> None:
    # Stamp structural dependency closure (`dependency_reachable*`),
    # evidence-backed `graph_reachable*` from the scan graph's attack paths
    # (the same rule the findings API applies; topology-only paths stay null),
    # and function-level symbol reach onto each blast-radius row. Wrapped in
    # try/except so a graph build failure never breaks `agent-bom agents`.
    try:
        from agent_bom.graph.blast_reach import (
            apply_dependency_reachability_to_blast_radii,
            apply_graph_path_reachability_to_blast_radii,
            apply_symbol_reachability_to_blast_radii,
            resync_cve_findings_from_blast_radii,
        )

        apply_dependency_reachability_to_blast_radii(
            st.blast_radii,
            st.agents,
            rescore=True,
            reachability_report=st.scan_graph_surface.dependency_reachability if st.scan_graph_surface else None,
        )
        if st.scan_graph_surface is not None:
            apply_graph_path_reachability_to_blast_radii(st.blast_radii, st.scan_graph_surface.attack_paths)
        # Join AST function-level symbol reach to CVE affected-symbols so each
        # Python finding carries a function_reachable / package_reachable /
        # unreachable signal. No-op when no Python entrypoints were analysed.
        if st.ast_result_for_reach is not None:
            apply_symbol_reachability_to_blast_radii(
                st.blast_radii,
                st.ast_result_for_reach,
                packages=st.all_packages,
            )
        # The dual-write `report.findings` was materialized before the stamping
        # above, so its CVE findings still carry null reachability. Re-project the
        # stamped rows onto them so the JSON `findings[]` view agrees with
        # `blast_radius[]`, CSV, Parquet, and SARIF.
        resync_cve_findings_from_blast_radii(st.report.findings, st.blast_radii)
    except Exception:  # noqa: BLE001
        # Reachability is best-effort enrichment — don't let it fail the scan.
        pass


def _generate_vex(opts: ScanOptions, st: ScanState) -> None:
    # Generate VEX only after dependency/function reachability has been
    # stamped and CVE findings have been resynchronized. Otherwise automatic
    # ``not_affected`` decisions can never use symbol execution evidence.
    if opts.generate_vex_flag and st.report.blast_radii:
        from agent_bom.vex import export_openvex, generate_vex
        from agent_bom.vex import to_serializable as _vex_to_ser

        _vex_doc = generate_vex(st.report, auto_triage=True)
        st.report.vex_data = _vex_to_ser(_vex_doc)
        _vex_out = opts.vex_output_path or "agent-bom.vex.json"
        import json as _vex_json

        with open(_vex_out, "w") as _vf:
            _vex_json.dump(export_openvex(_vex_doc), _vf, indent=2)
        if not opts.quiet:
            _n_stmts = len(_vex_doc.statements)
            st.con.print(f"  [green]✓[/green] VEX generated: {_n_stmts} statements → {_vex_out}")


def run_policy(opts: ScanOptions, st: ScanState) -> None:
    """AI enrichment, remediation, suppressions, reachability stamping and VEX."""
    _run_ai_enrichment(opts, st)
    _write_remediation(opts, st)
    _apply_fixes(opts, st)
    _correlate_runtime(opts, st)
    _apply_ignores(opts, st)
    _stamp_reachability(opts, st)
    _generate_vex(opts, st)
