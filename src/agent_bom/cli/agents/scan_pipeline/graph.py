"""Stage 8: graph-derived findings, context graph and correlation."""

from __future__ import annotations

import json

import click

from agent_bom.cli._common import logger
from agent_bom.cli.agents.scan_pipeline.options import ScanOptions
from agent_bom.cli.agents.scan_pipeline.state import ScanState


def _surface_graph_findings(opts: ScanOptions, st: ScanState) -> None:
    # ── Graph-derived findings on EVERY scan (surface parity) ───────
    # COMBINATION / CIEM_OVER_PRIVILEGE / NHI derive from the unified graph, not
    # the raw inventory. Surface them on the default path too — not only under
    # --context-graph — so the CLI emits the same finding categories as the API
    # and MCP surfaces (all three call one shared build+attach helper). The
    # unified stream (report.to_findings()) is the single source of truth for the
    # toxic COMBINATION count, so the printed count can never contradict it.
    st.scan_graph_surface = None
    if st.agents:
        from agent_bom.cli._tenant import resolve_cli_tenant_id as _resolve_cli_tenant_id
        from agent_bom.graph.scan_findings import surface_graph_derived_findings

        st.scan_graph_surface = surface_graph_derived_findings(
            st.report,
            scan_id=st.scan_id,
            tenant_id=_resolve_cli_tenant_id(),
            include_dependency_reachability=True,
        )
        if not opts.quiet:
            # Non-zero counts here are bad news — warn, don't checkmark.
            _n_toxic = len(st.report.toxic_combination_findings_data or [])
            _n_nhi = len(st.report.nhi_governance_findings or [])
            _n_ciem = len(st.report.ciem_over_privilege_findings_data or [])
            if _n_toxic:
                st.con.print(f"  [yellow]⚠[/yellow] Toxic combinations: {_n_toxic} finding(s)")
            if _n_nhi:
                st.con.print(f"  [yellow]⚠[/yellow] NHI governance: {_n_nhi} finding(s)")
            if _n_ciem:
                st.con.print(f"  [yellow]⚠[/yellow] CIEM over-privilege: {_n_ciem} finding(s)")
            if opts.verbose and (_n_toxic or _n_nhi or _n_ciem):
                from agent_bom.finding import FindingSource as _FindingSource

                for _gf in st.report.to_findings():
                    if _gf.source is _FindingSource.GRAPH_ANALYSIS:
                        st.con.print(f"      [dim]{str(_gf.severity).upper()}[/dim] {_gf.title}")


def _build_context_graph(opts: ScanOptions, st: ScanState) -> None:
    # ── Context graph: lateral movement analysis ────────────────────
    # Build whenever requested — credential exposure and tool-reach edges exist
    # independent of any CVE, so gating on blast_radii would hide the credential
    # graph for vulnerability-free estates.
    if opts.context_graph_flag:
        from agent_bom.context_graph import (
            build_context_graph,
            collect_lateral_paths,
            compute_interaction_risks,
            to_serializable,
        )
        from agent_bom.output import to_json as _to_json_for_graph

        _graph_json = _to_json_for_graph(st.report)
        _cg = build_context_graph(_graph_json["agents"], _graph_json.get("blast_radius", []))
        _all_paths, _paths_truncated = collect_lateral_paths(
            _cg,
            (f"agent:{_a.name}" for _a in st.agents),
        )
        _cg_risks = compute_interaction_risks(_cg)
        st.report.context_graph_data = to_serializable(_cg, _all_paths, _cg_risks)
        st.report.context_graph_data["stats"]["lateral_paths_truncated"] = _paths_truncated

        from agent_bom.graph_backend import from_context_graph as _from_cg

        _gb = _from_cg(st.report.context_graph_data, backend=opts.graph_backend)
        _centrality = _gb.centrality_scores()
        _bottleneck_analysis = _gb.bottleneck_analysis(top_n=5)
        _bottlenecks = _bottleneck_analysis.nodes
        if st.report.context_graph_data is not None:
            st.report.context_graph_data["centrality"] = _centrality
            st.report.context_graph_data["bottleneck_nodes"] = [{"id": nid, "score": score} for nid, score in _bottlenecks]
            # Betweenness over an estate graph is approximated from a bounded
            # source sample; ship the sample size with the ranking so no
            # downstream reader mistakes it for an exhaustive traversal.
            st.report.context_graph_data["bottleneck_provenance"] = {
                "sampled": _bottleneck_analysis.sampled,
                "sampled_sources": _bottleneck_analysis.sampled_sources,
                "total_nodes": _bottleneck_analysis.total_nodes,
            }
            st.report.context_graph_data["stats"]["graph_backend"] = type(_gb).__name__

        _n_paths = len(_all_paths)
        _n_risks = len(_cg_risks)
        _n_bottlenecks = len(_bottlenecks)
        _bottleneck_qualifier = (
            f" (sampled {_bottleneck_analysis.sampled_sources} of {_bottleneck_analysis.total_nodes} sources)"
            if _bottleneck_analysis.sampled
            else ""
        )
        st.con.print(
            f"  [green]✓[/green] Context graph: {len(_cg.nodes)} nodes, {_n_paths} lateral path(s), "
            f"{_n_risks} risk pattern(s), {_n_bottlenecks} bottleneck(s){_bottleneck_qualifier}"
        )

        # ── Persist full unified graph (all entity types) ────────────
        try:
            from agent_bom.cli._tenant import resolve_cli_tenant_id as _resolve_cli_tenant_id
            from agent_bom.db.graph_store import default_graph_db_path, open_graph_db, save_graph
            from agent_bom.graph.builder import build_unified_graph_from_report

            # Graph-derived findings (COMBINATION / NHI / CIEM) are surfaced
            # un-gated above, so every scan surface stays at parity. Here the
            # unified graph is (re)built only to persist the full snapshot to the
            # local graph DB — a --context-graph-only side effect.
            _ug = build_unified_graph_from_report(_graph_json, scan_id=st.scan_id, tenant_id=_resolve_cli_tenant_id())

            _graph_db_path = default_graph_db_path()
            _graph_db_path.parent.mkdir(parents=True, exist_ok=True)
            with open_graph_db(_graph_db_path) as _gconn:
                save_graph(_gconn, _ug)
            st.con.print(f"  [green]✓[/green] Graph persisted ({len(_ug.nodes)} nodes, scan {st.scan_id[:8]}…)")
        except Exception as _graph_err:  # noqa: BLE001
            import logging as _glog

            _glog.getLogger(__name__).debug("Graph persistence skipped: %s", _graph_err)


def _set_workstation_scopes(opts: ScanOptions, st: ScanState) -> None:
    if opts.preset == "workstation":
        from agent_bom.endpoint import workstation_scan_scopes

        _browser_extension_count = len((st.ctx._browser_ext_results or {}).get("extensions", []))
        _context_graph_node_count = len((st.report.context_graph_data or {}).get("nodes", []))
        st.report.scan_run.set_scopes(
            workstation_scan_scopes(
                agents=st.agents,
                browser_extension_count=_browser_extension_count,
                context_graph_node_count=_context_graph_node_count,
                endpoint_inventory=st.report.endpoint_inventory_data,
            )
        )


def _check_licenses(opts: ScanOptions, st: ScanState) -> None:
    # ── License compliance check ─────────────────────────────────────
    if opts.license_check and st.agents:
        from agent_bom.license_policy import evaluate_license_policy, print_license_report
        from agent_bom.license_policy import to_serializable as _lic_to_ser

        _lic_policy = None
        if opts.policy:
            import json as _lic_json

            try:
                with open(opts.policy) as _pf:
                    _raw_policy = _lic_json.load(_pf)
                    _lic_policy = {k: v for k, v in _raw_policy.items() if k.startswith("license_")}
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                logger.debug("Could not load license policy file, using defaults: %s", exc)
        _lic_report = evaluate_license_policy(st.agents, policy=_lic_policy if _lic_policy else None)
        st.report.license_report = _lic_to_ser(_lic_report)
        if not opts.quiet and opts.output_format == "console":
            print_license_report(_lic_report, st.con)
        elif not opts.quiet:
            _f_count = len(_lic_report.findings)
            _cov = _lic_report.coverage
            _status = {"compliant": "[green]compliant[/green]", "non_compliant": "[red]non-compliant[/red]"}.get(
                _lic_report.status, "[yellow]undetermined[/yellow]"
            )
            st.con.print(
                f"  [green]✓[/green] License check: {_lic_report.total_packages} packages, {_f_count} finding(s), {_status} "
                f"({_cov['percent']}% license coverage)"
            )


def _apply_vex(opts: ScanOptions, st: ScanState) -> None:
    # ── VEX support ──────────────────────────────────────────────────
    if opts.vex_path and st.agents:
        from agent_bom.vex import apply_vex, load_vex
        from agent_bom.vex import to_serializable as _vex_to_ser

        try:
            _vex_doc = load_vex(opts.vex_path)
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc
        _vex_count = apply_vex(st.report, _vex_doc)
        st.report.vex_data = _vex_to_ser(_vex_doc)
        if not opts.quiet:
            st.con.print(f"  [green]✓[/green] VEX applied: {_vex_count} vulnerabilities updated from {opts.vex_path}")


def _detect_toxic_combinations(opts: ScanOptions, st: ScanState) -> None:
    # ── Toxic combination detection ──────────────────────────────────
    if st.report.blast_radii and (opts.enrich or opts.preset == "enterprise"):
        from agent_bom.toxic_combos import detect_toxic_combinations as _detect_toxic
        from agent_bom.toxic_combos import prioritize_findings as _prioritize
        from agent_bom.toxic_combos import to_serializable as _toxic_ser

        # The legacy detector still feeds graph TRIGGERS edges (builder reads
        # report.toxic_combinations) and prioritized_findings, but it is NOT a
        # user-facing count: the single honest toxic number is the COMBINATION
        # category in the unified stream, printed once above from the graph
        # evaluator. Printing len(_toxic) here would resurrect the contradictory
        # "11 vs 5 vs 0" console output the 2026-07-19 audit flagged.
        _toxic = _detect_toxic(st.report, context_graph_data=st.report.context_graph_data)
        st.report.toxic_combinations = _toxic_ser(_toxic)
        st.report.prioritized_findings = _prioritize(st.report.blast_radii, _toxic)


def run_graph(opts: ScanOptions, st: ScanState) -> None:
    """Surface graph-derived findings and run the optional graph analyses."""
    _surface_graph_findings(opts, st)
    _build_context_graph(opts, st)
    _set_workstation_scopes(opts, st)
    _check_licenses(opts, st)
    _apply_vex(opts, st)
    _detect_toxic_combinations(opts, st)
