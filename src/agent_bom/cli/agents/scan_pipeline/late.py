"""Stage 9: AI-asset scanners that attach to the built report."""

from __future__ import annotations

from typing import Any

from agent_bom.cli._common import logger
from agent_bom.cli.agents.scan_pipeline.options import ScanOptions
from agent_bom.cli.agents.scan_pipeline.state import ScanState
from agent_bom.scanners import consume_coverage_warnings


def _detect_model_dirs(opts: ScanOptions, st: ScanState) -> None:
    # ── Step 1i: Model binary file scan ─────────────────────────────
    # Auto-detect: if no --model-dirs given, check project dir for model files
    if not opts.skill_only and not opts.no_discover and not opts.model_dirs and opts.project:
        from pathlib import Path as _MPath

        _project_path = _MPath(opts.project)
        _model_exts = {".safetensors", ".gguf", ".onnx", ".pt", ".pkl", ".h5", ".keras"}
        _has_models = any(_project_path.rglob(f"*{ext}") for ext in _model_exts if list(_project_path.rglob(f"*{ext}"))[:1])
        if _has_models:
            opts.model_dirs = (opts.project,)
            st.con.print("  [cyan]>[/cyan] Auto-detected model files in project — scanning...")


def _record_model_coverage_gaps(st: ScanState, mf_results: list[Any], warnings: list[str]) -> None:
    from agent_bom.evidence.scan_run import ScanIssue

    # Refused/missing scan roots and bounded pickle analysis are
    # coverage facts, not merely console warnings.  Preserve them on
    # scan_run so JSON/SARIF and the process exit fail closed together.
    for _model_warning in warnings:
        if _model_warning.startswith(("Model scan:", "Model manifest scan:")):
            st.report.scan_run.add_issue(
                ScanIssue(
                    code="scanner_coverage_gap",
                    stage="scanning",
                    source="model-scan",
                    message=_model_warning,
                    affects_coverage=True,
                )
            )
    _incomplete_model_flags = {
        "TRUNCATED_PICKLE_UNSCANNED",
        "OVERSIZE_PICKLE_UNSCANNED",
        "PICKLE_SCAN_ERROR",
    }
    for _model_result in mf_results:
        for _model_flag in _model_result.get("security_flags", []) or []:
            _flag_type = str(_model_flag.get("type") or "")
            if _flag_type in _incomplete_model_flags:
                st.report.scan_run.add_issue(
                    ScanIssue(
                        code="scanner_coverage_gap",
                        stage="scanning",
                        source="model-scan",
                        message=f"Model artifact analysis incomplete: {_flag_type}",
                        affects_coverage=True,
                    )
                )


def _scan_model_files(opts: ScanOptions, st: ScanState) -> None:
    if not opts.skill_only and opts.model_dirs:
        from agent_bom.model_files import (
            check_sigstore_signature,
            model_file_findings,
            scan_model_files,
            scan_model_manifests,
            verify_model_hash,
        )

        for mdir in opts.model_dirs:
            st.con.print(f"  [cyan]>[/cyan] Scanning for model files in {mdir}...")
            mf_results, mf_warnings = scan_model_files(mdir)
            manifest_results, manifest_warnings = scan_model_manifests(mdir)
            if opts.model_provenance or opts.require_model_signatures:
                for mf in mf_results:
                    if opts.model_provenance:
                        hash_result = verify_model_hash(mf["path"])
                        mf["sha256"] = hash_result["sha256"]
                        mf["security_flags"].extend(hash_result["security_flags"])

                    sig_result = check_sigstore_signature(mf["path"])
                    mf["signed"] = sig_result["signed"]
                    mf["signature_path"] = sig_result["signature_path"]
                    mf["security_flags"].extend(sig_result["security_flags"])
            st.report.model_files.extend(mf_results)
            _existing_finding_ids = {finding.id for finding in st.report.findings}
            st.report.findings.extend(
                finding
                for finding in model_file_findings(mf_results, require_model_signatures=opts.require_model_signatures)
                if finding.id not in _existing_finding_ids
            )
            st.report.model_manifests.extend(manifest_results)
            for w in mf_warnings:
                st.con.print(f"  [yellow]⚠[/yellow] {w}")
            for w in manifest_warnings:
                st.con.print(f"  [yellow]⚠[/yellow] {w}")
            _record_model_coverage_gaps(st, mf_results, [*mf_warnings, *manifest_warnings])
            if mf_results:
                security_count = sum(1 for m in mf_results if m["security_flags"])
                st.con.print(
                    f"    [green]{len(mf_results)} model file(s) found[/green]"
                    + (f" [red]({security_count} with security flags)[/red]" if security_count else "")
                )
            if manifest_results:
                lineage_refs = sum(1 for m in manifest_results if m.get("repo_id") or m.get("base_model_id"))
                st.con.print(
                    f"    [green]{len(manifest_results)} model manifest(s) found[/green]"
                    + (f" [cyan]({lineage_refs} lineage refs)[/cyan]" if lineage_refs else "")
                )


def _check_hf_provenance(opts: ScanOptions, st: ScanState) -> None:
    # ── Step 1j: HuggingFace model provenance ─────────────────────────
    if opts.hf_models:
        from agent_bom.model_files import check_huggingface_provenance

        hf_provenance: list[dict] = []
        for hf_name in opts.hf_models:
            st.con.print(f"  [cyan]>[/cyan] Checking HuggingFace provenance: {hf_name}...")
            hf_result = check_huggingface_provenance(hf_name)
            hf_provenance.append(hf_result)
            if hf_result["security_flags"]:
                for flag in hf_result["security_flags"]:
                    st.con.print(f"    [yellow]⚠[/yellow] {flag['type']}: {flag['description']}")
            else:
                author = hf_result.get("author") or "unknown"
                license_val = hf_result.get("license") or "unspecified"
                st.con.print(f"    [green]✓[/green] {hf_name} — author: {author}, license: {license_val}")
        st.report.model_provenance = hf_provenance


def _scan_datasets(opts: ScanOptions, st: ScanState) -> None:
    # ── Step 1k: Dataset card scan ──────────────────────────────────
    # Auto-detect: check project for dataset_info.json or .dvc files
    if not opts.skill_only and not opts.no_discover and not opts.dataset_dirs and opts.project:
        from pathlib import Path as _DPath

        _proj = _DPath(opts.project)
        _has_datasets = list(_proj.rglob("dataset_info.json"))[:1] or list(_proj.rglob("*.dvc"))[:1]
        if _has_datasets:
            opts.dataset_dirs = (opts.project,)
            st.con.print("  [cyan]>[/cyan] Auto-detected dataset files — scanning...")

    if not opts.skill_only and opts.dataset_dirs:
        from agent_bom.parsers.dataset_cards import DatasetInfo, scan_dataset_directory

        all_datasets: list[DatasetInfo] = []
        all_ds_warnings: list[str] = []
        for ddir in opts.dataset_dirs:
            st.con.print(f"  [cyan]>[/cyan] Scanning for dataset cards in {ddir}...")
            ds_result = scan_dataset_directory(ddir)
            all_datasets.extend(ds_result.datasets)
            all_ds_warnings.extend(ds_result.warnings)
        if all_datasets:
            flagged = sum(1 for d in all_datasets if d.security_flags)
            st.con.print(
                f"    [green]{len(all_datasets)} dataset(s) found[/green]"
                + (f" [yellow]({flagged} with flags)[/yellow]" if flagged else "")
            )
            st.report.dataset_cards = {
                "datasets": [d.to_dict() for d in all_datasets],
                "total_datasets": len(all_datasets),
                "flagged_count": flagged,
            }
            st.scan_sources.append("dataset_cards")
        for w in all_ds_warnings:
            st.con.print(f"  [yellow]⚠[/yellow] {w}")

        # PII content scan (opt-in via --scan-pii)
        if opts.scan_pii:
            from pathlib import Path as _PIIPath

            from agent_bom.parsers.dataset_pii_scanner import scan_directory_for_pii

            for ddir in opts.dataset_dirs:
                st.con.print(f"  [cyan]>[/cyan] Scanning dataset content for PII/PHI in {ddir}...")
                pii_result = scan_directory_for_pii(_PIIPath(ddir))
                if pii_result.total_findings > 0:
                    st.con.print(
                        f"    [red]PII detected:[/red] {pii_result.total_findings} finding(s)"
                        f" across {pii_result.files_with_pii} file(s)"
                        + (
                            f" [bold red]({pii_result.high_severity_count} high-severity)[/bold red]"
                            if pii_result.high_severity_count
                            else ""
                        )
                    )
                else:
                    st.con.print(f"    [green]No PII found[/green] in {pii_result.files_scanned} file(s)")
                if st.report.dataset_cards is None:
                    st.report.dataset_cards = {}
                st.report.dataset_cards["pii_scan"] = pii_result.to_dict()
                st.scan_sources.append("dataset_pii")
                for w in pii_result.warnings:
                    st.con.print(f"  [yellow]⚠[/yellow] {w}")


def _scan_training_pipelines(opts: ScanOptions, st: ScanState) -> None:
    # ── Step 1l: Training pipeline scan ──────────────────────────────
    # Auto-detect: check project for MLmodel, wandb-metadata.json, pipeline YAML
    if not opts.skill_only and not opts.no_discover and not opts.training_dirs and opts.project:
        from pathlib import Path as _TPath

        _tproj = _TPath(opts.project)
        _has_training = (
            list(_tproj.rglob("MLmodel"))[:1] or list(_tproj.rglob("wandb-metadata.json"))[:1] or list(_tproj.rglob("meta.yaml"))[:1]
        )
        if _has_training:
            opts.training_dirs = (opts.project,)
            st.con.print("  [cyan]>[/cyan] Auto-detected training artifacts — scanning...")

    if not opts.skill_only and opts.training_dirs:
        from agent_bom.parsers.training_pipeline import scan_training_directory

        all_runs: list = []
        all_serving: list = []
        all_tp_warnings: list[str] = []
        for tdir in opts.training_dirs:
            st.con.print(f"  [cyan]>[/cyan] Scanning for training pipelines in {tdir}...")
            tp_result = scan_training_directory(tdir)
            all_runs.extend(tp_result.training_runs)
            all_serving.extend(tp_result.serving_configs)
            all_tp_warnings.extend(tp_result.warnings)
        if all_runs:
            flagged = sum(1 for r in all_runs if r.security_flags)
            st.con.print(
                f"    [green]{len(all_runs)} training run(s) found[/green]"
                + (f" [yellow]({flagged} with flags)[/yellow]" if flagged else "")
            )
            st.report.training_pipelines = {
                "training_runs": [r.to_dict() for r in all_runs],
                "total_runs": len(all_runs),
                "flagged_count": flagged,
            }
            st.scan_sources.append("training_pipelines")
        if all_serving:
            st.con.print(f"    [green]{len(all_serving)} serving config(s) found[/green]")
            st.report.serving_configs = [s.to_dict() for s in all_serving]
        for w in all_tp_warnings:
            st.con.print(f"  [yellow]⚠[/yellow] {w}")


def _analyze_source(opts: ScanOptions, st: ScanState) -> None:
    from agent_bom.evidence.scan_run import ScanIssue

    # ── Step 1m: AST source code analysis (explicit project scope) ──
    st.ast_result_for_reach = None
    if not opts.skill_only and opts.project and not opts.dry_run:
        from pathlib import Path as _APath

        _aproj = _APath(opts.project)
        from agent_bom.ast.project_scope import analyze_project_once as _ast_analyze
        from agent_bom.ast_analyzer import project_has_analyzable_sources as _has_ast_sources

        if _has_ast_sources(_aproj):
            try:
                _ast_result = _ast_analyze(opts.project)
                st.ast_result_for_reach = _ast_result
                if (
                    _ast_result.prompts
                    or _ast_result.guardrails
                    or _ast_result.tools
                    or _ast_result.flow_findings
                    or _ast_result.application_entrypoints
                    or _ast_result.dependency_symbol_reach
                ):
                    st.report.ai_inventory_data = st.report.ai_inventory_data or {}
                    st.report.ai_inventory_data["ast_analysis"] = _ast_result.to_dict()
                    _n_prompts = len(_ast_result.prompts)
                    _n_guards = len(_ast_result.guardrails)
                    _n_tools = len(_ast_result.tools)
                    _n_entrypoints = len(_ast_result.application_entrypoints)
                    _n_risky = sum(1 for p in _ast_result.prompts if p.risk_flags)
                    if _n_prompts or _n_guards or _n_tools or _n_entrypoints:
                        st.con.print(
                            f"  [cyan]>[/cyan] Code analysis: {_n_prompts} prompts, "
                            f"{_n_guards} guardrails, {_n_tools} tools, {_n_entrypoints} application entrypoints"
                            + (f" [red]({_n_risky} risky prompts)[/red]" if _n_risky else "")
                        )
                    st.scan_sources.append("ast_analysis")
            except Exception as exc:  # noqa: BLE001
                from agent_bom.security import sanitize_error

                logger.debug("AST analysis unavailable: %s", sanitize_error(exc, generic=True))
                st.report.scan_run.add_issue(
                    ScanIssue(
                        code="scanner_unavailable",
                        stage="scanning",
                        source="ast-analysis",
                        message="AST analysis could not complete.",
                        affects_coverage=True,
                    )
                )


def _scan_secrets(opts: ScanOptions, st: ScanState) -> None:
    from agent_bom.evidence.scan_run import ScanIssue

    # ── Step 1n: Secret scanning (auto-detect in project) ──────────
    if not opts.skill_only and not opts.no_discover and opts.project and not opts.dry_run:
        try:
            from agent_bom.secret_scanner import scan_secrets as _scan_secrets

            _secret_result = _scan_secrets(opts.project, aws_live_validation=False) if opts.offline else _scan_secrets(opts.project)
            if _secret_result.total > 0 or _secret_result.warnings or _secret_result.exclusions:
                st.report.ai_inventory_data = st.report.ai_inventory_data or {}
                st.report.ai_inventory_data["secrets"] = _secret_result.to_dict()
                st.scan_sources.append("secret_scan")
            if _secret_result.total > 0:
                st.con.print(
                    f"  [red]![/red] Secrets: {_secret_result.total} hardcoded secrets/PII found ({_secret_result.critical_count} critical)"
                )
            for _secret_warning in _secret_result.warnings:
                st.report.scan_run.add_issue(
                    ScanIssue(
                        code="scanner_coverage_gap",
                        stage="scanning",
                        source="secret-scan",
                        message=f"Secret scan incomplete: {_secret_warning}",
                        affects_coverage=True,
                    )
                )
        except Exception as exc:  # noqa: BLE001
            from agent_bom.security import sanitize_error

            logger.debug("Secret scanning unavailable: %s", sanitize_error(exc, generic=True))
            st.report.scan_run.add_issue(
                ScanIssue(
                    code="scanner_unavailable",
                    stage="scanning",
                    source="secret-scan",
                    message="Secret scanning could not complete.",
                    affects_coverage=True,
                )
            )


def _summarize_model_supply_chain(opts: ScanOptions, st: ScanState) -> None:
    # AST source-budget diagnostics are recorded after the early scanner-state
    # drain above. Fold that late evidence into the report at the last producer
    # boundary so JSON/SARIF and the process exit all see the same outcome.
    for _warning in consume_coverage_warnings():
        if str(_warning.get("release", "")) not in {str(w.get("release", "")) for w in st.report.coverage_warnings}:
            st.report.coverage_warnings.append(_warning)

    if st.report.model_files or st.report.model_provenance or st.report.model_hash_verification_data:
        from agent_bom.model_files import evaluate_model_provenance_policy, summarize_model_supply_chain

        st.report.model_supply_chain_data = summarize_model_supply_chain(
            st.report.model_files,
            st.report.model_provenance,
            st.report.model_hash_verification_data,
            st.report.model_manifests,
        )
        if opts.model_policy_mode != "off" or opts.require_model_signatures or opts.block_unsafe_model_formats:
            policy_result = evaluate_model_provenance_policy(
                st.report.model_files,
                mode=opts.model_policy_mode,
                require_signatures=opts.require_model_signatures,
                block_unsafe_formats=opts.block_unsafe_model_formats,
            )
            st.report.model_supply_chain_data["policy"] = policy_result
            for warning in policy_result.get("warnings", []):
                st.con.print(f"  [yellow]⚠[/yellow] Model policy: {warning['type']} — {warning['file']}")
            for violation in policy_result.get("violations", []):
                st.con.print(f"  [red]✗[/red] Model policy: {violation['type']} — {violation['file']}")
            if policy_result["passed"] is False:
                st.ctx.policy_passed = False

    # Persist browser extension results to report
    if st.ctx._browser_ext_results is not None:
        st.report.browser_extensions = st.ctx._browser_ext_results


def run_ai_asset_scanners(opts: ScanOptions, st: ScanState) -> None:
    """Scan model, dataset, training, source and secret assets into the report."""
    _detect_model_dirs(opts, st)
    _scan_model_files(opts, st)
    _check_hf_provenance(opts, st)
    _scan_datasets(opts, st)
    _scan_training_pipelines(opts, st)
    _analyze_source(opts, st)
    _scan_secrets(opts, st)
    _summarize_model_supply_chain(opts, st)
