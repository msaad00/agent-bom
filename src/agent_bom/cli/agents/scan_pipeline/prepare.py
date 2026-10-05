"""Stage 1: resolve and validate the effective scan options."""

from __future__ import annotations

import sys
import time as _time
from pathlib import Path

import click
from rich.console import Console

from agent_bom.cli._common import _sync_runtime_consoles, logger
from agent_bom.cli.agents._modes import apply_demo_mode, apply_self_scan_mode, validate_primary_input_modes, validate_skill_mode
from agent_bom.cli.agents.scan_pipeline.helpers import _is_null_device, _output_format_was_explicit
from agent_bom.cli.agents.scan_pipeline.options import ScanOptions
from agent_bom.cli.agents.scan_pipeline.state import ScanState
from agent_bom.scanners import reset_scan_warnings


def _normalize_flags(opts: ScanOptions, st: ScanState) -> None:
    if opts.ai_gate_findings and not opts.ai_enrich:
        raise click.UsageError("--ai-gate-findings requires --ai-enrich")
    if opts.ai_gate_findings and not opts.ai_deterministic:
        raise click.UsageError("--ai-gate-findings requires --ai-deterministic")

    # `--inventory-only` is a deprecated hidden alias for `--no-discover`.
    opts.no_discover = opts.no_discover or opts.inventory_only

    # Always bind at function scope: the scan/consume site below sits in a nested
    # block that early-return paths (dry-run, format validation) never enter, but
    # the report-build site at the outer scope always references it.
    st.coverage_warnings = []
    st.scan_warnings = []
    # The scanner keeps warnings in thread-local state so nested/parallel scans
    # do not collide. Reset at the command boundary as well as inside the
    # package scanner so mocked or collector-only paths cannot inherit a prior
    # invocation's degraded outcome.
    reset_scan_warnings()

    st.scan_start = _time.monotonic()

    from agent_bom.cli._agent_mode import agent_mode_requested

    opts.agent_mode = opts.agent_mode or agent_mode_requested()

    # `--aws-deep` is a convenience alias that ORs on every granular AWS
    # discovery toggle. It never turns anything off, so it composes with any
    # individually supplied --aws-include-* flag and leaves defaults unchanged
    # when absent.
    if opts.aws_deep:
        opts.aws_include_eks = True
        opts.aws_include_step_functions = True
        opts.aws_include_ec2 = True
        opts.aws_include_iam = True


def _apply_profile_and_agent_mode(opts: ScanOptions, st: ScanState) -> None:
    from agent_bom.cli._profiles import apply_scan_profile_defaults
    from agent_bom.logging_config import setup_logging

    if opts._apply_profile_defaults:
        (
            opts.output,
            opts.output_format,
            opts.preset,
            opts.nvd_api_key,
            opts.push_url,
            opts.push_api_key,
            opts.clickhouse_url,
        ) = apply_scan_profile_defaults(
            output=opts.output,
            output_format=opts.output_format,
            preset=opts.preset,
            nvd_api_key=opts.nvd_api_key,
            push_url=opts.push_url,
            push_api_key=opts.push_api_key,
            clickhouse_url=opts.clickhouse_url,
            agent_mode=opts.agent_mode,
        )

    if opts.agent_token_budget < 0:
        raise click.ClickException("--agent-token-budget must be greater than or equal to 0.")
    if opts.agent_mode:
        if _output_format_was_explicit() and opts.output_format != "json":
            raise click.ClickException("--agent-mode requires --format json.")
        opts.output_format = "json"
        click_ctx = click.get_current_context(silent=True)
        output_source = click_ctx.get_parameter_source("output") if click_ctx is not None else None
        explicit_output = output_source in {click.core.ParameterSource.COMMANDLINE, click.core.ParameterSource.ENVIRONMENT}
        opts.output = opts.output if explicit_output and opts.output else "-"
        opts.quiet = True
        opts.no_color = True

    # Configure logging — explicit --log-level overrides --verbose
    if opts.quiet and opts.log_level is None and not opts.verbose and not opts.log_json and not opts.log_file:
        _log_level = "ERROR"
    else:
        _log_level = opts.log_level or ("DEBUG" if opts.verbose else "WARNING")
    setup_logging(level=_log_level, json_output=opts.log_json, log_file=opts.log_file)


def _apply_project_config(opts: ScanOptions, st: ScanState) -> None:
    from agent_bom.project_config import get_fail_on_severity, get_policy_path, load_project_config

    # ── Positional PATH is Docker-style shorthand for --project/-p ──
    # `agent-bom scan .` / `agent-bom scan ./dir` resolve to a project scan.
    # If both the positional PATH and --project/-p are given, they must point at
    # the same directory; otherwise --project/-p wins and we warn so the
    # intent is never silently dropped. The positional value is purely a
    # project alias and does not interfere with --image/--sbom/--filesystem/
    # --self-scan/--demo input modes.
    if opts.path is not None:
        if opts.project is not None and Path(opts.project).resolve() != Path(opts.path).resolve():
            logger.warning(
                "Both PATH (%s) and --project/-p (%s) were given; using --project/-p.",
                opts.path,
                opts.project,
            )
        elif opts.project is None:
            opts.project = opts.path

    # Load .agent-bom.yaml project config — CLI flags always win
    _proj_cfg = load_project_config()
    if _proj_cfg:
        if not opts.fail_on_severity:
            opts.fail_on_severity = get_fail_on_severity(_proj_cfg)
        if not opts.enrich and _proj_cfg.get("enrich"):
            opts.enrich = True
        if not opts.transitive and _proj_cfg.get("transitive"):
            opts.transitive = True
        if not opts.fail_on_kev and _proj_cfg.get("fail_on_kev"):
            opts.fail_on_kev = True
        if not opts.policy and (cfg_policy := get_policy_path(_proj_cfg)):
            opts.policy = str(cfg_policy)


def _apply_presets_and_modes(opts: ScanOptions, st: ScanState) -> None:
    # Apply presets (override defaults, don't override explicit flags)
    if opts.preset == "ci":
        opts.quiet = True
        opts.output_format = opts.output_format if opts.output_format != "console" else "json"
        opts.fail_on_severity = opts.fail_on_severity or "critical"
        opts.warn_on_severity = opts.warn_on_severity or "high"
    elif opts.preset == "enterprise":
        opts.enrich = True
        opts.introspect = True
        opts.transitive = True
        opts.deps_dev = True
        opts.license_check = True
        opts.verify_integrity = True
        opts.verify_instructions = True

    if opts.output_format == "sarif" and not opts.enrich and not opts.no_scan and not opts.offline:
        # SARIF benefits from EPSS/KEV enrichment (annotation only — never adds or
        # removes findings). Do NOT auto-enable dynamic discovery or the context
        # graph here: those *change the finding set* (e.g. the graph evaluator
        # emits toxic-combination COMBINATION findings). Gating them on the output
        # format made `-f sarif` surface findings that `-f json`/`-f csv` of the
        # same input never emitted — a SIEM/API parity bug (#3643). Discovery and
        # graph analysis stay driven by explicit flags/presets so the finding set
        # is identical across every output format.
        opts.enrich = True
    elif opts.preset == "quick":
        opts.transitive = False
        opts.enrich = False

    # A critical vulnerability is a failed security verdict by default. The
    # explicit escape hatch is deliberately limited to vulnerability severity:
    # malicious packages, policy failures, and incomplete evidence remain
    # fail-closed in ``compute_exit_code``.
    if opts.exit_zero:
        opts.fail_on_severity = None
    elif opts.fail_on_severity is None:
        opts.fail_on_severity = "critical"

    if opts.preset == "workstation":
        opts.browser_extensions = True
        opts.os_packages = True
        opts.include_processes = True
        opts.include_containers = True
        opts.context_graph_flag = True

    # ── CI environment detection (informational only) ──
    # Auto-quiet removed: tests run in CI and need output.
    # Users should use --preset ci for CI-specific defaults.
    # The ci_detect module is available for programmatic use.

    # ── Self-scan/demo modes materialize synthetic inventories before discovery ──
    validate_primary_input_modes(self_scan=opts.self_scan, demo=opts.demo, inventory=opts.inventory)
    opts.inventory, opts.enrich = apply_self_scan_mode(self_scan=opts.self_scan, inventory=opts.inventory, enrich=opts.enrich)
    opts.project, opts.inventory, opts.enrich, opts.compliance, opts.iac_paths = apply_demo_mode(
        demo=opts.demo,
        project=opts.project,
        inventory=opts.inventory,
        enrich=opts.enrich,
        compliance=opts.compliance,
        iac_paths=opts.iac_paths,
    )
    validate_skill_mode(no_skill=opts.no_skill, skill_only=opts.skill_only)


def _clone_repo(opts: ScanOptions, st: ScanState) -> None:
    # ── Public-repo clone-and-scan (--repo) ──────────────────────────────────
    # Shallow-clone the URL into a temp dir, point the local-directory scan path
    # at it, and remove the temp dir when the command finishes. Static only —
    # the repository's code is never executed.
    st.repo_trust_data = None
    if opts.repo_url:
        if opts.project:
            raise click.ClickException("--repo and --project/-p are mutually exclusive.")
        if opts.offline:
            raise click.ClickException(
                "--repo requires network access to clone the repository, so it cannot be "
                "combined with --offline. Clone the repository yourself and scan the local "
                "checkout with --project/-p (which honors --offline), or drop --offline."
            )
        from contextlib import ExitStack

        from agent_bom.repo_scan import RepoScanError, clone_repository, fetch_repo_trust

        _repo_cleanup = ExitStack()
        click_ctx = click.get_current_context(silent=True)
        if click_ctx is not None:
            click_ctx.call_on_close(_repo_cleanup.close)
        try:
            cloned_dir = _repo_cleanup.enter_context(clone_repository(opts.repo_url, token_env="AGENT_BOM_REPO_SCAN_TOKEN"))
        except RepoScanError as exc:
            _repo_cleanup.close()
            raise click.ClickException(str(exc)) from exc
        opts.project = str(cloned_dir)
        # Best-effort GitHub trust card (stars/contributors/license). Never fails
        # the scan; disable with AGENT_BOM_REPO_TRUST=0.
        st.repo_trust_data = fetch_repo_trust(opts.repo_url, token_env="AGENT_BOM_REPO_SCAN_TOKEN")


def _open_consoles(opts: ScanOptions, st: ScanState) -> None:
    # Keep phase/progress diagnostics redirectable separately from the final
    # human report. Both still render to a TTY during an interactive run, while
    # ``agent-bom scan > report.txt`` captures only the report and leaves
    # discovery/scanner progress visible on stderr.
    is_stdout = opts.output == "-"
    is_null_sink = _is_null_device(opts.output)
    st.con = Console(stderr=True, quiet=opts.quiet or is_stdout, no_color=opts.no_color)
    st.report_con = Console(
        file=sys.stdout,
        quiet=opts.quiet or is_stdout,
        no_color=opts.no_color,
    )
    _sync_runtime_consoles(st.con)

    # `-o /dev/null` is a discard sink: run the scan, write nothing, and let the
    # policy exit code stand. Without this the console-to-file guard below tripped
    # `SystemExit(2)` (because passing `-o` alone makes the format "explicit"),
    # masking `--fail-on-severity` (#3643).
    if opts.output and opts.output != "-" and not is_null_sink and opts.output_format == "console" and _output_format_was_explicit():
        click.echo(
            "Error: --format console renders to the terminal only; use --format plain, markdown, or json with --output.",
            err=True,
        )
        raise SystemExit(2)
    if not opts.output and opts.output_format == "pdf" and _output_format_was_explicit():
        click.echo("Error: --format pdf requires --output/-o (PDF is a binary file output).", err=True)
        raise SystemExit(2)

    # Also set the output module's console so print_summary etc. route correctly
    import agent_bom.output as _out
    import agent_bom.output.console_render as _console_render

    _out.console = st.con
    _console_render.console = st.con


def _validate_input_files(opts: ScanOptions, st: ScanState) -> None:
    st.validated_ignore_entries = None
    if opts.policy:
        from agent_bom.policy import load_policy as _load_policy_for_validation

        try:
            _load_policy_for_validation(opts.policy)
        except (FileNotFoundError, ValueError) as exc:
            raise click.ClickException(f"Policy error: {exc}") from exc
    if opts.ignore_file:
        from agent_bom.ignores import load_ignore_file as _load_ignore_file_for_validation

        try:
            st.validated_ignore_entries = _load_ignore_file_for_validation(opts.ignore_file)
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc
    if opts.vex_path:
        from agent_bom.vex import load_vex as _load_vex_for_validation

        try:
            _load_vex_for_validation(opts.vex_path)
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc
    if opts.baseline:
        from agent_bom.scan_delta import load_baseline as _load_baseline_for_validation

        try:
            _load_baseline_for_validation(opts.baseline)
        except (FileNotFoundError, ValueError) as exc:
            raise click.ClickException(f"Baseline error: {exc}") from exc

    if opts.demo:
        st.con.print("\n[bold yellow]Demo mode[/bold yellow] — curated agent + MCP sample with known-vulnerable packages.\n")


def run_prepare(opts: ScanOptions, st: ScanState) -> None:
    """Normalize flags, presets and modes; open consoles; validate input files."""
    _normalize_flags(opts, st)
    _apply_profile_and_agent_mode(opts, st)
    _apply_project_config(opts, st)
    _apply_presets_and_modes(opts, st)
    _clone_repo(opts, st)
    _open_consoles(opts, st)
    _validate_input_files(opts, st)
    from agent_bom.evidence.push_scope import cli_target_scope

    st.target_scope = cli_target_scope(opts)
