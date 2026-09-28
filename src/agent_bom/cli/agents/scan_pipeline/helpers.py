"""Helpers shared by the scan stages."""

from __future__ import annotations

import json
from typing import Any

import click

from agent_bom.cli.agents._context import ScanContext
from agent_bom.cli.agents._output import render_output
from agent_bom.cli.agents._posture import render_posture_summary
from agent_bom.models import AIBOMReport
from agent_bom.scanners import IncompleteScanError


def _agents_patchable(name: str) -> Any:
    """Resolve a test-patchable symbol from ``agent_bom.cli.agents``."""
    import agent_bom.cli.agents as agents_mod

    return getattr(agents_mod, name)


def _docker_image_ref(pkg: Any) -> str:
    version = str(getattr(pkg, "version", "") or "")
    name = str(getattr(pkg, "name", "") or "")
    if version.startswith("sha256:"):
        return f"{name}@{version}"
    return f"{name}:{version}" if version else name


def _expand_docker_mcp_packages(
    *,
    server: Any,
    discovered: list[Any],
    docker_image_cache: dict[str, list[Any]],
    scan_image_fn: Any,
    registry_user: str | None,
    registry_pass: str | None,
    image_platform: str | None,
) -> tuple[list[Any], list[str]]:
    """Replace Docker MCP image stubs with native image package inventory."""
    docker_refs = [_docker_image_ref(pkg) for pkg in discovered if str(getattr(pkg, "ecosystem", "")).lower() == "docker"]
    if not docker_refs:
        return discovered, []

    expanded: list[Any] = []
    failures: list[str] = []
    for image_ref in dict.fromkeys(docker_refs):
        try:
            if image_ref not in docker_image_cache:
                image_packages, _strategy = scan_image_fn(
                    image_ref,
                    registry_user=registry_user,
                    registry_pass=registry_pass,
                    platform=image_platform,
                )
                docker_image_cache[image_ref] = image_packages
            expanded.extend(docker_image_cache[image_ref])
        except Exception as exc:
            from agent_bom.security import sanitize_error

            message = f"{server.name}: Docker MCP image {image_ref} could not be expanded: {sanitize_error(exc)}"
            failures.append(message)
            if message not in server.security_warnings:
                server.security_warnings.append(message)

    return [pkg for pkg in discovered if str(getattr(pkg, "ecosystem", "")).lower() != "docker"] + expanded, failures


def _incomplete_scan_report(agents: list[Any], exc: IncompleteScanError) -> AIBOMReport:
    from agent_bom.evidence.scan_run import ScanIssue, ScanRun
    from agent_bom.mcp_blocklist import blocklist_findings_for_agents

    return AIBOMReport(
        agents=agents,
        blast_radii=[],
        findings=blocklist_findings_for_agents(agents),
        scan_sources=["agent_discovery"],
        scan_run=ScanRun(
            issues=[
                ScanIssue(
                    code="required_scanner_unavailable",
                    stage="scanning",
                    source="vulnerability-data",
                    message=str(exc),
                    severity="error",
                    affects_coverage=True,
                )
            ]
        ),
        scan_performance_data={
            "coverage_state": "incomplete",
            "coverage_reason": str(exc),
        },
    )


def _exit_incomplete_scan_with_partial_summary(
    ctx: ScanContext,
    *,
    agents: list[Any],
    exc: IncompleteScanError,
    output: Any,
    output_format: str,
    no_tree: bool,
    quiet: bool,
    no_color: bool,
    open_report: bool,
    offline_html: bool,
    compliance_export: Any,
    mermaid_mode: str,
    push_gateway: Any,
    otel_endpoint: Any,
    baseline: Any,
    delta_mode: bool,
    verbose: bool,
    exclude_unfixable: bool,
    fixable_only: bool,
    posture: bool,
) -> None:
    """Render discovered inventory before exiting an incomplete scan."""
    ctx.blast_radii = []
    ctx.report = _incomplete_scan_report(agents, exc)
    explicit_output_target = _scan_output_target_was_explicit()
    machine_stdout = explicit_output_target and output_format != "console" and output in (None, "", "-")
    if not machine_stdout:
        ctx.con.print(f"  [yellow]⚠[/yellow] {exc}")
    profile_defaulted_output = not explicit_output_target
    render_kwargs: dict[str, Any] = {
        "no_tree": no_tree,
        "quiet": quiet,
        "no_color": no_color,
        "open_report": open_report,
        "offline_html": offline_html,
        "compliance_export": compliance_export,
        "mermaid_mode": mermaid_mode,
        "push_gateway": push_gateway,
        "otel_endpoint": otel_endpoint,
        "baseline": baseline,
        "delta_mode": delta_mode,
        "verbose": verbose,
        "exclude_unfixable": exclude_unfixable,
        "fixable_only": fixable_only,
    }
    if explicit_output_target:
        render_output(ctx, output=output, output_format=output_format, **render_kwargs)
    elif ((output_format == "console" and not output) or profile_defaulted_output) and not quiet:
        render_output(ctx, output=None, output_format="console", **render_kwargs)
        if posture:
            render_posture_summary(agents, [])
    # The command produced a truthful partial artifact, so this is a failed
    # scan verdict rather than a caller/usage error.  Keep exit 2 reserved for
    # invalid arguments and empty inputs; CI must fail closed on incomplete
    # evidence through the same exit-1 family as other scan verdicts.
    raise SystemExit(1)


def _reset_offline_mode() -> None:
    """Restore process-global network mode after an offline CLI invocation."""
    from agent_bom.scanners import set_offline_mode

    set_offline_mode(False)


def _output_format_was_explicit() -> bool:
    ctx = click.get_current_context(silent=True)
    if ctx is None:
        return False
    return ctx.get_parameter_source("output_format") is click.core.ParameterSource.COMMANDLINE


def _scan_output_target_was_explicit() -> bool:
    """Return true when the caller explicitly selected a machine output target."""
    ctx = click.get_current_context(silent=True)
    if ctx is None:
        return False
    explicit_sources = {click.core.ParameterSource.COMMANDLINE, click.core.ParameterSource.ENVIRONMENT}
    return ctx.get_parameter_source("output") in explicit_sources or ctx.get_parameter_source("output_format") in explicit_sources


def _is_null_device(output: Any) -> bool:
    """Return True when ``-o`` points at the platform null device (discard sink).

    Writing to the null device must succeed silently and never override the
    policy exit code, so callers treat it as "produce no file" rather than a
    real path (which would otherwise gain a format suffix and fail to write).
    """
    import os

    if not output or output == "-":
        return False
    candidates = {os.devnull, "/dev/null"}
    try:
        return os.path.realpath(str(output)) in {os.path.realpath(c) for c in candidates}
    except OSError:
        return str(output) in candidates


def _reproducible_generated_at(enabled: bool):
    """Return a pinned report timestamp when reproducible output is requested."""
    import os
    from datetime import datetime, timezone

    raw_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if raw_epoch is None and not enabled:
        return None
    epoch = 0 if raw_epoch is None else raw_epoch
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise click.ClickException("SOURCE_DATE_EPOCH must be an integer Unix timestamp.") from exc


_SCAN_ID_NAMESPACE = "7f3e4b2a-9c1d-5f8e-a0b4-12c3d4e5f6a7"


def _cloud_scan_scope(
    *,
    providers: list[str],
    aws_region: str | None,
    aws_profile: str | None,
    azure_subscription: str | None,
    gcp_project: str | None,
) -> dict[str, dict[str, str]]:
    """Return the requested cloud boundary for each provider this scan touched.

    Explicit CLI values win; otherwise the same environment fallbacks the
    collectors use are recorded, so two scans of different accounts never share
    an identity.
    """
    import os

    candidates: dict[str, dict[str, str]] = {
        "aws": {
            "region": aws_region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "",
            "profile": aws_profile or os.environ.get("AWS_PROFILE") or "",
        },
        "azure": {"subscription": azure_subscription or os.environ.get("AZURE_SUBSCRIPTION_ID") or ""},
        "gcp": {"project": gcp_project or os.environ.get("GOOGLE_CLOUD_PROJECT") or ""},
    }
    scope: dict[str, dict[str, str]] = {}
    for provider in sorted(set(providers)):
        fields = {key: value for key, value in candidates.get(provider, {}).items() if value}
        scope[provider] = dict(sorted(fields.items()))
    return scope


def _compute_scan_id(
    *,
    pkg_fingerprints: list[str],
    endpoint_fingerprint: str,
    cloud_scope: dict[str, dict[str, str]],
    reproducible: bool,
) -> str:
    """Derive the scan identity.

    Reproducible runs hash only the inputs (packages, endpoint inventory, cloud
    boundary) so identical inputs yield an identical id. Every other run adds a
    random nonce: a scan id keys the persisted graph snapshot, so two ordinary
    runs must never collide — a cloud-only scan has no packages and would
    otherwise share one id with every other cloud-only scan.
    """
    import uuid as _uuid

    parts = [
        "|".join(sorted(pkg_fingerprints)) or "empty",
        endpoint_fingerprint,
        json.dumps(cloud_scope, sort_keys=True, separators=(",", ":")),
    ]
    if not reproducible:
        parts.append(_uuid.uuid4().hex)
    return str(_uuid.uuid5(_uuid.UUID(_SCAN_ID_NAMESPACE), "scan:" + "|".join(parts)))


_CLOUD_BENCHMARK_REPORTS = (
    ("aws", "cis_benchmark_report"),
    ("azure", "azure_cis_benchmark_report"),
    ("gcp", "gcp_cis_benchmark_report"),
    ("snowflake", "sf_cis_benchmark_report"),
)


def _benchmark_scan_issues(ctx: Any) -> list:
    """Project errored CIS checks and benchmark warnings onto scan-run issues.

    A benchmark that could not evaluate some controls produced incomplete
    evidence; the scan outcome must say ``partial`` and name why, rather than
    reporting ``complete`` beside errored checks.
    """
    from agent_bom.evidence.scan_run import ScanIssue

    issues: list = []
    for provider, attr in _CLOUD_BENCHMARK_REPORTS:
        report = getattr(ctx, attr, None)
        if report is None:
            continue
        errored = int(getattr(report, "errored", 0) or 0)
        if errored:
            issues.append(
                ScanIssue(
                    code="benchmark_checks_errored",
                    stage="cis_benchmark",
                    source=provider,
                    message=f"{errored} CIS check(s) could not be evaluated; see the benchmark evidence for each.",
                    affects_coverage=True,
                )
            )
        for warning in list(getattr(report, "warnings", []) or [])[:20]:
            issues.append(
                ScanIssue(
                    code="benchmark_warning",
                    stage="cis_benchmark",
                    source=provider,
                    message=str(warning),
                    affects_coverage=True,
                )
            )
    return issues
