"""Stage 7: assemble the AI-BOM report from the scan context."""

from __future__ import annotations

import json
from pathlib import Path

from agent_bom.cli.agents.scan_pipeline.helpers import (
    _benchmark_scan_issues,
    _cloud_scan_scope,
    _compute_scan_id,
    _reproducible_generated_at,
)
from agent_bom.cli.agents.scan_pipeline.options import ScanOptions
from agent_bom.cli.agents.scan_pipeline.state import ScanState
from agent_bom.models import AIBOMReport
from agent_bom.resolver import consume_performance_stats as consume_resolution_performance
from agent_bom.scanners import consume_coverage_warnings, consume_scan_performance


def _collect_scan_sources(opts: ScanOptions, st: ScanState) -> None:
    # Build report
    st.scan_sources = []
    if opts.inventory or opts.dynamic_discovery:
        st.scan_sources.append("agent_discovery")
    if opts.images or opts.image_tars:
        st.scan_sources.append("image")
    if opts.sbom_file:
        st.scan_sources.append("sbom")
    if opts.external_scan_path:
        st.scan_sources.append("external_scan")
    if opts.k8s or opts.k8s_mcp:
        st.scan_sources.append("k8s")
    if opts.filesystem_paths:
        st.scan_sources.append("filesystem")
    if opts.tf_dirs:
        st.scan_sources.append("terraform")
    _collect_surface_sources(opts, st)


def _collect_surface_sources(opts: ScanOptions, st: ScanState) -> None:
    # ``iac`` is claimed only when the misconfiguration rules actually executed
    # — ``ctx.iac_findings_data`` is set by the IaC step itself, so the source
    # list can never advertise a scan that was skipped.
    if st.ctx.iac_findings_data is not None:
        st.scan_sources.append("iac")
    if opts.gha_path:
        st.scan_sources.append("github_actions")
    if st.ctx.skill_audit_data is not None:
        st.scan_sources.append("skill")
    if opts.browser_extensions:
        st.scan_sources.append("browser_extensions")
    if opts.scan_prompts:
        st.scan_sources.append("prompt_scan")
    if opts.jupyter_dirs:
        st.scan_sources.append("jupyter")
    if opts.gpu_scan_flag:
        st.scan_sources.append("gpu_infra")
    for _cloud_success in st.ctx.cloud_provider_successes:
        _provider = str(_cloud_success.get("provider") or "cloud")
        _source = f"cloud:{_provider}"
        if _source not in st.scan_sources:
            st.scan_sources.append(_source)
    if not st.scan_sources:
        st.scan_sources.append("agent_discovery")


def _seed_findings_and_scan_id(opts: ScanOptions, st: ScanState) -> None:
    from agent_bom.a2a_auth_posture import evaluate_a2a_auth_posture
    from agent_bom.finding import blast_radius_to_finding
    from agent_bom.mcp_auth_posture import evaluate_mcp_auth_posture
    from agent_bom.mcp_blocklist import blocklist_findings_for_agents

    st.findings = [blast_radius_to_finding(br) for br in st.blast_radii]
    st.findings.extend(blocklist_findings_for_agents(st.agents))
    st.findings.extend(evaluate_a2a_auth_posture(st.agents))
    st.findings.extend(evaluate_mcp_auth_posture(st.agents))

    st.endpoint_inventory_data = None
    if opts.preset == "workstation":
        from agent_bom.endpoint import inventory as _endpoint_inventory

        st.endpoint_inventory_data = _endpoint_inventory.collect_endpoint_inventory()
        if "endpoint_inventory" not in st.scan_sources:
            st.scan_sources.append("endpoint_inventory")

    _generated_at = _reproducible_generated_at(opts.reproducible)
    _pkg_fingerprints = [f"{p.ecosystem}:{p.name}@{p.version}" for a in st.agents for s in a.mcp_servers for p in s.packages]
    _endpoint_fingerprint = (
        json.dumps(st.endpoint_inventory_data, sort_keys=True, separators=(",", ":"), default=str)
        if st.endpoint_inventory_data is not None
        else ""
    )
    _scope_providers = [
        str(record.get("provider") or "cloud")
        for record in [*st.ctx.cloud_provider_successes, *st.ctx.cloud_provider_warnings, *st.ctx.cloud_provider_failures]
    ]
    for _requested, _provider_name in (
        (opts.aws or opts.aws_cis_benchmark, "aws"),
        (opts.azure_flag or opts.azure_cis_benchmark, "azure"),
        (opts.gcp_flag or opts.gcp_cis_benchmark, "gcp"),
    ):
        if _requested:
            _scope_providers.append(_provider_name)
    _cloud_scope = _cloud_scan_scope(
        providers=_scope_providers,
        aws_region=opts.aws_region,
        aws_profile=opts.aws_profile,
        azure_subscription=opts.azure_subscription,
        gcp_project=opts.gcp_project,
    )
    st.scan_id = _compute_scan_id(
        pkg_fingerprints=_pkg_fingerprints,
        endpoint_fingerprint=_endpoint_fingerprint,
        cloud_scope=_cloud_scope,
        reproducible=_generated_at is not None,
    )
    st.report_kwargs = {"generated_at": _generated_at} if _generated_at is not None else {}
    if _generated_at is not None:
        # Reproducible/attestable output: entity discovery timestamps are
        # wall-clock by default, so two scans of the same input diverged on every
        # agent's discovered_at/last_seen (#3643). Pin them to the same pinned
        # report timestamp so `--reproducible` (or SOURCE_DATE_EPOCH) yields a
        # byte-identical artifact.
        _pinned_ts = _generated_at.isoformat().replace("+00:00", "Z")
        for _agent in st.agents:
            _agent.discovered_at = _pinned_ts
            _agent.last_seen = _pinned_ts


def _collect_scan_issues(opts: ScanOptions, st: ScanState) -> None:
    from agent_bom.evidence.scan_run import ScanIssue, ScanOutcome

    st.scan_issues = [
        ScanIssue(
            code="scanner_warning",
            stage="scanning",
            source="vulnerability-data",
            message=_warning,
            affects_coverage=True,
        )
        for _warning in st.scan_warnings
    ]
    st.scan_issues.extend(
        ScanIssue(
            code="collector_warning",
            stage=str(_warning.get("stage") or "discovery"),
            source=str(_warning.get("provider") or "cloud"),
            message=str(_warning.get("warning") or "Cloud collector warning"),
            affects_coverage=True,
        )
        for _warning in st.ctx.cloud_provider_warnings
    )
    st.scan_issues.extend(
        ScanIssue(
            code="collector_failed",
            stage=str(_failure.get("stage") or "discovery"),
            source=str(_failure.get("provider") or "cloud"),
            message=str(_failure.get("error") or "Requested cloud collector failed"),
            severity="error",
            affects_coverage=True,
        )
        for _failure in st.ctx.cloud_provider_failures
    )
    st.scan_issues.extend(
        ScanIssue(
            code=str(_notice.get("code") or "discovery_notice"),
            stage="discovery",
            source=str(_notice.get("source") or "discovery"),
            message=str(_notice.get("message") or ""),
            affects_coverage=False,
        )
        for _notice in st.ctx.scan_notices
    )
    st.scan_issues.extend(_benchmark_scan_issues(st.ctx))
    st.scan_outcome = (
        ScanOutcome.FAILED
        if st.ctx.cloud_provider_failures and not st.ctx.cloud_provider_successes and not st.agents
        else ScanOutcome.COMPLETE
    )


def _collect_cloud_scopes(opts: ScanOptions, st: ScanState) -> None:
    from agent_bom.evidence.scan_run import ScanScope, ScanScopeStatus

    _cloud_scope_names = list(
        dict.fromkeys(
            str(record.get("provider") or "cloud")
            for record in [
                *st.ctx.cloud_provider_successes,
                *st.ctx.cloud_provider_warnings,
                *st.ctx.cloud_provider_failures,
            ]
        )
    )
    st.cloud_scopes = []
    for _provider in _cloud_scope_names:
        _success = next(
            (record for record in st.ctx.cloud_provider_successes if str(record.get("provider") or "cloud") == _provider),
            None,
        )
        _has_warning = any(str(record.get("provider") or "cloud") == _provider for record in st.ctx.cloud_provider_warnings)
        _has_failure = any(str(record.get("provider") or "cloud") == _provider for record in st.ctx.cloud_provider_failures)
        if _has_failure and _success is None:
            _scope_status = ScanScopeStatus.UNAVAILABLE
            _scope_count = None
            _scope_message = "Requested cloud collector did not complete."
        elif _has_failure or _has_warning:
            _scope_status = ScanScopeStatus.PARTIAL
            _scope_count = int(_success.get("item_count", 0)) if _success is not None else None
            _scope_message = "Requested cloud collector returned incomplete evidence."
        else:
            _scope_status = ScanScopeStatus.COMPLETE
            _scope_count = int(_success.get("item_count", 0)) if _success is not None else 0
            _scope_message = ""
        st.cloud_scopes.append(
            ScanScope(
                name=f"cloud:{_provider}",
                status=_scope_status,
                item_count=_scope_count,
                message=_scope_message,
            )
        )


def _build_report(opts: ScanOptions, st: ScanState) -> None:
    from agent_bom.evidence.scan_run import ScanRun

    _codeowners: list[dict[str, object]] = []
    try:
        _project_root = Path(opts.project or ".").resolve()
        if _project_root.is_dir():
            from agent_bom.graph.codeowners import load_codeowners

            _codeowners = [rule.to_dict() for rule in load_codeowners(_project_root)]
    except OSError:
        _codeowners = []
    st.report = AIBOMReport(
        agents=st.agents,
        blast_radii=st.blast_radii,
        findings=st.findings,
        scan_sources=st.scan_sources,
        scan_run=ScanRun(outcome=st.scan_outcome, issues=st.scan_issues, scopes=st.cloud_scopes),
        scan_id=st.scan_id,
        endpoint_inventory_data=st.endpoint_inventory_data,
        codeowners=_codeowners,
        **st.report_kwargs,
    )
    from agent_bom.advisory_sources import summarize_advisory_coverage

    # Drain here, at the single point every branch reaches. A manifest that
    # cannot be read parses to zero packages, and the zero-package branch skips
    # the vulnerability-scan block entirely — so draining inside that block
    # dropped the warning in precisely the runs whose coverage was most
    # degraded. Accumulate rather than assign so an earlier drain elsewhere in
    # the command cannot silently replace what it already collected.
    for _warning in consume_coverage_warnings():
        if str(_warning.get("release", "")) not in {str(w.get("release", "")) for w in st.coverage_warnings}:
            st.coverage_warnings.append(_warning)
    if st.coverage_warnings:
        st.report.coverage_warnings = st.coverage_warnings

    _resolver_perf = consume_resolution_performance()
    _scan_perf = consume_scan_performance()
    _all_packages = [pkg for agent in st.agents for server in agent.mcp_servers for pkg in server.packages]
    _scan_perf_data = {
        "osv": {
            "packages_seen": _scan_perf.get("packages_seen", 0),
            "packages_deduplicated": _scan_perf.get("packages_deduplicated", 0),
            "cache_hits": _scan_perf.get("osv_cache_hits", 0),
            "cache_hits_with_vulns": _scan_perf.get("osv_cache_hits_with_vulns", 0),
            "cache_hits_clean": _scan_perf.get("osv_cache_hits_clean", 0),
            "cache_misses": _scan_perf.get("osv_cache_misses", 0),
            "packages_queried": _scan_perf.get("osv_packages_queried", 0),
            "queries_sent": _scan_perf.get("osv_queries_sent", 0),
            "batches": _scan_perf.get("osv_batches", 0),
            "lookup_errors": _scan_perf.get("osv_lookup_errors", 0),
            "offline_skips": _scan_perf.get("offline_skips", 0),
            "skipped_unresolvable_versions": _scan_perf.get("skipped_unresolvable_versions", 0),
            "skipped_non_osv_ecosystems": _scan_perf.get("skipped_non_osv_ecosystems", 0),
            "cache_hit_rate_pct": _scan_perf.get("osv_cache_hit_rate_pct", 0),
        },
        "registry": _resolver_perf.get("registry_metadata", {}),
        "version_resolution": _resolver_perf.get("version_resolution", {}),
        "license_enrichment": _resolver_perf.get("license_enrichment", {}),
        "supply_chain_enrichment": _resolver_perf.get("supply_chain_enrichment", {}),
        "advisory_coverage": summarize_advisory_coverage(_all_packages),
    }
    if any(
        isinstance(section, dict) and any(int(v) > 0 for v in section.values() if isinstance(v, int))
        for section in _scan_perf_data.values()
    ):
        st.report.scan_performance_data = _scan_perf_data


def _attach_context_data(opts: ScanOptions, st: ScanState) -> None:
    # Cross-surface freshness: attach the same snapshot the CLI rendered so the
    # API and MCP tool return the vuln-data source/age/staleness verbatim.
    if st.vuln_freshness is not None:
        try:
            st.report.vuln_data_freshness = st.vuln_freshness.to_dict()
        except Exception:
            pass

    # Attach skill/trust/prompt/enforcement data from context
    if st.ctx.skill_audit_data:
        st.report.skill_audit_data = st.ctx.skill_audit_data
        from agent_bom.parsers.skill_audit import replace_skill_findings

        replace_skill_findings(st.report, st.ctx.skill_audit_data)
    if st.ctx.trust_assessment_data:
        st.report.trust_assessment_data = st.ctx.trust_assessment_data
    if st.ctx.prompt_scan_data:
        st.report.prompt_scan_data = st.ctx.prompt_scan_data
        from agent_bom.parsers.prompt_scanner import prompt_scan_data_to_findings

        st.report.findings.extend(prompt_scan_data_to_findings(st.ctx.prompt_scan_data))
    if st.ctx.external_findings:
        _known_ids = {f.id for f in st.report.findings}
        st.report.findings.extend(f for f in st.ctx.external_findings if f.id not in _known_ids)
    if st.ctx.enforcement_data:
        st.report.enforcement_data = st.ctx.enforcement_data
    if st.ctx.sast_data:
        st.report.sast_data = st.ctx.sast_data
    if st.ctx.ai_inventory_data:
        st.report.ai_inventory_data = st.ctx.ai_inventory_data
    if st.ctx.project_inventory_data:
        st.report.project_inventory_data = st.ctx.project_inventory_data
    if st.ctx.repo_trust_data:
        st.report.repo_trust_data = st.ctx.repo_trust_data
    if st.ctx.model_hash_verification_data:
        st.report.model_hash_verification_data = st.ctx.model_hash_verification_data


def _attach_benchmarks(opts: ScanOptions, st: ScanState) -> None:
    # Attach benchmark reports
    if st.ctx.cis_benchmark_report is not None:
        st.report.cis_benchmark_data = st.ctx.cis_benchmark_report.to_dict()
    if st.ctx.sf_cis_benchmark_report is not None:
        st.report.snowflake_cis_benchmark_data = st.ctx.sf_cis_benchmark_report.to_dict()
    if opts.snowflake_flag:
        # Estate discoveries (object graph, login anomalies, exfil, auth posture,
        # services, pipeline, integrations, external data, governance, activity).
        # Shared with the gated AGENT_BOM_SNOWFLAKE_INVENTORY enrichment path so
        # the CLI flag and the env gate run identical logic. Each discovery is
        # best-effort and never fails the scan.
        from agent_bom.cloud.snowflake import enrich_report_with_snowflake_estate

        enrich_report_with_snowflake_estate(st.report)
    if st.ctx.azure_cis_benchmark_report is not None:
        st.report.azure_cis_benchmark_data = st.ctx.azure_cis_benchmark_report.to_dict()
    if st.ctx.gcp_cis_benchmark_report is not None:
        st.report.gcp_cis_benchmark_data = st.ctx.gcp_cis_benchmark_report.to_dict()
    if st.ctx.databricks_security_report is not None:
        st.report.databricks_security_data = st.ctx.databricks_security_report.to_dict()
    if st.ctx.aisvs_report is not None:
        st.report.aisvs_benchmark_data = st.ctx.aisvs_report.to_dict()
    if st.ctx.vector_db_results:
        st.report.vector_db_scan_data = [r.to_dict() for r in st.ctx.vector_db_results]
    if st.ctx.gpu_infra_report is not None:
        st.report.gpu_infra_data = st.ctx.gpu_infra_report.risk_summary
    if st.ctx.iac_findings_data:
        st.report.iac_findings_data = st.ctx.iac_findings_data


def _attach_estate_and_runtime(opts: ScanOptions, st: ScanState) -> None:
    # Opt-in estate enrichment (cloud inventory + NHI discovery). Default OFF:
    # no-op and no network I/O unless AGENT_BOM_CLOUD_INVENTORY / *_INVENTORY /
    # *_DISCOVERY flags are set. The graph builder consumes the attached blocks.
    from agent_bom.scan_enrichment import enrich_report_with_estate_discovery

    enrich_report_with_estate_discovery(
        st.report,
        aws_region=opts.aws_region,
        aws_profile=opts.aws_profile,
        azure_subscription=opts.azure_subscription,
        gcp_project=opts.gcp_project,
    )

    # Attach introspection / health check results so they're in JSON/BOM exports
    if st.intro_report is not None:
        st.report.introspection_data = {
            "total_servers": st.intro_report.total_servers,
            "successful": st.intro_report.successful,
            "failed": st.intro_report.failed,
            "total_tools": st.intro_report.total_tools,
            "total_resources": st.intro_report.total_resources,
            "drift_count": st.intro_report.drift_count,
            "results": [r.to_dict() for r in st.intro_report.results],
        }
    if st.hc_results is not None:
        st.report.health_check_data = {
            "total": len(st.hc_results),
            "reachable": sum(1 for h in st.hc_results if h.reachable),
            "results": [
                {
                    "server_name": h.server_name,
                    "reachable": h.reachable,
                    "latency_ms": h.latency_ms,
                    "protocol_version": h.protocol_version,
                    "tool_count": h.tool_count,
                    "error": h.error,
                }
                for h in st.hc_results
            ],
        }


def run_report(opts: ScanOptions, st: ScanState) -> None:
    """Build the AI-BOM report and attach every collected evidence block."""
    _collect_scan_sources(opts, st)
    _seed_findings_and_scan_id(opts, st)
    _collect_scan_issues(opts, st)
    _collect_cloud_scopes(opts, st)
    _build_report(opts, st)
    _attach_context_data(opts, st)
    _attach_benchmarks(opts, st)
    _attach_estate_and_runtime(opts, st)
