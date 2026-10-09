"""Extraction, scanning, analysis and report-building stages of the API scan pipeline."""

from __future__ import annotations

import logging
from typing import Any

from agent_bom.api.models import JobStatus
from agent_bom.api.scan_context import ScanContext
from agent_bom.api.scan_report_support import (
    _apply_tenant_workflow_metadata,
    _ast_result_for_symbol_reach,
    _project_paths_for_symbol_reach,
    _promote_repo_dependency_inventory,
    _rendered_result_document,
    _surface_graph_derived_findings,
)
from agent_bom.parsers.sbom_context import imported_cloud_inventory
from agent_bom.scanners.supplied_findings import build_supplied_findings
from agent_bom.security import sanitize_error, sanitize_sensitive_payload, sanitize_text

_logger = logging.getLogger("agent_bom.api.pipeline")


def extract_packages_stage(ctx: ScanContext) -> bool:
    from agent_bom.parsers import extract_packages

    agents = ctx.agents
    ctx.pipeline.start_step("extraction", f"Extracting packages from {len(agents)} agent(s)...")
    for agent in agents:
        for server in agent.mcp_servers:
            if server.security_blocked:
                continue  # Don't extract packages from security-blocked servers
            if not server.packages and server.command != "external-scan":
                server.packages = extract_packages(
                    server,
                    resolve_transitive=True,  # Match CLI behavior — resolve full dep tree
                    max_depth=3,
                )
    if ctx.req.external_scan:
        from agent_bom.parsers.external_import import fold_external_packages

        ctx.warnings_all.extend(fold_external_packages(agents, findings=ctx.external_findings))
    total_pkgs = sum(len(server.packages) for agent in agents for server in agent.mcp_servers if not server.security_blocked)
    ctx.all_packages = [package for agent in agents for server in agent.mcp_servers for package in server.packages]
    ctx.pipeline.complete_step("extraction", f"Extracted {total_pkgs} packages", {"packages": total_pkgs})
    return False


def _scan_message(ctx: ScanContext, total_pkgs: int) -> str:
    if ctx.req.offline:
        return f"Scanning {total_pkgs} packages against the local vulnerability DB only..."
    if ctx.effective_enrich:
        return f"Scanning {total_pkgs} packages via OSV.dev with vulnerability enrichment..."
    return f"Scanning {total_pkgs} packages via OSV.dev..."


def _retry_scan_without_enrichment(ctx: ScanContext, safe_scan_error: str) -> list[Any]:
    from agent_bom.scanners import scan_agents_sync

    # Log but don't crash — return what we have with warning
    _logger.warning("Scan phase error (retrying without enrichment): %s", safe_scan_error)
    ctx.pipeline.update_step("scanning", f"Scan error: {safe_scan_error} — retrying without enrichment")
    try:
        return scan_agents_sync(ctx.agents, enable_enrichment=False, offline=False, compliance_enabled=True)
    except Exception as retry_exc:  # noqa: BLE001
        _logger.error("Scan retry also failed: %s", sanitize_text(sanitize_error(retry_exc)))
        from agent_bom.scanners.executor import ScannerDriverError, apply_registered_failure_mode

        # Registry marks sca-vulnerability FAIL_CLOSED; honor that after retries.
        try:
            soft = apply_registered_failure_mode("sca-vulnerability", retry_exc)
        except ScannerDriverError:
            raise
        ctx.record_coverage_warning(f"CVE scanning failed: {sanitize_error(retry_exc)}")
        if soft is not None and soft.telemetry.warnings:
            ctx.warnings_all.extend(soft.telemetry.warnings)
        return []


def _scan_vulnerabilities(ctx: ScanContext) -> list[Any]:
    from agent_bom.scanners import scan_agents_sync

    req = ctx.req
    try:
        return scan_agents_sync(ctx.agents, enable_enrichment=ctx.effective_enrich, offline=req.offline, compliance_enabled=True)
    except Exception as scan_exc:  # noqa: BLE001
        safe_scan_error = sanitize_error(scan_exc)
        if not req.offline:
            return _retry_scan_without_enrichment(ctx, safe_scan_error)
        _logger.warning("Offline scan phase error: %s", safe_scan_error)
        ctx.pipeline.update_step("scanning", f"Offline scan error: {safe_scan_error}")
        ctx.record_coverage_warning(f"Offline CVE scanning failed: {safe_scan_error}")
        return []


def _record_enrichment_step(ctx: ScanContext) -> None:
    req = ctx.req
    if not req.no_scan and req.offline and req.enrich:
        ctx.warnings_all.append("Enrichment skipped because offline mode was requested")
    if req.no_scan:
        ctx.pipeline.skip_step("enrichment", "Vulnerability scanning skipped")
    elif ctx.effective_enrich:
        # Enrichment is executed inside scan_agents_sync, alongside the
        # vulnerability query. Emit a terminal event only so SSE timing does
        # not claim a separate enrichment phase ran after scanning.
        ctx.pipeline.complete_step("enrichment", "Enrichment completed during scanning", {"executed_in_step": "scanning"})
    else:
        ctx.pipeline.skip_step("enrichment", "Enrichment not requested")


def _filter_and_suppress(ctx: ScanContext) -> None:
    req = ctx.req
    if req.min_severity:
        _sev_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        _min = _sev_order.get(req.min_severity.lower(), 0)
        ctx.blast_radii = [br for br in ctx.blast_radii if _sev_order.get(br.vulnerability.severity.value.lower(), 0) >= _min]
    try:
        from agent_bom.api.stores import _get_exception_store
        from agent_bom.suppression_rules import apply_tenant_suppression_rules

        suppression = (
            {"suppressed": 0}
            if req.no_scan
            else apply_tenant_suppression_rules(ctx.blast_radii, _get_exception_store(), tenant_id=ctx.tenant_or_default)
        )
        if suppression["suppressed"]:
            ctx.warnings_all.append(f"{suppression['suppressed']} finding(s) suppressed by tenant feedback/rules")
    except Exception as exc:  # noqa: BLE001
        _logger.warning("Tenant suppression-rule evaluation skipped: %s", sanitize_text(sanitize_error(exc)))
        ctx.warnings_all.append("Tenant suppression-rule evaluation skipped")


def scan_vulnerabilities_stage(ctx: ScanContext) -> bool:
    """Query vulnerabilities (or fold supplied findings), then filter and suppress."""
    req = ctx.req
    ctx.blast_radii = build_supplied_findings(ctx.agents) if req.no_scan else []
    if req.no_scan:
        ctx.pipeline.skip_step("scanning", "Vulnerability scanning skipped by request")
        ctx.warnings_all.append("Vulnerability scanning skipped by request")
    else:
        total_pkgs = sum(len(server.packages) for agent in ctx.agents for server in agent.mcp_servers if not server.security_blocked)
        ctx.pipeline.start_step("scanning", _scan_message(ctx, total_pkgs))
        ctx.blast_radii = _scan_vulnerabilities(ctx)
        total_vulns = sum(len(p.vulnerabilities) for a in ctx.agents for s in a.mcp_servers for p in s.packages)
        ctx.pipeline.complete_step("scanning", f"Found {total_vulns} vulnerabilities", {"vulnerabilities": total_vulns})
    _record_enrichment_step(ctx)
    _filter_and_suppress(ctx)
    return False


def analyse_reachability_stage(ctx: ScanContext) -> bool:
    """Stamp graph-walk and symbol reachability onto each blast-radius row."""
    ctx.pipeline.start_step("analysis", "Computing blast radius...")
    # Surface graph-walk reachability onto each blast-radius row before
    # the report is built so the JSON payload (and risk_score) reflects
    # whether each vulnerable package is actually reachable from an
    # agent entrypoint, not just present in the dependency closure.
    try:
        from agent_bom.graph.blast_reach import (
            apply_dependency_reachability_to_blast_radii,
            apply_symbol_reachability_to_blast_radii,
        )

        stamped = apply_dependency_reachability_to_blast_radii(ctx.blast_radii, ctx.agents, rescore=True)
        if stamped:
            ctx.progress(f"Reachability: stamped {stamped} blast-radius row(s) with graph-walk evidence")
        ctx.ast_for_reach = _ast_result_for_symbol_reach(_project_paths_for_symbol_reach(ctx.req, extra_paths=ctx.extra_symbol_paths))
        if ctx.ast_for_reach is not None:
            sym_stamped = apply_symbol_reachability_to_blast_radii(ctx.blast_radii, ctx.ast_for_reach, packages=ctx.all_packages)
            if sym_stamped:
                ctx.progress(f"Symbol reachability: stamped {sym_stamped} blast-radius row(s) with function-level evidence")
    except Exception as reach_exc:  # noqa: BLE001
        _logger.warning("Reachability surfacing skipped: %s", sanitize_text(sanitize_error(reach_exc)))
    ctx.pipeline.complete_step("analysis", f"Computed {len(ctx.blast_radii)} blast radius entries", {"blast_radius": len(ctx.blast_radii)})
    return False


def _report_findings(ctx: ScanContext) -> list[Any]:
    from agent_bom.a2a_auth_posture import evaluate_a2a_auth_posture
    from agent_bom.finding import blast_radius_to_finding
    from agent_bom.mcp_auth_posture import evaluate_mcp_auth_posture
    from agent_bom.mcp_blocklist import blocklist_findings_for_agents

    report_findings = [blast_radius_to_finding(br) for br in ctx.blast_radii]
    report_findings.extend(ctx.external_findings)
    report_findings.extend(blocklist_findings_for_agents(ctx.agents))
    try:
        report_findings.extend(evaluate_a2a_auth_posture(ctx.agents))
    except Exception as a2a_exc:  # noqa: BLE001
        _logger.warning("A2A auth posture evaluation skipped: %s", sanitize_text(sanitize_error(a2a_exc)))
    try:
        report_findings.extend(evaluate_mcp_auth_posture(ctx.agents))
    except Exception as mcp_auth_exc:  # noqa: BLE001
        _logger.warning("MCP auth posture evaluation skipped: %s", sanitize_text(sanitize_error(mcp_auth_exc)))
    return report_findings


def attach_repo_evidence(ctx: ScanContext, report: Any) -> None:
    """Attach the static repository evidence collected during discovery."""
    if ctx.skill_audit_data is not None:
        report.skill_audit_data = ctx.skill_audit_data
        from agent_bom.parsers.skill_audit import replace_skill_findings

        replace_skill_findings(report, ctx.skill_audit_data)
    if ctx.iac_findings_data is not None:
        report.iac_findings_data = ctx.iac_findings_data
    if ctx.repo_ai_inventory_data is not None:
        report.ai_inventory_data = ctx.repo_ai_inventory_data
        _promote_repo_dependency_inventory(report, ctx.repo_ai_inventory_data)


def attach_repo_metadata(ctx: ScanContext, report: Any) -> None:
    if ctx.repo_sast_data is not None:
        report.sast_data = ctx.repo_sast_data
    if ctx.repo_trust_data is not None:
        report.repo_trust_data = ctx.repo_trust_data
    report.codeowners = dict(ctx.repo_codeowners)


def _apply_vex(ctx: ScanContext, report: Any) -> None:
    req = ctx.req
    if not req.vex:
        return
    from agent_bom.finding import blast_radius_to_finding
    from agent_bom.vex import apply_vex, load_vex
    from agent_bom.vex import to_serializable as vex_to_serializable

    try:
        _vex_doc = load_vex(req.vex)
    except ValueError as vex_exc:
        raise RuntimeError(f"Failed to load VEX file: {vex_exc}") from vex_exc
    _vex_count = apply_vex(report, _vex_doc)
    report.vex_data = vex_to_serializable(_vex_doc)
    # Preserve non-CVE policy findings while replacing stale CVE
    # projections with the VEX-updated blast-radius representation.
    non_cve_findings = [
        finding
        for finding in report.findings
        if finding.finding_type.value != "CVE" or finding.evidence.get("package_resolution") == "unresolved"
    ]
    report.findings = [blast_radius_to_finding(br) for br in ctx.blast_radii] + non_cve_findings
    ctx.progress(str(sanitize_sensitive_payload(f"VEX applied: {_vex_count} vulnerabilities updated from {req.vex}")))


def _build_report(ctx: ScanContext) -> Any:
    from agent_bom.models import AIBOMReport

    report = AIBOMReport(
        agents=ctx.agents,
        blast_radii=ctx.blast_radii,
        findings=_report_findings(ctx),
        cloud_inventory_data=imported_cloud_inventory(ctx.agents),
        scan_id=ctx.job.job_id,
        scan_run=ctx.build_scan_run(has_usable_evidence=True),
    )
    if ctx.ast_for_reach is not None:
        report.ai_inventory_data = report.ai_inventory_data or {}
        report.ai_inventory_data["ast_analysis"] = ctx.ast_for_reach.to_dict()
    attach_repo_evidence(ctx, report)
    attach_repo_metadata(ctx, report)
    _apply_vex(ctx, report)
    try:
        from agent_bom.scanners import consume_coverage_warnings

        _coverage_warnings = consume_coverage_warnings()
        if _coverage_warnings:
            report.coverage_warnings = _coverage_warnings
    except Exception as cov_exc:  # noqa: BLE001
        _logger.debug("coverage-warning attach skipped: %s", sanitize_text(sanitize_error(cov_exc)))
    return report


def _enrich_report(ctx: ScanContext, report: Any) -> None:
    # Opt-in estate enrichment (cloud inventory + NHI discovery). Default
    # OFF: no-op and no network I/O unless the per-provider env flags are
    # set; the graph builder consumes the attached blocks. Never raises.
    try:
        from agent_bom.scan_enrichment import enrich_report_with_estate_discovery

        enrich_report_with_estate_discovery(report)
    except Exception as enrich_exc:  # noqa: BLE001
        _logger.warning("Estate enrichment skipped: %s", sanitize_text(sanitize_error(enrich_exc)))

    req = ctx.req
    if req.ai_enrich:
        try:
            from agent_bom.ai_enrich import run_ai_enrichment_sync

            run_ai_enrichment_sync(report, model=req.ai_model, deterministic=req.ai_deterministic)
        except Exception as ai_exc:  # noqa: BLE001
            _logger.warning("Advisory AI enrichment skipped: %s", sanitize_text(sanitize_error(ai_exc, generic=True)))
            ctx.progress("Advisory AI enrichment skipped")

    # Graph-derived findings: build the unified graph once (after every report
    # side block is set) and surface NHI-governance + toxic-combination findings
    # onto the report so the hosted scan reaches CLI parity — before to_json()
    # serializes the unified stream. Best-effort: never fails the scan. MCP
    # tool-rule findings derive from report tools inside to_findings(), so they
    # need no graph and are already covered.
    #
    # The surfacing graph + its interim JSON are scoped to the helper so they
    # are released before the persist phase rebuilds the graph — otherwise the
    # full-scan path holds two full current graphs (each with its own node
    # dict, edge list, and adjacency indexes) at the persist peak (#4055/#4075).
    try:
        _surface_graph_derived_findings(report, scan_id=ctx.job.job_id, tenant_id=ctx.job.tenant_id or "")
    except Exception as gderiv_exc:  # noqa: BLE001
        _logger.warning("Graph-derived findings surfacing skipped: %s", sanitize_text(sanitize_error(gderiv_exc)))


def build_report_stage(ctx: ScanContext) -> bool:
    """Build, enrich and serialize the report, then publish it on the job."""
    from agent_bom.output import to_json

    ctx.pipeline.start_step("output", "Building report...")
    report = _build_report(ctx)
    _enrich_report(ctx, report)
    _apply_tenant_workflow_metadata(report, tenant_id=ctx.tenant_or_default)
    report_json = to_json(report)
    if ctx.req.no_scan and ctx.has_static_repo_evidence():
        # Adding inventory evidence must not erase the established status
        # of a static-findings-only repository scan.
        report_json["status"] = "findings_only"
    result_document, document_note = _rendered_result_document(ctx.job, report)
    with ctx.lock:
        ctx.job.result = report_json
        ctx.job.result_document = result_document
        if document_note:
            ctx.job.progress.append(document_note)
        ctx.job.status = JobStatus.DONE
    ctx.report = report
    ctx.report_json = report_json
    return False
