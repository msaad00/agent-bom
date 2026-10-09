"""Report helpers shared by the API scan pipeline stages.

Re-exported from :mod:`agent_bom.api.pipeline`, their historical home.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from datetime import datetime
from typing import Any

from agent_bom.api.models import ScanJob
from agent_bom.security import sanitize_error, sanitize_text

_logger = logging.getLogger("agent_bom.api.pipeline")


def _surface_graph_derived_findings(
    report: Any,
    *,
    scan_id: str,
    tenant_id: str,
) -> None:
    """Attach graph-derived findings (NHI-governance, toxic-combination) to the report.

    The unified graph built here — with its node dict, edge list, and adjacency /
    reverse-adjacency indexes — plus the interim JSON are locals of the shared
    helper, so they are released when it returns. Scoping them keeps the surfacing
    graph from outliving the call and overlapping the persist phase's own graph
    rebuild, which would otherwise leave the full-scan path holding two full current
    graphs at the persist peak (#4055/#4075).

    Delegates to the single build+attach helper the CLI and MCP scan surfaces also
    use, so all three emit the same graph-derived finding categories.
    """
    from agent_bom.graph.scan_findings import surface_graph_derived_findings

    surface_graph_derived_findings(report, scan_id=scan_id, tenant_id=tenant_id)


def _project_paths_for_symbol_reach(req: Any, *, extra_paths: Iterable[str] | None = None) -> list[str]:
    """Collect scan-target paths that may contain Python source for symbol reach."""
    paths: list[str] = []
    seen: set[str] = set()
    for raw in (
        list(getattr(req, "agent_projects", []) or [])
        + list(getattr(req, "filesystem_paths", []) or [])
        + list(getattr(req, "jupyter_dirs", []) or [])
        + ([req.gha_path] if getattr(req, "gha_path", None) else [])
        + list(extra_paths or [])
    ):
        if raw and raw not in seen:
            seen.add(raw)
            paths.append(raw)
    return paths


def _ast_result_for_symbol_reach(paths: Iterable[str]) -> Any | None:
    """Best-effort AST symbol-reach for API pipeline parity with CLI --project."""
    from pathlib import Path

    from agent_bom.ast_analyzer import analyze_project, project_has_analyzable_sources
    from agent_bom.ast_models import ASTAnalysisResult

    merged: ASTAnalysisResult | None = None
    for raw in paths:
        project = Path(raw)
        try:
            if not project_has_analyzable_sources(project):
                continue
        except OSError as path_exc:
            _logger.debug("AST symbol-reach path skipped for %s: %s", raw, sanitize_text(sanitize_error(path_exc)))
            continue
        try:
            result = analyze_project(project)
        except Exception as ast_exc:  # noqa: BLE001
            _logger.debug("AST symbol-reach analysis skipped for %s: %s", raw, sanitize_text(sanitize_error(ast_exc)))
            continue
        if merged is None:
            merged = result
        else:
            if result.application_entrypoints:
                merged.application_entrypoints.extend(result.application_entrypoints)
            if result.dependency_symbol_reach:
                merged.dependency_symbol_reach.extend(result.dependency_symbol_reach)
            merged.files_analyzed += result.files_analyzed
            merged.analysis_coverage.eligible_files += result.analysis_coverage.eligible_files
            merged.analysis_coverage.analyzed_files += result.analysis_coverage.analyzed_files
            if result.analysis_coverage.status == "partial":
                merged.analysis_coverage.status = "partial"
                merged.analysis_coverage.partial_files.extend(result.analysis_coverage.partial_files)
            merged.warnings.extend(result.warnings)
    return merged


def _promote_repo_dependency_inventory(report: Any, ai_inventory: dict[str, Any]) -> None:
    """Lift nested API dependency inventory to top-level for graph overlay parity with CLI."""
    if getattr(report, "project_inventory_data", None):
        return
    nested = ai_inventory.get("dependency_inventory")
    if isinstance(nested, dict) and nested:
        report.project_inventory_data = nested


def _apply_tenant_workflow_metadata(report: Any, *, tenant_id: str) -> None:
    """Join tenant-scoped owner and current lifecycle metadata before export.

    Scan documents are rendered from ``AIBOMReport`` objects, while control-plane
    assignments live in the tenant exception store.  Joining once here keeps
    JSON and every requested document format aligned on a rescan without making
    the formatters aware of authentication or persistence.
    """
    from agent_bom.api.routes.enterprise import build_tenant_triage_owner_index, triage_owner_for

    try:
        owner_index = build_tenant_triage_owner_index(tenant_id)
    except Exception as exc:  # noqa: BLE001 - workflow metadata must not fail the scan artifact
        _logger.warning("Finding owner enrichment unavailable: %s", sanitize_text(sanitize_error(exc, generic=True)))
        owner_index = {}
    observed_at = getattr(report, "generated_at", None)
    observed_text = observed_at.isoformat() if isinstance(observed_at, datetime) else str(observed_at or "")

    for finding in getattr(report, "findings", ()) or ():
        if getattr(finding, "first_seen", None) is None and observed_text:
            finding.first_seen = observed_text
        if getattr(finding, "lifecycle_status", None) is None:
            finding.lifecycle_status = "suppressed" if bool(getattr(finding, "suppressed", False)) else "open"
        if getattr(finding, "owner", None) or not owner_index:
            continue
        evidence = getattr(finding, "evidence", None)
        evidence = evidence if isinstance(evidence, dict) else {}
        affected_servers = getattr(finding, "affected_servers", None) or []
        server_name = str(affected_servers[0]) if affected_servers else ""
        package = str(evidence.get("package_name") or getattr(getattr(finding, "asset", None), "name", "") or "")
        owner = triage_owner_for(
            owner_index,
            vuln_id=str(getattr(finding, "cve_id", None) or getattr(finding, "id", "")),
            package=package,
            server_name=server_name,
        )
        if owner:
            finding.owner = owner


def _rendered_result_document(job: ScanJob, report: Any, blast_radii: list | None = None) -> tuple[dict[str, Any] | str | None, str | None]:
    """Render the finished report in the format the request asked for.

    Returns ``(document, note)``. ``document`` is ``None`` for ``format=json``
    (``job.result`` already carries the AI-BOM JSON) and on a render failure,
    in which case ``note`` explains why — never a silent empty document that
    would read as an audited result.
    """
    requested = str(getattr(job.request, "format", "json") or "json")
    if requested == "json":
        return None, None
    try:
        from agent_bom.output.scan_document import render_scan_document

        return render_scan_document(report, requested, blast_radii=blast_radii), None
    except Exception as exc:  # noqa: BLE001 — a formatting failure never fails the scan
        _logger.warning("Rendering scan result as %s failed: %s", requested, sanitize_text(sanitize_error(exc, generic=True)))
        return None, f"Requested {requested} output could not be rendered; result carries AI-BOM JSON only"
