"""Route graph-derived findings onto the scan report.

Several evaluators compute findings over the *unified graph* (built after every
overlay has enriched it) rather than from the raw agent inventory: NHI/CIEM
governance (over-grant, dormant/orphaned, high-risk identities) and
toxic-combination attack chains. Historically only the CLI scan command lifted
these onto the report, so the API/hosted scan surfaced fewer finding categories
than the CLI.

This module is the single place both callers use to attach those findings, so
the CLI and the API stay in parity. MCP tool-schema rule findings are *not*
handled here — they derive from the report's own tools inside
:meth:`AIBOMReport.to_findings` and need no graph, so they surface on every path
automatically.

Every step is best-effort and never raises into the scan: a graph-derived
failure must never fail the scan job.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_bom.graph.container import UnifiedGraph
    from agent_bom.models import AIBOMReport

_logger = logging.getLogger(__name__)


def attach_graph_derived_findings(report: "AIBOMReport", graph: "UnifiedGraph") -> None:
    """Surface NHI-governance and toxic-combination findings from ``graph`` onto
    ``report`` so the unified stream (``report.to_findings()``) — and therefore
    the findings API, SARIF, and the severity gate — reaches CLI parity.

    Idempotent: the underlying findings carry deterministic ids, and
    ``to_findings()`` dedupes by id, so re-running does not multiply findings.
    Fail-closed: absent evidence yields no finding; nothing is fabricated.
    """
    # ── NHI / CIEM governance ────────────────────────────────────────────────
    # The builder materializes these onto the graph via
    # apply_nhi_governance_with_findings; lift the Finding objects onto the report.
    try:
        nhi = list(getattr(graph, "nhi_governance_findings", None) or [])
        if nhi:
            report.nhi_governance_findings = nhi
    except Exception as exc:  # noqa: BLE001 — never fail the scan on findings surfacing
        _logger.debug("NHI governance findings surfacing skipped: %s", exc)

    # ── Toxic combinations ───────────────────────────────────────────────────
    # Run the declarative rule evaluator on the fully-enriched graph and store the
    # serialized findings; to_findings() rehydrates them (mirrors the CLI path).
    try:
        from agent_bom.graph.toxic_findings import build_toxic_combination_findings_data

        toxic = build_toxic_combination_findings_data(graph)
        if toxic:
            report.toxic_combination_findings_data = toxic
    except Exception as exc:  # noqa: BLE001
        _logger.debug("Toxic-combination findings surfacing skipped: %s", exc)

    # ── CIEM over-privilege (Access-Advisor right-sizing) ────────────────────
    # Usage-evidence right-sizing findings; serialized like toxic combinations
    # and rehydrated by to_findings().
    try:
        from agent_bom.graph.nhi_governance import build_ciem_over_privilege_findings_data

        ciem = build_ciem_over_privilege_findings_data(graph)
        if ciem:
            report.ciem_over_privilege_findings_data = ciem
    except Exception as exc:  # noqa: BLE001
        _logger.debug("CIEM over-privilege findings surfacing skipped: %s", exc)

    # ── Finding ↔ graph node FK stamping ─────────────────────────────────────
    # Prefer stable Finding.id on vuln nodes and Finding.node_id on estate nodes
    # so investigation paths are not CVE-label-only.
    try:
        from agent_bom.graph.asset_entity import link_findings_to_graph_nodes

        findings = list(report.to_findings())
        linked = link_findings_to_graph_nodes(findings, graph)
        if linked:
            # Persist stamped FKs onto report.findings when the dual-write list
            # is empty so subsequent to_findings() / API serialization see them.
            if not getattr(report, "findings", None):
                report.findings = findings
            else:
                by_id = {str(getattr(f, "id", "")): f for f in findings}
                for existing in report.findings:
                    stamped = by_id.get(str(getattr(existing, "id", "")))
                    if stamped is None:
                        continue
                    if not getattr(existing, "node_id", None) and getattr(stamped, "node_id", None):
                        existing.node_id = stamped.node_id
                    if not getattr(existing, "finding_node_id", None) and getattr(stamped, "finding_node_id", None):
                        existing.finding_node_id = stamped.finding_node_id
                    if not getattr(existing, "entity_type", None) and getattr(stamped, "entity_type", None):
                        existing.entity_type = stamped.entity_type
    except Exception as exc:  # noqa: BLE001
        _logger.debug("finding↔node linking skipped: %s", exc)


def surface_graph_derived_findings(report: "AIBOMReport", *, scan_id: str, tenant_id: str) -> None:
    """Build the unified graph from ``report`` and attach graph-derived findings.

    The single build+attach entry point shared by the CLI (default path), the API
    scan pipeline, and the MCP scan tool, so every scan surface emits the same
    graph-derived categories (``COMBINATION`` / ``CIEM_OVER_PRIVILEGE`` / ``NHI``).

    The interim JSON and the throwaway graph are locals released when this returns,
    so the surfacing graph never outlives the call. Best-effort: a graph-build or
    surfacing failure is logged and swallowed — it must never fail the scan.
    """
    try:
        from agent_bom.graph.builder import build_unified_graph_from_report
        from agent_bom.output import to_json

        interim_json = to_json(report)
        graph = build_unified_graph_from_report(interim_json, scan_id=scan_id, tenant_id=tenant_id)
        attach_graph_derived_findings(report, graph)
    except Exception as exc:  # noqa: BLE001 — never fail the scan on findings surfacing
        _logger.debug("graph-derived findings surfacing skipped: %s", exc)


__all__ = ["attach_graph_derived_findings", "surface_graph_derived_findings"]
