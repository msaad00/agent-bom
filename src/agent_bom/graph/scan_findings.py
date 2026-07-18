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


__all__ = ["attach_graph_derived_findings"]
