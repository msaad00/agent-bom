"""Surface graph-walk reachability into BlastRadius rows.

Bridge between the engine in ``agent_bom.graph.dependency_reach`` and the
report-layer ``BlastRadius`` model. Closes the v0.82.2 honest gap where
the engine shipped but no caller wired the answer back into scoring or
the dashboard. Operators see the new fields on every blast-radius row
and the score adjustment is documented in
``site-docs/deployment/scaling-slo.md``-adjacent docs.

The surfacing is intentionally thin: build the unified graph from the
agents+blast_radii produced by the scan, walk it via
``compute_dependency_reach``, and stamp three new fields on each
``BlastRadius`` row that match the engine's per-vulnerability output.
The risk-score nudge is applied next time ``br.calculate_risk_score()``
runs (or immediately if the caller wants the new value reflected — see
``apply_dependency_reachability_to_blast_radii``).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.dependency_reach import compute_dependency_reach

if TYPE_CHECKING:
    from agent_bom.ast_models import ASTAnalysisResult
    from agent_bom.models import Agent, BlastRadius

_logger = logging.getLogger(__name__)

# Ecosystems where a symbol-level call graph join is supported.
_SYMBOL_REACH_ECOSYSTEMS: frozenset[str] = frozenset(
    {"pypi", "python", "npm", "go", "maven", "java", "cargo", "rust"}
)


def apply_dependency_reachability_to_blast_radii(
    blast_radii: list["BlastRadius"],
    agents: list["Agent"],
    *,
    rescore: bool = True,
) -> int:
    """Stamp graph-walk reachability fields on each BlastRadius row.

    Returns the count of rows whose reachability fields were populated.
    Failures (graph build error, empty graph, edge case) downgrade to a
    no-op rather than fail the scan — callers expect this to be
    best-effort enrichment.

    When ``rescore`` is true (the default), each affected row's
    ``calculate_risk_score()`` is re-run so the optional boost/penalty
    in ``BlastRadius.calculate_risk_score`` is applied immediately.
    """
    if not blast_radii or not agents:
        return 0

    try:
        # Build a minimal report dict — the engine only needs the topology
        # the graph builder can reconstruct from agents + blast_radii. Using
        # `to_json` here would couple us to the full output package and
        # double-build the graph.
        from agent_bom.models import AIBOMReport
        from agent_bom.output import to_json

        report = AIBOMReport(agents=agents, blast_radii=blast_radii, scan_id="reachability-scratch")
        graph = build_unified_graph_from_report(to_json(report))
        reach = compute_dependency_reach(graph)
    except Exception as exc:  # noqa: BLE001
        _logger.warning("Graph reachability surfacing skipped: %s", exc)
        return 0

    stamped = 0
    for br in blast_radii:
        # The graph builder mints vulnerability node ids as "vuln:<id>" so
        # the engine's report is keyed by that, not the bare CVE id.
        node_id = f"vuln:{br.vulnerability.id}"
        vuln_reach = reach.vulnerabilities.get(node_id)
        if vuln_reach is None:
            continue
        br.graph_reachable = vuln_reach.reachable
        br.graph_min_hop_distance = vuln_reach.min_hop_distance if vuln_reach.reachable else None
        br.graph_reachable_from_agents = list(vuln_reach.reachable_from)
        if rescore:
            br.calculate_risk_score()
        stamped += 1

    return stamped


def apply_symbol_reachability_to_blast_radii(
    blast_radii: list["BlastRadius"],
    ast_result: "ASTAnalysisResult",
) -> int:
    """Join CVE affected-symbols to AST symbol reach on each BlastRadius row.

    Thin additive surfacing of :mod:`agent_bom.reachability_cve`. For Python, npm,
    Go, Maven, and Cargo findings it stamps ``symbol_reachability``
    (function_reachable / package_reachable / unreachable) when AST evidence
    passes conservative import-proof guards. Rust/Java parsers are regex-backed:
    they never invent Maven coordinates or walk unresolved MCP tool handlers.

    The graph-walk reach already on the row (``graph_reachable``) is fed in as
    the import / dependency-closure fallback so a package that is reached but
    whose symbols were not individually captured reports ``package_reachable``
    rather than ``unreachable``.

    Returns the count of rows whose signal was populated. Best-effort: any
    failure downgrades to a no-op rather than failing the scan.
    """
    if not blast_radii or ast_result is None:
        return 0

    try:
        from agent_bom.reachability_cve import SymbolReachIndex, classify_reachability

        index = SymbolReachIndex.from_ast_result(ast_result)
    except Exception as exc:  # noqa: BLE001
        _logger.warning("Symbol reachability surfacing skipped: %s", exc)
        return 0

    # No symbol-reach evidence at all (no Python entrypoints analysed). Stamping
    # would mark every Python finding "unreachable" on no basis, which is a
    # false negative — skip entirely rather than over-claim.
    if not index:
        return 0

    stamped = 0
    for br in blast_radii:
        ecosystem = (getattr(br.package, "ecosystem", "") or "").lower()
        if ecosystem not in _SYMBOL_REACH_ECOSYSTEMS:
            continue
        try:
            signal = classify_reachability(
                package=br.package.name,
                advisory=br.vulnerability,
                index=index,
                package_reachable=br.graph_reachable,
                ecosystem=ecosystem,
            )
        except Exception as exc:  # noqa: BLE001
            _logger.warning("Symbol reachability classify skipped for %s: %s", br.package.name, exc)
            continue
        br.symbol_reachability = signal.state
        br.reachable_affected_symbols = list(signal.matched_symbols)
        stamped += 1

    return stamped


__all__ = [
    "apply_dependency_reachability_to_blast_radii",
    "apply_symbol_reachability_to_blast_radii",
]
