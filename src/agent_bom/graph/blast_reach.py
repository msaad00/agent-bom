"""Surface dependency and attack-path reachability into BlastRadius rows.

Bridge between the engine in ``agent_bom.graph.dependency_reach`` and the
report-layer ``BlastRadius`` model. Structural dependency closure is useful
context, but it is not evidence that a vulnerable function or attack path can
execute. Keep those semantics separate so a topology walk cannot inflate risk.

The surfacing is intentionally thin: build the unified graph from the
agents+blast_radii produced by the scan, walk it via
``compute_dependency_reach``, and stamp the dependency-specific fields on each
``BlastRadius`` row that match the engine's per-vulnerability output.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.dependency_reach import compute_dependency_reach

if TYPE_CHECKING:
    from agent_bom.ast_models import ASTAnalysisResult
    from agent_bom.finding import Finding
    from agent_bom.graph.dependency_reach import ReachabilityReport
    from agent_bom.models import Agent, BlastRadius, Package

_logger = logging.getLogger(__name__)

# Ecosystems where a symbol-level call graph join is supported.
_SYMBOL_REACH_ECOSYSTEMS: frozenset[str] = frozenset(
    {
        "pypi",
        "python",
        "npm",
        "go",
        "maven",
        "java",
        "cargo",
        "rust",
        "nuget",
        "rubygems",
        "composer",
        "swift",
    }
)


def apply_dependency_reachability_to_blast_radii(
    blast_radii: list["BlastRadius"],
    agents: list["Agent"],
    *,
    rescore: bool = True,
    reachability_report: "ReachabilityReport | None" = None,
) -> int:
    """Stamp structural dependency-closure fields on each BlastRadius row.

    Returns the count of rows whose reachability fields were populated.
    Failures (graph build error, empty graph, edge case) downgrade to a
    no-op rather than fail the scan — callers expect this to be
    best-effort enrichment.

    ``rescore`` preserves the existing caller contract, but structural closure
    does not trigger the attack-path score adjustment.
    """
    if not blast_radii or not agents:
        return 0

    try:
        if reachability_report is None:
            # Standalone callers retain the existing self-contained behavior.
            # Scan surfaces that already projected the unified graph pass the
            # precomputed report to avoid repeated serialization and building.
            from agent_bom.models import AIBOMReport
            from agent_bom.output import to_json

            report = AIBOMReport(agents=agents, blast_radii=blast_radii, scan_id="reachability-scratch")
            graph = build_unified_graph_from_report(to_json(report))
            reach = compute_dependency_reach(graph)
        else:
            reach = reachability_report
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
        br.dependency_reachable = vuln_reach.reachable
        br.dependency_min_hop_distance = vuln_reach.min_hop_distance if vuln_reach.reachable else None
        br.dependency_reachable_from_agents = list(vuln_reach.reachable_from)
        if rescore:
            br.calculate_risk_score()
        stamped += 1

    return stamped


def apply_symbol_reachability_to_blast_radii(
    blast_radii: list["BlastRadius"],
    ast_result: "ASTAnalysisResult",
    *,
    packages: list["Package"] | None = None,
    rescore: bool = True,
) -> int:
    """Join CVE affected-symbols to AST symbol reach on each BlastRadius row.

    Thin additive surfacing of :mod:`agent_bom.reachability_cve`. For Python, npm,
    Go, Maven, Cargo, NuGet, and RubyGems findings it stamps ``symbol_reachability``
    (function_reachable / package_reachable / unreachable) when AST evidence
    passes conservative import-proof guards. Rust/Java/C#/Ruby parsers are regex-backed:
    they never invent manifest coordinates or walk unresolved MCP tool handlers.

    Evidence-backed attack-path reach on the row (``graph_reachable``) and
    resolved runtime-only parent edges descending from a symbol-reached package
    are package fallbacks. Structural ``dependency_reachable`` manifest closure
    remains separate context and cannot upgrade symbol execution reachability.

    Returns the count of rows whose signal was populated. Scores are
    recalculated by default so the report cannot carry a post-analysis verdict
    beside a pre-analysis score; callers that are deliberately batching score
    calculation may opt out with ``rescore=False``. Best-effort: any failure
    downgrades to a no-op rather than failing the scan.
    """
    if not blast_radii or ast_result is None:
        return 0

    try:
        from agent_bom.reachability_cve import RuntimeDependencyReachIndex, SymbolReachIndex, classify_reachability

        index = SymbolReachIndex.from_ast_result(ast_result)
        runtime_index = RuntimeDependencyReachIndex.from_packages(packages or (), index)
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
            runtime_chain = runtime_index.chain_for_package(br.package.name, ecosystem=ecosystem)
            signal = classify_reachability(
                package=br.package.name,
                advisory=br.vulnerability,
                index=index,
                package_reachable=br.graph_reachable,
                runtime_dependency_chain=runtime_chain,
                ecosystem=ecosystem,
            )
        except Exception as exc:  # noqa: BLE001
            _logger.warning("Symbol reachability classify skipped for %s: %s", br.package.name, exc)
            continue
        br.symbol_reachability = signal.state
        br.reachable_affected_symbols = list(signal.matched_symbols)
        br.symbol_reachability_reason = signal.reason
        br.runtime_dependency_chain = list(signal.runtime_dependency_chain)
        if rescore:
            br.calculate_risk_score()
        stamped += 1

    return stamped


def resync_cve_findings_from_blast_radii(
    findings: list["Finding"] | None,
    blast_radii: list["BlastRadius"],
) -> int:
    """Re-project stamped reachability from ``blast_radii`` onto CVE findings.

    The CLI dual-write path materializes ``report.findings`` from ``blast_radii``
    *before* ``apply_dependency_reachability_to_blast_radii`` /
    ``apply_symbol_reachability_to_blast_radii`` stamp the rows. As a result the
    JSON ``findings[]`` projection (which reads ``report.findings``) carried
    ``symbol_reachability`` / ``graph_reachable`` = null while ``blast_radius[]``,
    CSV, Parquet, and SARIF — all rebuilt fresh from the stamped rows — carried
    the verdict. Rebuild each CVE finding from its stamped row (matched by
    canonical id) so every view agrees, without reordering or double-counting.

    Non-CVE findings (secrets, auth posture, prompt-scan, …) and CVE findings
    with no matching row are left untouched. Returns the number of CVE findings
    replaced. Best-effort: never raises.
    """
    if not findings or not blast_radii:
        return 0
    try:
        from agent_bom.finding import FindingType, blast_radius_to_finding

        fresh_by_id: dict[str, Finding] = {}
        for br in blast_radii:
            fresh = blast_radius_to_finding(br)
            fresh_by_id[fresh.id] = fresh

        replaced = 0
        for idx, finding in enumerate(findings):
            if finding.finding_type != FindingType.CVE:
                continue
            stamped = fresh_by_id.get(finding.id)
            if stamped is None:
                continue
            findings[idx] = stamped
            replaced += 1
        return replaced
    except Exception as exc:  # noqa: BLE001
        _logger.warning("CVE finding reachability resync skipped: %s", exc)
        return 0


__all__ = [
    "apply_dependency_reachability_to_blast_radii",
    "apply_symbol_reachability_to_blast_radii",
    "resync_cve_findings_from_blast_radii",
]
