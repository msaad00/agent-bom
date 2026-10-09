"""Post-projection report overlays applied by the unified graph builder's analysis stage."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_bom.core.severity import SEVERITY_RANK
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.types import EntityType


def _apply_cost_overlay(graph: UnifiedGraph, report_json: Mapping[str, Any]) -> None:
    """Fuse LLM cost into the graph from cost records carried on the report.

    Reads the optional ``llm_cost_records`` block (a list of priced cost-record
    dicts the caller loaded from the cost store — never fetched here) and hands
    it to :func:`agent_bom.graph.cost_overlay.apply_cost_overlay`. Gated to a
    clean no-op when the block is absent or empty, so an ordinary scan (no cost
    data) leaves the graph byte-identical. Mirrors how ``cnapp_overlay`` /
    ``governance_overlay`` are invoked above.
    """
    raw = report_json.get("llm_cost_records")
    if not isinstance(raw, list) or not raw:
        return
    records = [r for r in raw if isinstance(r, dict)]
    if not records:
        return
    from datetime import datetime, timezone

    from agent_bom.graph.cost_overlay import apply_cost_overlay

    apply_cost_overlay(graph, records, datetime.now(timezone.utc))


def _apply_agent_reach_risk(graph: UnifiedGraph) -> None:
    """Score each agent by the worst vulnerability in its dependency closure.

    Agents reaching no vulnerability stay unassessed rather than being claimed
    risk-free, because the closure only covers vulnerability evidence.

    Walks the inverse of the dependency-reach edges once, worst vulnerability
    first: a node already reached by a worse vulnerability bounds all of its
    ancestors, so every node is visited at most once.
    """
    from collections import deque

    from agent_bom.graph.dependency_reach import _REACH_EDGE_TYPES, _vulnerability_packages

    agent_ids = {node.id for node in graph.iter_nodes_by_type(EntityType.AGENT)}
    if not agent_ids:
        return
    vulns = sorted(
        (
            (node.risk_score, SEVERITY_RANK.get(node.severity.lower(), 0), node.id, node.severity, node.severity_id)
            for node in graph.iter_nodes_by_type(EntityType.VULNERABILITY)
            if node.risk_score > 0 or node.severity
        ),
        reverse=True,
    )
    visited: set[str] = set()
    for risk_score, _rank, vuln_id, severity, severity_id in vulns:
        queue = deque(pkg for pkg in _vulnerability_packages(graph, vuln_id) if pkg not in visited)
        visited.update(queue)
        while queue:
            current = queue.popleft()
            if current in agent_ids:
                agent = graph.get_node(current)
                if agent is not None and agent.risk_score <= risk_score:
                    agent.risk_score = risk_score
                    agent.severity = severity
                    agent.severity_id = severity_id
                    agent.mark_risk_assessed(basis="max_reachable_vulnerability_risk", scope="agent_dependency_closure_vulnerabilities")
            for edge in graph.reverse_adjacency.get(current, []):
                if edge.relationship in _REACH_EDGE_TYPES and edge.source not in visited:
                    visited.add(edge.source)
                    queue.append(edge.source)


def _apply_aspm_overlay(graph: UnifiedGraph, report_json: Mapping[str, Any]) -> None:
    """Correlate AppSec findings around applications from the report's findings.

    Reads the optional unified ``findings`` block (a list of ``Finding.to_dict()``
    dicts the report already carries) and hands it to
    :func:`agent_bom.graph.aspm_overlay.apply_aspm_overlay`, which derives
    APPLICATION roots, attaches each finding via ``BELONGS_TO``, rolls up per-app
    risk, dedupes duplicate CVE/rule across sources, and flags reachability from
    existing attack-path data. Gated to a clean no-op when the block is absent or
    empty, so a scan with no findings leaves the graph byte-identical. Mirrors how
    ``_apply_cost_overlay`` is invoked above.
    """
    raw = report_json.get("findings")
    if not isinstance(raw, list) or not raw:
        return
    from datetime import datetime, timezone

    from agent_bom.graph.aspm_overlay import apply_aspm_overlay

    apply_aspm_overlay(graph, dict(report_json), datetime.now(timezone.utc))


def _apply_runtime_evidence_overlay(graph: UnifiedGraph, report_json: Mapping[str, Any]) -> None:
    from agent_bom.graph.evidence_overlay import apply_runtime_evidence_overlay

    apply_runtime_evidence_overlay(graph, report_json)


def _apply_repo_structure_overlay(graph: UnifiedGraph, report_json: Mapping[str, Any]) -> None:
    """Attach repository directories, manifests, packages and finding files.

    The owning overlay supplies file-to-package and finding-to-file edges.
    Reports with neither project inventory nor file findings are a no-op.
    """
    has_inventory = isinstance(report_json.get("project_inventory"), Mapping)
    if not has_inventory and not any(node.entity_type == EntityType.MISCONFIGURATION for node in graph.nodes.values()):
        return
    from datetime import datetime, timezone

    from agent_bom.graph.repo_structure_overlay import apply_repo_structure_overlay

    apply_repo_structure_overlay(graph, dict(report_json), datetime.now(timezone.utc))


def _apply_code_graph_overlay(graph: UnifiedGraph, report_json: Mapping[str, Any]) -> None:
    """Emit CODE_MODULE nodes from SOURCE_FILE evidence already on the graph."""
    if not any(node.entity_type == EntityType.SOURCE_FILE for node in graph.nodes.values()):
        return
    from datetime import datetime, timezone

    from agent_bom.graph.code_graph_overlay import apply_code_graph_overlay

    apply_code_graph_overlay(graph, dict(report_json), datetime.now(timezone.utc))


def _apply_repo_trust_overlay(graph: UnifiedGraph, report_json: Mapping[str, Any]) -> None:
    """Stamp ``repo_trust`` metadata onto APPLICATION (+ root DIRECTORY when present)."""
    has_trust = isinstance(report_json.get("repo_trust"), Mapping) and bool(report_json.get("repo_trust"))
    inventory = report_json.get("project_inventory")
    has_nested = isinstance(inventory, Mapping) and isinstance(inventory.get("repo_trust"), Mapping) and bool(inventory.get("repo_trust"))
    if not has_trust and not has_nested:
        return
    from datetime import datetime, timezone

    from agent_bom.graph.repo_trust_overlay import apply_repo_trust_overlay

    apply_repo_trust_overlay(graph, dict(report_json), datetime.now(timezone.utc))


def _apply_ci_graph_overlay(graph: UnifiedGraph, report_json: Mapping[str, Any]) -> None:
    """Emit CI_JOB topology from github-actions agents in the report."""
    agents = report_json.get("agents")
    if not isinstance(agents, list):
        return
    if not any(isinstance(agent, dict) and agent.get("source") == "github-actions" for agent in agents):
        return
    from datetime import datetime, timezone

    from agent_bom.graph.ci_graph_overlay import apply_ci_graph_overlay

    apply_ci_graph_overlay(graph, dict(report_json), datetime.now(timezone.utc))
