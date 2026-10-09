"""Agent framework topology and cross-environment correlation projection."""

from __future__ import annotations

from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.projection_support import _agent_identity_scope, _agent_node_id
from agent_bom.graph.types import EntityType, RelationshipType


def _add_cross_env_correlation(
    graph: UnifiedGraph,
    agents_data: Any,
    data_source: str,
) -> None:
    """Emit local↔cloud correlation edges across all configured providers.

    The strict-bar matcher in :mod:`agent_bom.cross_env_correlation` decides
    whether each candidate qualifies for ``CORRELATES_WITH`` (HIGH-confidence
    triplet match) or only ``POSSIBLY_CORRELATES_WITH`` (single-signal). Both
    relationships carry the matched signals and rationale so reviewers can see
    why the platform drew the line.
    """
    from agent_bom.cross_env_correlation import (
        CorrelationConfidence,
        correlate_cross_environment,
    )

    if not isinstance(agents_data, list):
        return
    result = correlate_cross_environment(agents_data)
    if not result.matches:
        return

    for match in result.matches:
        local_id = f"agent:{match.local_agent_name}"
        cloud_id = f"agent:{match.cloud_agent_name}"
        # Only wire edges between agents we already added as nodes — the
        # matcher operates over the report payload but the graph may have
        # filtered some agents out earlier.
        if not graph.get_node(local_id) or not graph.get_node(cloud_id):
            continue
        relationship = (
            RelationshipType.CORRELATES_WITH
            if match.confidence is CorrelationConfidence.HIGH
            else RelationshipType.POSSIBLY_CORRELATES_WITH
        )
        graph.add_edge(
            UnifiedEdge(
                source=local_id,
                target=cloud_id,
                relationship=relationship,
                # Cross-env correlation is semantically symmetric ("local
                # agent X corresponds to cloud agent Y" reads the same in
                # either direction), so the edge must be traversable both
                # ways. Without `bidirectional`, a query "for this cloud
                # Bedrock/Azure/Vertex agent, which local agent talks to
                # it?" misses the edge on the forward adjacency index and
                # only finds it via reverse_adjacency — silently
                # inconsistent with how the graph treats peer relations
                # like SHARES_SERVER and SHARES_CRED.
                direction="bidirectional",
                evidence={
                    "data_source": data_source,
                    "confidence": match.confidence.value,
                    "matched_signals": list(match.matched_signals),
                    "cloud_provider": match.cloud_provider,
                    "cloud_service": match.cloud_service,
                    "cloud_account_id": match.cloud_account_id or "",
                    "cloud_region": match.cloud_region or "",
                    "cloud_model_id": match.cloud_model_id or "",
                    "rationale": match.rationale,
                },
            )
        )


def _project_host_agent_id(graph: UnifiedGraph, agents_data: Any) -> str | None:
    """The single project agent that owns this report's source-code inventory.

    Code-level framework constructs are evidence about that project agent, not
    additional agents. With zero or several project roots there is no single
    owner, so the constructs keep their own nodes.
    """
    if not isinstance(agents_data, list):
        return None
    hosts: list[str] = []
    for agent in agents_data:
        if not isinstance(agent, dict):
            continue
        metadata = agent.get("metadata")
        if not (isinstance(metadata, dict) and metadata.get("project_root")):
            continue
        node_id = _agent_node_id(agent.get("name"), _agent_identity_scope(agent))
        node = graph.nodes.get(node_id)
        if node is not None and node.entity_type == EntityType.AGENT:
            hosts.append(node_id)
    return hosts[0] if len(hosts) == 1 else None
