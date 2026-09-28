"""Shared report projection primitives; independent of builder orchestration."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.types import RelationshipType
from agent_bom.graph.util import clean_graph_part as _clean_graph_part


def _mapping_list(value: Any) -> list[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _agent_identity_scope(agent_dict: dict[str, Any]) -> str:
    """Return the endpoint/source scope that disambiguates fleet agents."""
    for key in ("source_id", "endpoint_id", "device_id"):
        value = str(agent_dict.get(key) or "").strip()
        if value:
            return value
    metadata = agent_dict.get("metadata")
    if isinstance(metadata, dict):
        for key in ("source_id", "endpoint_id", "device_id"):
            value = str(metadata.get(key) or "").strip()
            if value:
                return value
    return ""


def _agent_node_id(agent_name: Any, source_id: str = "") -> str:
    """Build an agent graph ID without collapsing same-name fleet endpoints."""
    name = str(agent_name or "unknown").strip() or "unknown"
    source = _clean_graph_part(source_id).replace(":", "%3A")
    if source:
        return f"agent:{source}:{name}"
    return f"agent:{name}"


def _add_rel_edge(
    graph: UnifiedGraph,
    source_id: str,
    target_id: str,
    relationship: RelationshipType,
    evidence: dict[str, Any] | None = None,
) -> None:
    """Add a relationship edge; thin wrapper over ``graph.add_edge(UnifiedEdge(...))``.

    ``evidence=None`` is normalized to ``{}`` to match the ``UnifiedEdge``
    default, so routed call sites stay byte-identical.
    """
    graph.add_edge(
        UnifiedEdge(
            source=source_id,
            target=target_id,
            relationship=relationship,
            evidence=evidence if evidence is not None else {},
        )
    )
