"""Shared report projection primitives; independent of builder orchestration."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import PurePath
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


def _is_sbom_import(agent: Mapping[str, Any]) -> bool:
    servers = agent.get("mcp_servers", [])
    return (
        bool(servers)
        and all(srv.get("surface") == "sbom" for srv in servers)
        and (agent.get("source") == "sbom" or str(agent.get("name") or "").startswith("sbom:"))
    )


def _is_repository_inventory(agent: Mapping[str, Any]) -> bool:
    """Recognize the explicit manifest-collector wrappers, not arbitrary agents."""
    servers = agent.get("mcp_servers", [])
    if not servers:
        return False
    if agent.get("source") == "repo-lockfiles":
        return all(srv.get("surface") == "filesystem" and not srv.get("command") for srv in servers)
    if agent.get("source") == "project":
        return all(srv.get("surface") == "other" and srv.get("command") in {"project", "github-actions"} for srv in servers)
    return False


def _repository_manifest_directory(agent: Mapping[str, Any], server: Mapping[str, Any]) -> str:
    if agent.get("source") == "repo-lockfiles":
        label = str(server.get("name") or "").removeprefix("repo-deps:")
        return "" if label == "root" else label
    args = server.get("args") or []
    root = str(agent.get("config_path") or "")
    if args and root:
        try:
            relative = str(PurePath(str(args[0])).relative_to(PurePath(root)))
            return "" if relative == "." else relative
        except ValueError:
            pass
    label = str(server.get("name") or "")
    return "" if label == str(agent.get("name") or "").removeprefix("project:") else label


def _normalized_environment(*candidates: object) -> str:
    """Return the first non-empty environment label among candidates."""
    for raw in candidates:
        if raw is None:
            continue
        text = str(raw).strip()
        if text:
            return text
    return ""
