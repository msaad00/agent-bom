"""Credential-slot occurrence evidence, without credential values."""

from collections.abc import Callable, Mapping
from typing import Any

from agent_bom.graph.correlation_scope import CORRELATION_IDENTITY_VERSION
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType


def is_credential_slot(node: UnifiedNode) -> bool:
    """Keep independent credential resources separate from server-local slots."""
    return any(key in node.attributes for key in ("server", "servers", "credential_occurrence"))


def slot_receipt(name: str, server_identity: tuple[str, str, str]) -> dict[str, Any]:
    """Bind an environment-variable slot to its server's correlation identity."""
    return {"identity_version": CORRELATION_IDENTITY_VERSION, "name": name, "server_identity": list(server_identity[:2])}


def credential_occurrence(
    node: UnifiedNode,
    *,
    nodes: Mapping[str, UnifiedNode],
    resolve_server: Callable[[UnifiedNode], tuple[str, str, str]],
) -> dict[str, Any] | None:
    """Recover raw legacy slots, but never reinterpret a previously unsafe join."""
    correlation = node.attributes.get("correlation")
    if correlation and (not isinstance(correlation, dict) or correlation.get("identity_version") != CORRELATION_IDENTITY_VERSION):
        return None
    source_ids = node.attributes.get("source_ids")
    source_ids = source_ids if isinstance(source_ids, dict) else {}
    name = source_ids.get("env_key")
    marker = node.attributes.get("credential_occurrence")
    if isinstance(marker, dict):
        identity = marker.get("server_identity")
        if (
            marker.get("identity_version") != CORRELATION_IDENTITY_VERSION
            or not isinstance(marker.get("name"), str)
            or not marker["name"]
            or not isinstance(identity, list)
            or len(identity) != 2
            or identity[0] != EntityType.SERVER.value
            or not isinstance(identity[1], str)
            or not identity[1]
            or name
            and marker["name"] != name
        ):
            return None
        name = marker["name"]
    else:
        marker = None
    if not isinstance(name, str) or not name:
        return None
    recorded = node.attributes.get("servers", [])
    recorded = recorded if isinstance(recorded, list) else []
    parents = {
        value for value in [node.attributes.get("server"), source_ids.get("server_id"), *recorded] if isinstance(value, str) and value
    }
    if len(parents) != 1:
        return None
    parent = nodes.get(next(iter(parents)))
    if parent is None:
        return marker
    if parent.entity_type != EntityType.SERVER:
        return None
    expected = slot_receipt(name, resolve_server(parent))
    return expected if marker is None or marker == expected else None
