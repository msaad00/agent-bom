"""Deterministic canonical identity helpers for scan and graph entities."""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from agent_bom.package_utils import canonical_package_key

AGENT_BOM_ID_NAMESPACE = uuid.UUID("7f3e4b2a-9c1d-5f8e-a0b4-12c3d4e5f6a7")
CANONICAL_ID_SCHEMA_VERSION = "1"


def _part_to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, Mapping):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return json.dumps(list(value), sort_keys=True, separators=(",", ":"), default=str)
    return str(value)


def canonical_fingerprint(*parts: Any) -> str:
    """Return the normalized fingerprint material used for canonical IDs."""
    return ":".join(text.lower().strip() for text in (_part_to_text(part) for part in parts) if text)


def canonical_id(*parts: Any) -> str:
    """Return a deterministic UUID v5 for normalized content parts."""
    return str(uuid.uuid5(AGENT_BOM_ID_NAMESPACE, canonical_fingerprint(*parts)))


def source_ids(**values: Any) -> dict[str, str]:
    """Return source identifiers as provenance without empty values."""
    result: dict[str, str] = {}
    for key, value in values.items():
        if value in (None, "", [], {}):
            continue
        result[str(key)] = _part_to_text(value)
    return result


def canonical_package_id(name: str, version: str, ecosystem: str, purl: str | None = None) -> str:
    return canonical_id("package", canonical_package_key(name, version, ecosystem, purl))


def canonical_agent_id(agent_type: str, name: str, *, source_id: str = "") -> str:
    source = (source_id or "").strip()
    if source:
        return canonical_id("agent", agent_type, source)
    return canonical_id("agent", agent_type, name)


def canonical_mcp_server_id(name: str, command: str = "", *, registry_id: str | None = None) -> str:
    identifier = registry_id or f"{name}:{command}"
    return canonical_id("mcp_server", identifier)


def canonical_mcp_tool_id(name: str, input_schema: Mapping[str, Any] | None = None) -> str:
    schema = json.dumps(input_schema or {}, sort_keys=True, separators=(",", ":"))
    return canonical_id("mcp_tool", name, schema)


def canonical_mcp_resource_id(uri: str, mime_type: str | None = None) -> str:
    return canonical_id("mcp_resource", uri, mime_type or "")


def canonical_mcp_prompt_id(name: str, arguments: Sequence[Mapping[str, Any]] | None = None) -> str:
    args = json.dumps(list(arguments or []), sort_keys=True, separators=(",", ":"))
    return canonical_id("mcp_prompt", name, args)


def canonical_finding_id(asset_canonical_id: str, finding_key: str, *qualifiers: Any) -> str:
    return canonical_id(asset_canonical_id, finding_key, *qualifiers)


def canonical_graph_node_id(entity_type: str, graph_id: str) -> str:
    return canonical_id("graph_node", entity_type, graph_id)


def canonical_graph_edge_id(source: str, target: str, relationship: str) -> str:
    return canonical_id("graph_edge", relationship, source, target)
