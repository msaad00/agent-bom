"""Deterministic canonical identity helpers for scan and graph entities."""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

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


def canonical_agent_id(agent_type: str, name: str, *, source_id: str = "", device_fingerprint: str = "") -> str:
    """Return a deterministic agent identity.

    A hardware-backed ``device_fingerprint`` (derived from attestation evidence)
    is preferred when present, so the identity is rooted in the physical device
    rather than a mutable hostname/config path. Falls back to ``source_id`` and
    finally the agent name when no fingerprint is available — preserving the
    identity of agents that carry no hardware evidence.
    """
    fingerprint = (device_fingerprint or "").strip()
    if fingerprint:
        return canonical_id("agent", agent_type, f"device:{fingerprint}")
    source = (source_id or "").strip()
    if source:
        return canonical_id("agent", agent_type, source)
    return canonical_id("agent", agent_type, name)


def normalize_command_arg(arg: str) -> str:
    """Normalize a server command argument for identity comparison."""
    text = str(arg).strip()
    if not text:
        return ""
    if text.startswith(("/", "~", ".")):
        try:
            return os.path.normpath(os.path.expanduser(text)).lower()
        except (OSError, ValueError):
            return text.lower()
    return text.lower()


def mcp_server_identity_discriminator(
    name: str,
    command: str = "",
    *,
    url: str | None = None,
    args: Sequence[str] | None = None,
) -> str:
    """Non-registry server identity key shared by canonical IDs and discovery dedup.

    Mirrors the url/command/name fallback used by discovery's ``server_identity_key``
    so a server's served canonical id is as fine-grained as its dedup identity:
    remote SSE/HTTP servers (empty command) stay distinct by url, and stdio servers
    fold in their normalized args.
    """
    if url and url.strip():
        parsed = urlparse(url.strip())
        netloc = parsed.netloc.lower()
        path = parsed.path.rstrip("/")
        return f"url:{urlunparse((parsed.scheme.lower(), netloc, path, '', '', ''))}"

    cmd = Path(command or "").name.lower().strip()
    normalized_args = tuple(value for value in (normalize_command_arg(arg) for arg in (args or [])) if value)
    if cmd or normalized_args:
        arg_str = " ".join(normalized_args)
        if not normalized_args:
            # A bare command with no args is not distinctive enough on its own;
            # fold in the server name so distinct servers keep distinct identities.
            return f"cmd:{cmd}:{arg_str}:{name.strip().lower()}"
        return f"cmd:{cmd}:{arg_str}"

    return f"name:{name.strip().lower()}"


def canonical_mcp_server_id(
    name: str,
    command: str = "",
    *,
    registry_id: str | None = None,
    url: str | None = None,
    args: Sequence[str] | None = None,
) -> str:
    if registry_id:
        identifier = registry_id
    else:
        identifier = mcp_server_identity_discriminator(name, command, url=url, args=args)
    return canonical_id("mcp_server", identifier)


def canonical_mcp_tool_id(name: str, input_schema: Mapping[str, Any] | None = None, *, server_id: str | None = None) -> str:
    schema = json.dumps(input_schema or {}, sort_keys=True, separators=(",", ":"))
    return canonical_id("mcp_tool", server_id or "", name, schema)


def canonical_mcp_resource_id(uri: str, mime_type: str | None = None, *, server_id: str | None = None) -> str:
    return canonical_id("mcp_resource", server_id or "", uri, mime_type or "")


def canonical_mcp_prompt_id(
    name: str,
    arguments: Sequence[Mapping[str, Any]] | None = None,
    *,
    server_id: str | None = None,
) -> str:
    args = json.dumps(list(arguments or []), sort_keys=True, separators=(",", ":"))
    return canonical_id("mcp_prompt", server_id or "", name, args)


def canonical_finding_id(asset_canonical_id: str, finding_key: str, *qualifiers: Any) -> str:
    return canonical_id(asset_canonical_id, finding_key, *qualifiers)


def canonical_graph_node_id(entity_type: str, graph_id: str) -> str:
    return canonical_id("graph_node", entity_type, graph_id)


def canonical_graph_edge_id(source: str, target: str, relationship: str) -> str:
    return canonical_id("graph_edge", relationship, source, target)
