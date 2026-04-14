"""Canonical event relationship normalization helpers.

These helpers keep event producers source-aware while providing one stable
relationship envelope for audit logs, graph delta alerts, and later
event-oriented integrations. The canonical agent-bom model stays primary;
OCSF remains a projection layered on top when it fits.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

_RESOURCE_ARG_TYPES = {
    "path": "path",
    "url": "url",
    "uri": "uri",
    "resource_id": "resource",
}
_RUNTIME_DETAIL_TARGET_LIST_FIELDS = {
    "new_tools": "observed_tool",
    "removed_tools": "removed_tool",
}


def _scalar_attributes(attributes: Mapping[str, Any] | None) -> dict[str, Any]:
    if not attributes:
        return {}
    return {key: value for key, value in attributes.items() if isinstance(value, (str, int, float, bool)) and value not in ("", None)}


def build_event_ref(
    *,
    ref_type: str,
    ref_id: str,
    name: str | None = None,
    role: str | None = None,
    source_field: str | None = None,
    attributes: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Return a stable event relationship reference."""
    if not ref_id:
        return None

    ref: dict[str, Any] = {
        "type": ref_type,
        "id": ref_id,
    }
    if name:
        ref["name"] = name
    if role:
        ref["role"] = role
    if source_field:
        ref["source_field"] = source_field

    scalar_attrs = _scalar_attributes(attributes)
    if scalar_attrs:
        ref["attributes"] = scalar_attrs
    return ref


def build_event_relationships(
    *,
    source: str,
    actor: dict[str, Any] | None = None,
    targets: list[dict[str, Any]] | None = None,
    resources: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """Return a stable event relationship envelope."""
    clean_targets = [target for target in (targets or []) if target]
    clean_resources = [resource for resource in (resources or []) if resource]
    if actor is None and not clean_targets and not clean_resources:
        return None

    envelope: dict[str, Any] = {
        "normalization_version": "1",
        "source": source,
    }
    if actor is not None:
        envelope["actor"] = actor
    if clean_targets:
        envelope["targets"] = clean_targets
    if clean_resources:
        envelope["resources"] = clean_resources
    return envelope


def build_proxy_event_relationships(
    *,
    tool_name: str,
    arguments: Mapping[str, Any],
    agent_id: str | None,
    anonymous_id: str,
) -> dict[str, Any] | None:
    """Normalize proxy tool-call relationships.

    Tool calls expose a concrete target (the invoked tool), and may expose a
    concrete caller identity when agent identity is resolved. Resource
    references are only extracted from a small allowlist of direct argument
    fields to avoid guesswork.
    """
    actor = None
    if agent_id and agent_id != anonymous_id:
        actor = build_event_ref(
            ref_type="agent",
            ref_id=agent_id,
            name=agent_id,
            role="caller",
            source_field="agent_id",
        )

    targets: list[dict[str, Any]] = []
    tool_target = build_event_ref(
        ref_type="tool",
        ref_id=tool_name,
        name=tool_name,
        role="invoked_tool",
        source_field="tool",
    )
    if tool_target is not None:
        targets.append(tool_target)

    seen: set[tuple[str, str, str]] = set()
    resources: list[dict[str, Any]] = []
    for field_name, value in arguments.items():
        resource_type = _RESOURCE_ARG_TYPES.get(field_name)
        if resource_type is None or not isinstance(value, (str, int, float, bool)) or value in ("", None):
            continue
        resource_id = str(value)
        dedupe_key = (resource_type, resource_id, field_name)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        resource = build_event_ref(
            ref_type=resource_type,
            ref_id=resource_id,
            name=resource_id,
            role="referenced_input",
            source_field=field_name,
        )
        if resource is not None:
            resources.append(resource)

    return build_event_relationships(
        source="proxy_tool_call",
        actor=actor,
        targets=targets,
        resources=resources,
    )


def build_runtime_alert_relationships(
    *,
    detector: str,
    details: Mapping[str, Any] | None,
    agent_id: str | None = None,
) -> dict[str, Any] | None:
    """Normalize runtime alert relationships.

    Runtime alerts are event-like, but the exact actor/target/resource shape
    varies by detector. Only explicit fields are normalized. Unknown or
    detector-specific fields remain in ``details``.
    """
    clean_details = details if isinstance(details, Mapping) else {}

    actor = None
    resolved_agent_id = agent_id or clean_details.get("agent_id")
    if isinstance(resolved_agent_id, str) and resolved_agent_id:
        actor = build_event_ref(
            ref_type="agent",
            ref_id=resolved_agent_id,
            name=resolved_agent_id,
            role="caller",
            source_field="agent_id",
        )

    targets: list[dict[str, Any]] = []
    tool_name = clean_details.get("tool")
    if isinstance(tool_name, str) and tool_name:
        tool_target = build_event_ref(
            ref_type="tool",
            ref_id=tool_name,
            name=tool_name,
            role="implicated_tool",
            source_field="details.tool",
        )
        if tool_target is not None:
            targets.append(tool_target)

    for field_name, role in _RUNTIME_DETAIL_TARGET_LIST_FIELDS.items():
        raw_values = clean_details.get(field_name)
        if not isinstance(raw_values, list):
            continue
        for value in raw_values:
            if not isinstance(value, str) or not value:
                continue
            target = build_event_ref(
                ref_type="tool",
                ref_id=value,
                name=value,
                role=role,
                source_field=f"details.{field_name}",
            )
            if target is not None:
                targets.append(target)

    resources: list[dict[str, Any]] = []
    seen_resources: set[tuple[str, str, str]] = set()
    for field_name, resource_type in _RESOURCE_ARG_TYPES.items():
        value = clean_details.get(field_name)
        if not isinstance(value, (str, int, float, bool)) or value in ("", None):
            continue
        resource_id = str(value)
        dedupe_key = (resource_type, resource_id, field_name)
        if dedupe_key in seen_resources:
            continue
        seen_resources.add(dedupe_key)
        resource = build_event_ref(
            ref_type=resource_type,
            ref_id=resource_id,
            name=resource_id,
            role="referenced_resource",
            source_field=f"details.{field_name}",
        )
        if resource is not None:
            resources.append(resource)

    return build_event_relationships(
        source=f"runtime_alert:{detector}",
        actor=actor,
        targets=targets,
        resources=resources,
    )
