"""Canonical event relationship normalization helpers.

These helpers keep event producers source-aware while providing one stable
relationship envelope for audit logs, graph delta alerts, and later
event-oriented integrations. The canonical agent-bom model stays primary;
OCSF remains a projection layered on top when it fits.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_bom.security import sanitize_sensitive_payload, sanitize_text

ENTITY_AGENT = "agent"
ENTITY_TOOL = "tool"
ENTITY_TOOL_CALL = "tool_call"
ENTITY_USER = "user"
ENTITY_SERVICE_ACCOUNT = "service_account"
ENTITY_SERVICE_PRINCIPAL = "service_principal"
ENTITY_FEDERATED_IDENTITY = "federated_identity"
ENTITY_SERVER = "server"
ENTITY_CREDENTIAL = "credential"
ENTITY_CREDENTIAL_REF = "credential_ref"
ENTITY_RESOURCE = "resource"
ENTITY_CLOUD_RESOURCE = "cloud_resource"
ENTITY_DATASET = "dataset"

REL_INVOKED = "invoked"
REL_CALLED = "called"
REL_USED_CREDENTIAL = "used_credential"
REL_ACCESSED = "accessed"

_RESOURCE_ARG_TYPES = {
    "path": "path",
    "url": "url",
    "uri": "uri",
    "resource_id": "resource",
}
_CREDENTIAL_REF_ARG_FIELDS = {
    "credential_ref",
    "credential_ref_id",
    "credential_env",
    "credential_env_name",
    "credential_env_var",
}
_RUNTIME_DETAIL_TARGET_LIST_FIELDS = {
    "new_tools": "observed_tool",
    "removed_tools": "removed_tool",
}
_REF_TYPE_TO_ENTITY_TYPE = {
    "agent": ENTITY_AGENT,
    "user": ENTITY_USER,
    "service_account": ENTITY_SERVICE_ACCOUNT,
    "service_principal": ENTITY_SERVICE_PRINCIPAL,
    "federated_identity": ENTITY_FEDERATED_IDENTITY,
    "server": ENTITY_SERVER,
    "mcp_server": ENTITY_SERVER,
    "tool": ENTITY_TOOL,
    "credential": ENTITY_CREDENTIAL,
    "credential_ref": ENTITY_CREDENTIAL_REF,
    "path": ENTITY_RESOURCE,
    "url": ENTITY_RESOURCE,
    "uri": ENTITY_RESOURCE,
    "resource": ENTITY_RESOURCE,
    "cloud_resource": ENTITY_CLOUD_RESOURCE,
    "dataset": ENTITY_DATASET,
}


def _scalar_attributes(attributes: Mapping[str, Any] | None) -> dict[str, Any]:
    if not attributes:
        return {}
    return {
        sanitize_text(key, max_len=200): sanitize_sensitive_payload(value, key=key)
        for key, value in attributes.items()
        if isinstance(value, (str, int, float, bool)) and value not in ("", None)
    }


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
    redaction_key = "reference" if ref_type == "credential_ref" else source_field or ref_type
    safe_ref_id = sanitize_sensitive_payload(ref_id, key=redaction_key)
    safe_name = sanitize_sensitive_payload(name, key=redaction_key) if name else None
    if not safe_ref_id:
        return None

    ref: dict[str, Any] = {
        "type": ref_type,
        "id": str(safe_ref_id),
    }
    if safe_name:
        ref["name"] = str(safe_name)
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


def _safe_ref_label(value: object, *, key: str) -> str:
    sanitized = sanitize_sensitive_payload(value, key=key)
    if not sanitized or sanitized == "***REDACTED***":
        return f"<{key}>"
    return str(sanitized)


def _safe_id_part(value: object, *, max_len: int = 80) -> str:
    text = sanitize_text(value, max_len=max_len)
    if not text or text == "***REDACTED***":
        return "redacted"
    return text.replace(":", "_")


def _graph_node_id(entity_type: str, ref: Mapping[str, Any]) -> str:
    source_field = _safe_id_part(ref.get("source_field", ""), max_len=80)
    ref_type = _safe_id_part(ref.get("type", ""), max_len=80)
    role = _safe_id_part(ref.get("role", ""), max_len=80)
    raw_id = str(ref.get("id", "") or "")
    stable_id = "redacted" if not raw_id or raw_id == "***REDACTED***" else _safe_id_part(raw_id, max_len=80)
    return f"{entity_type}:{source_field}:{ref_type}:{role}:{stable_id}"


def _graph_node_from_ref(ref: Mapping[str, Any]) -> dict[str, Any] | None:
    ref_type = str(ref.get("type", "")).strip()
    entity_type = _REF_TYPE_TO_ENTITY_TYPE.get(ref_type)
    if not entity_type:
        return None
    label = str(ref.get("name") or ref.get("id") or ref_type)
    node = {
        "id": _graph_node_id(entity_type, ref),
        "entity_type": entity_type,
        "label": label,
        "source_ref": {
            "type": ref_type,
            "id": str(ref.get("id", "")),
            "role": str(ref.get("role", "")),
            "source_field": str(ref.get("source_field", "")),
        },
    }
    attributes = ref.get("attributes")
    if isinstance(attributes, Mapping) and attributes:
        node["attributes"] = dict(attributes)
    return node


def build_agentic_identity_graph_projection(
    event_relationships: Mapping[str, Any] | None,
    *,
    event_id: str | int | None = None,
    tenant_id: str | None = None,
) -> dict[str, Any] | None:
    """Project normalized event refs into an agentic identity graph slice.

    The projection intentionally starts from ``event_relationships`` instead
    of raw runtime arguments. That keeps prompt text, argument values, and
    credential material out of the graph while preserving the accountable
    path: actor → tool_call → tool / credential reference / resource.
    """
    if not event_relationships:
        return None

    source = sanitize_text(event_relationships.get("source", "runtime_event"), max_len=160)
    actor_ref = event_relationships.get("actor")
    targets = [target for target in event_relationships.get("targets", []) if isinstance(target, Mapping)]
    resources = [resource for resource in event_relationships.get("resources", []) if isinstance(resource, Mapping)]
    if not isinstance(actor_ref, Mapping) and not targets and not resources:
        return None

    actor_seed = (
        f"{actor_ref.get('type', '')}:{actor_ref.get('role', '')}:{actor_ref.get('source_field', '')}"
        if isinstance(actor_ref, Mapping)
        else "anonymous"
    )
    target_seed = ",".join(f"{target.get('type', '')}:{target.get('role', '')}:{target.get('source_field', '')}" for target in targets)
    resource_seed = ",".join(
        f"{resource.get('type', '')}:{resource.get('role', '')}:{resource.get('source_field', '')}" for resource in resources
    )
    call_id = _safe_id_part(f"{source}:{event_id or 'event'}:{actor_seed}:{target_seed}:{resource_seed}", max_len=220)
    tool_call_id = f"{ENTITY_TOOL_CALL}:{call_id}"
    evidence = {
        "source": source,
        "event_id": sanitize_text(str(event_id or "runtime_event"), max_len=200),
    }
    if tenant_id:
        evidence["tenant_id"] = sanitize_text(tenant_id, max_len=200)

    nodes_by_id: dict[str, dict[str, Any]] = {
        tool_call_id: {
            "id": tool_call_id,
            "entity_type": ENTITY_TOOL_CALL,
            "label": "Tool call",
            "attributes": {
                "source": source,
                "event_id": evidence["event_id"],
            },
        }
    }
    edges: list[dict[str, Any]] = []

    def add_node(node: dict[str, Any] | None) -> str | None:
        if node is None:
            return None
        nodes_by_id[node["id"]] = node
        return str(node["id"])

    if isinstance(actor_ref, Mapping):
        actor_node_id = add_node(_graph_node_from_ref(actor_ref))
        if actor_node_id:
            edges.append(
                {
                    "source": actor_node_id,
                    "target": tool_call_id,
                    "relationship": REL_INVOKED,
                    "evidence": dict(evidence),
                }
            )

    for target_ref in targets:
        target_node_id = add_node(_graph_node_from_ref(target_ref))
        if not target_node_id:
            continue
        target_type = str(target_ref.get("type", ""))
        relationship = REL_USED_CREDENTIAL if target_type in {"credential", "credential_ref"} else REL_CALLED
        edges.append(
            {
                "source": tool_call_id,
                "target": target_node_id,
                "relationship": relationship,
                "evidence": dict(evidence),
            }
        )

    for resource_ref in resources:
        resource_node_id = add_node(_graph_node_from_ref(resource_ref))
        if not resource_node_id:
            continue
        relationship = REL_USED_CREDENTIAL if str(resource_ref.get("type", "")) in {"credential", "credential_ref"} else REL_ACCESSED
        edges.append(
            {
                "source": tool_call_id,
                "target": resource_node_id,
                "relationship": relationship,
                "evidence": dict(evidence),
            }
        )

    if len(nodes_by_id) == 1 and not edges:
        return None
    return {
        "schema_version": "agentic_identity_graph.v1",
        "nodes": sorted(nodes_by_id.values(), key=lambda node: str(node["id"])),
        "edges": edges,
        "source": source,
    }


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

    for field_name, value in arguments.items():
        if field_name not in _CREDENTIAL_REF_ARG_FIELDS or not isinstance(value, (str, int, float, bool)) or value in ("", None):
            continue
        credential_id = _safe_ref_label(value, key="reference")
        dedupe_key = ("credential_ref", credential_id, field_name)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        credential_ref = build_event_ref(
            ref_type="credential_ref",
            ref_id=credential_id,
            name=credential_id,
            role="credential_reference",
            source_field=field_name,
        )
        if credential_ref is not None:
            resources.append(credential_ref)

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
