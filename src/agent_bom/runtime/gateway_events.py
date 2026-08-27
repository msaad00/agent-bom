"""Typed, redaction-safe standalone gateway runtime events.

The gateway's legacy audit ``action`` values are retained for compatibility,
but feed classification and durable evidence use these exact event types.  The
builder intentionally accepts metadata only: raw arguments, prompts, results,
tokens, and previews have no parameter and therefore cannot enter this event.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class GatewayRuntimeEventType(str, Enum):
    TOOL_CALL_ALLOWED = "gateway.tool_call.allowed"
    TOOL_CALL_BLOCKED = "gateway.tool_call.blocked"
    DLP_ARGUMENTS_REDACTED = "gateway.dlp.arguments_redacted"
    DLP_RESULT_REDACTED = "gateway.dlp.result_redacted"
    DLP_RESULT_BLOCKED = "gateway.dlp.result_blocked"
    VISUAL_REDACTED = "gateway.visual.redacted"
    RUNTIME_PROFILE_WARNED = "gateway.runtime_profile.warned"
    RUNTIME_PROFILE_DEV_BYPASS = "gateway.runtime_profile.dev_bypass"
    RUNTIME_PROFILE_BLOCKED = "gateway.runtime_profile.blocked"


GATEWAY_ALLOWED_EVENT_TYPES = frozenset({GatewayRuntimeEventType.TOOL_CALL_ALLOWED.value})
GATEWAY_BLOCKED_EVENT_TYPES = frozenset(
    {
        GatewayRuntimeEventType.TOOL_CALL_BLOCKED.value,
        GatewayRuntimeEventType.DLP_RESULT_BLOCKED.value,
    }
)
GATEWAY_DATA_FILTER_EVENT_TYPES = frozenset(
    {
        GatewayRuntimeEventType.DLP_ARGUMENTS_REDACTED.value,
        GatewayRuntimeEventType.DLP_RESULT_REDACTED.value,
        GatewayRuntimeEventType.VISUAL_REDACTED.value,
    }
)
GATEWAY_PROFILE_EVENT_TYPES = frozenset(
    {
        GatewayRuntimeEventType.RUNTIME_PROFILE_WARNED.value,
        GatewayRuntimeEventType.RUNTIME_PROFILE_DEV_BYPASS.value,
        GatewayRuntimeEventType.RUNTIME_PROFILE_BLOCKED.value,
    }
)
GATEWAY_DENIED_EVENT_TYPES = GATEWAY_BLOCKED_EVENT_TYPES | frozenset(
    {GatewayRuntimeEventType.RUNTIME_PROFILE_BLOCKED.value}
)
GATEWAY_CANONICAL_EVENT_TYPES = (
    GATEWAY_ALLOWED_EVENT_TYPES
    | GATEWAY_BLOCKED_EVENT_TYPES
    | GATEWAY_DATA_FILTER_EVENT_TYPES
    | GATEWAY_PROFILE_EVENT_TYPES
)


def build_gateway_runtime_event(
    event_type: GatewayRuntimeEventType,
    *,
    tenant_id: str,
    agent_id: str,
    profile_id: str,
    upstream: str,
    tool: str,
    decision: str,
    policy_source: str,
    trace_id: str,
    identity_id: str = "",
    profile_revision: int = 0,
    blueprint_id: str = "",
    blueprint_revision: int = 0,
    policy_ids: tuple[str, ...] | list[str] = (),
    reason_code: str = "",
    data_action: str = "",
    policy_id: str = "",
    evidence_id: str = "",
) -> dict[str, Any]:
    """Build one safe metadata event for audit ingest and feed projection."""

    event_id = f"gw_{uuid.uuid4().hex}"
    event: dict[str, Any] = {
        "schema_version": "gateway.runtime.event.v1",
        "event_id": event_id,
        "decision_id": event_id,
        "event_type": event_type.value,
        "event_timestamp": datetime.now(timezone.utc).isoformat(),
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "profile_id": profile_id,
        "upstream": upstream,
        "tool": tool,
        "decision": decision,
        "policy_source": policy_source,
        "trace_id": trace_id,
    }
    if identity_id:
        event["identity_id"] = identity_id
    if profile_revision > 0:
        event["profile_revision"] = profile_revision
    if blueprint_id:
        event["blueprint_id"] = blueprint_id
    if blueprint_revision > 0:
        event["blueprint_revision"] = blueprint_revision
    normalized_policy_ids = list(dict.fromkeys(value for value in policy_ids if value))
    if normalized_policy_ids:
        event["policy_ids"] = normalized_policy_ids
    if reason_code:
        event["reason_code"] = reason_code
    if data_action:
        event["data_action"] = data_action
    if policy_id:
        event["policy_id"] = policy_id
    if evidence_id:
        event["evidence_id"] = evidence_id
    return event


__all__ = [
    "GATEWAY_ALLOWED_EVENT_TYPES",
    "GATEWAY_BLOCKED_EVENT_TYPES",
    "GATEWAY_CANONICAL_EVENT_TYPES",
    "GATEWAY_DATA_FILTER_EVENT_TYPES",
    "GATEWAY_DENIED_EVENT_TYPES",
    "GATEWAY_PROFILE_EVENT_TYPES",
    "GatewayRuntimeEventType",
    "build_gateway_runtime_event",
]
