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
    data_action: str = "",
    policy_id: str = "",
    evidence_id: str = "",
) -> dict[str, Any]:
    """Build one safe metadata event for audit ingest and feed projection."""

    event: dict[str, Any] = {
        "event_id": f"gw_{uuid.uuid4().hex}",
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
    "GATEWAY_DATA_FILTER_EVENT_TYPES",
    "GatewayRuntimeEventType",
    "build_gateway_runtime_event",
]
