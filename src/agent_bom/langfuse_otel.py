"""Langfuse-compatible OTLP span attributes.

This module does not depend on Langfuse's SDK. It projects the existing
agent-bom runtime/proxy/gateway span metadata into safe `langfuse.*`
attributes for operators who point OTLP/HTTP export at Langfuse.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

_MAX_ATTR_VALUE = 256
_MAX_REASON_VALUE = 512
_SECRET_KEY_HINTS = ("key", "token", "secret", "password", "credential", "authorization", "cookie")


def _bounded(value: object, *, limit: int = _MAX_ATTR_VALUE) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)] + "..."


def _safe_argument_keys(arguments: Mapping[str, object] | None) -> list[str]:
    if not arguments:
        return []
    keys: list[str] = []
    for raw_key in sorted(str(key) for key in arguments):
        lowered = raw_key.lower()
        if any(hint in lowered for hint in _SECRET_KEY_HINTS):
            keys.append("<redacted>")
        else:
            keys.append(_bounded(raw_key, limit=64))
    return keys[:20]


def _arguments_fingerprint(arguments: Mapping[str, object] | None) -> str:
    keys = _safe_argument_keys(arguments)
    if not keys:
        return ""
    digest = hashlib.sha256("\n".join(keys).encode("utf-8")).hexdigest()
    return digest[:16]


def langfuse_runtime_attributes(
    *,
    surface: str,
    tenant_id: str,
    method: str,
    tool_name: str | None = None,
    decision: str | None = None,
    reason: str | None = None,
    upstream: str | None = None,
    agent_id: str | None = None,
    event_id: str | None = None,
    trace_id: str | None = None,
    arguments: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Return redaction-safe Langfuse OTLP attributes for runtime spans."""
    safe_tool = _bounded(tool_name or method or "unknown")
    safe_surface = _bounded(surface or "runtime")
    safe_method = _bounded(method or "unknown")
    safe_tenant = _bounded(tenant_id or "default")
    safe_decision = _bounded((decision or "observed").lower())
    argument_keys = _safe_argument_keys(arguments)

    attrs: dict[str, object] = {
        "langfuse.trace.name": f"agent-bom.{safe_surface}",
        "langfuse.trace.tags": ["agent-bom", safe_surface, "security"],
        "langfuse.trace.metadata.tenant_id": safe_tenant,
        "langfuse.trace.metadata.surface": safe_surface,
        "langfuse.trace.metadata.method": safe_method,
        "langfuse.trace.metadata.policy_decision": safe_decision,
        "langfuse.observation.type": "span",
        "langfuse.observation.metadata.surface": safe_surface,
        "langfuse.observation.metadata.method": safe_method,
        "langfuse.observation.metadata.policy_decision": safe_decision,
        "agent_bom.runtime.surface": safe_surface,
        "agent_bom.runtime.tenant_id": safe_tenant,
        "agent_bom.runtime.method": safe_method,
        "agent_bom.runtime.policy_decision": safe_decision,
        "agent_bom.runtime.argument_count": len(arguments or {}),
    }
    if tool_name:
        attrs["langfuse.observation.metadata.tool"] = safe_tool
        attrs["agent_bom.runtime.tool"] = safe_tool
    if upstream:
        attrs["langfuse.trace.metadata.upstream"] = _bounded(upstream)
        attrs["agent_bom.runtime.upstream"] = _bounded(upstream)
    if agent_id:
        attrs["langfuse.user.id"] = _bounded(agent_id)
        attrs["agent_bom.runtime.agent_id"] = _bounded(agent_id)
    if event_id:
        attrs["langfuse.observation.metadata.event_id"] = _bounded(event_id)
        attrs["agent_bom.runtime.event_id"] = _bounded(event_id)
    if trace_id:
        attrs["langfuse.trace.metadata.trace_id"] = _bounded(trace_id)
        attrs["agent_bom.runtime.trace_id"] = _bounded(trace_id)
    if reason:
        attrs["langfuse.observation.metadata.reason_code"] = _bounded(reason, limit=_MAX_REASON_VALUE)
        attrs["agent_bom.runtime.reason"] = _bounded(reason, limit=_MAX_REASON_VALUE)
    if argument_keys:
        attrs["agent_bom.runtime.argument_keys"] = argument_keys
        attrs["agent_bom.runtime.argument_fingerprint"] = _arguments_fingerprint(arguments)
    return attrs


def set_langfuse_runtime_attributes(span: Any, **kwargs: Any) -> None:
    """Set redaction-safe Langfuse attributes on an OpenTelemetry span."""
    if span is None:
        return
    for key, value in langfuse_runtime_attributes(**kwargs).items():
        span.set_attribute(key, value)
