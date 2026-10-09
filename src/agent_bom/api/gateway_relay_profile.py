"""Relay stage: canonical runtime client-profile resolution.

Opt-in while OAuth/JWKS deployments migrate to managed identity assignments.
In enforce mode every caller must resolve before any upstream network call;
warn mode records the same stable reason code without upgrading unresolved
evidence into a profile attribution.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi.responses import JSONResponse

from agent_bom.api.gateway_auth import _is_loopback_host
from agent_bom.api.gateway_relay_context import RelayContext, RelayRuntime, _public_gateway_block_reason, _public_gateway_error
from agent_bom.api.metrics import record_gateway_relay
from agent_bom.proxy import is_tools_call
from agent_bom.runtime.gateway_events import GatewayRuntimeEventType
from agent_bom.runtime.profile_resolution import ProfileResolutionCode
from agent_bom.security import sanitize_text

logger = logging.getLogger("agent_bom.gateway_server")

_OUT_OF_SCOPE_CODES = frozenset({"upstream_not_allowed", "tool_not_allowed"})


def _resolve_assignment(runtime: RelayRuntime, ctx: RelayContext) -> str:
    """Resolve the managed identity's profile; return a failure code or ''."""
    settings = runtime.settings
    try:
        from agent_bom.api.mcp_config_store import get_mcp_config_store
        from agent_bom.runtime.profile_resolution import resolve_runtime_profile

        resolution = resolve_runtime_profile(
            get_mcp_config_store(),
            identity=ctx.scoped_identity,
            tenant_id=ctx.tenant_id,
            issuer=settings.runtime_profile_issuer.strip(),
            environment=settings.runtime_profile_environment.strip(),
            granted_scopes=ctx.token_scopes,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("gateway runtime profile lookup unavailable: %s", sanitize_text(_public_gateway_error(exc)))
        return ProfileResolutionCode.PROFILE_STORE_UNAVAILABLE.value
    if not resolution.resolved or resolution.profile is None:
        return str(resolution.code.value)
    profile = resolution.profile
    ctx.profile_id = profile.client_profile_id
    ctx.profile_revision = profile.revision
    ctx.blueprint_id = profile.blueprint_id
    ctx.blueprint_revision = profile.blueprint_revision
    ctx.profile_policy_ids = profile.policy_ids
    if not profile.allows_upstream(ctx.upstream.name):
        return "upstream_not_allowed"
    if is_tools_call(ctx.message) and not profile.allows_tool(ctx.event_tool):
        return "tool_not_allowed"
    return ""


def _profile_failure_code(runtime: RelayRuntime, ctx: RelayContext) -> str:
    if ctx.managed_identity_lookup_unavailable:
        return ProfileResolutionCode.IDENTITY_STORE_UNAVAILABLE.value
    if ctx.scoped_identity is None:
        return ProfileResolutionCode.MANAGED_IDENTITY_REQUIRED.value
    ctx.profile_identity_id = str(getattr(ctx.scoped_identity, "identity_id", "") or "")
    return _resolve_assignment(runtime, ctx)


def _profile_audit_event(ctx: RelayContext, *, mode: str, failure_code: str, dev_bypass: bool) -> dict[str, Any]:
    enforced = mode == "enforce" and not dev_bypass
    if mode == "enforce" and dev_bypass:
        action, decision = "gateway.runtime_profile_dev_bypass", "allow"
    elif mode == "enforce":
        action, decision = "gateway.runtime_profile_blocked", "deny"
    else:
        action, decision = "gateway.runtime_profile_warned", "warn"
    event: dict[str, Any] = {
        "schema_version": "gateway.runtime.event.v1",
        "action": action,
        "event_timestamp": datetime.now(timezone.utc).isoformat(),
        "upstream": ctx.upstream.name,
        "tenant_id": ctx.tenant_id,
        "source_agent": ctx.source_agent,
        "agent_id": ctx.source_agent,
        "identity_id": ctx.profile_identity_id,
        "profile_id": ctx.profile_id,
        "profile_revision": ctx.profile_revision,
        "blueprint_id": ctx.blueprint_id,
        "blueprint_revision": ctx.blueprint_revision,
        "policy_ids": list(ctx.profile_policy_ids),
        "decision": decision,
        "policy_source": "runtime_profile",
        "reason_code": failure_code,
        "development_mode": bool(dev_bypass),
        "trace_id": str(ctx.trace_meta["trace_id"]),
    }
    if enforced:
        event_type = (
            GatewayRuntimeEventType.TOOL_CALL_BLOCKED if is_tools_call(ctx.message) else GatewayRuntimeEventType.RUNTIME_PROFILE_BLOCKED
        )
        event.update(ctx.runtime_event(event_type, decision="deny", policy_source="runtime_profile", reason_code=failure_code))
        return event
    event_type = GatewayRuntimeEventType.RUNTIME_PROFILE_DEV_BYPASS if dev_bypass else GatewayRuntimeEventType.RUNTIME_PROFILE_WARNED
    event.update(ctx.runtime_event(event_type, decision="allow", policy_source="runtime_profile", reason_code=failure_code))
    event["development_mode"] = bool(dev_bypass)
    return event


async def apply_runtime_profile(runtime: RelayRuntime, ctx: RelayContext) -> JSONResponse | None:
    """Resolve the caller's client profile; block, warn or dev-bypass on failure."""
    mode = runtime.runtime_profile_mode
    if mode == "off":
        return None
    failure_code = _profile_failure_code(runtime, ctx)
    if not failure_code:
        return None
    settings = runtime.settings
    dev_bypass = bool(settings.allow_runtime_profile_dev_bypass and _is_loopback_host(settings.listener_host))
    if settings.audit_sink is not None:
        await settings.audit_sink(_profile_audit_event(ctx, mode=mode, failure_code=failure_code, dev_bypass=dev_bypass))
    if mode == "enforce" and not dev_bypass:
        record_gateway_relay(ctx.upstream.name, "blocked")
        return ctx.jsonrpc_error(
            -32001,
            "Blocked by agent-bom gateway runtime profile policy",
            {
                "reason": _public_gateway_block_reason("runtime_profile"),
                "policy_source": "runtime_profile",
                "reason_code": failure_code,
            },
        )
    # Warn/bypass paths must not claim an unresolved assignment as canonical. A
    # valid-but-out-of-scope assignment remains known and retains its profile
    # attribution for the final allow event.
    if ctx.profile_id and failure_code not in _OUT_OF_SCOPE_CODES:
        ctx.profile_id = ""
        ctx.profile_revision = 0
        ctx.profile_policy_ids = ()
    return None
