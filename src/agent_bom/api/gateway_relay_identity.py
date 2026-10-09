"""Relay stages: request admission, policy availability and caller identity.

Runs before any enforcement lane. Identity resolution is secure by default:

1. an invalid/revoked token (present but unresolved) always fails closed,
   regardless of ``require_agent_identity`` or the listener bind;
2. ``require_agent_identity`` with a missing token fails closed;
3. a fully missing token is permitted on a loopback bind (local dev) or with
   the explicit opt-out, and fails closed on a non-loopback bind otherwise.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from agent_bom.agent_identity import ANONYMOUS, check_caller_identity, extract_identity_token, identity_token_scopes
from agent_bom.api.gateway_auth import (
    _authenticate_gateway_request,
    _configured_gateway_tenant_id,
    _gateway_allows_anonymous_agents,
    _gateway_requires_auth,
)
from agent_bom.api.gateway_policy import _agent_identity_revoked
from agent_bom.api.gateway_relay_context import RelayContext, RelayRuntime, _message_tool_label
from agent_bom.api.gateway_request import _read_bounded_gateway_body, _request_environment, _request_source_ip, _sanitize_for_log
from agent_bom.api.metrics import record_gateway_relay
from agent_bom.api.tracing import make_request_trace
from agent_bom.proxy_policy import GatewayDecision, context_from_now
from agent_bom.runtime.gateway_events import GatewayRuntimeEventType
from agent_bom.runtime.gateway_relay_contract import MAX_GATEWAY_RELAY_MESSAGE_BYTES
from agent_bom.runtime.profile_resolution import ProfileResolutionCode
from agent_bom.security import sanitize_error, sanitize_text

logger = logging.getLogger("agent_bom.gateway_server")

_FAIL_CLOSED_REASON = "policy unavailable; fail-closed mode denies"


def _reject_declared_oversize(request: Request) -> None:
    content_length = request.headers.get("content-length")
    if not content_length:
        return
    try:
        if int(content_length) > MAX_GATEWAY_RELAY_MESSAGE_BYTES:
            raise HTTPException(status_code=413, detail="gateway request exceeds maximum JSON-RPC message size")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid Content-Length header") from exc


def _parse_jsonrpc_body(raw_body: bytes) -> dict[str, Any]:
    try:
        body = json.loads(raw_body)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"body is not valid JSON: {sanitize_error(exc)}") from exc
    if isinstance(body, dict) and "jsonrpc" in body:
        return body
    raise HTTPException(status_code=400, detail="request must be a JSON-RPC message")


async def parse_relay_request(runtime: RelayRuntime, server_name: str, request: Request) -> RelayContext:
    """Authenticate, route, bound and parse the request; snapshot the policy."""
    settings = runtime.settings
    trace_meta = make_request_trace(dict(request.headers))
    tenant_id = _configured_gateway_tenant_id()
    auth_method = "none"
    if _gateway_requires_auth(settings):
        tenant_id, auth_method = _authenticate_gateway_request(request, settings)
    request.state.tenant_id = tenant_id
    request.state.auth_method = auth_method

    upstream = settings.registry.get(server_name, tenant_id=tenant_id)
    if upstream is None:
        raise HTTPException(status_code=404, detail=f"unknown upstream {server_name!r}")
    request.state.gateway_upstream = upstream.name

    _reject_declared_oversize(request)
    message = _parse_jsonrpc_body(await _read_bounded_gateway_body(request))
    request.state.gateway_message_id = message.get("id")
    await runtime.bind_audit_tenant(request, tenant_id, auth_method)

    async with runtime.policy_reload.lock:
        current_policy = dict(runtime.policy_reload.state.policy)
        policy_load_failed = bool(runtime.policy_reload.state.load_failed)
    return RelayContext(
        request=request,
        trace_meta=trace_meta,
        tenant_id=tenant_id,
        upstream=upstream,
        message=message,
        current_policy=current_policy,
        policy_load_failed=policy_load_failed,
        event_tool=_message_tool_label(message),
    )


async def deny_if_policy_unavailable(runtime: RelayRuntime, ctx: RelayContext) -> JSONResponse | None:
    """Fail-closed: a configured policy that never loaded denies, not default-allows."""
    if not (runtime.fail_closed and ctx.policy_load_failed):
        return None
    record_gateway_relay(ctx.upstream.name, "blocked")
    decision_ctx = context_from_now(
        tenant_id=ctx.tenant_id,
        source_agent=ANONYMOUS,
        tool_name=_message_tool_label(ctx.message),
        now=time.time(),
        environment=_request_environment(ctx.request),
        source_ip=_request_source_ip(ctx.request),
    )
    await runtime.audit(
        {
            "action": "gateway.policy_fail_closed",
            "upstream": ctx.upstream.name,
            "tenant_id": ctx.tenant_id,
            "reason": _FAIL_CLOSED_REASON,
        }
    )
    await runtime.emit_policy_interop(
        runtime.settings,
        decision=GatewayDecision.DENY,
        reason=_FAIL_CLOSED_REASON,
        ctx=decision_ctx,
        policy_source="fail_closed",
    )
    return ctx.jsonrpc_error(
        -32001,
        "Blocked by agent-bom gateway policy",
        {"reason": "Gateway policy unavailable and fail-closed mode is active", "policy_source": "fail_closed"},
    )


def _lookup_managed_identity(ctx: RelayContext, token: str) -> None:
    try:
        from agent_bom.api.agent_identity_store import get_agent_identity_store, identity_for_token

        ctx.scoped_identity = identity_for_token(get_agent_identity_store(), token)
    except Exception as exc:  # noqa: BLE001
        ctx.managed_identity_lookup_unavailable = True
        logger.warning("gateway managed identity lookup failed: %s", sanitize_text(_sanitize_for_log(exc)))


def _adopt_managed_identity(runtime: RelayRuntime, ctx: RelayContext) -> None:
    identity = ctx.scoped_identity
    ctx.source_agent = identity.agent_id
    ctx.token_present = True
    ctx.identity_invalid_reason = None
    ctx.identity_verified = True
    if identity.tenant_id != ctx.tenant_id:
        ctx.identity_invalid_reason = "managed identity tenant mismatch"
        ctx.identity_failure_code = ProfileResolutionCode.TENANT_MISMATCH.value
    elif (
        not identity.blueprint_id
        and runtime.settings.drift_enforcement_mode == "enforce"
        and not _gateway_allows_anonymous_agents(runtime.settings)
    ):
        ctx.identity_invalid_reason = "managed identity has no role blueprint binding"
        ctx.identity_failure_code = ProfileResolutionCode.PROFILE_INCOMPLETE.value


def _adopt_policy_identity(ctx: RelayContext) -> None:
    source_agent, token_present, invalid_reason = check_caller_identity(ctx.message, ctx.current_policy)
    if invalid_reason is not None:
        ctx.identity_failure_code = ProfileResolutionCode.IDENTITY_INVALID.value
    ctx.source_agent = source_agent or ANONYMOUS
    ctx.token_present = token_present
    ctx.identity_invalid_reason = invalid_reason
    # "Verified" for inline mutual-auth: a resolved, non-anonymous caller whose
    # token was cryptographically checked — JWKS/OIDC-signed JWT or an
    # agent-bom-issued managed (``abi_``) token. An opaque policy.agent_tokens
    # mapping is NOT verified mutual auth.
    policy = ctx.current_policy
    ctx.identity_verified = bool(
        token_present
        and invalid_reason is None
        and ctx.source_agent != ANONYMOUS
        and (policy.get("jwks_uri") or policy.get("oidc_issuer") or (ctx.identity_token or "").startswith("abi_"))
    )
    if ctx.identity_token and invalid_reason is None:
        ctx.token_scopes = identity_token_scopes(ctx.identity_token)


async def _apply_revocation(runtime: RelayRuntime, ctx: RelayContext) -> None:
    # Revocation is agent-wide, so it runs before any tool-scoped stage (a
    # revoked caller must not reach initialize / tools/list either) and before
    # the JIT-grant path, which could otherwise override a per-tool deny.
    revoked, lookup_incomplete, lookup_failed = await asyncio.to_thread(_agent_identity_revoked, ctx.tenant_id, ctx.source_agent)
    if revoked:
        ctx.identity_invalid_reason = "agent identity revoked"
        ctx.identity_failure_code = ProfileResolutionCode.IDENTITY_INACTIVE.value
    elif lookup_incomplete:
        # A knowingly partial answer is not a negative. Revocation is an
        # emergency control, so this denies on every listener.
        ctx.identity_invalid_reason = "agent identity revocation status unavailable"
        ctx.identity_failure_code = ProfileResolutionCode.IDENTITY_STORE_UNAVAILABLE.value
    elif lookup_failed and (ctx.current_policy.get("require_agent_identity") or not _gateway_allows_anonymous_agents(runtime.settings)):
        ctx.identity_invalid_reason = "agent identity revocation status unavailable"
        ctx.identity_failure_code = ProfileResolutionCode.IDENTITY_STORE_UNAVAILABLE.value


async def resolve_caller_identity(runtime: RelayRuntime, ctx: RelayContext) -> None:
    """Resolve the calling agent from a managed token or the policy mapping."""
    ctx.identity_token = extract_identity_token(ctx.message)
    if ctx.identity_token:
        _lookup_managed_identity(ctx, ctx.identity_token)
    if ctx.scoped_identity is not None:
        _adopt_managed_identity(runtime, ctx)
    else:
        _adopt_policy_identity(ctx)
    if ctx.scoped_identity is None and ctx.identity_invalid_reason is None and ctx.source_agent != ANONYMOUS:
        await _apply_revocation(runtime, ctx)
    # A role blueprint is not a client profile; profile fields stay empty until
    # a canonical assignment resolves.
    ctx.blueprint_id = str(getattr(ctx.scoped_identity, "blueprint_id", "") or "")


def _identity_block_reason(runtime: RelayRuntime, ctx: RelayContext) -> str | None:
    if ctx.identity_invalid_reason is not None:
        return f"Identity invalid: {ctx.identity_invalid_reason}"
    if ctx.token_present:
        return None
    if ctx.current_policy.get("require_agent_identity"):
        ctx.identity_failure_code = ProfileResolutionCode.MANAGED_IDENTITY_REQUIRED.value
        return "Identity required: no agent_identity token in _meta"
    if not _gateway_allows_anonymous_agents(runtime.settings):
        ctx.identity_failure_code = ProfileResolutionCode.MANAGED_IDENTITY_REQUIRED.value
        return (
            "Anonymous agent caller denied on non-loopback listener; supply an agent_identity "
            "token or set AGENT_BOM_GATEWAY_ALLOW_ANONYMOUS_AGENTS for local development only"
        )
    return None


async def deny_if_identity_invalid(runtime: RelayRuntime, ctx: RelayContext) -> JSONResponse | None:
    """Block invalid, revoked, missing-but-required or anonymous-remote callers."""
    block_reason = _identity_block_reason(runtime, ctx)
    if block_reason is None:
        return None
    record_gateway_relay(ctx.upstream.name, "blocked")
    logger.info(
        "Gateway identity policy blocked request for upstream=%s tenant_id=%s source_agent=%s reason=%s",
        ctx.upstream.name,
        ctx.tenant_id,
        _sanitize_for_log(ctx.source_agent),
        _sanitize_for_log(block_reason),
    )
    await runtime.audit(
        {
            "action": "gateway.identity_blocked",
            "upstream": ctx.upstream.name,
            "tenant_id": ctx.tenant_id,
            "source_agent": ctx.source_agent,
            "reason": block_reason,
            **ctx.runtime_event(
                GatewayRuntimeEventType.TOOL_CALL_BLOCKED,
                decision="deny",
                policy_source="identity",
                reason_code=ctx.identity_failure_code,
            ),
        }
    )
    return ctx.jsonrpc_error(-32001, "Blocked by agent-bom gateway identity policy", {"reason": "Identity validation failed"})
