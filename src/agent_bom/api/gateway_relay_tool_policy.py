"""Relay stage: the layered verdict for policy-gated JSON-RPC methods.

The file policy decides first; every later layer may only tighten an allow
(scope/JIT, store-backed conditional access, control-plane binding, drift,
graph reachability, conditional rules and plugins, OAuth scopes, argument
DLP). A QUARANTINE verdict blocks the tool but flags the agent instead of
hard-denying it. Layers run in a fixed order; see ``TOOL_POLICY_LAYERS``.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable

from fastapi.responses import JSONResponse

from agent_bom.api.gateway_auth import _gateway_allows_anonymous_agents
from agent_bom.api.gateway_policy import (
    _conditional_access_fail_closed,
    _DriftLookup,
    _evaluate_control_plane_bundle,
    _open_drift_violates_tool,
)
from agent_bom.api.gateway_relay_context import (
    RelayContext,
    RelayRuntime,
    ToolDecision,
    _emit_gateway_governance_event,
    _public_gateway_block_reason,
    _redact_obj_pii,
)
from agent_bom.api.gateway_relay_reachability import apply_graph_reachability
from agent_bom.api.gateway_request import (
    _request_client_id,
    _request_context_attributes,
    _request_device_id,
    _request_environment,
    _request_groups,
    _request_risk_score,
    _request_source_ip,
    _sanitize_for_log,
)
from agent_bom.api.metrics import record_gateway_relay
from agent_bom.proxy import check_policy, policy_subject_from_message
from agent_bom.proxy_policy import (
    DecisionContext,
    GatewayDecision,
    check_policy_warning,
    context_from_now,
    evaluate_conditional_rules,
    evaluate_policy_plugins,
)
from agent_bom.proxy_scanner import scan_tool_call
from agent_bom.runtime.gateway_events import GatewayRuntimeEventType
from agent_bom.security import sanitize_text

logger = logging.getLogger("agent_bom.gateway_server")

ToolPolicyLayer = Callable[[RelayRuntime, RelayContext, ToolDecision], Awaitable[None]]

_DECISION_RANK = {GatewayDecision.ALLOW: 0, GatewayDecision.QUARANTINE: 1, GatewayDecision.DENY: 2}


async def apply_identity_scope(runtime: RelayRuntime, ctx: RelayContext, decision: ToolDecision) -> None:
    """Managed identities carry a per-identity tool scope; a JIT grant may widen it."""
    if not decision.allowed:
        return
    identity = ctx.scoped_identity
    if identity is None:
        # A managed token whose scope could not be loaded fails closed even if
        # it also resolves through a policy mapping.
        if ctx.managed_identity_lookup_unavailable and (ctx.identity_token or "").startswith("abi_"):
            decision.deny("managed identity store unavailable; tool scope cannot be verified", "identity_scope")
        return
    if identity.tool_allowed(decision.tool_name):
        return
    try:
        from agent_bom.api.agent_identity_store import active_jit_grant_for_tool, get_agent_identity_store

        jit_grant = active_jit_grant_for_tool(
            get_agent_identity_store(),
            tenant_id=identity.tenant_id,
            identity_id=identity.identity_id,
            tool_name=decision.tool_name,
        )
    except Exception:  # noqa: BLE001
        jit_grant = None
    if jit_grant is None:
        decision.deny(f"tool '{decision.tool_name}' not in identity scope", "identity_scope")
        return
    decision.policy_source = "identity_jit"
    await runtime.audit(
        {
            "action": "gateway.identity_jit_grant_used",
            "upstream": ctx.upstream.name,
            "tenant_id": ctx.tenant_id,
            "source_agent": ctx.source_agent,
            "identity_id": identity.identity_id,
            "grant_id": jit_grant.grant_id,
            "tool": decision.tool_name,
            "expires_at": jit_grant.expires_at,
        }
    )


def _evaluate_store_conditional_access(ctx: RelayContext, decision: ToolDecision) -> tuple[bool, str, str]:
    try:
        from agent_bom.api.agent_identity_store import (
            AccessContext,
            evaluate_conditional_access_for_request,
            get_agent_identity_store,
        )

        access = AccessContext(
            identity_id=ctx.scoped_identity.identity_id if ctx.scoped_identity is not None else "",
            agent_id=ctx.source_agent,
            tool_name=decision.tool_name,
            environment=_request_environment(ctx.request),
            source_ip=_request_source_ip(ctx.request),
            device_id=_request_device_id(ctx.request),
            groups=_request_groups(ctx.request),
            client_id=_request_client_id(ctx.request),
        )
        # EDR/MDM posture enrichment; unknown devices leave posture None so a
        # device guardrail fails closed.
        try:
            from agent_bom.device_posture import apply_device_posture, get_device_posture_store

            apply_device_posture(get_device_posture_store(), access, tenant_id=ctx.tenant_id)
        except Exception:  # noqa: BLE001 — enrichment must not break the decision path
            pass
        return evaluate_conditional_access_for_request(get_agent_identity_store(), tenant_id=ctx.tenant_id, ctx=access)
    except Exception:  # noqa: BLE001 — fail CLOSED: an eval error must not bypass a policy
        return _conditional_access_fail_closed(ctx.tenant_id)


async def apply_store_conditional_access(runtime: RelayRuntime, ctx: RelayContext, decision: ToolDecision) -> None:
    """Time window, source CIDR, environment and device guardrails (after JIT)."""
    if not decision.allowed:
        return
    allowed, reason, policy_id = _evaluate_store_conditional_access(ctx, decision)
    if allowed:
        return
    decision.deny(reason, "conditional_access")
    identity_id = ctx.scoped_identity.identity_id if ctx.scoped_identity is not None else ""
    await runtime.audit(
        {
            "action": "gateway.conditional_access_blocked",
            "upstream": ctx.upstream.name,
            "tenant_id": ctx.tenant_id,
            "source_agent": ctx.source_agent,
            "identity_id": identity_id,
            "tool": decision.tool_name,
            "policy_id": policy_id,
            "reason": reason,
        }
    )
    _emit_gateway_governance_event(
        "identity.conditional_access_blocked",
        tenant_id=ctx.tenant_id,
        subject_id=identity_id or ctx.source_agent,
        payload={
            "source_agent": ctx.source_agent,
            "identity_id": identity_id,
            "tool": decision.tool_name,
            "policy_id": policy_id,
            "reason": reason,
        },
    )


async def apply_control_plane_binding(runtime: RelayRuntime, ctx: RelayContext, decision: ToolDecision) -> None:
    """Control-plane GatewayPolicy agent/type/environment binding for the caller."""
    policies = runtime.settings.control_plane_policies
    if not (decision.allowed and policies):
        return
    allowed, reason = _evaluate_control_plane_bundle(policies, ctx.source_agent, decision.tool_name, decision.arguments)
    if not allowed:
        decision.deny(reason or "blocked by control-plane policy binding", "control_plane")


def _drift_lookup(ctx: RelayContext, tool_name: str) -> _DriftLookup:
    if not ctx.blueprint_id or ctx.managed_identity_lookup_unavailable:
        reason = (
            "managed identity store unavailable"
            if ctx.managed_identity_lookup_unavailable
            else "managed identity has no role blueprint binding"
        )
        return _DriftLookup(unavailable=True, reason=reason)
    return _open_drift_violates_tool(ctx.tenant_id, ctx.blueprint_id, tool_name)


async def apply_drift_enforcement(runtime: RelayRuntime, ctx: RelayContext, decision: ToolDecision) -> None:
    """Block or flag a tool an open drift incident named as out-of-blueprint."""
    settings = runtime.settings
    mode = settings.drift_enforcement_mode
    if not decision.allowed or mode not in ("warn", "enforce"):
        return
    secured_enforce = mode == "enforce" and (
        bool(ctx.current_policy.get("require_agent_identity")) or not _gateway_allows_anonymous_agents(settings)
    )
    # Drift incidents are keyed by the managed identity's own role blueprint.
    ctx.blueprint_id = str(getattr(ctx.scoped_identity, "blueprint_id", "") or "")
    lookup = _drift_lookup(ctx, decision.tool_name)
    base = {"upstream": ctx.upstream.name, "tenant_id": ctx.tenant_id, "source_agent": ctx.source_agent}
    if lookup.unavailable and secured_enforce:
        decision.deny(lookup.reason, "drift_enforcement")
    elif lookup.unavailable and settings.audit_sink is not None:
        await runtime.audit({"action": "gateway.drift_binding_unavailable", **base, "tool": decision.tool_name, "reason": lookup.reason})
    elif lookup.violates and mode == "enforce":
        decision.deny(lookup.reason, "drift_enforcement")
        _emit_gateway_governance_event(
            "drift.blocked",
            tenant_id=ctx.tenant_id,
            subject_id=ctx.source_agent,
            payload={
                "source_agent": ctx.source_agent,
                "blueprint_id": ctx.blueprint_id,
                "tool": decision.tool_name,
                "reason": lookup.reason,
            },
        )
    elif lookup.violates:
        await runtime.audit(
            {
                "action": "gateway.drift_warned",
                **base,
                "blueprint_id": ctx.blueprint_id,
                "tool": decision.tool_name,
                "reason": lookup.reason,
            }
        )


async def apply_conditional_rules_and_plugins(runtime: RelayRuntime, ctx: RelayContext, decision: ToolDecision) -> None:
    """Deterministic declarative rules + third-party plugins; DENY > QUARANTINE > ALLOW.

    Conditional-rule errors always deny (a fixed fail-closed lane). Plugin
    errors follow the gateway fail mode. Rules win ties over plugins.
    """
    if not decision.allowed:
        return
    request = ctx.request
    decision_ctx = context_from_now(
        tenant_id=ctx.tenant_id,
        source_agent=ctx.source_agent,
        tool_name=decision.tool_name,
        now=time.time(),
        risk_score=_request_risk_score(request),
        environment=_request_environment(request),
        source_ip=_request_source_ip(request),
        device_id=_request_device_id(request),
        groups=_request_groups(request),
        client_id=_request_client_id(request),
        attributes=_request_context_attributes(request),
    )
    try:
        cond_decision, cond_reason, _cond_rule = evaluate_conditional_rules(ctx.current_policy, decision_ctx)
    except Exception as exc:  # noqa: BLE001
        logger.warning("gateway conditional-rules evaluation error: %s", sanitize_text(_sanitize_for_log(exc)))
        cond_decision, cond_reason = GatewayDecision.DENY, "conditional rules evaluation error"
    try:
        plugin_decision, plugin_reason, _plugin_name = evaluate_policy_plugins(
            decision_ctx,
            ctx.current_policy,
            fail_closed=runtime.fail_closed,
        )
        plugin_eval_error = False
    except Exception as exc:  # noqa: BLE001
        logger.warning("gateway plugin evaluation error: %s", sanitize_text(_sanitize_for_log(exc)))
        plugin_decision, plugin_reason = GatewayDecision.ALLOW, ""
        plugin_eval_error = True
    if _DECISION_RANK[plugin_decision] > _DECISION_RANK[cond_decision]:
        composed, composed_reason, composed_source = plugin_decision, plugin_reason, "policy_plugin"
    else:
        composed, composed_reason, composed_source = cond_decision, cond_reason, "conditional_access"
    if plugin_eval_error and runtime.fail_closed:
        decision.deny("policy evaluation error", "conditional_access")
    elif composed == GatewayDecision.DENY:
        decision.deny(composed_reason, composed_source)
    elif composed == GatewayDecision.QUARANTINE:
        decision.quarantine, decision.quarantine_reason, decision.policy_source = True, composed_reason, composed_source


async def apply_oauth_scope(runtime: RelayRuntime, ctx: RelayContext, decision: ToolDecision) -> None:
    """Deny unless the caller's token carries every scope mapped to the tool ("*" = all)."""
    scope_map = runtime.settings.tool_scope_map
    if not (decision.allowed and scope_map):
        return
    required: set[str] = set()
    for key in ("*", decision.tool_name):
        mapped = scope_map.get(key)
        if mapped:
            required |= {s for s in mapped if s}
    missing = required - ctx.token_scopes
    if not (required and missing):
        return
    decision.deny(
        f"caller token missing required OAuth scope(s) for '{decision.tool_name}': {', '.join(sorted(missing))}",
        "oauth_scope",
    )
    await runtime.audit(
        {
            "action": "gateway.oauth_scope_blocked",
            "upstream": ctx.upstream.name,
            "tenant_id": ctx.tenant_id,
            "source_agent": ctx.source_agent,
            "tool": decision.tool_name,
            "required_scopes": sorted(required),
            "missing_scopes": sorted(missing),
        }
    )


async def apply_argument_dlp(runtime: RelayRuntime, ctx: RelayContext, decision: ToolDecision) -> None:
    """Scan tool arguments; enforce mode blocks, or redacts PII in place before forwarding."""
    config = runtime.dlp_config
    if not (decision.allowed and config.enabled):
        return
    findings = scan_tool_call(decision.tool_name, decision.arguments, config)
    blocked = config.mode == "enforce" and any(f.blocked for f in findings)
    redacted = config.mode == "enforce" and config.pii_action == "redact" and bool(findings) and not blocked
    if findings and runtime.settings.audit_sink is not None:
        typed_event = (
            ctx.runtime_event(
                GatewayRuntimeEventType.DLP_ARGUMENTS_REDACTED,
                decision="allow",
                policy_source="dlp",
                tool=decision.tool_name,
                data_action="pii_redacted",
            )
            if redacted
            else {}
        )
        await runtime.audit(
            {
                "action": "gateway.dlp_arguments",
                "upstream": ctx.upstream.name,
                "tenant_id": ctx.tenant_id,
                "source_agent": ctx.source_agent,
                "tool": decision.tool_name,
                "findings": sorted({f"{f.scanner}/{f.rule_id}" for f in findings}),
                "blocked": blocked,
                **typed_event,
            }
        )
    if blocked:
        first = next(f for f in findings if f.blocked)
        decision.deny(f"DLP blocked tool arguments: {first.scanner}/{first.rule_id}", "dlp")
    elif redacted:
        redacted_args = {k: _redact_obj_pii(v) for k, v in decision.arguments.items()}
        params = ctx.message.get("params")
        if isinstance(params, dict):
            params["arguments"] = redacted_args


TOOL_POLICY_LAYERS: tuple[ToolPolicyLayer, ...] = (
    apply_identity_scope,
    apply_store_conditional_access,
    apply_control_plane_binding,
    apply_drift_enforcement,
    apply_graph_reachability,
    apply_conditional_rules_and_plugins,
    apply_oauth_scope,
    apply_argument_dlp,
)


def _interop_context(ctx: RelayContext, tool_name: str) -> DecisionContext:
    return context_from_now(
        tenant_id=ctx.tenant_id,
        source_agent=ctx.source_agent,
        tool_name=tool_name,
        now=time.time(),
        environment=_request_environment(ctx.request),
        source_ip=_request_source_ip(ctx.request),
    )


async def _deny_tool_call(runtime: RelayRuntime, ctx: RelayContext, decision: ToolDecision) -> JSONResponse:
    record_gateway_relay(ctx.upstream.name, "blocked")
    await runtime.audit(
        {
            "action": "gateway.policy_blocked",
            "upstream": ctx.upstream.name,
            "tenant_id": ctx.tenant_id,
            "method": ctx.message.get("method"),
            "tool": decision.tool_name,
            "reason": decision.reason,
            "source_agent": ctx.source_agent,
            "policy_source": decision.policy_source,
            **ctx.runtime_event(
                GatewayRuntimeEventType.TOOL_CALL_BLOCKED,
                decision="deny",
                policy_source=decision.policy_source,
                tool=decision.tool_name,
            ),
        }
    )
    await runtime.emit_policy_interop(
        runtime.settings,
        decision=GatewayDecision.DENY,
        reason=decision.reason,
        ctx=_interop_context(ctx, decision.tool_name),
        policy_source=decision.policy_source,
    )
    return ctx.jsonrpc_error(
        -32001,
        "Blocked by agent-bom gateway policy",
        {"reason": _public_gateway_block_reason(decision.policy_source), "policy_source": decision.policy_source},
    )


async def _quarantine_tool_call(runtime: RelayRuntime, ctx: RelayContext, decision: ToolDecision) -> JSONResponse:
    # The client gets a structured, client-safe reason; the full reason and
    # the OCSF event stay in audit.
    record_gateway_relay(ctx.upstream.name, "blocked")
    await runtime.audit(
        {
            "action": "gateway.policy_quarantined",
            "upstream": ctx.upstream.name,
            "tenant_id": ctx.tenant_id,
            "method": ctx.message.get("method"),
            "tool": decision.tool_name,
            "reason": decision.quarantine_reason,
            "source_agent": ctx.source_agent,
            "policy_source": decision.policy_source,
        }
    )
    _emit_gateway_governance_event(
        "policy.quarantined",
        tenant_id=ctx.tenant_id,
        subject_id=ctx.source_agent,
        payload={
            "source_agent": ctx.source_agent,
            "tool": decision.tool_name,
            "reason": decision.quarantine_reason,
            "policy_source": decision.policy_source,
        },
    )
    await runtime.emit_policy_interop(
        runtime.settings,
        decision=GatewayDecision.QUARANTINE,
        reason=decision.quarantine_reason,
        ctx=_interop_context(ctx, decision.tool_name),
        policy_source=decision.policy_source,
    )
    return ctx.jsonrpc_error(
        -32002,
        "Quarantined by agent-bom gateway policy",
        {
            "reason": "Agent quarantined: this tool is restricted while the session is under review",
            "policy_source": decision.policy_source,
            "decision": "quarantine",
        },
    )


async def evaluate_tool_call(runtime: RelayRuntime, ctx: RelayContext) -> JSONResponse | None:
    """Run every tool-policy layer for a gated method; deny, quarantine or warn."""
    subject = policy_subject_from_message(ctx.message)
    if not subject:
        return None
    tool_name, arguments = subject
    allowed, reason = check_policy(ctx.current_policy, tool_name, arguments)
    decision = ToolDecision(tool_name=tool_name, arguments=arguments, allowed=allowed, reason=reason)
    for layer in TOOL_POLICY_LAYERS:
        await layer(runtime, ctx, decision)
    if not decision.allowed:
        return await _deny_tool_call(runtime, ctx, decision)
    ctx.resolved_policy_source = decision.policy_source
    if decision.quarantine:
        return await _quarantine_tool_call(runtime, ctx, decision)
    warned, warning_reason, warning_rule_id = check_policy_warning(ctx.current_policy, tool_name, arguments)
    if warned:
        await runtime.audit(
            {
                "action": "gateway.policy_warned",
                "upstream": ctx.upstream.name,
                "tenant_id": ctx.tenant_id,
                "method": ctx.message.get("method"),
                "tool": tool_name,
                "rule_id": warning_rule_id,
                "reason": warning_reason,
            }
        )
    return None
