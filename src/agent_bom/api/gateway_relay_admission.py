"""Relay stages: per-caller admission before any tool-level policy.

Edge controls (A2A mutual auth, inter-agent firewall), runtime rate limiting,
spend budgets, cost anomaly and fleet containment. Each stage returns a
response to short-circuit the relay, or ``None`` to continue.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from fastapi.responses import JSONResponse

from agent_bom.a2a_auth_posture import evaluate_inline_mutual_auth
from agent_bom.api.gateway_policy import _agent_cost_anomaly, _fleet_containment_reason
from agent_bom.api.gateway_rate_limit import _rate_limit_bucket_component
from agent_bom.api.gateway_relay_context import RelayContext, RelayRuntime, _emit_gateway_governance_event, _public_gateway_block_reason
from agent_bom.api.gateway_request import _request_cost_center, _sanitize_for_log
from agent_bom.api.metrics import record_gateway_relay, record_rate_limit_hit
from agent_bom.firewall import AgentFirewallPolicy, FirewallDecision, FirewallEvaluation
from agent_bom.firewall import evaluate as evaluate_firewall_policy
from agent_bom.security import sanitize_text

logger = logging.getLogger("agent_bom.gateway_server")

_BUDGET_BLOCK_CODE = -32001


async def enforce_a2a_mutual_auth(runtime: RelayRuntime, ctx: RelayContext) -> JSONResponse | None:
    """Every inter-agent edge must carry a verified caller identity when enabled."""
    mode = runtime.settings.a2a_mutual_auth_enforcement_mode
    if mode not in ("warn", "enforce"):
        return None
    result = evaluate_inline_mutual_auth(
        source_agent=ctx.source_agent,
        target=ctx.upstream.name,
        token_present=ctx.token_present,
        verified=ctx.identity_verified,
        identity_invalid_reason=ctx.identity_invalid_reason,
    )
    if not result.weak:
        return None
    await runtime.audit(
        {
            "action": "gateway.a2a_mutual_auth_blocked" if mode == "enforce" else "gateway.a2a_mutual_auth_warned",
            "upstream": ctx.upstream.name,
            "tenant_id": ctx.tenant_id,
            "source_agent": ctx.source_agent,
            "target_agent": ctx.upstream.name,
            "weakness": result.weakness,
            "reason": result.reason,
        }
    )
    if mode != "enforce":
        return None
    record_gateway_relay(ctx.upstream.name, "blocked")
    _emit_gateway_governance_event(
        "a2a.mutual_auth_blocked",
        tenant_id=ctx.tenant_id,
        subject_id=ctx.source_agent,
        payload={
            "source_agent": ctx.source_agent,
            "target_agent": ctx.upstream.name,
            "weakness": result.weakness,
            "reason": result.reason,
        },
    )
    logger.info(
        "Gateway A2A mutual-auth blocked edge source_agent=%s target=%s weakness=%s",
        _sanitize_for_log(ctx.source_agent),
        _sanitize_for_log(ctx.upstream.name),
        _sanitize_for_log(result.weakness),
    )
    return ctx.jsonrpc_error(
        -32001,
        "Blocked by agent-bom gateway: inter-agent mutual authentication required",
        {"reason": _public_gateway_block_reason("a2a_mutual_auth"), "policy_source": "a2a_mutual_auth"},
    )


def _firewall_audit_event(ctx: RelayContext, result: FirewallEvaluation, policy: AgentFirewallPolicy) -> dict[str, Any]:
    rule = result.matched_rule
    return {
        "action": "gateway.firewall_blocked" if result.effective_decision == FirewallDecision.DENY else "gateway.firewall_warned",
        "upstream": ctx.upstream.name,
        "tenant_id": ctx.tenant_id,
        "source_agent": ctx.source_agent,
        "target_agent": ctx.upstream.name,
        "decision": result.decision.value,
        "effective_decision": result.effective_decision.value,
        "matched_rule": (
            {"source": rule.source, "target": rule.target, "decision": rule.decision.value, "description": rule.description}
            if rule is not None
            else None
        ),
        "enforcement_mode": policy.enforcement_mode.value,
    }


async def enforce_firewall(runtime: RelayRuntime, ctx: RelayContext) -> JSONResponse | None:
    """Evaluate the configured inter-agent firewall for source_agent -> upstream.

    Without a configured policy file the firewall is default-allow. WARN is
    advisory (audited only); an effective DENY fails the relay closed.
    """
    if runtime.settings.firewall_policy_path is None:
        return None
    async with runtime.firewall_reload.lock:
        policy: AgentFirewallPolicy = runtime.firewall_reload.state.policy
        load_failed = bool(runtime.firewall_reload.state.load_failed)
    if runtime.fail_closed and load_failed:
        record_gateway_relay(ctx.upstream.name, "blocked")
        return JSONResponse(
            status_code=403,
            content={"jsonrpc": "2.0", "error": {"code": -32000, "message": "gateway firewall policy unavailable"}, "id": ctx.message_id},
        )
    result = evaluate_firewall_policy(policy, source_agent=ctx.source_agent, target_agent=ctx.upstream.name)
    if result.effective_decision == FirewallDecision.ALLOW:
        return None
    audit_event = _firewall_audit_event(ctx, result, policy)
    await runtime.audit(audit_event)
    if result.effective_decision != FirewallDecision.DENY:
        return None
    record_gateway_relay(ctx.upstream.name, "blocked")
    _emit_gateway_governance_event(
        "firewall.blocked",
        tenant_id=ctx.tenant_id,
        subject_id=ctx.source_agent,
        payload={
            "source_agent": ctx.source_agent,
            "target_agent": ctx.upstream.name,
            "decision": result.decision.value,
            "matched_rule": audit_event["matched_rule"],
        },
    )
    logger.info(
        "Gateway firewall blocked request source_agent=%s target=%s tenant_id=%s",
        _sanitize_for_log(ctx.source_agent),
        _sanitize_for_log(ctx.upstream.name),
        ctx.tenant_id,
    )
    return ctx.jsonrpc_error(
        -32001,
        "Blocked by agent-bom gateway inter-agent firewall",
        {"reason": _public_gateway_block_reason("firewall"), "policy_source": "firewall"},
    )


async def enforce_rate_limit(runtime: RelayRuntime, ctx: RelayContext) -> JSONResponse | None:
    """Per tenant + source-agent runtime rate limit; sets the response headers."""
    store = runtime.rate_limit_store
    if store is None:
        return None
    now = time.time()
    bucket = f"gateway:tenant:{_rate_limit_bucket_component(ctx.tenant_id)}:source_agent:{_rate_limit_bucket_component(ctx.source_agent)}"
    hit_count, reset_at = await asyncio.to_thread(store.hit, bucket, now)
    limit = runtime.settings.runtime_rate_limit_per_tenant_per_minute
    ctx.rate_limit_headers = {
        "X-RateLimit-Limit": str(limit),
        "X-RateLimit-Remaining": str(max(0, limit - hit_count)),
        "X-RateLimit-Reset": str(reset_at),
    }
    if hit_count <= limit:
        return None
    retry_after = max(int(reset_at - now), 1)
    record_gateway_relay(ctx.upstream.name, "rate_limited")
    record_rate_limit_hit("gateway_source_agent")
    await runtime.audit(
        {
            "action": "gateway.rate_limited",
            "upstream": ctx.upstream.name,
            "tenant_id": ctx.tenant_id,
            "source_agent": ctx.source_agent,
            "limit": limit,
            "bucket": bucket,
            "reason": "source_agent_runtime_rate_limit",
        }
    )
    return JSONResponse(
        status_code=429,
        content={"detail": "Gateway source-agent rate limit exceeded"},
        headers={**ctx.rate_limit_headers, "Retry-After": str(retry_after)},
    )


async def _budget_block(
    runtime: RelayRuntime,
    ctx: RelayContext,
    *,
    audit_fields: dict[str, Any],
    governance_payload: dict[str, Any],
    message: str,
    error_data: dict[str, Any],
) -> JSONResponse:
    record_gateway_relay(ctx.upstream.name, "blocked")
    await runtime.audit(
        {
            "action": "gateway.budget_exceeded",
            "upstream": ctx.upstream.name,
            "tenant_id": ctx.tenant_id,
            "source_agent": ctx.source_agent,
            **audit_fields,
            "reason": "budget_enforced",
        }
    )
    _emit_gateway_governance_event(
        "budget.exceeded",
        tenant_id=ctx.tenant_id,
        subject_id=ctx.source_agent,
        payload={"source_agent": ctx.source_agent, **governance_payload},
    )
    return ctx.jsonrpc_error(_BUDGET_BLOCK_CODE, message, error_data)


async def enforce_agent_budget(runtime: RelayRuntime, ctx: RelayContext) -> JSONResponse | None:
    """Enforce-mode agent/tenant spend caps; cost-store failures fail open."""
    try:
        from agent_bom.api.cost_store import check_budget_enforcement, get_cost_store

        blocked, budget, spend = check_budget_enforcement(get_cost_store(), ctx.tenant_id, ctx.source_agent)
    except Exception as exc:  # noqa: BLE001
        logger.warning("gateway budget check failed: %s", sanitize_text(_sanitize_for_log(exc)))
        blocked, budget, spend = False, None, 0.0
    if not (blocked and budget is not None):
        return None
    fields = {"limit_usd": budget.limit_usd, "spend_usd": round(spend, 6), "budget_scope": "agent" if budget.agent else "tenant"}
    return await _budget_block(
        runtime,
        ctx,
        audit_fields=fields,
        governance_payload=fields,
        message="Blocked by agent-bom gateway: spend budget exceeded",
        error_data={"limit_usd": budget.limit_usd, "spend_usd": round(spend, 6)},
    )


async def enforce_cost_center_budget(runtime: RelayRuntime, ctx: RelayContext) -> JSONResponse | None:
    """Enforce-mode chargeback budget for the declared cost-center, if any."""
    cost_center = _request_cost_center(ctx.request, ctx.message)
    if not cost_center:
        return None
    try:
        from agent_bom.api.cost_store import check_cost_center_budget_enforcement, get_cost_store

        blocked, budget, spend = check_cost_center_budget_enforcement(get_cost_store(), ctx.tenant_id, cost_center)
    except Exception as exc:  # noqa: BLE001
        logger.warning("gateway cost-center budget check failed: %s", sanitize_text(_sanitize_for_log(exc)))
        blocked, budget, spend = False, None, 0.0
    if not (blocked and budget is not None):
        return None
    fields = {"cost_center": cost_center, "limit_usd": budget.limit_usd, "spend_usd": round(spend, 6), "budget_scope": "cost_center"}
    return await _budget_block(
        runtime,
        ctx,
        audit_fields=fields,
        governance_payload=fields,
        message="Blocked by agent-bom gateway: cost-center spend budget exceeded",
        error_data={"cost_center": cost_center, "limit_usd": budget.limit_usd, "spend_usd": round(spend, 6)},
    )


async def enforce_owner_budget(runtime: RelayRuntime, ctx: RelayContext) -> JSONResponse | None:
    """Enforce-mode cap for the governing blueprint's accountable owner."""
    try:
        from agent_bom.api.cost_owner import enforce_owner_budget as _enforce_owner_budget
        from agent_bom.api.cost_store import get_cost_store

        blocked, budget, spend, owner, workflow = _enforce_owner_budget(get_cost_store(), ctx.tenant_id, ctx.source_agent)
    except Exception as exc:  # noqa: BLE001
        logger.warning("gateway owner budget check failed: %s", sanitize_text(_sanitize_for_log(exc)))
        blocked, budget, spend, owner, workflow = False, None, 0.0, "", ""
    if not (blocked and budget is not None):
        return None
    fields = {
        "owner": owner,
        "workflow": workflow or None,
        "limit_usd": budget.limit_usd,
        "spend_usd": round(spend, 6),
        "budget_scope": "owner",
    }
    return await _budget_block(
        runtime,
        ctx,
        audit_fields=fields,
        governance_payload=fields,
        message="Blocked by agent-bom gateway: owner spend budget exceeded",
        error_data={"owner": owner, "limit_usd": budget.limit_usd, "spend_usd": round(spend, 6)},
    )


async def enforce_anomaly(runtime: RelayRuntime, ctx: RelayContext) -> JSONResponse | None:
    """Block or flag a spend outlier before its next call (cached, fail-open)."""
    mode = runtime.settings.anomaly_enforcement_mode
    if mode not in ("warn", "enforce"):
        return None
    anomalous, reason = _agent_cost_anomaly(ctx.tenant_id, ctx.source_agent)
    if not anomalous:
        return None
    base = {"upstream": ctx.upstream.name, "tenant_id": ctx.tenant_id, "source_agent": ctx.source_agent, "reason": reason}
    if mode != "enforce":
        await runtime.audit({"action": "gateway.anomaly_warned", **base})
        return None
    record_gateway_relay(ctx.upstream.name, "blocked")
    await runtime.audit({"action": "gateway.anomaly_blocked", **base})
    _emit_gateway_governance_event(
        "anomaly.blocked",
        tenant_id=ctx.tenant_id,
        subject_id=ctx.source_agent,
        payload={"source_agent": ctx.source_agent, "reason": reason},
    )
    return ctx.jsonrpc_error(
        -32001,
        "Blocked by agent-bom gateway: anomalous spend",
        {"reason": _public_gateway_block_reason("anomaly_enforcement"), "policy_source": "anomaly_enforcement"},
    )


async def enforce_fleet_containment(runtime: RelayRuntime, ctx: RelayContext) -> JSONResponse | None:
    """Isolate a quarantined agent; a store failure is unknown, never allow."""
    mode = runtime.settings.fleet_enforcement_mode
    if mode not in ("warn", "enforce"):
        return None
    fleet_reason = await asyncio.to_thread(_fleet_containment_reason, ctx.tenant_id, ctx.source_agent)
    if not fleet_reason:
        return None
    detail = "agent quarantined in fleet roster" if fleet_reason == "fleet_quarantine" else "fleet identity lookup unavailable"
    base = {"upstream": ctx.upstream.name, "tenant_id": ctx.tenant_id, "source_agent": ctx.source_agent, "reason": detail}
    if mode != "enforce":
        await runtime.audit({"action": "gateway.fleet_warned", **base})
        return None
    record_gateway_relay(ctx.upstream.name, "blocked")
    await runtime.audit({"action": "gateway.fleet_blocked", **base})
    _emit_gateway_governance_event(
        "fleet.blocked",
        tenant_id=ctx.tenant_id,
        subject_id=ctx.source_agent,
        payload={"source_agent": ctx.source_agent, "reason": detail},
    )
    return ctx.jsonrpc_error(
        -32001,
        "Blocked by agent-bom gateway: fleet containment",
        {"reason": _public_gateway_block_reason(fleet_reason), "policy_source": fleet_reason},
    )
