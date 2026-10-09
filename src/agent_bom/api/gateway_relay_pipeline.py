"""The ordered relay pipeline behind ``POST /mcp/{server_name}``.

Every stage takes the app-scoped ``RelayRuntime`` and the request's
``RelayContext`` and either returns a response (short-circuit: block, rate
limit, quarantine) or ``None`` to continue. A request that clears every stage
is handed to ``forward_authorized_request`` for upstream forwarding, response
inspection/redaction and completion auditing.

Stage order is a security contract: identity precedes every enforcement lane,
revocation precedes JIT, admission controls precede tool-level policy, and no
upstream network call happens before all of them pass.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Request
from fastapi.responses import JSONResponse

from agent_bom.api.gateway_forward import GatewayForwardContext, forward_authorized_request
from agent_bom.api.gateway_relay_admission import (
    enforce_a2a_mutual_auth,
    enforce_agent_budget,
    enforce_anomaly,
    enforce_cost_center_budget,
    enforce_firewall,
    enforce_fleet_containment,
    enforce_owner_budget,
    enforce_rate_limit,
)
from agent_bom.api.gateway_relay_context import (
    RelayContext,
    RelayRuntime,
    _public_gateway_block_reason,
    _public_gateway_error,
)
from agent_bom.api.gateway_relay_identity import (
    deny_if_identity_invalid,
    deny_if_policy_unavailable,
    parse_relay_request,
    resolve_caller_identity,
)
from agent_bom.api.gateway_relay_profile import apply_runtime_profile
from agent_bom.api.gateway_relay_tool_policy import evaluate_tool_call

RelayStage = Callable[[RelayRuntime, RelayContext], Awaitable[JSONResponse | None]]

RELAY_STAGES: tuple[RelayStage, ...] = (
    deny_if_policy_unavailable,
    resolve_caller_identity,
    deny_if_identity_invalid,
    apply_runtime_profile,
    enforce_a2a_mutual_auth,
    enforce_firewall,
    enforce_rate_limit,
    enforce_agent_budget,
    enforce_cost_center_budget,
    enforce_owner_budget,
    enforce_anomaly,
    enforce_fleet_containment,
    evaluate_tool_call,
)


def forward_context(runtime: RelayRuntime, ctx: RelayContext) -> GatewayForwardContext:
    """Project the authorized request onto the forwarding stage's inputs."""
    settings = runtime.settings
    return GatewayForwardContext(
        upstream=ctx.upstream,
        message=ctx.message,
        tenant_id=ctx.tenant_id,
        source_agent=ctx.source_agent,
        resolved_policy_source=ctx.resolved_policy_source,
        rate_limit_headers=ctx.rate_limit_headers,
        trace_meta=ctx.trace_meta,
        audit_sink=settings.audit_sink,
        upstream_caller=runtime.upstream_caller,
        runtime_event=ctx.runtime_event,
        audit_unavailable=runtime.audit_unavailable,
        public_error=_public_gateway_error,
        block_reason=_public_gateway_block_reason,
        visual_enabled=settings.enable_visual_leak_detection,
        visual_detector=runtime.visual_detector,
        dlp_config=runtime.dlp_config,
        response_scanner=runtime.response_scanner,
        tracer=runtime.tracer,
    )


async def run_relay(runtime: RelayRuntime, server_name: str, request: Request) -> JSONResponse:
    """Admit, evaluate and forward one MCP JSON-RPC request."""
    ctx = await parse_relay_request(runtime, server_name, request)
    for stage in RELAY_STAGES:
        response = await stage(runtime, ctx)
        if response is not None:
            return response
    return await forward_authorized_request(forward_context(runtime, ctx))
