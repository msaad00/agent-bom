"""Typed state passed between the gateway relay stages.

``RelayRuntime`` holds what ``create_gateway_app`` resolves once per app;
``RelayContext`` carries one request's evolving decision state from stage to
stage. Stages read and write only these objects, never closure-captured state.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from fastapi import Request
from fastapi.responses import JSONResponse

from agent_bom.api.gateway_forward import AuditUnavailableResponse
from agent_bom.gateway_upstreams import UpstreamConfig
from agent_bom.proxy_policy import DecisionContext, GatewayDecision
from agent_bom.proxy_scanner import ScanConfig, ScanResult, redact_pii
from agent_bom.runtime.correlation_facts import RuntimeFactsPoller
from agent_bom.runtime.gateway_contracts import UpstreamCaller
from agent_bom.runtime.gateway_events import GatewayRuntimeEventType, build_gateway_runtime_event
from agent_bom.runtime.gateway_policy_reload import GatewayPolicyReloader
from agent_bom.runtime.gateway_settings import GatewaySettings
from agent_bom.runtime.graph_reachability import ReachabilityMap
from agent_bom.security import sanitize_error

logger = logging.getLogger("agent_bom.gateway_server")

_BLOCK_REASONS = {
    "conditional_access": "Conditional access blocked this request",
    "control_plane": "Control-plane gateway policy blocked this request",
    "drift_enforcement": "Drift enforcement blocked this request",
    "anomaly_enforcement": "Anomaly enforcement blocked this request",
    "fleet_quarantine": "Agent is quarantined in the fleet roster",
    "identity_scope": "Identity scope blocked this tool",
    "identity_jit": "Gateway policy blocked this request",
    "a2a_mutual_auth": "Inter-agent mutual authentication is required for this edge",
    "oauth_scope": "The caller's OAuth token is missing a required scope for this tool",
    "dlp": "Data-loss-prevention policy blocked sensitive content in this request",
    "firewall": "Inter-agent firewall blocked this request",
    "graph_reachability": "Graph reachability policy blocked this request",
    "graph_reachability_evidence": "Graph reachability evidence unavailable and strict mode is active",
    "policy_plugin": "A gateway policy plugin blocked this request",
    "fail_closed": "Gateway policy unavailable and fail-closed mode is active",
    "runtime_profile": "Runtime client profile validation blocked this request",
}


def _public_gateway_error(exc: Exception | str) -> str:
    """Return a non-diagnostic gateway error safe for clients and audit sinks."""
    return sanitize_error(exc, generic=True)


def _public_gateway_block_reason(policy_source: str) -> str:
    """Return a client-safe gateway block reason.

    Policy evaluator reasons can include user-controlled paths, regexes, or
    exception-derived text. Keep those details in audit records only.
    """
    return _BLOCK_REASONS.get(policy_source, "Gateway policy blocked this request")


def _redact_obj_pii(value: Any, *, depth: int = 0) -> Any:
    """Recursively redact PII in string leaves of a JSON-RPC result.

    Bounded depth so a deeply-nested or adversarial result cannot cause runaway
    recursion. Non-string scalars pass through unchanged.
    """
    if depth > 12:
        return value
    if isinstance(value, str):
        return redact_pii(value)
    if isinstance(value, dict):
        return {k: _redact_obj_pii(v, depth=depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_obj_pii(v, depth=depth + 1) for v in value]
    return value


def _message_tool_label(message: dict[str, Any]) -> str:
    """Best-effort tool label for audit/event records.

    ``params`` and ``params.name`` are caller-controlled and need not be the
    declared types. An ill-typed call must still be labelled and recorded, not
    dropped as an unhandled AttributeError with no audit trail.
    """
    params = message.get("params")
    name = params.get("name") if isinstance(params, dict) else None
    if isinstance(name, str) and name:
        return name
    method = message.get("method")
    return method if isinstance(method, str) else ""


def _emit_gateway_governance_event(event_type: str, *, tenant_id: str, subject_id: str, payload: dict[str, Any]) -> None:
    """Fan a gateway governance event to subscribed webhooks (best-effort).

    Uses the shared subscription store + durable outbox; in DB-backed
    deployments the gateway and API processes share both, so API-registered
    subscriptions receive gateway events.
    """
    try:
        from agent_bom.api.webhook_store import emit_governance_event

        emit_governance_event(event_type=event_type, tenant_id=tenant_id, source="gateway", subject_id=subject_id, payload=payload)
    except Exception:  # noqa: BLE001
        logger.debug("gateway governance webhook emit failed for %s", event_type, exc_info=False)


class PolicyInteropEmitter(Protocol):
    def __call__(
        self,
        settings: GatewaySettings,
        *,
        decision: GatewayDecision,
        reason: str,
        ctx: DecisionContext,
        policy_source: str,
    ) -> Awaitable[None]: ...


@dataclass(frozen=True)
class RelayRuntime:
    """App-scoped collaborators resolved once by ``create_gateway_app``."""

    settings: GatewaySettings
    policy_reload: GatewayPolicyReloader[dict[str, Any]]
    firewall_reload: GatewayPolicyReloader[Any]
    fail_closed: bool
    runtime_profile_mode: str
    rate_limit_store: Any
    reachability_map: ReachabilityMap
    runtime_facts_poller: RuntimeFactsPoller | None
    runtime_facts_configured: bool
    runtime_facts_config_error: str
    dlp_config: ScanConfig
    upstream_caller: UpstreamCaller
    audit_unavailable: AuditUnavailableResponse
    bind_audit_tenant: Callable[[Request, str, str], Awaitable[None]]
    emit_policy_interop: PolicyInteropEmitter
    visual_detector: Callable[[], Any]
    response_scanner: Callable[[dict[str, Any], ScanConfig], tuple[dict[str, Any], list[ScanResult]]]
    tracer: Any

    async def audit(self, event: dict[str, Any]) -> None:
        if self.settings.audit_sink is not None:
            await self.settings.audit_sink(event)


@dataclass
class RelayContext:
    """One relayed request's decision state, threaded through every stage."""

    request: Request
    trace_meta: dict[str, Any]
    tenant_id: str
    upstream: UpstreamConfig
    message: dict[str, Any]
    current_policy: dict[str, Any]
    policy_load_failed: bool
    event_tool: str
    source_agent: str = ""
    identity_token: str | None = None
    token_scopes: set[str] = field(default_factory=set)
    scoped_identity: Any = None
    managed_identity_lookup_unavailable: bool = False
    identity_failure_code: str = ""
    token_present: bool = False
    identity_invalid_reason: str | None = None
    identity_verified: bool = False
    profile_id: str = ""
    profile_revision: int = 0
    blueprint_id: str = ""
    blueprint_revision: int = 0
    profile_policy_ids: tuple[str, ...] = ()
    profile_identity_id: str = ""
    rate_limit_headers: dict[str, str] = field(default_factory=dict)
    resolved_policy_source: str = "gateway"

    @property
    def message_id(self) -> Any:
        return self.message.get("id")

    def runtime_event(
        self,
        event_type: GatewayRuntimeEventType,
        *,
        decision: str,
        policy_source: str,
        tool: str | None = None,
        reason_code: str = "",
        data_action: str = "",
        policy_id: str = "",
        evidence_id: str = "",
    ) -> dict[str, Any]:
        """Typed runtime event fields, read from the context at call time."""
        return build_gateway_runtime_event(
            event_type,
            tenant_id=self.tenant_id,
            agent_id=self.source_agent,
            identity_id=self.profile_identity_id,
            profile_id=self.profile_id,
            upstream=self.upstream.name,
            tool=self.event_tool if tool is None else tool,
            decision=decision,
            policy_source=policy_source,
            trace_id=str(self.trace_meta["trace_id"]),
            profile_revision=self.profile_revision,
            blueprint_id=self.blueprint_id,
            blueprint_revision=self.blueprint_revision,
            policy_ids=self.profile_policy_ids,
            reason_code=reason_code,
            data_action=data_action,
            policy_id=policy_id,
            evidence_id=evidence_id,
        )

    def jsonrpc_error(self, code: int, message: str, data: dict[str, Any]) -> JSONResponse:
        """A JSON-RPC error answered with HTTP 200, carrying any rate-limit headers."""
        return JSONResponse(
            {"jsonrpc": "2.0", "id": self.message_id, "error": {"code": code, "message": message, "data": data}},
            status_code=200,
            headers=self.rate_limit_headers or None,
        )


@dataclass
class ToolDecision:
    """The accumulating verdict for one ``tools/call``-shaped request."""

    tool_name: str
    arguments: dict[str, Any]
    allowed: bool
    reason: str
    policy_source: str = "file"
    quarantine: bool = False
    quarantine_reason: str = ""

    def deny(self, reason: str, policy_source: str) -> None:
        self.allowed, self.reason, self.policy_source = False, reason, policy_source


__all__ = [
    "PolicyInteropEmitter",
    "RelayContext",
    "RelayRuntime",
    "ToolDecision",
    "_emit_gateway_governance_event",
    "_message_tool_label",
    "_public_gateway_block_reason",
    "_public_gateway_error",
    "_redact_obj_pii",
]
