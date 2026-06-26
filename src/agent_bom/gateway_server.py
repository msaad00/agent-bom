"""Multi-MCP gateway server (`agent-bom gateway serve`).

One FastAPI service that fronts N upstream MCP servers, applies policy
inline on every JSON-RPC request, and logs every call into the audit
trail. Laptops point at one URL (``/mcp/{server-name}``) instead of
configuring a proxy per MCP.

Design doc: docs/design/MULTI_MCP_GATEWAY.md.

MVP scope:
  * Request/response relay over HTTP (POST). Streamable-HTTP transport
    with bidirectional streaming is a v2 addition — the MVP handles
    the dominant request/response case where the client expects one
    response per request.
  * Policy evaluation via ``agent_bom.proxy.check_policy`` (reused —
    no new policy engine).
  * Audit events emitted via a caller-supplied sink; in-cluster deploys
    point it at ``/v1/proxy/audit``.
  * Pooled upstream HTTP relay with per-upstream circuit breakers.
  * Per-upstream static header / bearer / OAuth2 auth injection from
    ``UpstreamRegistry``.

Non-goals for MVP (see design doc):
  * stdio upstreams (per-MCP ``agent-bom proxy`` wrapper still handles these)
  * SSE long-poll / Streamable HTTP streaming
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import threading
import time
import uuid
from contextlib import asynccontextmanager, nullcontext
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from agent_bom.agent_identity import ANONYMOUS, check_caller_identity, extract_identity_token
from agent_bom.api.auth import Role, get_key_store
from agent_bom.api.metrics import record_gateway_relay, record_rate_limit_hit
from agent_bom.api.middleware import InMemoryRateLimitStore, PostgresRateLimitStore
from agent_bom.api.tracing import get_tracer, inject_trace_headers, make_request_trace
from agent_bom.firewall import (
    AgentFirewallPolicy,
    FirewallDecision,
    FirewallPolicyError,
    load_firewall_policy_file,
)
from agent_bom.firewall import evaluate as evaluate_firewall_policy
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry
from agent_bom.langfuse_otel import set_langfuse_runtime_attributes
from agent_bom.proxy import check_policy, is_tools_call, parse_jsonrpc, policy_subject_from_message
from agent_bom.proxy_policy import (
    DecisionContext,
    GatewayDecision,
    build_policy_ocsf_event,
    check_policy_warning,
    context_from_now,
    deliver_policy_webhook,
    evaluate_conditional_rules,
    evaluate_policy_plugins,
    resolve_fail_mode,
    summarize_policy_bundle,
)
from agent_bom.runtime.graph_reachability import ReachabilityMap, load_reachability_map

logger = logging.getLogger(__name__)
_GATEWAY_TRACER = get_tracer("agent_bom.gateway")
_MAX_GATEWAY_MESSAGE_BYTES = 2 * 1024 * 1024
_GATEWAY_RELAY_SCOPE = "gateway:relay"

AuditSink = Callable[[dict[str, Any]], Awaitable[None]]
UpstreamCaller = Callable[[UpstreamConfig, dict[str, Any], dict[str, str]], Awaitable[dict[str, Any]]]

# Lazy singleton so disabled deploys don't pay the import cost of the
# visual detector (Pillow/pytesseract). Built on first use when
# ``enable_visual_leak_detection`` is True.
_visual_detector_singleton: Any = None
_visual_detector_lock = threading.Lock()


def _sanitize_for_log(value: Any) -> str:
    """Return a single-line representation safe for plain-text logs."""
    return str(value).replace("\r", "").replace("\n", "")


def _public_gateway_block_reason(policy_source: str) -> str:
    """Return a client-safe gateway block reason.

    Policy evaluator reasons can include user-controlled paths, regexes, or
    exception-derived text. Keep those details in audit records only.
    """
    return {
        "conditional_access": "Conditional access blocked this request",
        "control_plane": "Control-plane gateway policy blocked this request",
        "drift_enforcement": "Drift enforcement blocked this request",
        "anomaly_enforcement": "Anomaly enforcement blocked this request",
        "fleet_quarantine": "Agent is quarantined in the fleet roster",
        "identity_scope": "Identity scope blocked this tool",
        "identity_jit": "Gateway policy blocked this request",
        "firewall": "Inter-agent firewall blocked this request",
        "graph_reachability": "Graph reachability policy blocked this request",
        "policy_plugin": "A gateway policy plugin blocked this request",
        "fail_closed": "Gateway policy unavailable and fail-closed mode is active",
    }.get(policy_source, "Gateway policy blocked this request")


def _get_visual_leak_detector() -> Any:
    global _visual_detector_singleton
    if _visual_detector_singleton is None:
        with _visual_detector_lock:
            if _visual_detector_singleton is None:
                from agent_bom.runtime.visual_leak_detector import VisualLeakDetector

                _visual_detector_singleton = VisualLeakDetector()
    return _visual_detector_singleton


@dataclass
class GatewaySettings:
    """Runtime configuration the caller wires in."""

    registry: UpstreamRegistry
    policy: dict[str, Any]  # dict passed to check_policy — same shape proxy uses
    audit_sink: AuditSink | None = None
    upstream_caller: UpstreamCaller | None = None  # injectable for tests
    bearer_token: str | None = None
    # Visual-leak detection on image tool responses (closes the screenshot
    # channel that CredentialLeakDetector can't see — #1568). Opt-in
    # because OCR is CPU-heavy; see docs/ENTERPRISE_SECURITY_PLAYBOOK.md §2.2.
    # Set to True AND install `agent-bom[visual]` to enable.
    enable_visual_leak_detection: bool = False
    require_visual_leak_detection_ready: bool = False
    runtime_rate_limit_per_tenant_per_minute: int = 0
    require_shared_rate_limit: bool = False
    policy_path: Path | None = None
    policy_reload_interval_seconds: int = 0
    # Inter-agent firewall policy (#982). Optional and independent from the
    # MCP method-gating policy above so operators can rotate firewall rules
    # without touching the MCP allow/deny patterns.
    firewall_policy_path: Path | None = None
    firewall_policy_reload_interval_seconds: int = 0
    # Graph-derived reachability enforcement (consume direction). The unified
    # graph statically detects which agents reach a credential / privileged-tool
    # node (the AGENT_REACHES_PRIVILEGED toxic-combination rule). Today that is
    # advisory-only. Point this at a scan-report JSON and an over-reaching agent's
    # FIRST call against one of its reachable privileged tools is blocked
    # ("enforce") or flagged ("warn") in-path — pre-emptively, before any runtime
    # correlation. Default "off" + no facts path = zero behaviour change. Loading
    # is read-only/no-network and fail-safe: a missing/malformed report is a no-op
    # and never breaks a relay. The reverse runtime→graph feedback loop is a
    # documented follow-up and is NOT wired here.
    graph_reachability_path: Path | None = None
    graph_reachability_enforcement_mode: str = "off"
    upstream_failure_threshold: int = 3
    upstream_circuit_cooldown_seconds: float = 30.0
    upstream_http_timeout_seconds: float = 30.0
    upstream_http_max_connections: int = 100
    upstream_http_max_keepalive_connections: int = 20
    listener_host: str = "127.0.0.1"
    allow_insecure_no_auth: bool = False
    # Caller-identity fail-closed posture (mirrors ``allow_insecure_no_auth``
    # for incoming transport auth). An INVALID or REVOKED agent-identity token
    # ALWAYS fails closed regardless of this flag. A fully-MISSING identity is
    # only permitted when the listener is loopback OR this opt-out is set (via
    # this field or AGENT_BOM_GATEWAY_ALLOW_ANONYMOUS_AGENTS). On a non-loopback
    # bind without the opt-out, a missing identity fails closed by default.
    allow_anonymous_agents: bool = False
    # Control-plane GatewayPolicy bundle (raw dicts with bound_agents /
    # bound_agent_types / bound_environments). The flattened ``policy`` dict
    # above is agent-agnostic; this bundle lets the relay enforce per-agent
    # binding the way the per-MCP proxy does, scoped to the resolved
    # source_agent. Empty list = no control-plane binding (file policy only).
    control_plane_policies: list[dict[str, Any]] = field(default_factory=list)
    # Drift-triggered enforcement (#detection→enforcement). When an agent has an
    # open behavioral-drift incident, the tools that incident named as out-of-
    # blueprint violations can be blocked ("enforce") or flagged ("warn") at the
    # gateway. Default "off" keeps drift purely advisory (visibility only), so
    # enabling enforcement is an explicit operator decision. Fail-open: a drift
    # store error never blocks the relay.
    drift_enforcement_mode: str = "off"
    # Anomaly-triggered enforcement. An agent whose spend is a statistical
    # outlier vs the tenant fleet (cost-spike anomaly) can be blocked ("enforce")
    # or flagged ("warn") at the gateway — catching a runaway agent before it
    # exhausts an absolute budget. Default "off" keeps anomalies advisory.
    anomaly_enforcement_mode: str = "off"
    # Fleet-state enforcement. An agent the operator has moved to the
    # QUARANTINED lifecycle state in the fleet roster can be fully blocked
    # ("enforce") or flagged ("warn") at the gateway — isolating a compromised
    # or under-review agent without touching per-tool policy. Default "off".
    fleet_enforcement_mode: str = "off"
    # Fail-closed posture for the policy engine. "open" (default) preserves
    # today's behaviour: a missing/unloadable policy or an evaluation error
    # degrades to default-allow. "closed" makes those paths DENY so a
    # security-conscious operator never silently runs unprotected. Resolved from
    # AGENT_BOM_GATEWAY_FAIL_MODE when left at the sentinel ``None``.
    fail_mode: str | None = None
    # SIEM/SOAR webhook for deny/quarantine OCSF events. Unset (default) is a
    # no-op; when set, every DENY/QUARANTINE POSTs a normalized OCSF event with
    # an idempotency key. Webhook failures NEVER block the relay (bounded
    # retries + drop-with-warning). Resolved from AGENT_BOM_POLICY_WEBHOOK_URL /
    # AGENT_BOM_POLICY_WEBHOOK_TOKEN when left as ``None``.
    policy_webhook_url: str | None = None
    policy_webhook_token: str | None = None


def _agent_cost_anomaly(tenant_id: str, source_agent: str) -> tuple[bool, str]:
    """Return (anomalous, reason) if ``source_agent`` currently has a cost-spike
    anomaly vs the tenant fleet. Cached upstream; fail-open on any store error."""
    if not source_agent:
        return False, ""
    try:
        from agent_bom.api.anomaly import cost_anomalous_agents

        flagged = cost_anomalous_agents(tenant_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("gateway anomaly check failed: %s", _sanitize_for_log(exc))
        return False, ""
    info = flagged.get(source_agent)
    if info:
        return True, (f"agent '{source_agent}' has anomalous spend (z={info.get('z_score')}) vs the tenant fleet baseline")
    return False, ""


def _agent_is_quarantined(tenant_id: str, source_agent: str) -> bool:
    """Return True when ``source_agent`` is quarantined in this tenant's fleet.

    Fail-open: fleet-store errors are logged and never block the relay.
    """
    if not source_agent:
        return False
    try:
        from agent_bom.api.fleet_store import FleetLifecycleState
        from agent_bom.api.stores import _get_fleet_store

        agents = _get_fleet_store().list_by_tenant(tenant_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("gateway fleet check failed: %s", _sanitize_for_log(exc))
        return False
    key = source_agent.strip().lower()
    for agent in agents:
        identifiers = (
            (getattr(agent, "name", "") or "").strip().lower(),
            (getattr(agent, "agent_id", "") or "").strip().lower(),
            (getattr(agent, "canonical_id", "") or "").strip().lower(),
        )
        if key in identifiers:
            return getattr(agent, "lifecycle_state", None) == FleetLifecycleState.QUARANTINED
    return False


def _open_drift_violates_tool(tenant_id: str, source_agent: str, tool_name: str) -> tuple[bool, str]:
    """Return (violates, reason) if an open drift incident for ``source_agent``
    names ``tool_name`` as an out-of-blueprint violation. Fail-open — any drift
    store error returns ``(False, "")`` and never blocks the relay.
    """
    if not source_agent or not tool_name:
        return False, ""
    try:
        from agent_bom.api.drift_incident_store import get_drift_incident_store

        incidents = get_drift_incident_store().list(tenant_id, include_resolved=False, limit=200)
    except Exception as exc:  # noqa: BLE001
        logger.warning("gateway drift check failed: %s", _sanitize_for_log(exc))
        return False, ""
    agent_key = source_agent.strip().lower()
    for incident in incidents:
        if (getattr(incident, "blueprint_id", "") or "").strip().lower() != agent_key:
            continue
        drifted_tools = {
            str(v.get("tool_name", "")).strip() for v in (getattr(incident, "top_violations", None) or []) if isinstance(v, dict)
        }
        if tool_name in drifted_tools:
            return True, (f"agent '{source_agent}' has an open drift incident; tool '{tool_name}' is outside its declared blueprint")
    return False, ""


def _evaluate_control_plane_bundle(
    policy_dicts: list[dict[str, Any]], source_agent: str, tool_name: str, arguments: dict
) -> tuple[bool, str]:
    """Enforce control-plane GatewayPolicy binding for one relayed call.

    Mirrors the per-MCP proxy: policies are scoped to the resolved source_agent
    via bound_agents before evaluation, so a policy bound to other agents never
    applies here. Returns ``(allowed, reason)``; an empty bundle allows.
    """
    if not policy_dicts:
        return True, ""
    try:
        from agent_bom.api.policy_store import GatewayPolicy
        from agent_bom.proxy import _evaluate_gateway_policy_bundle

        policies = []
        parse_errors = 0
        for item in policy_dicts:
            try:
                policies.append(GatewayPolicy(**item))
            except (TypeError, ValueError):
                parse_errors += 1
                continue
        if not policies:
            # The bundle was configured but nothing parsed — an operator typo must
            # not silently disable all control-plane enforcement. Fail closed.
            if parse_errors:
                logger.error(
                    "gateway control-plane bundle: all %d policy/policies failed to parse; failing closed",
                    parse_errors,
                )
                return False, "control-plane policy malformed"
            return True, ""
        if parse_errors:
            logger.warning("gateway control-plane bundle: %d policy/policies failed to parse and were skipped", parse_errors)
        return _evaluate_gateway_policy_bundle(policies, source_agent, tool_name, arguments)
    except Exception as exc:  # noqa: BLE001
        # Fail closed: a bundle that cannot be evaluated must not silently pass.
        logger.warning("gateway control-plane bundle evaluation failed: %s", _sanitize_for_log(exc))
        return False, "control-plane policy evaluation error"


def _request_source_ip(request: Request) -> str:
    """Resolve the caller IP for conditional-access CIDR conditions.

    Prefers the first hop of ``X-Forwarded-For`` (the original client behind a
    trusted reverse proxy), falling back to the direct socket peer.
    """
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    client = getattr(request, "client", None)
    return getattr(client, "host", "") or ""


def _request_environment(request: Request) -> str:
    """Resolve the caller-declared environment for conditional-access conditions."""
    return (request.headers.get("x-agent-environment", "") or "").strip()[:60]


def _request_risk_score(request: Request) -> float | None:
    """Resolve a caller/proxy-asserted risk score for conditional-access gates.

    Read from the ``x-agent-risk-score`` header (set by an upstream risk engine
    or trust proxy). Absent/invalid → ``None`` so a min/max-risk condition that
    requires a score simply does not match and the call is unaffected.
    """
    raw = (request.headers.get("x-agent-risk-score", "") or "").strip()
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


def _request_context_attributes(request: Request) -> dict[str, str]:
    """Resolve required-context attributes for conditional-access gates.

    Attributes arrive as ``x-agent-ctx-<name>`` headers (e.g.
    ``x-agent-ctx-mfa: true``) so a policy can require ``{"mfa": "true"}``.
    Bounded to keep the decision context small and deterministic.
    """
    attributes: dict[str, str] = {}
    for header, value in request.headers.items():
        lowered = header.lower()
        if lowered.startswith("x-agent-ctx-"):
            key = lowered[len("x-agent-ctx-") :]
            if key:
                attributes[key] = str(value).strip()[:200]
        if len(attributes) >= 32:
            break
    return attributes


def _request_cost_center(request: Request, message: dict[str, Any]) -> str:
    """Resolve the chargeback cost-center this call is allocated to.

    Mirrors how cost-center flows elsewhere (OTLP span attrs / allocation tags):
    the caller declares it via the ``x-cost-center`` header or the JSON-RPC
    ``_meta.cost_center`` field. Empty when unset, in which case cost-center
    budget enforcement is a no-op and existing per-agent/tenant semantics are
    untouched.
    """
    header_cc = (request.headers.get("x-cost-center", "") or "").strip()
    if header_cc:
        return header_cc[:120]
    # The caller declares allocation in the MCP ``_meta`` block (the same place
    # ``agent_identity`` lives, under ``params``); also accept a top-level
    # ``_meta`` for callers that flatten it.
    params = message.get("params")
    metas = []
    if isinstance(params, dict) and isinstance(params.get("_meta"), dict):
        metas.append(params["_meta"])
    if isinstance(message.get("_meta"), dict):
        metas.append(message["_meta"])
    for meta in metas:
        meta_cc = meta.get("cost_center")
        if isinstance(meta_cc, str) and meta_cc.strip():
            return meta_cc.strip()[:120]
    return ""


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
        logger.debug("gateway governance webhook emit failed for %s", event_type, exc_info=True)


async def _emit_policy_interop_event(
    settings: GatewaySettings,
    *,
    decision: GatewayDecision,
    reason: str,
    ctx: DecisionContext,
    policy_source: str,
) -> None:
    """Emit a normalized OCSF event for a DENY/QUARANTINE and POST it to the
    configured SIEM/SOAR webhook (best-effort).

    Determinism: the event id derives from the decision inputs (it doubles as
    the webhook idempotency key), so a retried delivery never double-records
    downstream. Webhook failures are bounded-retry + drop-with-warning inside
    ``deliver_policy_webhook`` and run off the event loop, so they never block
    or crash the relay.
    """
    if decision == GatewayDecision.ALLOW:
        return
    # Only build/emit when a webhook target is configured. The OCSF event is an
    # interop artifact for SIEM/SOAR; it deliberately does NOT fan into the
    # audit_sink so the existing audit-event stream (and its counts) are
    # unchanged when no webhook is set — the default no-op posture.
    webhook_url = settings.policy_webhook_url
    if webhook_url is None:
        webhook_url = os.environ.get("AGENT_BOM_POLICY_WEBHOOK_URL", "")
    if not (webhook_url or "").strip():
        return
    try:
        event = build_policy_ocsf_event(decision=decision, reason=reason, ctx=ctx, policy_source=policy_source)
    except Exception as exc:  # noqa: BLE001
        logger.warning("gateway OCSF event build failed: %s", _sanitize_for_log(exc))
        return
    try:
        await asyncio.to_thread(
            deliver_policy_webhook,
            event,
            url=settings.policy_webhook_url,
            token=settings.policy_webhook_token,
        )
    except Exception as exc:  # noqa: BLE001 — webhook must never break the relay
        logger.warning("gateway policy webhook dispatch error (event dropped, relay unaffected): %s", _sanitize_for_log(exc))


class GatewayCircuitOpenError(RuntimeError):
    """Raised when an upstream circuit is open and calls should fail fast."""

    def __init__(self, upstream_name: str, retry_after_seconds: float) -> None:
        self.upstream_name = upstream_name
        self.retry_after_seconds = max(1.0, retry_after_seconds)
        super().__init__(f"upstream {upstream_name!r} circuit open; retry after {int(self.retry_after_seconds)}s")


@dataclass
class _CircuitState:
    failures: int = 0
    opened_until: float = 0.0


class GatewayCircuitBreaker:
    """Small per-upstream circuit breaker for gateway relay calls."""

    def __init__(self, *, failure_threshold: int, cooldown_seconds: float) -> None:
        self.failure_threshold = max(1, failure_threshold)
        self.cooldown_seconds = max(1.0, cooldown_seconds)
        self._states: dict[str, _CircuitState] = {}
        self._lock = asyncio.Lock()

    async def before_call(self, key: str, upstream_name: str) -> None:
        now = time.monotonic()
        async with self._lock:
            state = self._states.get(key)
            if state is None or state.opened_until <= 0:
                return
            if state.opened_until > now:
                raise GatewayCircuitOpenError(upstream_name, state.opened_until - now)
            # Half-open: allow one trial request and reset on success/failure path.
            state.opened_until = 0.0

    async def record_success(self, key: str) -> None:
        async with self._lock:
            self._states.pop(key, None)

    async def record_failure(self, key: str) -> None:
        now = time.monotonic()
        async with self._lock:
            state = self._states.setdefault(key, _CircuitState())
            state.failures += 1
            if state.failures >= self.failure_threshold:
                state.opened_until = now + self.cooldown_seconds


class GatewayUpstreamRelay:
    """Lifecycle-managed upstream relay with connection pooling and breakers."""

    def __init__(self, settings: GatewaySettings) -> None:
        self._timeout_seconds = max(1.0, settings.upstream_http_timeout_seconds)
        self._max_connections = max(1, settings.upstream_http_max_connections)
        self._max_keepalive_connections = max(1, settings.upstream_http_max_keepalive_connections)
        self._client: Any | None = None
        self._client_lock = asyncio.Lock()
        self._breaker = GatewayCircuitBreaker(
            failure_threshold=settings.upstream_failure_threshold,
            cooldown_seconds=settings.upstream_circuit_cooldown_seconds,
        )

    async def aclose(self) -> None:
        async with self._client_lock:
            if self._client is not None:
                await self._client.aclose()
                self._client = None

    async def _client_for_call(self) -> Any:
        if self._client is not None:
            return self._client
        async with self._client_lock:
            if self._client is None:
                import httpx

                self._client = httpx.AsyncClient(
                    timeout=httpx.Timeout(self._timeout_seconds),
                    limits=httpx.Limits(
                        max_connections=self._max_connections,
                        max_keepalive_connections=self._max_keepalive_connections,
                    ),
                )
            return self._client

    async def __call__(
        self,
        upstream: UpstreamConfig,
        message: dict[str, Any],
        extra_headers: dict[str, str],
    ) -> dict[str, Any]:
        circuit_key = _upstream_circuit_key(upstream)
        await self._breaker.before_call(circuit_key, upstream.name)
        try:
            response = await _post_upstream_jsonrpc(upstream, message, extra_headers, client=await self._client_for_call())
        except Exception:
            await self._breaker.record_failure(circuit_key)
            raise
        await self._breaker.record_success(circuit_key)
        return response


def _load_policy_file(policy_path: Path) -> dict[str, Any]:
    payload = json.loads(policy_path.read_text())
    if not isinstance(payload, dict):
        raise ValueError("gateway policy file must contain a JSON object")
    return payload


def _gateway_configured_replicas() -> int:
    raw = os.environ.get("AGENT_BOM_GATEWAY_REPLICAS", "").strip()
    if not raw:
        return 1
    try:
        return max(1, int(raw))
    except ValueError:
        logger.warning("Invalid AGENT_BOM_GATEWAY_REPLICAS=%r; defaulting to 1", _sanitize_for_log(raw))
        return 1


def _gateway_shared_rate_limit_required(settings: GatewaySettings) -> bool:
    if settings.require_shared_rate_limit:
        return True
    return _gateway_configured_replicas() > 1


def _build_gateway_rate_limit_store(settings: GatewaySettings):
    if settings.runtime_rate_limit_per_tenant_per_minute <= 0:
        return None
    if os.environ.get("AGENT_BOM_POSTGRES_URL"):
        try:
            return PostgresRateLimitStore(window_seconds=60)
        except Exception as exc:
            raise RuntimeError(
                "Configured Postgres gateway rate limiter could not initialize; refusing to fall back to process-local state"
            ) from exc
    if _gateway_shared_rate_limit_required(settings):
        raise RuntimeError(
            "Shared gateway rate limiting is required for multi-replica or fail-closed deployments. "
            "Configure AGENT_BOM_POSTGRES_URL before starting the gateway."
        )
    return InMemoryRateLimitStore(window_seconds=60)


def _gateway_rate_limit_runtime_status(settings: GatewaySettings) -> dict[str, object]:
    postgres_configured = bool(os.environ.get("AGENT_BOM_POSTGRES_URL", "").strip())
    replicas = _gateway_configured_replicas()
    enabled = settings.runtime_rate_limit_per_tenant_per_minute > 0
    shared_required = _gateway_shared_rate_limit_required(settings) if enabled else False
    backend = "disabled" if not enabled else ("postgres_shared" if postgres_configured else "inmemory_single_process")
    return {
        "enabled": enabled,
        "limit_per_tenant_per_minute": settings.runtime_rate_limit_per_tenant_per_minute,
        "backend": backend,
        "postgres_configured": postgres_configured,
        "configured_gateway_replicas": replicas,
        "shared_required": shared_required,
        "shared_across_replicas": enabled and postgres_configured,
        "fail_closed": (enabled and postgres_configured) or (enabled and shared_required),
        "message": (
            "Gateway runtime rate limiting disabled."
            if not enabled
            else (
                "Gateway runtime rate limiting uses Postgres-backed per-source-agent state across replicas."
                if postgres_configured
                else (
                    "Gateway runtime rate limiting is per-source-agent and process-local because the gateway "
                    "is configured for a single replica. Multi-replica deployments must configure AGENT_BOM_POSTGRES_URL."
                )
            )
        ),
    }


def _rate_limit_bucket_component(value: str) -> str:
    component = _sanitize_for_log(value).strip() or ANONYMOUS
    return component.replace(":", "_")[:160]


def _request_has_expected_token(request: Request, expected_token: str) -> bool:
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer ") :].strip() == expected_token
    return request.headers.get("x-api-key", "").strip() == expected_token


def _extract_request_token(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer ") :].strip()
    return request.headers.get("x-api-key", "").strip()


def _gateway_requires_auth(settings: GatewaySettings) -> bool:
    if settings.bearer_token:
        return True
    try:
        return get_key_store().has_keys()
    except Exception as exc:
        logger.warning("Gateway key store status unavailable: %s", _sanitize_for_log(exc))
        return True


def _is_loopback_host(host: str) -> bool:
    normalized = (host or "").strip().strip("[]").lower()
    if normalized in {"localhost", "127.0.0.1", "::1"}:
        return True
    if not normalized:
        return False
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _env_flag_enabled(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _enforce_gateway_auth_posture(settings: GatewaySettings) -> None:
    if _gateway_requires_auth(settings):
        return
    if _is_loopback_host(settings.listener_host):
        return
    if settings.allow_insecure_no_auth or _env_flag_enabled("AGENT_BOM_GATEWAY_ALLOW_INSECURE_NO_AUTH"):
        logger.warning(
            "Gateway starting without incoming authentication on non-loopback listener %s due to explicit insecure override",
            _sanitize_for_log(settings.listener_host),
        )
        return
    raise RuntimeError(
        "Refusing to start gateway on a non-loopback listener without incoming authentication. "
        "Configure AGENT_BOM_GATEWAY_BEARER_TOKEN or API keys, bind to loopback, "
        "or set AGENT_BOM_GATEWAY_ALLOW_INSECURE_NO_AUTH=1 for an explicit insecure override."
    )


def _gateway_allows_anonymous_agents(settings: GatewaySettings) -> bool:
    """Return True when a fully-MISSING agent identity may proceed.

    Permissive on a loopback listener (local development), and on a non-loopback
    listener only when the operator sets the explicit opt-out — mirroring the
    ``allow_insecure_no_auth`` precedent for incoming transport auth. An invalid
    or revoked token is NEVER governed by this function; it always fails closed.
    """
    if _is_loopback_host(settings.listener_host):
        return True
    return settings.allow_anonymous_agents or _env_flag_enabled("AGENT_BOM_GATEWAY_ALLOW_ANONYMOUS_AGENTS")


def _enforce_gateway_anonymous_agents_posture(settings: GatewaySettings) -> None:
    """Emit a loud startup warning when anonymous callers are permitted on a
    non-loopback listener via the explicit opt-out, paralleling the transport
    auth posture warning."""
    if _is_loopback_host(settings.listener_host):
        return
    if settings.allow_anonymous_agents or _env_flag_enabled("AGENT_BOM_GATEWAY_ALLOW_ANONYMOUS_AGENTS"):
        logger.warning(
            "SECURITY: gateway relay accepting anonymous (unidentified) agent callers on non-loopback "
            "listener %s due to explicit opt-out (AGENT_BOM_GATEWAY_ALLOW_ANONYMOUS_AGENTS / "
            "--allow-anonymous-agents). Invalid/revoked tokens are still denied. Use only when an "
            "upstream trust boundary already authenticates callers.",
            _sanitize_for_log(settings.listener_host),
        )


def _role_allows_gateway_relay(role: object) -> bool:
    try:
        normalized = role if isinstance(role, Role) else Role(str(role).lower())
    except ValueError:
        return False
    return normalized in {Role.ADMIN, Role.ANALYST}


def _api_key_allows_gateway_relay(api_key: Any) -> tuple[bool, str]:
    if not _role_allows_gateway_relay(getattr(api_key, "role", None)):
        role_value = getattr(getattr(api_key, "role", None), "value", getattr(api_key, "role", "unknown"))
        return False, f"gateway relay requires analyst role or higher; key has {role_value}"
    has_scope = getattr(api_key, "has_scope", None)
    if callable(has_scope) and not has_scope(_GATEWAY_RELAY_SCOPE):
        return False, f"gateway relay requires {_GATEWAY_RELAY_SCOPE} scope"
    return True, ""


def _authenticate_gateway_request(request: Request, settings: GatewaySettings) -> tuple[str, str]:
    raw_token = _extract_request_token(request)
    if settings.bearer_token:
        if not raw_token or not _request_has_expected_token(request, settings.bearer_token):
            raise HTTPException(status_code=401, detail="gateway authentication required")
        return "default", "static_gateway_token"

    try:
        store = get_key_store()
        has_keys = store.has_keys()
    except Exception as exc:
        logger.warning("Gateway key store unavailable: %s", _sanitize_for_log(exc))
        raise HTTPException(status_code=503, detail="gateway authentication unavailable") from exc

    if has_keys:
        try:
            api_key = store.verify(raw_token) if raw_token else None
        except Exception as exc:
            logger.warning("Gateway key verification unavailable: %s", _sanitize_for_log(exc))
            raise HTTPException(status_code=503, detail="gateway authentication unavailable") from exc
        if api_key is None:
            raise HTTPException(status_code=401, detail="gateway authentication required")
        allowed, reason = _api_key_allows_gateway_relay(api_key)
        if not allowed:
            raise HTTPException(status_code=403, detail=reason)
        return api_key.tenant_id or "default", "api_key"

    return "default", "none"


def _inject_jsonrpc_trace_meta(
    message: dict[str, Any],
    *,
    traceparent: str | None,
    tracestate: str | None,
    baggage: str | None,
) -> dict[str, Any]:
    """Return a JSON-RPC message with bounded W3C trace context in `_meta`.

    MCP clients and servers increasingly use `_meta` as the least-surprising
    place to carry end-to-end trace context across JSON-RPC boundaries.
    """
    if not traceparent and not tracestate and not baggage:
        return message

    enriched = dict(message)
    raw_meta = message.get("_meta")
    meta = dict(raw_meta) if isinstance(raw_meta, dict) else {}
    if traceparent:
        meta["traceparent"] = traceparent
    if tracestate:
        meta["tracestate"] = tracestate
    if baggage:
        meta["baggage"] = baggage
    enriched["_meta"] = meta
    return enriched


async def _default_upstream_caller(
    upstream: UpstreamConfig,
    message: dict[str, Any],
    extra_headers: dict[str, str],
) -> dict[str, Any]:
    """Forward a JSON-RPC message to an upstream MCP server via HTTP POST.

    Resolves per-upstream auth (bearer + OAuth2 client-credentials) via
    ``upstream.resolve_auth_headers`` so OAuth tokens are fetched + cached
    correctly instead of failing at send time.
    """
    import httpx

    async with httpx.AsyncClient(timeout=30.0) as client:
        return await _post_upstream_jsonrpc(upstream, message, extra_headers, client=client)


def _upstream_circuit_key(upstream: UpstreamConfig) -> str:
    return f"{upstream.tenant_id or 'global'}:{upstream.name}:{upstream.url}"


async def _post_upstream_jsonrpc(
    upstream: UpstreamConfig,
    message: dict[str, Any],
    extra_headers: dict[str, str],
    *,
    client: Any,
) -> dict[str, Any]:
    auth_headers = await upstream.resolve_auth_headers()
    headers = {"Content-Type": "application/json", **auth_headers, **extra_headers}
    response = await client.post(upstream.url, json=message, headers=headers)
    response.raise_for_status()
    if len(response.content) > _MAX_GATEWAY_MESSAGE_BYTES:
        raise ValueError(f"upstream response exceeded {_MAX_GATEWAY_MESSAGE_BYTES} bytes")
    if response.headers.get("content-type", "").startswith("application/json"):
        return response.json()
    # Some upstreams return text/event-stream; MVP treats non-JSON as an opaque
    # body wrapped in a success envelope so policy + audit still fire.
    return {"jsonrpc": "2.0", "id": message.get("id"), "result": {"raw": response.text}}


def build_control_plane_audit_sink(
    base_url: str,
    token: str | None,
    *,
    source_id: str = "gateway",
    session_id: str | None = None,
) -> AuditSink:
    """Build an audit sink that forwards gateway runtime events to the API."""
    audit_url = base_url.rstrip("/") + "/v1/proxy/audit"
    active_session_id = session_id or str(uuid.uuid4())

    async def _sink(event: dict[str, Any]) -> None:
        import httpx

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        payload = {
            "source_id": source_id,
            "session_id": active_session_id,
            "idempotency_key": event.get("event_id") or str(uuid.uuid4()),
            "alerts": [event],
        }
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(connect=5.0, read=10.0, write=10.0, pool=5.0)) as client:
                response = await client.post(audit_url, json=payload, headers=headers)
                response.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Gateway audit push failed: %s", _sanitize_for_log(exc))

    return _sink


def create_gateway_app(settings: GatewaySettings) -> FastAPI:
    """Build the FastAPI app for `agent-bom gateway serve`.

    Separating app construction from CLI entry point keeps the server
    testable end-to-end via ``TestClient(create_gateway_app(settings))``.
    """
    if settings.enable_visual_leak_detection and settings.require_visual_leak_detection_ready:
        from agent_bom.runtime.visual_leak_detector import require_visual_leak_runtime

        require_visual_leak_runtime()
    _enforce_gateway_auth_posture(settings)
    _enforce_gateway_anonymous_agents_posture(settings)

    managed_upstream_relay = GatewayUpstreamRelay(settings) if settings.upstream_caller is None else None
    upstream_caller = settings.upstream_caller or managed_upstream_relay
    assert upstream_caller is not None
    rate_limit_store = _build_gateway_rate_limit_store(settings)
    # Fail-closed posture resolved once at build time. "closed" makes a
    # missing/unloadable policy or an evaluation error DENY instead of silently
    # degrading to default-allow. Default "open" preserves current behaviour.
    resolved_fail_mode = resolve_fail_mode(settings.fail_mode)
    fail_closed = resolved_fail_mode == "closed"
    if fail_closed:
        logger.info("gateway policy engine starting in fail-CLOSED mode: unloadable policy or evaluation errors will DENY")
    policy_state: dict[str, Any] = {
        "policy": dict(settings.policy),
        "source": str(settings.policy_path) if settings.policy_path else "inline",
        "last_loaded_at": None,
        "last_error": None,
        "last_mtime": None,
        # True only when a file policy was configured but never successfully
        # loaded. In fail-closed mode this makes the relay DENY rather than
        # forward against the empty default policy.
        "load_failed": settings.policy_path is not None,
    }
    policy_lock = asyncio.Lock()
    reload_task: asyncio.Task[None] | None = None

    async def _reload_policy_if_changed(force: bool = False) -> bool:
        if settings.policy_path is None:
            return False

        async with policy_lock:
            try:
                stat = settings.policy_path.stat()
                mtime = stat.st_mtime
                if not force and policy_state["last_mtime"] == mtime:
                    return False
                next_policy = _load_policy_file(settings.policy_path)
            except FileNotFoundError as exc:
                policy_state["last_error"] = str(exc)
                logger.warning("gateway policy reload failed for %s: %s", settings.policy_path, _sanitize_for_log(exc))
                return False
            except Exception as exc:  # noqa: BLE001
                policy_state["last_error"] = str(exc)
                logger.warning("gateway policy reload failed for %s: %s", settings.policy_path, _sanitize_for_log(exc))
                return False

            policy_state["policy"] = next_policy
            policy_state["last_loaded_at"] = time.time()
            policy_state["last_error"] = None
            policy_state["last_mtime"] = mtime
            policy_state["load_failed"] = False
        logger.info("gateway policy reloaded from %s", settings.policy_path)
        return True

    async def _policy_reload_loop() -> None:
        while True:
            await asyncio.sleep(max(settings.policy_reload_interval_seconds, 1))
            await _reload_policy_if_changed()

    # === Inter-agent firewall (#982 PR 2) ============================
    # Parallel state and reload loop so firewall policy can be rotated
    # independently from the MCP method-gating policy. Empty / missing file
    # falls back to a permissive default-allow policy so a missing config
    # never breaks the gateway.
    firewall_state: dict[str, Any] = {
        "policy": AgentFirewallPolicy(),
        "source": str(settings.firewall_policy_path) if settings.firewall_policy_path else "default-allow",
        "last_loaded_at": None,
        "last_error": None,
        "last_mtime": None,
    }
    firewall_lock = asyncio.Lock()
    firewall_reload_task: asyncio.Task[None] | None = None

    # Graph-derived reachability facts (consume direction). Loaded once at build
    # time from a static scan-report JSON; fail-safe (a missing/malformed report
    # yields an empty no-op map and is logged, never raised). Enforcement is only
    # active when a facts path is set AND graph_reachability_enforcement_mode is
    # warn/enforce — otherwise this is dead-weight default-allow.
    reachability_map: ReachabilityMap = load_reachability_map(settings.graph_reachability_path)
    if settings.graph_reachability_path is not None:
        logger.info(
            "gateway graph-reachability facts loaded from %s: %d agent(s), mode=%s",
            _sanitize_for_log(settings.graph_reachability_path),
            len(reachability_map.by_agent),
            _sanitize_for_log(settings.graph_reachability_enforcement_mode),
        )

    async def _reload_firewall_policy_if_changed(force: bool = False) -> bool:
        if settings.firewall_policy_path is None:
            return False

        async with firewall_lock:
            try:
                stat = settings.firewall_policy_path.stat()
                mtime = stat.st_mtime
                if not force and firewall_state["last_mtime"] == mtime:
                    return False
                next_policy = load_firewall_policy_file(settings.firewall_policy_path)
            except (FileNotFoundError, FirewallPolicyError) as exc:
                firewall_state["last_error"] = str(exc)
                logger.warning(
                    "gateway firewall policy reload failed for %s: %s",
                    settings.firewall_policy_path,
                    _sanitize_for_log(exc),
                )
                return False
            except Exception as exc:  # noqa: BLE001
                firewall_state["last_error"] = str(exc)
                logger.warning(
                    "gateway firewall policy reload failed for %s: %s",
                    settings.firewall_policy_path,
                    _sanitize_for_log(exc),
                )
                return False

            firewall_state["policy"] = next_policy
            firewall_state["last_loaded_at"] = time.time()
            firewall_state["last_error"] = None
            firewall_state["last_mtime"] = mtime
        logger.info("gateway firewall policy reloaded from %s", settings.firewall_policy_path)
        return True

    async def _firewall_reload_loop() -> None:
        while True:
            await asyncio.sleep(max(settings.firewall_policy_reload_interval_seconds, 1))
            await _reload_firewall_policy_if_changed()

    @asynccontextmanager
    async def _lifespan(_app: FastAPI):
        nonlocal reload_task
        nonlocal firewall_reload_task
        try:
            if settings.policy_path is not None:
                await _reload_policy_if_changed(force=True)
                if settings.policy_reload_interval_seconds > 0:
                    reload_task = asyncio.create_task(_policy_reload_loop())
            if settings.firewall_policy_path is not None:
                await _reload_firewall_policy_if_changed(force=True)
                if settings.firewall_policy_reload_interval_seconds > 0:
                    firewall_reload_task = asyncio.create_task(_firewall_reload_loop())
            yield
        finally:
            if managed_upstream_relay is not None:
                await managed_upstream_relay.aclose()
            for task in (reload_task, firewall_reload_task):
                if task is not None:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
            reload_task = None
            firewall_reload_task = None

    app = FastAPI(title="agent-bom gateway", version="1", lifespan=_lifespan)

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        async with policy_lock:
            policy_summary = summarize_policy_bundle(policy_state["policy"])
            policy_runtime = {
                "source": policy_state["source"],
                "source_kind": "file" if settings.policy_path else "inline",
                "reload_enabled": bool(settings.policy_path and settings.policy_reload_interval_seconds > 0),
                "reload_interval_seconds": settings.policy_reload_interval_seconds,
                "last_loaded_at": policy_state["last_loaded_at"],
                "last_error": policy_state["last_error"],
                **policy_summary,
            }
        async with firewall_lock:
            firewall_policy: AgentFirewallPolicy = firewall_state["policy"]
            firewall_runtime = {
                "source": firewall_state["source"],
                "source_kind": "file" if settings.firewall_policy_path else "default-allow",
                "reload_enabled": bool(settings.firewall_policy_path and settings.firewall_policy_reload_interval_seconds > 0),
                "reload_interval_seconds": settings.firewall_policy_reload_interval_seconds,
                "last_loaded_at": firewall_state["last_loaded_at"],
                "last_error": firewall_state["last_error"],
                "rule_count": len(firewall_policy.rules),
                "default_decision": firewall_policy.default_decision.value,
                "enforcement_mode": firewall_policy.enforcement_mode.value,
                "tenant_id": firewall_policy.tenant_id,
            }
        health: dict[str, Any] = {
            "status": "ok",
            "upstreams": settings.registry.names(),
            "auth": {"incoming_token_required": _gateway_requires_auth(settings)},
            "upstream_runtime": {
                "pooled_http_client": managed_upstream_relay is not None,
                "circuit_breaker_enabled": managed_upstream_relay is not None,
                "failure_threshold": settings.upstream_failure_threshold,
                "cooldown_seconds": settings.upstream_circuit_cooldown_seconds,
                "max_connections": settings.upstream_http_max_connections,
                "max_keepalive_connections": settings.upstream_http_max_keepalive_connections,
            },
            "rate_limit_runtime": _gateway_rate_limit_runtime_status(settings),
            "policy_runtime": policy_runtime,
            "firewall_runtime": firewall_runtime,
        }
        if settings.enable_visual_leak_detection:
            from agent_bom.runtime.visual_leak_detector import visual_leak_runtime_health

            health["visual_leak_detection"] = {
                **visual_leak_runtime_health(),
                "required": settings.require_visual_leak_detection_ready,
            }
        return health

    @app.post("/v1/firewall/check")
    async def firewall_check(request: Request) -> JSONResponse:
        """Evaluate the inter-agent firewall policy for a source -> target pair.

        Body shape (#982 PR 2):
            {
              "source_agent": "cursor",
              "target_agent": "snowflake-cli",
              "source_roles": ["trusted"],          # optional
              "target_roles": ["data-plane"]        # optional
            }

        Returns the matched decision plus the *effective* decision (with
        dry-run mode applied). On any non-allow effective decision, an audit
        event is emitted to the configured audit_sink so denies and warns
        flow into the existing /v1/proxy/audit relay.
        """
        # gateway --bearer-token (or API-key store) must
        # gate the firewall-check endpoint, not just /mcp/{server}. Otherwise
        # the policy evaluator is reachable unauthenticated on shared
        # deployments and leaks every rule via the matched_rule field.
        if _gateway_requires_auth(settings):
            tenant_id, auth_method = _authenticate_gateway_request(request, settings)
            request.state.tenant_id = tenant_id
            request.state.auth_method = auth_method
        try:
            payload = await request.json()
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail=f"invalid JSON body: {exc.msg}") from exc
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="firewall check body must be a JSON object")

        source_agent = payload.get("source_agent")
        target_agent = payload.get("target_agent")
        if not isinstance(source_agent, str) or not source_agent.strip():
            raise HTTPException(status_code=400, detail="'source_agent' is required")
        if not isinstance(target_agent, str) or not target_agent.strip():
            raise HTTPException(status_code=400, detail="'target_agent' is required")

        raw_source_roles = payload.get("source_roles") or []
        raw_target_roles = payload.get("target_roles") or []
        if not isinstance(raw_source_roles, list) or not all(isinstance(r, str) for r in raw_source_roles):
            raise HTTPException(status_code=400, detail="'source_roles' must be a list of strings")
        if not isinstance(raw_target_roles, list) or not all(isinstance(r, str) for r in raw_target_roles):
            raise HTTPException(status_code=400, detail="'target_roles' must be a list of strings")

        async with firewall_lock:
            policy: AgentFirewallPolicy = firewall_state["policy"]
            policy_source = firewall_state["source"]
            policy_loaded_at = firewall_state["last_loaded_at"]
        result = evaluate_firewall_policy(
            policy,
            source_agent=source_agent,
            target_agent=target_agent,
            source_roles=set(raw_source_roles),
            target_roles=set(raw_target_roles),
        )

        response_payload = {
            "source_agent": source_agent,
            "target_agent": target_agent,
            "source_roles": list(raw_source_roles),
            "target_roles": list(raw_target_roles),
            "decision": result.decision.value,
            "effective_decision": result.effective_decision.value,
            "matched_rule": (
                {
                    "source": result.matched_rule.source,
                    "target": result.matched_rule.target,
                    "decision": result.matched_rule.decision.value,
                    "description": result.matched_rule.description,
                }
                if result.matched_rule is not None
                else None
            ),
            "policy": {
                "source": policy_source,
                "loaded_at": policy_loaded_at,
                "default_decision": policy.default_decision.value,
                "enforcement_mode": policy.enforcement_mode.value,
                "tenant_id": policy.tenant_id,
            },
        }

        # Audit fan-out: emit on any non-allow effective decision so denies
        # and warns flow into the existing /v1/proxy/audit HMAC-chained relay.
        if result.effective_decision != FirewallDecision.ALLOW and settings.audit_sink is not None:
            await settings.audit_sink(
                {
                    "action": "gateway.firewall_decision",
                    "decision": result.decision.value,
                    "effective_decision": result.effective_decision.value,
                    "source_agent": source_agent,
                    "target_agent": target_agent,
                    "source_roles": list(raw_source_roles),
                    "target_roles": list(raw_target_roles),
                    "matched_rule": response_payload["matched_rule"],
                    "tenant_id": policy.tenant_id,
                    "enforcement_mode": policy.enforcement_mode.value,
                    "timestamp": time.time(),
                }
            )

        return JSONResponse(response_payload)

    @app.get("/metrics")
    async def metrics(request: Request) -> Response:
        # Prometheus text-exposition format must be plain text, not JSON.
        # Previous JSONResponse wrapped the body in quotes + escaped newlines,
        # which breaks every Prometheus scraper. Serve as `Response` with the
        # exposition media type so scrapers parse it.
        #
        # scraping endpoints carry decision counters and
        # tenant tags — gate them with the same bearer/API-key check that
        # protects /mcp/{server} when incoming auth is configured.
        if _gateway_requires_auth(settings):
            tenant_id, auth_method = _authenticate_gateway_request(request, settings)
            request.state.tenant_id = tenant_id
            request.state.auth_method = auth_method
        from agent_bom.api.metrics import render_prometheus_lines

        body = "\n".join(render_prometheus_lines()) + "\n"
        return Response(content=body, media_type="text/plain; version=0.0.4; charset=utf-8")

    @app.post("/mcp/{server_name}")
    async def relay(server_name: str, request: Request) -> JSONResponse:
        """Route an MCP JSON-RPC request to the named upstream after policy + audit."""
        trace_meta = make_request_trace(dict(request.headers))
        tenant_id = "default"
        auth_method = "none"
        if _gateway_requires_auth(settings):
            tenant_id, auth_method = _authenticate_gateway_request(request, settings)
            request.state.tenant_id = tenant_id
            request.state.auth_method = auth_method

        upstream = settings.registry.get(server_name, tenant_id=tenant_id)
        if upstream is None:
            raise HTTPException(status_code=404, detail=f"unknown upstream {server_name!r}")

        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > _MAX_GATEWAY_MESSAGE_BYTES:
                    raise HTTPException(status_code=413, detail="gateway request exceeds maximum JSON-RPC message size")
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="invalid Content-Length header") from exc

        raw_body = await request.body()
        if len(raw_body) > _MAX_GATEWAY_MESSAGE_BYTES:
            raise HTTPException(status_code=413, detail="gateway request exceeds maximum JSON-RPC message size")

        try:
            body = json.loads(raw_body)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"body is not valid JSON: {exc}") from exc

        # Parse the JSON-RPC envelope so check_policy sees the real message shape.
        if isinstance(body, dict) and "jsonrpc" in body:
            message = body
        else:
            raise HTTPException(status_code=400, detail="request must be a JSON-RPC message")

        # Inline policy check — reuse the exact evaluator the per-MCP proxy uses.
        tenant_id = getattr(request.state, "tenant_id", None) or "default"
        async with policy_lock:
            current_policy = dict(policy_state["policy"])
            policy_load_failed = bool(policy_state["load_failed"])

        # Fail-closed posture: a configured file policy that never loaded means
        # the relay would otherwise forward against an empty default-allow
        # policy. In fail-closed mode that is a DENY instead — the gateway must
        # not silently run unprotected. Fail-open keeps the legacy behaviour.
        if fail_closed and policy_load_failed:
            record_gateway_relay(upstream.name, "blocked")
            fc_ctx = context_from_now(
                tenant_id=tenant_id,
                source_agent=ANONYMOUS,
                tool_name=str((message.get("params") or {}).get("name") or message.get("method") or ""),
                now=time.time(),
                environment=_request_environment(request),
                source_ip=_request_source_ip(request),
            )
            if settings.audit_sink is not None:
                await settings.audit_sink(
                    {
                        "action": "gateway.policy_fail_closed",
                        "upstream": upstream.name,
                        "tenant_id": tenant_id,
                        "reason": "policy unavailable; fail-closed mode denies",
                    }
                )
            await _emit_policy_interop_event(
                settings,
                decision=GatewayDecision.DENY,
                reason="policy unavailable; fail-closed mode denies",
                ctx=fc_ctx,
                policy_source="fail_closed",
            )
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "error": {
                        "code": -32001,
                        "message": "Blocked by agent-bom gateway policy",
                        "data": {
                            "reason": "Gateway policy unavailable and fail-closed mode is active",
                            "policy_source": "fail_closed",
                        },
                    },
                },
                status_code=200,
            )

        # Caller-identity resolution with secure-by-default fail-closed posture.
        #
        # ``check_caller_identity`` preserves the token-present signal that the
        # legacy ``check_identity`` collapsed, so three cases are distinct:
        #   1. invalid/revoked token (token present, did not resolve) — ALWAYS
        #      fail closed, regardless of ``require_agent_identity`` or bind.
        #      This closes the fail-open hole where a forged/revoked token
        #      previously degraded to ANONYMOUS and forwarded.
        #   2. ``require_agent_identity`` set + missing token — fail closed
        #      (unchanged policy-driven behavior).
        #   3. fully-missing token — permitted on a loopback bind (local dev)
        #      or with the explicit opt-out, else fail closed by default on a
        #      non-loopback bind (mirrors the transport-auth opt-out precedent).
        source_agent, token_present, identity_invalid_reason = check_caller_identity(message, current_policy)
        source_agent = source_agent or ANONYMOUS

        identity_block_reason: str | None = None
        if identity_invalid_reason is not None:
            identity_block_reason = f"Identity invalid: {identity_invalid_reason}"
        elif not token_present:
            if current_policy.get("require_agent_identity"):
                identity_block_reason = "Identity required: no agent_identity token in _meta"
            elif not _gateway_allows_anonymous_agents(settings):
                identity_block_reason = (
                    "Anonymous agent caller denied on non-loopback listener; supply an agent_identity "
                    "token or set AGENT_BOM_GATEWAY_ALLOW_ANONYMOUS_AGENTS for local development only"
                )

        if identity_block_reason is not None:
            record_gateway_relay(upstream.name, "blocked")
            logger.info(
                "Gateway identity policy blocked request for upstream=%s tenant_id=%s source_agent=%s reason=%s",
                upstream.name,
                tenant_id,
                _sanitize_for_log(source_agent),
                _sanitize_for_log(identity_block_reason),
            )
            if settings.audit_sink is not None:
                await settings.audit_sink(
                    {
                        "action": "gateway.identity_blocked",
                        "upstream": upstream.name,
                        "tenant_id": tenant_id,
                        "source_agent": source_agent,
                        "reason": identity_block_reason,
                    }
                )
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "error": {
                        "code": -32001,
                        "message": "Blocked by agent-bom gateway identity policy",
                        "data": {"reason": "Identity validation failed"},
                    },
                },
                status_code=200,
            )

        # Inter-agent firewall enforcement in the data path (#982 PR 2). The
        # firewall is only consulted when an operator actually configured a
        # policy file — no firewall_policy_path means default-allow and zero
        # behavior change. The resolved source_agent → target upstream pair is
        # evaluated; an effective DENY fails the relay closed (audited +
        # governance event), converting the previously advisory /v1/firewall/
        # check evaluator into a real in-path control. WARN is advisory: it is
        # audited but does not block (matching enforcement_mode dry-run).
        if settings.firewall_policy_path is not None:
            async with firewall_lock:
                fw_policy: AgentFirewallPolicy = firewall_state["policy"]
            fw_result = evaluate_firewall_policy(
                fw_policy,
                source_agent=source_agent,
                target_agent=upstream.name,
            )
            if fw_result.effective_decision != FirewallDecision.ALLOW:
                fw_audit: dict[str, Any] = {
                    "action": "gateway.firewall_blocked"
                    if fw_result.effective_decision == FirewallDecision.DENY
                    else "gateway.firewall_warned",
                    "upstream": upstream.name,
                    "tenant_id": tenant_id,
                    "source_agent": source_agent,
                    "target_agent": upstream.name,
                    "decision": fw_result.decision.value,
                    "effective_decision": fw_result.effective_decision.value,
                    "matched_rule": (
                        {
                            "source": fw_result.matched_rule.source,
                            "target": fw_result.matched_rule.target,
                            "decision": fw_result.matched_rule.decision.value,
                            "description": fw_result.matched_rule.description,
                        }
                        if fw_result.matched_rule is not None
                        else None
                    ),
                    "enforcement_mode": fw_policy.enforcement_mode.value,
                }
                if settings.audit_sink is not None:
                    await settings.audit_sink(fw_audit)
                if fw_result.effective_decision == FirewallDecision.DENY:
                    record_gateway_relay(upstream.name, "blocked")
                    _emit_gateway_governance_event(
                        "firewall.blocked",
                        tenant_id=tenant_id,
                        subject_id=source_agent,
                        payload={
                            "source_agent": source_agent,
                            "target_agent": upstream.name,
                            "decision": fw_result.decision.value,
                            "matched_rule": fw_audit["matched_rule"],
                        },
                    )
                    logger.info(
                        "Gateway firewall blocked request source_agent=%s target=%s tenant_id=%s",
                        _sanitize_for_log(source_agent),
                        _sanitize_for_log(upstream.name),
                        tenant_id,
                    )
                    return JSONResponse(
                        {
                            "jsonrpc": "2.0",
                            "id": message.get("id"),
                            "error": {
                                "code": -32001,
                                "message": "Blocked by agent-bom gateway inter-agent firewall",
                                "data": {
                                    "reason": _public_gateway_block_reason("firewall"),
                                    "policy_source": "firewall",
                                },
                            },
                        },
                        status_code=200,
                    )

        rate_limit_headers: dict[str, str] = {}
        if rate_limit_store is not None:
            now = time.time()
            bucket = f"gateway:tenant:{_rate_limit_bucket_component(tenant_id)}:source_agent:{_rate_limit_bucket_component(source_agent)}"
            hit_count, reset_at = await asyncio.to_thread(rate_limit_store.hit, bucket, now)
            limit = settings.runtime_rate_limit_per_tenant_per_minute
            remaining = max(0, limit - hit_count)
            rate_limit_headers = {
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": str(remaining),
                "X-RateLimit-Reset": str(reset_at),
            }
            if hit_count > limit:
                retry_after = max(int(reset_at - now), 1)
                record_gateway_relay(upstream.name, "rate_limited")
                record_rate_limit_hit("gateway_source_agent")
                if settings.audit_sink is not None:
                    await settings.audit_sink(
                        {
                            "action": "gateway.rate_limited",
                            "upstream": upstream.name,
                            "tenant_id": tenant_id,
                            "source_agent": source_agent,
                            "limit": limit,
                            "bucket": bucket,
                            "reason": "source_agent_runtime_rate_limit",
                        }
                    )
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Gateway source-agent rate limit exceeded"},
                    headers={
                        **rate_limit_headers,
                        "Retry-After": str(retry_after),
                    },
                )

        # Pre-invocation budget enforcement: an enforce-mode spend cap fails the
        # call closed once the agent/tenant has burned its budget, before the
        # upstream is touched. Report-mode budgets never block. Cost-store
        # failures must not break the relay.
        try:
            from agent_bom.api.cost_store import check_budget_enforcement, get_cost_store

            budget_blocked, budget, budget_spend = check_budget_enforcement(get_cost_store(), tenant_id, source_agent)
        except Exception as exc:  # noqa: BLE001
            logger.warning("gateway budget check failed: %s", _sanitize_for_log(exc))
            budget_blocked, budget, budget_spend = False, None, 0.0
        if budget_blocked and budget is not None:
            record_gateway_relay(upstream.name, "blocked")
            if settings.audit_sink is not None:
                await settings.audit_sink(
                    {
                        "action": "gateway.budget_exceeded",
                        "upstream": upstream.name,
                        "tenant_id": tenant_id,
                        "source_agent": source_agent,
                        "limit_usd": budget.limit_usd,
                        "spend_usd": round(budget_spend, 6),
                        "budget_scope": "agent" if budget.agent else "tenant",
                        "reason": "budget_enforced",
                    }
                )
            _emit_gateway_governance_event(
                "budget.exceeded",
                tenant_id=tenant_id,
                subject_id=source_agent,
                payload={
                    "source_agent": source_agent,
                    "limit_usd": budget.limit_usd,
                    "spend_usd": round(budget_spend, 6),
                    "budget_scope": "agent" if budget.agent else "tenant",
                },
            )
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "error": {
                        "code": -32001,
                        "message": "Blocked by agent-bom gateway: spend budget exceeded",
                        "data": {"limit_usd": budget.limit_usd, "spend_usd": round(budget_spend, 6)},
                    },
                },
                status_code=200,
                headers=rate_limit_headers or None,
            )

        # Cost-center (chargeback) budget enforcement: when the call is allocated
        # to a cost-center that has an enforce-mode budget already burned, block
        # it too — independent of the per-agent/tenant caps above (#2925). A call
        # with no declared cost-center, or a cost-center with no enforce budget,
        # is a no-op so existing per-agent/tenant semantics are unchanged.
        cost_center = _request_cost_center(request, message)
        if cost_center:
            try:
                from agent_bom.api.cost_store import check_cost_center_budget_enforcement, get_cost_store

                cc_blocked, cc_budget, cc_spend = check_cost_center_budget_enforcement(get_cost_store(), tenant_id, cost_center)
            except Exception as exc:  # noqa: BLE001
                logger.warning("gateway cost-center budget check failed: %s", _sanitize_for_log(exc))
                cc_blocked, cc_budget, cc_spend = False, None, 0.0
            if cc_blocked and cc_budget is not None:
                record_gateway_relay(upstream.name, "blocked")
                if settings.audit_sink is not None:
                    await settings.audit_sink(
                        {
                            "action": "gateway.budget_exceeded",
                            "upstream": upstream.name,
                            "tenant_id": tenant_id,
                            "source_agent": source_agent,
                            "cost_center": cost_center,
                            "limit_usd": cc_budget.limit_usd,
                            "spend_usd": round(cc_spend, 6),
                            "budget_scope": "cost_center",
                            "reason": "budget_enforced",
                        }
                    )
                _emit_gateway_governance_event(
                    "budget.exceeded",
                    tenant_id=tenant_id,
                    subject_id=source_agent,
                    payload={
                        "source_agent": source_agent,
                        "cost_center": cost_center,
                        "limit_usd": cc_budget.limit_usd,
                        "spend_usd": round(cc_spend, 6),
                        "budget_scope": "cost_center",
                    },
                )
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "error": {
                            "code": -32001,
                            "message": "Blocked by agent-bom gateway: cost-center spend budget exceeded",
                            "data": {
                                "cost_center": cost_center,
                                "limit_usd": cc_budget.limit_usd,
                                "spend_usd": round(cc_spend, 6),
                            },
                        },
                    },
                    status_code=200,
                    headers=rate_limit_headers or None,
                )

        # Anomaly-triggered enforcement: a runaway agent (spend outlier vs the
        # fleet) is blocked/flagged before its next call, even while it is still
        # under any absolute budget. Off by default; cached + fail-open.
        if settings.anomaly_enforcement_mode in ("warn", "enforce"):
            anomalous, anomaly_reason = _agent_cost_anomaly(tenant_id, source_agent)
            if anomalous and settings.anomaly_enforcement_mode == "enforce":
                record_gateway_relay(upstream.name, "blocked")
                if settings.audit_sink is not None:
                    await settings.audit_sink(
                        {
                            "action": "gateway.anomaly_blocked",
                            "upstream": upstream.name,
                            "tenant_id": tenant_id,
                            "source_agent": source_agent,
                            "reason": anomaly_reason,
                        }
                    )
                _emit_gateway_governance_event(
                    "anomaly.blocked",
                    tenant_id=tenant_id,
                    subject_id=source_agent,
                    payload={"source_agent": source_agent, "reason": anomaly_reason},
                )
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "error": {
                            "code": -32001,
                            "message": "Blocked by agent-bom gateway: anomalous spend",
                            "data": {
                                "reason": _public_gateway_block_reason("anomaly_enforcement"),
                                "policy_source": "anomaly_enforcement",
                            },
                        },
                    },
                    status_code=200,
                    headers=rate_limit_headers or None,
                )
            if anomalous and settings.audit_sink is not None:
                await settings.audit_sink(
                    {
                        "action": "gateway.anomaly_warned",
                        "upstream": upstream.name,
                        "tenant_id": tenant_id,
                        "source_agent": source_agent,
                        "reason": anomaly_reason,
                    }
                )

        # Fleet-state enforcement: a quarantined agent is isolated — every call
        # blocked/flagged regardless of tool — before the upstream is touched.
        # Off by default; fails open on a fleet-store error.
        if settings.fleet_enforcement_mode in ("warn", "enforce") and _agent_is_quarantined(tenant_id, source_agent):
            if settings.fleet_enforcement_mode == "enforce":
                record_gateway_relay(upstream.name, "blocked")
                if settings.audit_sink is not None:
                    await settings.audit_sink(
                        {
                            "action": "gateway.fleet_blocked",
                            "upstream": upstream.name,
                            "tenant_id": tenant_id,
                            "source_agent": source_agent,
                            "reason": "agent quarantined in fleet roster",
                        }
                    )
                _emit_gateway_governance_event(
                    "fleet.blocked",
                    tenant_id=tenant_id,
                    subject_id=source_agent,
                    payload={"source_agent": source_agent, "reason": "agent quarantined in fleet roster"},
                )
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "error": {
                            "code": -32001,
                            "message": "Blocked by agent-bom gateway: agent quarantined",
                            "data": {
                                "reason": _public_gateway_block_reason("fleet_quarantine"),
                                "policy_source": "fleet_quarantine",
                            },
                        },
                    },
                    status_code=200,
                    headers=rate_limit_headers or None,
                )
            if settings.audit_sink is not None:
                await settings.audit_sink(
                    {
                        "action": "gateway.fleet_warned",
                        "upstream": upstream.name,
                        "tenant_id": tenant_id,
                        "source_agent": source_agent,
                        "reason": "agent quarantined in fleet roster",
                    }
                )

        policy_subject = policy_subject_from_message(message)
        if policy_subject:
            tool_name, arguments = policy_subject
            allowed, reason = check_policy(current_policy, tool_name, arguments)
            # Quarantine is the middle decision tier: the call is blocked from
            # the sensitive tool but the agent is flagged + heavily audited
            # rather than hard-denied. ``quarantine`` is only set by the
            # conditional-access / plugin layers below; it stays False here so
            # existing deny/allow behaviour is byte-for-byte unchanged when the
            # new layers produce no opinion.
            quarantine = False
            quarantine_reason = ""
            policy_source = "file"
            if allowed:
                try:
                    from agent_bom.api.agent_identity_store import (
                        active_jit_grant_for_tool,
                        get_agent_identity_store,
                        identity_for_token,
                    )

                    identity_token = extract_identity_token(message)
                    scoped_identity = identity_for_token(get_agent_identity_store(), identity_token) if identity_token else None
                except Exception:  # noqa: BLE001
                    scoped_identity = None
                if scoped_identity is not None and not scoped_identity.tool_allowed(tool_name):
                    try:
                        jit_grant = active_jit_grant_for_tool(
                            get_agent_identity_store(),
                            tenant_id=scoped_identity.tenant_id,
                            identity_id=scoped_identity.identity_id,
                            tool_name=tool_name,
                        )
                    except Exception:  # noqa: BLE001
                        jit_grant = None
                    if jit_grant is None:
                        allowed, reason, policy_source = False, f"tool '{tool_name}' not in identity scope", "identity_scope"
                    else:
                        policy_source = "identity_jit"
                        if settings.audit_sink is not None:
                            await settings.audit_sink(
                                {
                                    "action": "gateway.identity_jit_grant_used",
                                    "upstream": upstream.name,
                                    "tenant_id": tenant_id,
                                    "source_agent": source_agent,
                                    "identity_id": scoped_identity.identity_id,
                                    "grant_id": jit_grant.grant_id,
                                    "tool": tool_name,
                                    "expires_at": jit_grant.expires_at,
                                }
                            )
            # Context-aware (conditional) access: time-of-day / weekday window,
            # source CIDR, and environment guardrails scoped to the identity,
            # agent, or tool. Deny policies win; require policies deny when the
            # request context does not satisfy them. Evaluated after scope/JIT so
            # a JIT grant cannot bypass an environment/CIDR/time guardrail.
            if allowed:
                try:
                    from agent_bom.api.agent_identity_store import (
                        AccessContext,
                        evaluate_conditional_access_for_request,
                        get_agent_identity_store,
                    )

                    ctx = AccessContext(
                        identity_id=scoped_identity.identity_id if scoped_identity is not None else "",
                        agent_id=source_agent,
                        tool_name=tool_name,
                        environment=_request_environment(request),
                        source_ip=_request_source_ip(request),
                    )
                    cond_allowed, cond_reason, cond_policy_id = evaluate_conditional_access_for_request(
                        get_agent_identity_store(),
                        tenant_id=tenant_id,
                        ctx=ctx,
                    )
                except Exception:  # noqa: BLE001
                    cond_allowed, cond_reason, cond_policy_id = True, "", ""
                if not cond_allowed:
                    allowed, reason, policy_source = False, cond_reason, "conditional_access"
                    if settings.audit_sink is not None:
                        await settings.audit_sink(
                            {
                                "action": "gateway.conditional_access_blocked",
                                "upstream": upstream.name,
                                "tenant_id": tenant_id,
                                "source_agent": source_agent,
                                "identity_id": ctx.identity_id,
                                "tool": tool_name,
                                "policy_id": cond_policy_id,
                                "reason": cond_reason,
                            }
                        )
                    _emit_gateway_governance_event(
                        "identity.conditional_access_blocked",
                        tenant_id=tenant_id,
                        subject_id=ctx.identity_id or source_agent,
                        payload={
                            "source_agent": source_agent,
                            "identity_id": ctx.identity_id,
                            "tool": tool_name,
                            "policy_id": cond_policy_id,
                            "reason": cond_reason,
                        },
                    )
            # Layer control-plane GatewayPolicy binding on top of the file
            # policy: enforce bound_agents/bound_agent_types/bound_environments
            # scoped to the resolved source_agent, matching the per-MCP proxy.
            if allowed and settings.control_plane_policies:
                cp_allowed, cp_reason = _evaluate_control_plane_bundle(settings.control_plane_policies, source_agent, tool_name, arguments)
                if not cp_allowed:
                    allowed, reason, policy_source = False, cp_reason or "blocked by control-plane policy binding", "control_plane"
            # Drift-triggered enforcement: a tool an open drift incident named as
            # out-of-blueprint is blocked ("enforce") or flagged ("warn"). Off by
            # default so drift stays advisory unless the operator opts in.
            if allowed and settings.drift_enforcement_mode in ("warn", "enforce"):
                drift_violates, drift_reason = _open_drift_violates_tool(tenant_id, source_agent, tool_name)
                if drift_violates:
                    if settings.drift_enforcement_mode == "enforce":
                        allowed, reason, policy_source = False, drift_reason, "drift_enforcement"
                        _emit_gateway_governance_event(
                            "drift.blocked",
                            tenant_id=tenant_id,
                            subject_id=source_agent,
                            payload={"source_agent": source_agent, "tool": tool_name, "reason": drift_reason},
                        )
                    elif settings.audit_sink is not None:
                        await settings.audit_sink(
                            {
                                "action": "gateway.drift_warned",
                                "upstream": upstream.name,
                                "tenant_id": tenant_id,
                                "source_agent": source_agent,
                                "tool": tool_name,
                                "reason": drift_reason,
                            }
                        )
            # Graph reachability enforcement (consume direction): the unified
            # graph statically flagged this source_agent as reaching a credential
            # / privileged-tool node (AGENT_REACHES_PRIVILEGED). When the call's
            # target tool is one of those reachable privileged nodes, block the
            # FIRST attempt ("enforce") or flag it ("warn") — pre-emptively,
            # before any runtime call-sequence correlation. Off by default and a
            # no-op when no facts are loaded; fail-safe so it never breaks a relay.
            if allowed and reachability_map and settings.graph_reachability_enforcement_mode in ("warn", "enforce"):
                try:
                    reach_hit = reachability_map.reaches_privileged(source_agent, tool_name)
                except Exception as exc:  # noqa: BLE001 — fail-open, never break the relay
                    logger.warning("gateway graph-reachability check failed: %s", _sanitize_for_log(exc))
                    reach_hit = None
                if reach_hit is not None:
                    reach_reason = (
                        f"agent '{source_agent}' statically reaches privileged/credential node "
                        f"'{tool_name}' ({reach_hit.rule_id}); blocking pre-emptively"
                    )
                    if settings.graph_reachability_enforcement_mode == "enforce":
                        allowed, reason, policy_source = False, reach_reason, "graph_reachability"
                        if settings.audit_sink is not None:
                            await settings.audit_sink(
                                {
                                    "action": "gateway.graph_reachability_blocked",
                                    "upstream": upstream.name,
                                    "tenant_id": tenant_id,
                                    "source_agent": source_agent,
                                    "tool": tool_name,
                                    "rule_id": reach_hit.rule_id,
                                    "severity": reach_hit.severity,
                                    "reason": reach_reason,
                                }
                            )
                        _emit_gateway_governance_event(
                            "graph_reachability.blocked",
                            tenant_id=tenant_id,
                            subject_id=source_agent,
                            payload={
                                "source_agent": source_agent,
                                "tool": tool_name,
                                "rule_id": reach_hit.rule_id,
                                "severity": reach_hit.severity,
                                "reason": reach_reason,
                            },
                        )
                    elif settings.audit_sink is not None:
                        await settings.audit_sink(
                            {
                                "action": "gateway.graph_reachability_warned",
                                "upstream": upstream.name,
                                "tenant_id": tenant_id,
                                "source_agent": source_agent,
                                "tool": tool_name,
                                "rule_id": reach_hit.rule_id,
                                "severity": reach_hit.severity,
                                "reason": reach_reason,
                            }
                        )
            # Declarative conditional access + plugin policy evaluators. Both are
            # deterministic: the decision context carries an injected ``now`` so
            # the same (agent, tool, request) under the same policy always yields
            # the same verdict (and the same OCSF event id). Conditional rules
            # gate on time-window / weekday / risk-score / required attributes;
            # plugins compose third-party evaluators. A QUARANTINE verdict blocks
            # the sensitive tool but flags + heavily audits the agent instead of
            # hard-denying. Evaluation errors honour the fail-mode posture:
            # fail-closed turns an unexpected engine error into a DENY.
            if allowed:
                decision_now = time.time()
                decision_ctx = context_from_now(
                    tenant_id=tenant_id,
                    source_agent=source_agent,
                    tool_name=tool_name,
                    now=decision_now,
                    risk_score=_request_risk_score(request),
                    environment=_request_environment(request),
                    source_ip=_request_source_ip(request),
                    attributes=_request_context_attributes(request),
                )
                try:
                    cond_decision, cond_reason, _cond_rule = evaluate_conditional_rules(current_policy, decision_ctx)
                    plugin_decision, plugin_reason, _plugin_name = evaluate_policy_plugins(decision_ctx, current_policy)
                    eval_error = False
                except Exception as exc:  # noqa: BLE001
                    logger.warning("gateway conditional/plugin evaluation error: %s", _sanitize_for_log(exc))
                    cond_decision = plugin_decision = GatewayDecision.ALLOW
                    cond_reason = plugin_reason = ""
                    eval_error = True
                # Compose: DENY outranks QUARANTINE outranks ALLOW. Conditional
                # rules win ties over plugins (an explicit policy deny is stronger
                # than a third-party quarantine). A fail-closed eval error denies.
                _rank = {GatewayDecision.ALLOW: 0, GatewayDecision.QUARANTINE: 1, GatewayDecision.DENY: 2}
                if _rank[plugin_decision] > _rank[cond_decision]:
                    composed, composed_reason, composed_source = plugin_decision, plugin_reason, "policy_plugin"
                else:
                    composed, composed_reason, composed_source = cond_decision, cond_reason, "conditional_access"
                if eval_error and fail_closed:
                    allowed, reason, policy_source = False, "policy evaluation error", "conditional_access"
                elif composed == GatewayDecision.DENY:
                    allowed, reason, policy_source = False, composed_reason, composed_source
                elif composed == GatewayDecision.QUARANTINE:
                    quarantine, quarantine_reason, policy_source = True, composed_reason, composed_source

            if not allowed:
                record_gateway_relay(upstream.name, "blocked")
                audit_event: dict[str, Any] = {
                    "action": "gateway.policy_blocked",
                    "upstream": upstream.name,
                    "tenant_id": tenant_id,
                    "method": message.get("method"),
                    "tool": tool_name,
                    "reason": reason,
                    "source_agent": source_agent,
                    "policy_source": policy_source,
                }
                if settings.audit_sink is not None:
                    await settings.audit_sink(audit_event)
                await _emit_policy_interop_event(
                    settings,
                    decision=GatewayDecision.DENY,
                    reason=reason,
                    ctx=context_from_now(
                        tenant_id=tenant_id,
                        source_agent=source_agent,
                        tool_name=tool_name,
                        now=time.time(),
                        environment=_request_environment(request),
                        source_ip=_request_source_ip(request),
                    ),
                    policy_source=policy_source,
                )
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "error": {
                            "code": -32001,  # Application-defined error
                            "message": "Blocked by agent-bom gateway policy",
                            "data": {
                                "reason": _public_gateway_block_reason(policy_source),
                                "policy_source": policy_source,
                            },
                        },
                    },
                    status_code=200,
                    headers=rate_limit_headers or None,
                )

            if quarantine:
                # QUARANTINE: block the sensitive tool but flag + heavily audit
                # the agent rather than hard-deny. The client sees a structured,
                # client-safe reason; the full reason + OCSF event stay in audit.
                record_gateway_relay(upstream.name, "blocked")
                if settings.audit_sink is not None:
                    await settings.audit_sink(
                        {
                            "action": "gateway.policy_quarantined",
                            "upstream": upstream.name,
                            "tenant_id": tenant_id,
                            "method": message.get("method"),
                            "tool": tool_name,
                            "reason": quarantine_reason,
                            "source_agent": source_agent,
                            "policy_source": policy_source,
                        }
                    )
                _emit_gateway_governance_event(
                    "policy.quarantined",
                    tenant_id=tenant_id,
                    subject_id=source_agent,
                    payload={"source_agent": source_agent, "tool": tool_name, "reason": quarantine_reason, "policy_source": policy_source},
                )
                await _emit_policy_interop_event(
                    settings,
                    decision=GatewayDecision.QUARANTINE,
                    reason=quarantine_reason,
                    ctx=context_from_now(
                        tenant_id=tenant_id,
                        source_agent=source_agent,
                        tool_name=tool_name,
                        now=time.time(),
                        environment=_request_environment(request),
                        source_ip=_request_source_ip(request),
                    ),
                    policy_source=policy_source,
                )
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "error": {
                            "code": -32002,  # Application-defined: quarantined
                            "message": "Quarantined by agent-bom gateway policy",
                            "data": {
                                "reason": "Agent quarantined: this tool is restricted while the session is under review",
                                "policy_source": policy_source,
                                "decision": "quarantine",
                            },
                        },
                    },
                    status_code=200,
                    headers=rate_limit_headers or None,
                )
            warned, warning_reason, warning_rule_id = check_policy_warning(current_policy, tool_name, arguments)
            if warned and settings.audit_sink is not None:
                await settings.audit_sink(
                    {
                        "action": "gateway.policy_warned",
                        "upstream": upstream.name,
                        "tenant_id": tenant_id,
                        "method": message.get("method"),
                        "tool": tool_name,
                        "rule_id": warning_rule_id,
                        "reason": warning_reason,
                    }
                )

        # Forward to the upstream with bounded W3C trace headers and JSON-RPC
        # `_meta` so both HTTP-aware and JSON-RPC-aware upstreams can stitch
        # the same end-to-end trace.
        extra_headers = inject_trace_headers(
            {},
            traceparent=str(trace_meta["traceparent"]),
            tracestate=str(trace_meta["tracestate"]) if trace_meta["tracestate"] else None,
            baggage=str(trace_meta["baggage"]) if trace_meta["baggage"] else None,
        )
        forwarded_message = _inject_jsonrpc_trace_meta(
            message,
            traceparent=str(trace_meta["traceparent"]),
            tracestate=str(trace_meta["tracestate"]) if trace_meta["tracestate"] else None,
            baggage=str(trace_meta["baggage"]) if trace_meta["baggage"] else None,
        )
        span_cm = _GATEWAY_TRACER.start_as_current_span("gateway.relay_upstream") if _GATEWAY_TRACER else nullcontext()
        try:
            with span_cm as span:
                if span is not None:
                    span.set_attribute("agent_bom.gateway.upstream", upstream.name)
                    span.set_attribute("agent_bom.gateway.tenant_id", tenant_id)
                    span.set_attribute("agent_bom.gateway.method", str(message.get("method", "unknown")))
                    span.set_attribute("agent_bom.gateway.trace_id", str(trace_meta["trace_id"]))
                    span.set_attribute("agent_bom.gateway.span_id", str(trace_meta["span_id"]))
                    span.set_attribute("agent_bom.gateway.incoming_traceparent", bool(trace_meta["incoming_traceparent"]))
                    if trace_meta["parent_span_id"]:
                        span.set_attribute("agent_bom.gateway.parent_span_id", str(trace_meta["parent_span_id"]))
                    if trace_meta["tracestate"]:
                        span.set_attribute("agent_bom.gateway.tracestate_present", True)
                    if trace_meta["baggage"]:
                        span.set_attribute("agent_bom.gateway.baggage_present", True)
                    set_langfuse_runtime_attributes(
                        span,
                        surface="gateway",
                        tenant_id=tenant_id,
                        method=str(message.get("method", "unknown")),
                        tool_name=message.get("params", {}).get("name") if is_tools_call(message) else None,
                        decision="allowed",
                        upstream=upstream.name,
                        trace_id=str(trace_meta["trace_id"]),
                    )
                upstream_response = await upstream_caller(upstream, forwarded_message, extra_headers)
        except GatewayCircuitOpenError as exc:
            logger.warning("gateway upstream circuit open for %s", upstream.name)
            record_gateway_relay(upstream.name, "circuit_open")
            retry_after_header = str(int(exc.retry_after_seconds))
            if settings.audit_sink is not None:
                await settings.audit_sink(
                    {
                        "action": "gateway.upstream_circuit_open",
                        "upstream": upstream.name,
                        "tenant_id": tenant_id,
                        "reason": "circuit_open",
                        "retry_after_seconds": int(exc.retry_after_seconds),
                    }
                )
            raise HTTPException(
                status_code=503,
                detail="upstream circuit open",
                headers={"Retry-After": retry_after_header},
            ) from exc
        except asyncio.TimeoutError as exc:
            logger.warning("gateway upstream call timed out for %s", upstream.name)
            record_gateway_relay(upstream.name, "upstream_timeout")
            if settings.audit_sink is not None:
                await settings.audit_sink(
                    {
                        "action": "gateway.upstream_error",
                        "upstream": upstream.name,
                        "tenant_id": tenant_id,
                        "error": "timeout",
                        "reason": "timeout",
                    }
                )
            raise HTTPException(status_code=502, detail="upstream error: timeout") from exc
        except Exception as exc:  # noqa: BLE001
            logger.exception("gateway upstream call failed for %s", upstream.name)
            record_gateway_relay(upstream.name, "upstream_error")
            if settings.audit_sink is not None:
                await settings.audit_sink(
                    {
                        "action": "gateway.upstream_error",
                        "upstream": upstream.name,
                        "tenant_id": tenant_id,
                        "error": str(exc),
                    }
                )
            raise HTTPException(status_code=502, detail=f"upstream error: {exc}") from exc

        record_gateway_relay(upstream.name, "forwarded")

        # Visual-leak detection on image tool responses. Opt-in because OCR
        # is CPU-heavy; startup can now require the OCR runtime so pilots
        # fail closed instead of silently skipping the screenshot channel.
        if settings.enable_visual_leak_detection and isinstance(upstream_response, dict):
            result = upstream_response.get("result")
            if isinstance(result, dict):
                content = result.get("content")
                if isinstance(content, list) and content:
                    detector = _get_visual_leak_detector()
                    tool_name_for_scan = message.get("params", {}).get("name", "") if is_tools_call(message) else message.get("method", "")
                    safe_tool_name_for_log = _sanitize_for_log(tool_name_for_scan)
                    from agent_bom.runtime.visual_leak_detector import run_visual_leak_check, run_visual_leak_redact

                    try:
                        alerts = await run_visual_leak_check(detector, tool_name_for_scan, content)
                    except asyncio.TimeoutError:
                        logger.warning(
                            "gateway visual leak scan timed out for upstream=%s tool=%s",
                            upstream.name,
                            safe_tool_name_for_log,
                        )
                        alerts = []
                    if alerts:
                        record_gateway_relay(upstream.name, "visual_leak_redacted")
                        if settings.audit_sink is not None:
                            await settings.audit_sink(
                                {
                                    "action": "gateway.visual_leak_blocked",
                                    "upstream": upstream.name,
                                    "tenant_id": tenant_id,
                                    "tool": tool_name_for_scan,
                                    "alert_count": len(alerts),
                                    "leak_types": sorted({a.details.get("leak_type", "") for a in alerts}),
                                }
                            )
                        try:
                            result["content"] = await run_visual_leak_redact(detector, content)
                        except asyncio.TimeoutError:
                            logger.warning(
                                "gateway visual leak redaction timed out for upstream=%s tool=%s",
                                upstream.name,
                                safe_tool_name_for_log,
                            )

        if settings.audit_sink is not None:
            await settings.audit_sink(
                {
                    "action": "gateway.tool_call" if is_tools_call(message) else "gateway.message",
                    "upstream": upstream.name,
                    "tenant_id": tenant_id,
                    "method": message.get("method"),
                    "tool": message.get("params", {}).get("name") if is_tools_call(message) else None,
                }
            )
        response_headers = dict(rate_limit_headers)
        response_headers["traceparent"] = str(trace_meta["traceparent"])
        if trace_meta["tracestate"]:
            response_headers["tracestate"] = str(trace_meta["tracestate"])
        if trace_meta["baggage"]:
            response_headers["baggage"] = str(trace_meta["baggage"])
        return JSONResponse(upstream_response, headers=response_headers or None)

    return app


# Re-export the parser for easier test authoring / CLI glue.
__all__ = [
    "GatewaySettings",
    "build_control_plane_audit_sink",
    "create_gateway_app",
    "parse_jsonrpc",
]
