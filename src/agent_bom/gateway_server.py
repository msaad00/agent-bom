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
import json
import logging
import os
import threading
import time
from contextlib import asynccontextmanager, nullcontext
from datetime import datetime, timezone
from typing import Any, Mapping

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from agent_bom.a2a_auth_posture import evaluate_inline_mutual_auth
from agent_bom.agent_identity import (
    ANONYMOUS,
    check_caller_identity,
    extract_identity_token,
    identity_token_scopes,
)
from agent_bom.api.gateway_auth import _api_key_allows_gateway_relay as _api_key_allows_gateway_relay
from agent_bom.api.gateway_auth import _authenticate_gateway_request as _authenticate_gateway_request
from agent_bom.api.gateway_auth import _configured_gateway_tenant_id as _configured_gateway_tenant_id
from agent_bom.api.gateway_auth import _enforce_gateway_anonymous_agents_posture as _enforce_gateway_anonymous_agents_posture
from agent_bom.api.gateway_auth import _enforce_gateway_auth_posture as _enforce_gateway_auth_posture
from agent_bom.api.gateway_auth import _env_flag_enabled as _env_flag_enabled
from agent_bom.api.gateway_auth import _extract_request_token as _extract_request_token
from agent_bom.api.gateway_auth import _gateway_allows_anonymous_agents as _gateway_allows_anonymous_agents
from agent_bom.api.gateway_auth import _gateway_requires_auth as _gateway_requires_auth
from agent_bom.api.gateway_auth import _is_loopback_host as _is_loopback_host
from agent_bom.api.gateway_auth import _parse_gateway_token_expiry as _parse_gateway_token_expiry
from agent_bom.api.gateway_auth import _request_has_expected_token as _request_has_expected_token
from agent_bom.api.gateway_auth import _role_allows_gateway_relay as _role_allows_gateway_relay
from agent_bom.api.gateway_auth import _validate_runtime_profile_posture as _validate_runtime_profile_posture
from agent_bom.api.gateway_context import create_gateway_http_app
from agent_bom.api.gateway_policy import _CONDITIONAL_ACCESS_EVAL_FAILED as _CONDITIONAL_ACCESS_EVAL_FAILED
from agent_bom.api.gateway_policy import _DRIFT_INCIDENT_LOOKUP_CAP as _DRIFT_INCIDENT_LOOKUP_CAP
from agent_bom.api.gateway_policy import _agent_cost_anomaly as _agent_cost_anomaly
from agent_bom.api.gateway_policy import _agent_identity_revoked as _agent_identity_revoked
from agent_bom.api.gateway_policy import _conditional_access_fail_closed as _conditional_access_fail_closed
from agent_bom.api.gateway_policy import _DriftLookup as _DriftLookup
from agent_bom.api.gateway_policy import _evaluate_control_plane_bundle as _evaluate_control_plane_bundle
from agent_bom.api.gateway_policy import _fleet_containment_reason as _fleet_containment_reason
from agent_bom.api.gateway_policy import _open_drift_violates_tool as _open_drift_violates_tool
from agent_bom.api.gateway_policy import _validate_gateway_rule_patterns as _validate_gateway_rule_patterns
from agent_bom.api.gateway_policy import _warn_on_quarantined_agents as _warn_on_quarantined_agents
from agent_bom.api.gateway_rate_limit import _build_gateway_rate_limit_store as _build_gateway_rate_limit_store
from agent_bom.api.gateway_rate_limit import _gateway_configured_replicas as _gateway_configured_replicas
from agent_bom.api.gateway_rate_limit import _gateway_rate_limit_runtime_status as _gateway_rate_limit_runtime_status
from agent_bom.api.gateway_rate_limit import _gateway_shared_rate_limit_required as _gateway_shared_rate_limit_required
from agent_bom.api.gateway_rate_limit import _rate_limit_bucket_component as _rate_limit_bucket_component
from agent_bom.api.gateway_request import _read_bounded_gateway_body as _read_bounded_gateway_body
from agent_bom.api.gateway_request import _request_client_id as _request_client_id
from agent_bom.api.gateway_request import _request_context_attributes as _request_context_attributes
from agent_bom.api.gateway_request import _request_cost_center as _request_cost_center
from agent_bom.api.gateway_request import _request_device_id as _request_device_id
from agent_bom.api.gateway_request import _request_environment as _request_environment
from agent_bom.api.gateway_request import _request_groups as _request_groups
from agent_bom.api.gateway_request import _request_risk_score as _request_risk_score
from agent_bom.api.gateway_request import _request_source_ip as _request_source_ip
from agent_bom.api.gateway_request import _sanitize_for_log as _sanitize_for_log
from agent_bom.api.gateway_request import _strip_gateway_identity_metadata as _strip_gateway_identity_metadata
from agent_bom.api.metrics import record_gateway_relay, record_rate_limit_hit
from agent_bom.api.oidc_discovery_shim import build_oidc_discovery_shim_router
from agent_bom.api.tracing import get_tracer, inject_trace_headers, make_request_trace
from agent_bom.firewall import (
    AgentFirewallPolicy,
    FirewallDecision,
    FirewallEvaluation,
    load_firewall_policy_file,
)
from agent_bom.firewall import evaluate as evaluate_firewall_policy
from agent_bom.langfuse_otel import set_langfuse_runtime_attributes
from agent_bom.proxy import check_policy, extract_tool_name, is_tools_call, parse_jsonrpc, policy_subject_from_message
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
from agent_bom.proxy_scanner import ScanConfig, redact_pii, scan_jsonrpc_response, scan_tool_call
from agent_bom.runtime.correlation_facts import (
    RUNTIME_FACTS_CACHE_INVALIDATING_ERRORS,
    RuntimeFactsBundleError,
    RuntimeFactsPoller,
    VerifiedRuntimeFacts,
)
from agent_bom.runtime.fail_mode import gateway_fail_mode_matrix
from agent_bom.runtime.gateway_audit import ControlPlaneAuditSink as ControlPlaneAuditSink
from agent_bom.runtime.gateway_audit import build_control_plane_audit_sink as build_control_plane_audit_sink
from agent_bom.runtime.gateway_audit_local import LocalGatewayAuditSink as LocalGatewayAuditSink
from agent_bom.runtime.gateway_audit_local import UnavailableGatewayAuditSink
from agent_bom.runtime.gateway_audit_local import build_local_gateway_audit_sink as build_local_gateway_audit_sink
from agent_bom.runtime.gateway_contracts import AuditSink as AuditSink
from agent_bom.runtime.gateway_contracts import GatewayAuditDeliveryUnavailableError as GatewayAuditDeliveryUnavailableError
from agent_bom.runtime.gateway_contracts import GatewayAuditSender as GatewayAuditSender
from agent_bom.runtime.gateway_contracts import UpstreamCaller as UpstreamCaller
from agent_bom.runtime.gateway_events import (
    GatewayRuntimeEventType,
    build_gateway_runtime_event,
)
from agent_bom.runtime.gateway_policy_reload import GatewayPolicyReloader, GatewayPolicyState
from agent_bom.runtime.gateway_policy_reload import _load_policy_file as _load_policy_file
from agent_bom.runtime.gateway_relay import GatewayCircuitBreaker as GatewayCircuitBreaker
from agent_bom.runtime.gateway_relay import GatewayCircuitOpenError as GatewayCircuitOpenError
from agent_bom.runtime.gateway_relay import GatewayUpstreamRelay as GatewayUpstreamRelay
from agent_bom.runtime.gateway_relay import _default_upstream_caller as _default_upstream_caller
from agent_bom.runtime.gateway_relay import _post_upstream_jsonrpc as _post_upstream_jsonrpc
from agent_bom.runtime.gateway_relay_contract import MAX_GATEWAY_RELAY_MESSAGE_BYTES
from agent_bom.runtime.gateway_settings import GatewaySettings as GatewaySettings
from agent_bom.runtime.graph_reachability import ReachabilityMap, load_reachability_map
from agent_bom.runtime.profile_resolution import ProfileResolutionCode
from agent_bom.runtime.trace_metadata import inject_jsonrpc_trace_meta
from agent_bom.security import sanitize_error, sanitize_text

logger = logging.getLogger(__name__)
_GATEWAY_TRACER = get_tracer("agent_bom.gateway")
_MAX_GATEWAY_MESSAGE_BYTES = MAX_GATEWAY_RELAY_MESSAGE_BYTES


# Lazy singleton so disabled deploys don't pay the import cost of the
# visual detector (Pillow/pytesseract). Built on first use when
# ``enable_visual_leak_detection`` is True.
_visual_detector_singleton: Any = None
_visual_detector_lock = threading.Lock()


def _public_gateway_error(exc: Exception | str) -> str:
    """Return a non-diagnostic gateway error safe for clients and audit sinks."""
    return sanitize_error(exc, generic=True)


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
        "a2a_mutual_auth": "Inter-agent mutual authentication is required for this edge",
        "oauth_scope": "The caller's OAuth token is missing a required scope for this tool",
        "dlp": "Data-loss-prevention policy blocked sensitive content in this request",
        "firewall": "Inter-agent firewall blocked this request",
        "graph_reachability": "Graph reachability policy blocked this request",
        "graph_reachability_evidence": "Graph reachability evidence unavailable and strict mode is active",
        "policy_plugin": "A gateway policy plugin blocked this request",
        "fail_closed": "Gateway policy unavailable and fail-closed mode is active",
        "runtime_profile": "Runtime client profile validation blocked this request",
    }.get(policy_source, "Gateway policy blocked this request")


def _get_visual_leak_detector() -> Any:
    global _visual_detector_singleton
    if _visual_detector_singleton is None:
        with _visual_detector_lock:
            if _visual_detector_singleton is None:
                from agent_bom.runtime.visual_leak_detector import VisualLeakDetector

                _visual_detector_singleton = VisualLeakDetector()
    return _visual_detector_singleton


def _gateway_dlp_config(settings: GatewaySettings) -> ScanConfig:
    """Build the inline-scanner config for the gateway DLP pass."""
    return ScanConfig(
        enabled=settings.dlp_enabled,
        mode=settings.dlp_mode if settings.dlp_mode in ("audit", "enforce") else "audit",
        scanners=list(settings.dlp_scanners),
        pii_action=settings.dlp_pii_action if settings.dlp_pii_action in ("redact", "block") else "redact",
    )


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
        logger.warning("gateway OCSF event build failed: %s", sanitize_text(_sanitize_for_log(exc)))
        return
    try:
        await asyncio.to_thread(
            deliver_policy_webhook,
            event,
            url=settings.policy_webhook_url,
            token=settings.policy_webhook_token,
        )
    except Exception as exc:  # noqa: BLE001 — webhook must never break the relay
        logger.warning("gateway policy webhook dispatch error (event dropped, relay unaffected): %s", sanitize_text(_sanitize_for_log(exc)))


def _inject_jsonrpc_trace_meta(
    message: dict[str, Any],
    *,
    traceparent: str | None,
    tracestate: str | None,
    baggage: str | None,
) -> dict[str, Any]:
    """Preserve the gateway's explicit trace arguments at its compatibility entry."""
    return inject_jsonrpc_trace_meta(message, traceparent=traceparent, tracestate=tracestate, baggage=baggage)


def create_gateway_app(settings: GatewaySettings) -> FastAPI:
    """Build the FastAPI app for `agent-bom gateway serve`.

    Separating app construction from CLI entry point keeps the server
    testable end-to-end via ``TestClient(create_gateway_app(settings))``.
    """
    if settings.oauth_as is not None:
        raise ValueError(
            "Embedded OAuth AS is unavailable until trusted client authorization is implemented; "
            "use configured bearer or API-key authentication"
        )
    if settings.bearer_token:
        settings._bearer_token_deadline = _parse_gateway_token_expiry(settings.bearer_token_expires_at)
    if settings.audit_sink is None:
        try:
            settings.audit_sink = build_local_gateway_audit_sink()
        except Exception as exc:  # noqa: BLE001 - relay remains fail-closed below
            logger.error("Gateway local audit initialization failed (error_type=%s)", type(exc).__name__)
            settings.audit_sink = UnavailableGatewayAuditSink()
    if settings.enable_visual_leak_detection and settings.require_visual_leak_detection_ready:
        from agent_bom.runtime.visual_leak_detector import require_visual_leak_runtime

        require_visual_leak_runtime()
    _enforce_gateway_auth_posture(settings)
    _enforce_gateway_anonymous_agents_posture(settings)
    _warn_on_quarantined_agents(settings)
    runtime_profile_mode = _validate_runtime_profile_posture(settings)

    managed_upstream_relay = GatewayUpstreamRelay(settings) if settings.upstream_caller is None else None
    upstream_caller = settings.upstream_caller or managed_upstream_relay
    assert upstream_caller is not None
    rate_limit_store = _build_gateway_rate_limit_store(settings)
    # Fail-closed posture resolved once at build time. "closed" makes a
    # missing/unloadable policy or an evaluation error DENY instead of silently
    # degrading to default-allow. Explicit "open" remains available for local
    # development, but production defaults to closed.
    resolved_fail_mode = resolve_fail_mode(settings.fail_mode)
    fail_closed = resolved_fail_mode == "closed"
    if fail_closed:
        logger.info("gateway policy engine starting in fail-CLOSED mode: unloadable policy or evaluation errors will DENY")
    policy_reload = GatewayPolicyReloader(
        state=GatewayPolicyState(
            policy=dict(settings.policy),
            source=str(settings.policy_path) if settings.policy_path else "inline",
            load_failed=settings.policy_path is not None,
        ),
        path=lambda: settings.policy_path,
        interval=lambda: settings.policy_reload_interval_seconds,
        load=lambda path: _load_policy_file(path),
        logger=logger,
        log_prefix="gateway policy",
        sanitize_log=_sanitize_for_log,
    )
    policy_state = policy_reload.state
    policy_lock = policy_reload.lock
    reload_task: asyncio.Task[None] | None = None

    # The firewall rotates independently and invalidates a failed reload;
    # method policy retains its last successfully loaded version.
    firewall_reload = GatewayPolicyReloader(
        state=GatewayPolicyState(
            policy=AgentFirewallPolicy(),
            source=str(settings.firewall_policy_path) if settings.firewall_policy_path else "default-allow",
            load_failed=settings.firewall_policy_path is not None,
        ),
        path=lambda: settings.firewall_policy_path,
        interval=lambda: settings.firewall_policy_reload_interval_seconds,
        load=lambda path: load_firewall_policy_file(path),
        logger=logger,
        log_prefix="gateway firewall policy",
        sanitize_log=_sanitize_for_log,
        invalidate_on_error=True,
    )
    firewall_state = firewall_reload.state
    firewall_lock = firewall_reload.lock
    firewall_reload_task: asyncio.Task[None] | None = None

    # Graph-derived reachability facts (consume direction). Static report mode is
    # retained for compatibility. A signed correlation bundle may be polled when
    # explicitly configured; the poller keeps the last valid unexpired bundle.
    reachability_map: ReachabilityMap = load_reachability_map(settings.graph_reachability_path)
    if settings.graph_reachability_path is not None:
        logger.info(
            "gateway graph-reachability facts loaded from %s: %d agent(s), mode=%s",
            _sanitize_for_log(settings.graph_reachability_path),
            len(reachability_map.by_agent),
            _sanitize_for_log(settings.graph_reachability_enforcement_mode),
        )

    runtime_facts_task: asyncio.Task[None] | None = None
    runtime_facts_configured = bool(settings.graph_reachability_bundle_fetcher or settings.graph_reachability_bundle_url.strip())
    runtime_facts_config_error = ""

    async def _fetch_runtime_facts_url() -> Mapping[str, Any]:
        import httpx

        headers: dict[str, str] = {"Accept": "application/json"}
        if settings.graph_reachability_bundle_bearer_token:
            headers["Authorization"] = f"Bearer {settings.graph_reachability_bundle_bearer_token}"
        async with httpx.AsyncClient(timeout=httpx.Timeout(connect=5.0, read=10.0, write=10.0, pool=5.0)) as client:
            response = await client.get(settings.graph_reachability_bundle_url, headers=headers)
            if response.status_code == 409:
                try:
                    failure_payload = response.json()
                except (TypeError, ValueError):
                    failure_payload = None
                failure_code = str(failure_payload.get("detail") or "") if isinstance(failure_payload, Mapping) else ""
                if failure_code in RUNTIME_FACTS_CACHE_INVALIDATING_ERRORS:
                    raise RuntimeFactsBundleError(failure_code)
            response.raise_for_status()
            if len(response.content) > 8 * 1024 * 1024:
                raise ValueError("bundle_response_too_large")
            payload = response.json()
        if not isinstance(payload, Mapping):
            raise ValueError("malformed_bundle_response")
        return payload

    runtime_facts_poller: RuntimeFactsPoller | None = None
    if runtime_facts_configured and settings.graph_reachability_enforcement_mode != "off":
        if settings.graph_reachability_bundle_signing_key is None:
            runtime_facts_config_error = "missing_signing_key"
        elif not settings.graph_reachability_bundle_tenant_id.strip():
            runtime_facts_config_error = "missing_tenant_id"
        else:
            runtime_facts_poller = RuntimeFactsPoller(
                fetch=settings.graph_reachability_bundle_fetcher or _fetch_runtime_facts_url,
                signing_key=settings.graph_reachability_bundle_signing_key,
                tenant_id=settings.graph_reachability_bundle_tenant_id,
            )

    async def _runtime_facts_refresh_loop() -> None:
        assert runtime_facts_poller is not None
        while True:
            await asyncio.sleep(max(settings.graph_reachability_bundle_poll_interval_seconds, 0.1))
            await runtime_facts_poller.refresh()

    @asynccontextmanager
    async def _lifespan(_app: FastAPI):
        nonlocal reload_task
        nonlocal firewall_reload_task
        nonlocal runtime_facts_task
        try:
            if isinstance(settings.audit_sink, ControlPlaneAuditSink):
                await settings.audit_sink.start()
            if settings.policy_path is not None:
                await policy_reload.reload(force=True)
                if settings.policy_reload_interval_seconds > 0:
                    reload_task = asyncio.create_task(policy_reload.run())
            if settings.firewall_policy_path is not None:
                await firewall_reload.reload(force=True)
                if settings.firewall_policy_reload_interval_seconds > 0:
                    firewall_reload_task = asyncio.create_task(firewall_reload.run())
            if runtime_facts_poller is not None:
                await runtime_facts_poller.refresh()
                if settings.graph_reachability_bundle_poll_interval_seconds > 0:
                    runtime_facts_task = asyncio.create_task(_runtime_facts_refresh_loop())
            yield
        finally:
            if managed_upstream_relay is not None:
                await managed_upstream_relay.aclose()
            for task in (reload_task, firewall_reload_task, runtime_facts_task):
                if task is not None:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
            reload_task = None
            firewall_reload_task = None
            runtime_facts_task = None
            if isinstance(settings.audit_sink, ControlPlaneAuditSink):
                await settings.audit_sink.aclose()

    app = create_gateway_http_app(settings, _lifespan)

    def _audit_unavailable_response(message_id: object, *, headers: dict[str, str] | None = None) -> JSONResponse:
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": message_id,
                "error": {
                    "code": -32003,
                    "message": "Gateway audit persistence unavailable",
                    "data": {
                        "reason": "Tool call was not executed because durable audit admission failed",
                        "policy_source": "audit_delivery",
                    },
                },
            },
            status_code=503,
            headers=headers,
        )

    @app.exception_handler(GatewayAuditDeliveryUnavailableError)
    async def _audit_delivery_unavailable(request: Request, _exc: GatewayAuditDeliveryUnavailableError) -> JSONResponse:
        """Turn any pre-upstream audit outage into a stable fail-closed response."""

        if request.url.path.startswith("/mcp/"):
            record_gateway_relay(str(getattr(request.state, "gateway_upstream", "unknown")), "audit_unavailable")
            return _audit_unavailable_response(getattr(request.state, "gateway_message_id", None))
        return JSONResponse(status_code=503, content={"detail": "Gateway audit persistence unavailable"})

    async def _bind_authenticated_audit_tenant(request: Request, tenant_id: str, auth_method: str) -> None:
        sink = settings.audit_sink
        if not isinstance(sink, ControlPlaneAuditSink):
            return
        request_token = _extract_request_token(request) if auth_method == "api_key" else None
        await sink.bind_authenticated_tenant(tenant_id, request_token)

    if settings.oidc_discovery_shim is not None:
        app.include_router(build_oidc_discovery_shim_router(settings.oidc_discovery_shim))

    dlp_config = _gateway_dlp_config(settings)

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        async with policy_lock:
            policy_summary = summarize_policy_bundle(policy_state.policy)
            policy_runtime = {
                "source": policy_state.source,
                "source_kind": "file" if settings.policy_path else "inline",
                "reload_enabled": bool(settings.policy_path and settings.policy_reload_interval_seconds > 0),
                "reload_interval_seconds": settings.policy_reload_interval_seconds,
                "last_loaded_at": policy_state.last_loaded_at,
                "last_error": policy_state.last_error,
                **policy_summary,
            }
        async with firewall_lock:
            firewall_policy: AgentFirewallPolicy = firewall_state.policy
            firewall_runtime = {
                "source": firewall_state.source,
                "source_kind": "file" if settings.firewall_policy_path else "default-allow",
                "reload_enabled": bool(settings.firewall_policy_path and settings.firewall_policy_reload_interval_seconds > 0),
                "reload_interval_seconds": settings.firewall_policy_reload_interval_seconds,
                "last_loaded_at": firewall_state.last_loaded_at,
                "last_error": firewall_state.last_error,
                "load_failed": bool(firewall_state.load_failed),
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
            "broker_runtime": {
                "oauth_as_enabled": False,
                "oidc_discovery_shim_enabled": settings.oidc_discovery_shim is not None,
                "a2a_mutual_auth_enforcement_mode": settings.a2a_mutual_auth_enforcement_mode,
                "tool_scope_mapped_tools": len(settings.tool_scope_map),
                "dlp_enabled": settings.dlp_enabled,
                "dlp_mode": settings.dlp_mode if settings.dlp_enabled else "disabled",
            },
            # Honest fail-open/fail-closed posture per enforcement subsystem
            # (docs/RUNTIME_FAIL_MODES.md). Resolved once at app build; the
            # matrix itself is static documentation-as-data from
            # agent_bom.runtime.fail_mode.
            "fail_mode_runtime": {
                "policy_fail_mode": resolved_fail_mode,
                "subsystems": gateway_fail_mode_matrix(resolved_fail_mode),
            },
        }
        if settings.enable_visual_leak_detection:
            from agent_bom.runtime.visual_leak_detector import visual_leak_runtime_health

            health["visual_leak_detection"] = {
                **visual_leak_runtime_health(),
                "required": settings.require_visual_leak_detection_ready,
            }
        audit_health = getattr(settings.audit_sink, "health", None)
        if callable(audit_health):
            audit_delivery_health = audit_health()
            health["audit_delivery"] = audit_delivery_health
            if audit_delivery_health["status"] != "healthy":
                health["status"] = "degraded"
        return health

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        """Report whether configured durable audit delivery can accept work."""

        health = await healthz()
        audit_delivery = health.get("audit_delivery")
        ready = not isinstance(audit_delivery, dict) or (
            bool(audit_delivery.get("durable"))
            and bool(audit_delivery.get("accepting_events"))
            and bool(audit_delivery.get("backlog_observable"))
        )
        return JSONResponse(status_code=200 if ready else 503, content={"ready": ready, **health})

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
        tenant_id = _configured_gateway_tenant_id()
        auth_method = "none"
        if _gateway_requires_auth(settings):
            tenant_id, auth_method = _authenticate_gateway_request(request, settings)
            request.state.tenant_id = tenant_id
            request.state.auth_method = auth_method
        await _bind_authenticated_audit_tenant(request, tenant_id, auth_method)
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
            policy: AgentFirewallPolicy = firewall_state.policy
            policy_source = firewall_state.source
            policy_loaded_at = firewall_state.last_loaded_at
            policy_load_failed = bool(firewall_state.load_failed)
        if policy.tenant_id is not None and policy.tenant_id != tenant_id:
            raise HTTPException(status_code=403, detail="firewall policy is not bound to the authenticated tenant")
        if fail_closed and policy_load_failed and settings.firewall_policy_path is not None:
            result = FirewallEvaluation(
                decision=FirewallDecision.DENY,
                matched_rule=None,
                effective_decision=FirewallDecision.DENY,
            )
        else:
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
                "tenant_id": tenant_id,
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
                    "tenant_id": tenant_id,
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

        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > _MAX_GATEWAY_MESSAGE_BYTES:
                    raise HTTPException(status_code=413, detail="gateway request exceeds maximum JSON-RPC message size")
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="invalid Content-Length header") from exc

        raw_body = await _read_bounded_gateway_body(request)

        try:
            body = json.loads(raw_body)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"body is not valid JSON: {sanitize_error(exc)}") from exc

        # Parse the JSON-RPC envelope so check_policy sees the real message shape.
        if isinstance(body, dict) and "jsonrpc" in body:
            message = body
            request.state.gateway_message_id = message.get("id")
        else:
            raise HTTPException(status_code=400, detail="request must be a JSON-RPC message")
        await _bind_authenticated_audit_tenant(request, tenant_id, auth_method)

        # Inline policy check — reuse the exact evaluator the per-MCP proxy uses.
        async with policy_lock:
            current_policy = dict(policy_state.policy)
            policy_load_failed = bool(policy_state.load_failed)

        # Fail-closed posture: a configured file policy that never loaded means
        # the relay would otherwise forward against an empty default-allow
        # policy. In fail-closed mode that is a DENY instead — the gateway must
        # not silently run unprotected. Fail-open keeps the legacy behaviour.
        if fail_closed and policy_load_failed:
            record_gateway_relay(upstream.name, "blocked")
            fc_ctx = context_from_now(
                tenant_id=tenant_id,
                source_agent=ANONYMOUS,
                tool_name=_message_tool_label(message),
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
        identity_token = extract_identity_token(message)
        token_scopes: set[str] = set()
        scoped_identity: Any = None
        managed_identity_lookup_unavailable = False
        identity_failure_code = ""
        if identity_token:
            try:
                from agent_bom.api.agent_identity_store import get_agent_identity_store, identity_for_token

                scoped_identity = identity_for_token(get_agent_identity_store(), identity_token)
            except Exception as exc:  # noqa: BLE001
                managed_identity_lookup_unavailable = True
                logger.warning("gateway managed identity lookup failed: %s", sanitize_text(_sanitize_for_log(exc)))
        if scoped_identity is not None:
            source_agent = scoped_identity.agent_id
            token_present = True
            identity_invalid_reason = None
            identity_verified = True
            if scoped_identity.tenant_id != tenant_id:
                identity_invalid_reason = "managed identity tenant mismatch"
                identity_failure_code = ProfileResolutionCode.TENANT_MISMATCH.value
            elif (
                not scoped_identity.blueprint_id
                and settings.drift_enforcement_mode == "enforce"
                and not _gateway_allows_anonymous_agents(settings)
            ):
                identity_invalid_reason = "managed identity has no role blueprint binding"
                identity_failure_code = ProfileResolutionCode.PROFILE_INCOMPLETE.value
        else:
            source_agent, token_present, identity_invalid_reason = check_caller_identity(message, current_policy)
            if identity_invalid_reason is not None:
                identity_failure_code = ProfileResolutionCode.IDENTITY_INVALID.value
            source_agent = source_agent or ANONYMOUS
            # "Verified" for inline mutual-auth: a resolved, non-anonymous caller
            # whose token was cryptographically checked — JWKS/OIDC-signed JWT or
            # an agent-bom-issued managed (``abi_``) token. An opaque
            # policy.agent_tokens mapping is NOT verified mutual auth.
            identity_verified = bool(
                token_present
                and identity_invalid_reason is None
                and source_agent != ANONYMOUS
                and (current_policy.get("jwks_uri") or current_policy.get("oidc_issuer") or (identity_token or "").startswith("abi_"))
            )
            if identity_token and identity_invalid_reason is None:
                token_scopes = identity_token_scopes(identity_token)

        # Revocation is agent-wide, so it is checked here — above the tool-call
        # branch — rather than beside ``allowed_tools``. Stages that key off a
        # resolved tool only run for ``tools/call``, which would leave a revoked
        # caller free to run ``initialize`` / ``tools/list`` / ``resources/read``.
        # It also has to precede the JIT-grant path, which can override a
        # per-tool deny: a revoked identity must never be JIT-grantable.
        if scoped_identity is None and identity_invalid_reason is None and source_agent != ANONYMOUS:
            agent_revoked, revocation_lookup_incomplete, revocation_lookup_failed = await asyncio.to_thread(
                _agent_identity_revoked, tenant_id, source_agent
            )
            if agent_revoked:
                identity_invalid_reason = "agent identity revoked"
                identity_failure_code = ProfileResolutionCode.IDENTITY_INACTIVE.value
            elif revocation_lookup_incomplete:
                # A knowingly partial answer is not a negative. Revocation is an
                # emergency control, so this denies on every listener — the
                # loopback anonymous-agent allowance does not govern it.
                identity_invalid_reason = "agent identity revocation status unavailable"
                identity_failure_code = ProfileResolutionCode.IDENTITY_STORE_UNAVAILABLE.value
            elif revocation_lookup_failed and (
                current_policy.get("require_agent_identity") or not _gateway_allows_anonymous_agents(settings)
            ):
                identity_invalid_reason = "agent identity revocation status unavailable"
                identity_failure_code = ProfileResolutionCode.IDENTITY_STORE_UNAVAILABLE.value

        identity_block_reason: str | None = None
        if identity_invalid_reason is not None:
            identity_block_reason = f"Identity invalid: {identity_invalid_reason}"
        elif not token_present:
            if current_policy.get("require_agent_identity"):
                identity_block_reason = "Identity required: no agent_identity token in _meta"
                identity_failure_code = ProfileResolutionCode.MANAGED_IDENTITY_REQUIRED.value
            elif not _gateway_allows_anonymous_agents(settings):
                identity_block_reason = (
                    "Anonymous agent caller denied on non-loopback listener; supply an agent_identity "
                    "token or set AGENT_BOM_GATEWAY_ALLOW_ANONYMOUS_AGENTS for local development only"
                )
                identity_failure_code = ProfileResolutionCode.MANAGED_IDENTITY_REQUIRED.value

        # A role blueprint is not a client profile. Keep them distinct until a
        # canonical assignment resolves successfully.
        profile_id = ""
        profile_revision = 0
        blueprint_id = str(getattr(scoped_identity, "blueprint_id", "") or "")
        blueprint_revision = 0
        profile_policy_ids: tuple[str, ...] = ()
        profile_identity_id = ""
        event_tool = _message_tool_label(message)

        def _typed_runtime_event(
            event_type: GatewayRuntimeEventType,
            *,
            decision: str,
            policy_source: str,
            tool: str = event_tool,
            reason_code: str = "",
            data_action: str = "",
            policy_id: str = "",
            evidence_id: str = "",
        ) -> dict[str, Any]:
            return build_gateway_runtime_event(
                event_type,
                tenant_id=tenant_id,
                agent_id=source_agent,
                identity_id=profile_identity_id,
                profile_id=profile_id,
                upstream=upstream.name,
                tool=tool,
                decision=decision,
                policy_source=policy_source,
                trace_id=str(trace_meta["trace_id"]),
                profile_revision=profile_revision,
                blueprint_id=blueprint_id,
                blueprint_revision=blueprint_revision,
                policy_ids=profile_policy_ids,
                reason_code=reason_code,
                data_action=data_action,
                policy_id=policy_id,
                evidence_id=evidence_id,
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
                        **_typed_runtime_event(
                            GatewayRuntimeEventType.TOOL_CALL_BLOCKED,
                            decision="deny",
                            policy_source="identity",
                            reason_code=identity_failure_code,
                        ),
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

        # Canonical profile resolution is deliberately opt-in while existing
        # OAuth/JWKS deployments migrate to managed identity assignments. In
        # enforce mode every caller must resolve before any upstream network
        # call. Warn mode records the same stable reason code without upgrading
        # unresolved evidence into a profile attribution.
        if runtime_profile_mode != "off":
            profile_failure_code = ""
            if managed_identity_lookup_unavailable:
                profile_failure_code = ProfileResolutionCode.IDENTITY_STORE_UNAVAILABLE.value
            elif scoped_identity is None:
                profile_failure_code = ProfileResolutionCode.MANAGED_IDENTITY_REQUIRED.value
            else:
                profile_identity_id = str(getattr(scoped_identity, "identity_id", "") or "")
                try:
                    from agent_bom.api.mcp_config_store import get_mcp_config_store
                    from agent_bom.runtime.profile_resolution import resolve_runtime_profile

                    resolution = resolve_runtime_profile(
                        get_mcp_config_store(),
                        identity=scoped_identity,
                        tenant_id=tenant_id,
                        issuer=settings.runtime_profile_issuer.strip(),
                        environment=settings.runtime_profile_environment.strip(),
                        granted_scopes=token_scopes,
                    )
                except Exception as exc:  # noqa: BLE001
                    profile_failure_code = ProfileResolutionCode.PROFILE_STORE_UNAVAILABLE.value
                    logger.warning("gateway runtime profile lookup unavailable: %s", sanitize_text(_public_gateway_error(exc)))
                else:
                    if not resolution.resolved or resolution.profile is None:
                        profile_failure_code = resolution.code.value
                    else:
                        resolved_profile = resolution.profile
                        profile_id = resolved_profile.client_profile_id
                        profile_revision = resolved_profile.revision
                        blueprint_id = resolved_profile.blueprint_id
                        blueprint_revision = resolved_profile.blueprint_revision
                        profile_policy_ids = resolved_profile.policy_ids
                        if not resolved_profile.allows_upstream(upstream.name):
                            profile_failure_code = "upstream_not_allowed"
                        elif is_tools_call(message) and not resolved_profile.allows_tool(event_tool):
                            profile_failure_code = "tool_not_allowed"

            if profile_failure_code:
                explicit_dev_bypass = settings.allow_runtime_profile_dev_bypass and _is_loopback_host(settings.listener_host)
                profile_action = "gateway.runtime_profile_warned"
                profile_decision = "warn"
                if runtime_profile_mode == "enforce" and explicit_dev_bypass:
                    profile_action = "gateway.runtime_profile_dev_bypass"
                    profile_decision = "allow"
                elif runtime_profile_mode == "enforce":
                    profile_action = "gateway.runtime_profile_blocked"
                    profile_decision = "deny"

                if settings.audit_sink is not None:
                    profile_audit: dict[str, Any] = {
                        "schema_version": "gateway.runtime.event.v1",
                        "action": profile_action,
                        "event_timestamp": datetime.now(timezone.utc).isoformat(),
                        "upstream": upstream.name,
                        "tenant_id": tenant_id,
                        "source_agent": source_agent,
                        "agent_id": source_agent,
                        "identity_id": profile_identity_id,
                        "profile_id": profile_id,
                        "profile_revision": profile_revision,
                        "blueprint_id": blueprint_id,
                        "blueprint_revision": blueprint_revision,
                        "policy_ids": list(profile_policy_ids),
                        "decision": profile_decision,
                        "policy_source": "runtime_profile",
                        "reason_code": profile_failure_code,
                        "development_mode": bool(explicit_dev_bypass),
                        "trace_id": str(trace_meta["trace_id"]),
                    }
                    if runtime_profile_mode == "enforce" and not explicit_dev_bypass:
                        profile_audit.update(
                            _typed_runtime_event(
                                GatewayRuntimeEventType.TOOL_CALL_BLOCKED
                                if is_tools_call(message)
                                else GatewayRuntimeEventType.RUNTIME_PROFILE_BLOCKED,
                                decision="deny",
                                policy_source="runtime_profile",
                                reason_code=profile_failure_code,
                            )
                        )
                    else:
                        profile_audit.update(
                            _typed_runtime_event(
                                GatewayRuntimeEventType.RUNTIME_PROFILE_DEV_BYPASS
                                if explicit_dev_bypass
                                else GatewayRuntimeEventType.RUNTIME_PROFILE_WARNED,
                                decision="allow",
                                policy_source="runtime_profile",
                                reason_code=profile_failure_code,
                            )
                        )
                        profile_audit["development_mode"] = bool(explicit_dev_bypass)
                    await settings.audit_sink(profile_audit)

                if runtime_profile_mode == "enforce" and not explicit_dev_bypass:
                    record_gateway_relay(upstream.name, "blocked")
                    return JSONResponse(
                        {
                            "jsonrpc": "2.0",
                            "id": message.get("id"),
                            "error": {
                                "code": -32001,
                                "message": "Blocked by agent-bom gateway runtime profile policy",
                                "data": {
                                    "reason": _public_gateway_block_reason("runtime_profile"),
                                    "policy_source": "runtime_profile",
                                    "reason_code": profile_failure_code,
                                },
                            },
                        },
                        status_code=200,
                    )

                # Warn/bypass paths must not claim an unresolved assignment as
                # canonical. A valid-but-out-of-scope assignment remains known
                # and retains its profile attribution for the final allow event.
                if profile_id and profile_failure_code not in {"upstream_not_allowed", "tool_not_allowed"}:
                    profile_id = ""
                    profile_revision = 0
                    profile_policy_ids = ()

        # A2A inline mutual-auth enforcement (assess → enforce). When enabled,
        # every inter-agent / agent-MCP edge must carry a cryptographically
        # verified caller identity; an anonymous / unverified / invalid edge is
        # flagged ("warn") or rejected closed ("enforce") in-path. Off by
        # default so the existing identity posture is unchanged.
        if settings.a2a_mutual_auth_enforcement_mode in ("warn", "enforce"):
            ma_result = evaluate_inline_mutual_auth(
                source_agent=source_agent,
                target=upstream.name,
                token_present=token_present,
                verified=identity_verified,
                identity_invalid_reason=identity_invalid_reason,
            )
            if ma_result.weak:
                if settings.audit_sink is not None:
                    await settings.audit_sink(
                        {
                            "action": "gateway.a2a_mutual_auth_blocked"
                            if settings.a2a_mutual_auth_enforcement_mode == "enforce"
                            else "gateway.a2a_mutual_auth_warned",
                            "upstream": upstream.name,
                            "tenant_id": tenant_id,
                            "source_agent": source_agent,
                            "target_agent": upstream.name,
                            "weakness": ma_result.weakness,
                            "reason": ma_result.reason,
                        }
                    )
                if settings.a2a_mutual_auth_enforcement_mode == "enforce":
                    record_gateway_relay(upstream.name, "blocked")
                    _emit_gateway_governance_event(
                        "a2a.mutual_auth_blocked",
                        tenant_id=tenant_id,
                        subject_id=source_agent,
                        payload={
                            "source_agent": source_agent,
                            "target_agent": upstream.name,
                            "weakness": ma_result.weakness,
                            "reason": ma_result.reason,
                        },
                    )
                    logger.info(
                        "Gateway A2A mutual-auth blocked edge source_agent=%s target=%s weakness=%s",
                        _sanitize_for_log(source_agent),
                        _sanitize_for_log(upstream.name),
                        _sanitize_for_log(ma_result.weakness),
                    )
                    return JSONResponse(
                        {
                            "jsonrpc": "2.0",
                            "id": message.get("id"),
                            "error": {
                                "code": -32001,
                                "message": "Blocked by agent-bom gateway: inter-agent mutual authentication required",
                                "data": {
                                    "reason": _public_gateway_block_reason("a2a_mutual_auth"),
                                    "policy_source": "a2a_mutual_auth",
                                },
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
                fw_policy: AgentFirewallPolicy = firewall_state.policy
                fw_load_failed = bool(firewall_state.load_failed)
            if fail_closed and fw_load_failed:
                record_gateway_relay(upstream.name, "blocked")
                return JSONResponse(
                    status_code=403,
                    content={
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32000,
                            "message": "gateway firewall policy unavailable",
                        },
                        "id": message.get("id"),
                    },
                )
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
            logger.warning("gateway budget check failed: %s", sanitize_text(_sanitize_for_log(exc)))
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
                logger.warning("gateway cost-center budget check failed: %s", sanitize_text(_sanitize_for_log(exc)))
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

        # Owner (accountable-human) budget enforcement: when the source agent is
        # governed by an approved blueprint, the blueprint's accountable owner may
        # carry an enforce-mode spend cap (#3909). The owner's aggregate spend
        # across every agent they govern is checked here, at the same pre-invocation
        # point as the agent/tenant/cost-center caps. An ungoverned agent, or an
        # owner with no enforce budget, is a no-op; cost-store failures fail open.
        try:
            from agent_bom.api.cost_owner import enforce_owner_budget
            from agent_bom.api.cost_store import get_cost_store

            owner_blocked, owner_budget, owner_spend_usd, budget_owner, budget_workflow = enforce_owner_budget(
                get_cost_store(), tenant_id, source_agent
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("gateway owner budget check failed: %s", sanitize_text(_sanitize_for_log(exc)))
            owner_blocked, owner_budget, owner_spend_usd, budget_owner, budget_workflow = False, None, 0.0, "", ""
        if owner_blocked and owner_budget is not None:
            record_gateway_relay(upstream.name, "blocked")
            if settings.audit_sink is not None:
                await settings.audit_sink(
                    {
                        "action": "gateway.budget_exceeded",
                        "upstream": upstream.name,
                        "tenant_id": tenant_id,
                        "source_agent": source_agent,
                        "owner": budget_owner,
                        "workflow": budget_workflow or None,
                        "limit_usd": owner_budget.limit_usd,
                        "spend_usd": round(owner_spend_usd, 6),
                        "budget_scope": "owner",
                        "reason": "budget_enforced",
                    }
                )
            _emit_gateway_governance_event(
                "budget.exceeded",
                tenant_id=tenant_id,
                subject_id=source_agent,
                payload={
                    "source_agent": source_agent,
                    "owner": budget_owner,
                    "workflow": budget_workflow or None,
                    "limit_usd": owner_budget.limit_usd,
                    "spend_usd": round(owner_spend_usd, 6),
                    "budget_scope": "owner",
                },
            )
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "error": {
                        "code": -32001,
                        "message": "Blocked by agent-bom gateway: owner spend budget exceeded",
                        "data": {"owner": budget_owner, "limit_usd": owner_budget.limit_usd, "spend_usd": round(owner_spend_usd, 6)},
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
        # A store failure is an unknown decision, never an allow in enforce mode.
        fleet_reason = None
        if settings.fleet_enforcement_mode in ("warn", "enforce"):
            fleet_reason = await asyncio.to_thread(_fleet_containment_reason, tenant_id, source_agent)
        if fleet_reason:
            fleet_detail = (
                "agent quarantined in fleet roster" if fleet_reason == "fleet_quarantine" else "fleet identity lookup unavailable"
            )
            if settings.fleet_enforcement_mode == "enforce":
                record_gateway_relay(upstream.name, "blocked")
                if settings.audit_sink is not None:
                    await settings.audit_sink(
                        {
                            "action": "gateway.fleet_blocked",
                            "upstream": upstream.name,
                            "tenant_id": tenant_id,
                            "source_agent": source_agent,
                            "reason": fleet_detail,
                        }
                    )
                _emit_gateway_governance_event(
                    "fleet.blocked",
                    tenant_id=tenant_id,
                    subject_id=source_agent,
                    payload={"source_agent": source_agent, "reason": fleet_detail},
                )
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "error": {
                            "code": -32001,
                            "message": "Blocked by agent-bom gateway: fleet containment",
                            "data": {
                                "reason": _public_gateway_block_reason(fleet_reason),
                                "policy_source": fleet_reason,
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
                        "reason": fleet_detail,
                    }
                )

        resolved_policy_source = "gateway"
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
            # A managed (``abi_``) token carries a per-identity tool scope; if the
            # identity store was unavailable we could not load that scope, so the
            # call must fail closed rather than forward unscoped even when the
            # token still resolves to an agent via a policy mapping. A non-managed
            # token legitimately has no identity scope and is unaffected.
            if allowed and scoped_identity is None and managed_identity_lookup_unavailable and (identity_token or "").startswith("abi_"):
                allowed, reason, policy_source = (
                    False,
                    "managed identity store unavailable; tool scope cannot be verified",
                    "identity_scope",
                )
            elif allowed and scoped_identity is not None and not scoped_identity.tool_allowed(tool_name):
                try:
                    from agent_bom.api.agent_identity_store import active_jit_grant_for_tool, get_agent_identity_store

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
                        device_id=_request_device_id(request),
                        groups=_request_groups(request),
                        client_id=_request_client_id(request),
                    )
                    # Enrich the access context with EDR/MDM device posture so a
                    # require_device_managed/compliant/disk_encrypted policy can
                    # be evaluated. Unknown devices leave posture None → the
                    # guardrail fails closed.
                    try:
                        from agent_bom.device_posture import apply_device_posture, get_device_posture_store

                        apply_device_posture(get_device_posture_store(), ctx, tenant_id=tenant_id)
                    except Exception:  # noqa: BLE001 — enrichment must not break the decision path
                        pass
                    cond_allowed, cond_reason, cond_policy_id = evaluate_conditional_access_for_request(
                        get_agent_identity_store(),
                        tenant_id=tenant_id,
                        ctx=ctx,
                    )
                except Exception:  # noqa: BLE001 — fail CLOSED: an eval error must not bypass a policy
                    cond_allowed, cond_reason, cond_policy_id = _conditional_access_fail_closed(tenant_id)
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
                secured_enforce = settings.drift_enforcement_mode == "enforce" and (
                    bool(current_policy.get("require_agent_identity")) or not _gateway_allows_anonymous_agents(settings)
                )
                blueprint_id = str(getattr(scoped_identity, "blueprint_id", "") or "")
                if not blueprint_id or managed_identity_lookup_unavailable:
                    drift_lookup = _DriftLookup(
                        unavailable=True,
                        reason=(
                            "managed identity store unavailable"
                            if managed_identity_lookup_unavailable
                            else "managed identity has no role blueprint binding"
                        ),
                    )
                else:
                    drift_lookup = _open_drift_violates_tool(tenant_id, blueprint_id, tool_name)

                if drift_lookup.unavailable and secured_enforce:
                    allowed, reason, policy_source = False, drift_lookup.reason, "drift_enforcement"
                elif drift_lookup.unavailable and settings.audit_sink is not None:
                    await settings.audit_sink(
                        {
                            "action": "gateway.drift_binding_unavailable",
                            "upstream": upstream.name,
                            "tenant_id": tenant_id,
                            "source_agent": source_agent,
                            "tool": tool_name,
                            "reason": drift_lookup.reason,
                        }
                    )
                elif drift_lookup.violates:
                    if settings.drift_enforcement_mode == "enforce":
                        allowed, reason, policy_source = False, drift_lookup.reason, "drift_enforcement"
                        _emit_gateway_governance_event(
                            "drift.blocked",
                            tenant_id=tenant_id,
                            subject_id=source_agent,
                            payload={
                                "source_agent": source_agent,
                                "blueprint_id": blueprint_id,
                                "tool": tool_name,
                                "reason": drift_lookup.reason,
                            },
                        )
                    elif settings.audit_sink is not None:
                        await settings.audit_sink(
                            {
                                "action": "gateway.drift_warned",
                                "upstream": upstream.name,
                                "tenant_id": tenant_id,
                                "source_agent": source_agent,
                                "blueprint_id": blueprint_id,
                                "tool": tool_name,
                                "reason": drift_lookup.reason,
                            }
                        )
            # Graph reachability enforcement (consume direction). Prefer the
            # current signed correlation bundle, then fall back to the legacy
            # static report. Bundle verification failures expose only stable
            # reason codes. Missing evidence preserves the legacy allow posture
            # unless the operator explicitly selected failure_mode=deny.
            if allowed and settings.graph_reachability_enforcement_mode in ("warn", "enforce"):
                fetched_runtime_facts: VerifiedRuntimeFacts | None = (
                    runtime_facts_poller.current() if runtime_facts_poller is not None else None
                )
                request_tenant_mismatch = bool(fetched_runtime_facts is not None and fetched_runtime_facts.tenant_id != tenant_id)
                verified_runtime_facts = None if request_tenant_mismatch else fetched_runtime_facts
                effective_reachability = verified_runtime_facts.reachability if verified_runtime_facts is not None else reachability_map
                analysis_incomplete = bool(verified_runtime_facts is not None and not verified_runtime_facts.analysis_complete)
                bundle_unavailable = runtime_facts_configured and (verified_runtime_facts is None or analysis_incomplete)
                strict_evidence_missing = settings.graph_reachability_failure_mode == "deny" and (
                    analysis_incomplete or (verified_runtime_facts is None and (runtime_facts_configured or not reachability_map))
                )
                if bundle_unavailable or strict_evidence_missing:
                    if request_tenant_mismatch:
                        reason_code = "request_tenant_mismatch"
                    elif analysis_incomplete:
                        reason_code = "analysis_incomplete"
                    elif runtime_facts_config_error:
                        reason_code = runtime_facts_config_error
                    elif runtime_facts_poller is not None and runtime_facts_poller.last_error:
                        reason_code = runtime_facts_poller.last_error
                    elif settings.graph_reachability_path is not None:
                        reason_code = "static_evidence_unavailable"
                    else:
                        reason_code = "evidence_not_configured"
                    unavailable_reason = reason_code or "bundle_unavailable"
                    if settings.audit_sink is not None:
                        await settings.audit_sink(
                            {
                                "action": "gateway.graph_reachability_evidence_unavailable",
                                "upstream": upstream.name,
                                "tenant_id": tenant_id,
                                "source_agent": source_agent,
                                "tool": tool_name,
                                "failure_mode": settings.graph_reachability_failure_mode,
                                "reason_code": unavailable_reason,
                            }
                        )
                    if strict_evidence_missing:
                        allowed = False
                        reason = "signed graph reachability evidence unavailable"
                        policy_source = "graph_reachability_evidence"
                        _emit_gateway_governance_event(
                            "graph_reachability.evidence_unavailable",
                            tenant_id=tenant_id,
                            subject_id=source_agent,
                            payload={
                                "source_agent": source_agent,
                                "tool": tool_name,
                                "failure_mode": "deny",
                                "reason_code": unavailable_reason,
                            },
                        )

                reach_hit = None
                try:
                    if allowed and effective_reachability:
                        reach_hit = effective_reachability.reaches_privileged(source_agent, tool_name)
                except Exception as exc:  # noqa: BLE001 — fail-open, never break the relay
                    logger.warning("gateway graph-reachability check failed: %s", sanitize_text(_sanitize_for_log(exc)))
                    if settings.graph_reachability_failure_mode == "deny":
                        allowed = False
                        reason = "graph reachability evaluation unavailable"
                        policy_source = "graph_reachability_evidence"
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
                                    "evidence_source": ("correlation_bundle" if verified_runtime_facts is not None else "scan_report"),
                                    "correlation_id": (verified_runtime_facts.correlation_id if verified_runtime_facts is not None else ""),
                                    "manifest_sha256": (
                                        verified_runtime_facts.manifest_sha256 if verified_runtime_facts is not None else ""
                                    ),
                                    "evidence_freshness": (
                                        verified_runtime_facts.evidence_freshness if verified_runtime_facts is not None else "unknown"
                                    ),
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
                                "evidence_source": ("correlation_bundle" if verified_runtime_facts is not None else "scan_report"),
                                "correlation_id": (verified_runtime_facts.correlation_id if verified_runtime_facts is not None else ""),
                                "manifest_sha256": (verified_runtime_facts.manifest_sha256 if verified_runtime_facts is not None else ""),
                                "evidence_freshness": (
                                    verified_runtime_facts.evidence_freshness if verified_runtime_facts is not None else "unknown"
                                ),
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
                                "evidence_source": ("correlation_bundle" if verified_runtime_facts is not None else "scan_report"),
                                "correlation_id": (verified_runtime_facts.correlation_id if verified_runtime_facts is not None else ""),
                                "manifest_sha256": (verified_runtime_facts.manifest_sha256 if verified_runtime_facts is not None else ""),
                                "evidence_freshness": (
                                    verified_runtime_facts.evidence_freshness if verified_runtime_facts is not None else "unknown"
                                ),
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
                    device_id=_request_device_id(request),
                    groups=_request_groups(request),
                    client_id=_request_client_id(request),
                    attributes=_request_context_attributes(request),
                )
                # Conditional-access rules are a fixed fail-closed lane: an
                # evaluate_conditional_rules error ALWAYS denies and is never
                # softened by AGENT_BOM_GATEWAY_FAIL_MODE (matches the store-backed
                # conditional-access lane and docs/RUNTIME_FAIL_MODES.md).
                try:
                    cond_decision, cond_reason, _cond_rule = evaluate_conditional_rules(current_policy, decision_ctx)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("gateway conditional-rules evaluation error: %s", sanitize_text(_sanitize_for_log(exc)))
                    cond_decision, cond_reason = GatewayDecision.DENY, "conditional rules evaluation error"
                # Policy plugins follow the gateway fail-mode knob (fail-open
                # forwards on a plugin engine error, fail-closed denies).
                try:
                    plugin_decision, plugin_reason, _plugin_name = evaluate_policy_plugins(
                        decision_ctx,
                        current_policy,
                        fail_closed=fail_closed,
                    )
                    plugin_eval_error = False
                except Exception as exc:  # noqa: BLE001
                    logger.warning("gateway plugin evaluation error: %s", sanitize_text(_sanitize_for_log(exc)))
                    plugin_decision, plugin_reason = GatewayDecision.ALLOW, ""
                    plugin_eval_error = True
                # Compose: DENY outranks QUARANTINE outranks ALLOW. Conditional
                # rules win ties over plugins (an explicit policy deny is stronger
                # than a third-party quarantine). A fail-closed plugin eval error denies.
                _rank = {GatewayDecision.ALLOW: 0, GatewayDecision.QUARANTINE: 1, GatewayDecision.DENY: 2}
                if _rank[plugin_decision] > _rank[cond_decision]:
                    composed, composed_reason, composed_source = plugin_decision, plugin_reason, "policy_plugin"
                else:
                    composed, composed_reason, composed_source = cond_decision, cond_reason, "conditional_access"
                if plugin_eval_error and fail_closed:
                    allowed, reason, policy_source = False, "policy evaluation error", "conditional_access"
                elif composed == GatewayDecision.DENY:
                    allowed, reason, policy_source = False, composed_reason, composed_source
                elif composed == GatewayDecision.QUARANTINE:
                    quarantine, quarantine_reason, policy_source = True, composed_reason, composed_source

            # Per-tool-call OAuth scope mapping. A tool with a configured
            # required-scope set is denied unless the caller's token (AS-issued
            # or JWKS-signed) carries every required scope. The "*" key applies a
            # baseline scope to every tool. Empty map = no scope gating.
            if allowed and settings.tool_scope_map:
                required_scopes: set[str] = set()
                for key in ("*", tool_name):
                    mapped = settings.tool_scope_map.get(key)
                    if mapped:
                        required_scopes |= {s for s in mapped if s}
                if required_scopes:
                    missing = required_scopes - token_scopes
                    if missing:
                        allowed, reason, policy_source = (
                            False,
                            f"caller token missing required OAuth scope(s) for '{tool_name}': {', '.join(sorted(missing))}",
                            "oauth_scope",
                        )
                        if settings.audit_sink is not None:
                            await settings.audit_sink(
                                {
                                    "action": "gateway.oauth_scope_blocked",
                                    "upstream": upstream.name,
                                    "tenant_id": tenant_id,
                                    "source_agent": source_agent,
                                    "tool": tool_name,
                                    "required_scopes": sorted(required_scopes),
                                    "missing_scopes": sorted(missing),
                                }
                            )

            # DLP pass on tool-call arguments. Reuses the inline proxy scanner
            # (injection / PII / secrets / payload-vuln). In enforce mode a
            # blocked finding (secrets/payload/injection) denies the call;
            # sensitive args are redacted in-place before forwarding when
            # pii_action=redact. Audit-only otherwise.
            if allowed and dlp_config.enabled:
                arg_findings = scan_tool_call(tool_name, arguments, dlp_config)
                arg_blocked = dlp_config.mode == "enforce" and any(f.blocked for f in arg_findings)
                arg_redacted = dlp_config.mode == "enforce" and dlp_config.pii_action == "redact" and bool(arg_findings) and not arg_blocked
                if arg_findings and settings.audit_sink is not None:
                    typed_arg_event = (
                        _typed_runtime_event(
                            GatewayRuntimeEventType.DLP_ARGUMENTS_REDACTED,
                            decision="allow",
                            policy_source="dlp",
                            tool=tool_name,
                            data_action="pii_redacted",
                        )
                        if arg_redacted
                        else {}
                    )
                    await settings.audit_sink(
                        {
                            "action": "gateway.dlp_arguments",
                            "upstream": upstream.name,
                            "tenant_id": tenant_id,
                            "source_agent": source_agent,
                            "tool": tool_name,
                            "findings": sorted({f"{f.scanner}/{f.rule_id}" for f in arg_findings}),
                            "blocked": arg_blocked,
                            **typed_arg_event,
                        }
                    )
                if arg_blocked:
                    first = next(f for f in arg_findings if f.blocked)
                    allowed, reason, policy_source = (
                        False,
                        f"DLP blocked tool arguments: {first.scanner}/{first.rule_id}",
                        "dlp",
                    )
                elif arg_redacted:
                    # Redact PII in string arguments before forwarding upstream.
                    redacted_args = {k: _redact_obj_pii(v) for k, v in arguments.items()}
                    params = message.get("params")
                    if isinstance(params, dict):
                        params["arguments"] = redacted_args

            if allowed:
                resolved_policy_source = policy_source
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
                    **_typed_runtime_event(
                        GatewayRuntimeEventType.TOOL_CALL_BLOCKED,
                        decision="deny",
                        policy_source=policy_source,
                        tool=tool_name,
                    ),
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

        # Durably admit an authorized tool call before any upstream side effect.
        # Readiness can remove an unhealthy pod from service, but it cannot
        # protect an in-flight/direct request. Persisting the authorization here
        # makes a full/unavailable audit backlog fail closed before execution.
        _forward_is_tool_call = is_tools_call(message)
        if _forward_is_tool_call and settings.audit_sink is None:
            record_gateway_relay(upstream.name, "audit_unavailable")
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "error": {
                        "code": -32003,
                        "message": "Gateway audit persistence unavailable",
                        "data": {
                            "reason": "Tool call was not executed because no durable audit sink is configured",
                            "policy_source": "audit_delivery",
                        },
                    },
                },
                status_code=503,
                headers=rate_limit_headers or None,
            )
        if _forward_is_tool_call and settings.audit_sink is not None:
            try:
                admission = getattr(settings.audit_sink, "admit_before_tool_execution", settings.audit_sink)
                await admission(
                    {
                        "action": "gateway.tool_call",
                        "upstream": upstream.name,
                        "tenant_id": tenant_id,
                        "method": message.get("method"),
                        "tool": extract_tool_name(message),
                        "source_agent": source_agent,
                        **_typed_runtime_event(
                            GatewayRuntimeEventType.TOOL_CALL_ALLOWED,
                            decision="allow",
                            policy_source=resolved_policy_source,
                            tool=extract_tool_name(message) or "",
                        ),
                    }
                )
            except GatewayAuditDeliveryUnavailableError:
                record_gateway_relay(upstream.name, "audit_unavailable")
                return _audit_unavailable_response(message.get("id"), headers=rate_limit_headers or None)

        post_forward_audit_degraded = False

        async def _audit_after_forward(event: dict[str, Any]) -> None:
            """Never turn a completed upstream side effect into an ambiguous 500."""

            nonlocal post_forward_audit_degraded
            if settings.audit_sink is None:
                return
            try:
                await settings.audit_sink(event)
            except Exception as exc:  # noqa: BLE001 - outcome is already produced
                post_forward_audit_degraded = True
                record_gateway_relay(upstream.name, "audit_unavailable")
                logger.error(
                    "Gateway post-forward audit degraded (error_type=%s)",
                    type(exc).__name__,
                )

        def _post_forward_headers(headers: dict[str, str]) -> dict[str, str]:
            if post_forward_audit_degraded:
                headers["X-Agent-BOM-Audit-Delivery"] = "degraded"
            return headers

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
            _strip_gateway_identity_metadata(message),
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
            await _audit_after_forward(
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
                headers=_post_forward_headers({"Retry-After": retry_after_header}),
            ) from exc
        except asyncio.TimeoutError as exc:
            logger.warning("gateway upstream call timed out for %s", upstream.name)
            record_gateway_relay(upstream.name, "upstream_timeout")
            await _audit_after_forward(
                {
                    "action": "gateway.upstream_error",
                    "upstream": upstream.name,
                    "tenant_id": tenant_id,
                    "error": "timeout",
                    "reason": "timeout",
                }
            )
            raise HTTPException(
                status_code=502,
                detail="upstream error: timeout",
                headers=_post_forward_headers({}),
            ) from exc
        except Exception as exc:  # noqa: BLE001
            logger.error("gateway upstream call failed for %s", upstream.name)
            record_gateway_relay(upstream.name, "upstream_error")
            await _audit_after_forward(
                {
                    "action": "gateway.upstream_error",
                    "upstream": upstream.name,
                    "tenant_id": tenant_id,
                    "error": _public_gateway_error(exc),
                }
            )
            raise HTTPException(
                status_code=502,
                detail=f"upstream error: {_public_gateway_error(exc)}",
                headers=_post_forward_headers({}),
            ) from exc

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
                            await _audit_after_forward(
                                {
                                    "action": "gateway.visual_leak_blocked",
                                    "upstream": upstream.name,
                                    "tenant_id": tenant_id,
                                    "tool": tool_name_for_scan,
                                    "alert_count": len(alerts),
                                    "leak_types": sorted({a.details.get("leak_type", "") for a in alerts}),
                                    **_typed_runtime_event(
                                        GatewayRuntimeEventType.VISUAL_REDACTED,
                                        decision="allow",
                                        policy_source="visual_dlp",
                                        tool=str(tool_name_for_scan),
                                        data_action="visual_redacted",
                                    ),
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

        # Shared response policy covers results, errors and notification payloads.
        if dlp_config.enabled and isinstance(upstream_response, dict):
            tool_name_for_dlp = message.get("params", {}).get("name", "") if is_tools_call(message) else str(message.get("method", ""))
            safe_response, resp_findings = scan_jsonrpc_response(upstream_response, dlp_config)
            safe_error = safe_response.get("error")
            result_blocked = isinstance(safe_error, dict) and safe_error.get("code") == -32600 and safe_response != upstream_response
            result_redacted = safe_response != upstream_response and not result_blocked
            if resp_findings and settings.audit_sink is not None:
                typed_result_event: dict[str, Any] = {}
                if result_blocked:
                    typed_result_event = _typed_runtime_event(
                        GatewayRuntimeEventType.DLP_RESULT_BLOCKED,
                        decision="deny",
                        policy_source="dlp",
                        tool=str(tool_name_for_dlp),
                        data_action="sensitive_result_blocked",
                    )
                elif result_redacted:
                    typed_result_event = _typed_runtime_event(
                        GatewayRuntimeEventType.DLP_RESULT_REDACTED,
                        decision="allow",
                        policy_source="dlp",
                        tool=str(tool_name_for_dlp),
                        data_action="pii_redacted",
                    )
                await _audit_after_forward(
                    {
                        "action": "gateway.dlp_result",
                        "upstream": upstream.name,
                        "tenant_id": tenant_id,
                        "source_agent": source_agent,
                        "tool": tool_name_for_dlp,
                        "findings": sorted({f"{f.scanner}/{f.rule_id}" for f in resp_findings}),
                        "blocked": result_blocked,
                        **typed_result_event,
                    }
                )
            if result_blocked:
                record_gateway_relay(upstream.name, "blocked")
                first = next((f for f in resp_findings if f.blocked), resp_findings[0])
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "error": {
                            "code": -32001,
                            "message": "Blocked by agent-bom gateway DLP: sensitive data in tool result",
                            "data": {
                                "reason": _public_gateway_block_reason("dlp"),
                                "policy_source": "dlp",
                                "rule": f"{first.scanner}/{first.rule_id}",
                            },
                        },
                    },
                    status_code=200,
                    headers=_post_forward_headers(dict(rate_limit_headers)) or None,
                )
            upstream_response = safe_response

        if settings.audit_sink is not None and not _forward_is_tool_call:
            forward_audit_event: dict[str, Any] = {
                "action": "gateway.message",
                "upstream": upstream.name,
                "tenant_id": tenant_id,
                "method": message.get("method"),
                "tool": None,
            }
            await _audit_after_forward(forward_audit_event)
        response_headers = dict(rate_limit_headers)
        response_headers["traceparent"] = str(trace_meta["traceparent"])
        if trace_meta["tracestate"]:
            response_headers["tracestate"] = str(trace_meta["tracestate"])
        if trace_meta["baggage"]:
            response_headers["baggage"] = str(trace_meta["baggage"])
        _post_forward_headers(response_headers)
        return JSONResponse(upstream_response, headers=response_headers or None)

    return app


# Re-export the parser for easier test authoring / CLI glue.
__all__ = [
    "ControlPlaneAuditSink",
    "GatewayAuditDeliveryUnavailableError",
    "GatewaySettings",
    "build_control_plane_audit_sink",
    "create_gateway_app",
    "parse_jsonrpc",
]
