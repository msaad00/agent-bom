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
from contextlib import asynccontextmanager
from typing import Any, Mapping

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response

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
from agent_bom.api.gateway_policy import _warn_on_quarantined_agents as _warn_on_quarantined_agents
from agent_bom.api.gateway_rate_limit import _build_gateway_rate_limit_store as _build_gateway_rate_limit_store
from agent_bom.api.gateway_rate_limit import _gateway_configured_replicas as _gateway_configured_replicas
from agent_bom.api.gateway_rate_limit import _gateway_rate_limit_runtime_status as _gateway_rate_limit_runtime_status
from agent_bom.api.gateway_rate_limit import _gateway_shared_rate_limit_required as _gateway_shared_rate_limit_required
from agent_bom.api.gateway_rate_limit import _rate_limit_bucket_component as _rate_limit_bucket_component
from agent_bom.api.gateway_relay_context import RelayRuntime
from agent_bom.api.gateway_relay_context import _emit_gateway_governance_event as _emit_gateway_governance_event
from agent_bom.api.gateway_relay_context import _message_tool_label as _message_tool_label
from agent_bom.api.gateway_relay_context import _public_gateway_block_reason as _public_gateway_block_reason
from agent_bom.api.gateway_relay_context import _public_gateway_error as _public_gateway_error
from agent_bom.api.gateway_relay_context import _redact_obj_pii as _redact_obj_pii
from agent_bom.api.gateway_relay_pipeline import run_relay
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
from agent_bom.api.metrics import record_gateway_relay
from agent_bom.api.oidc_discovery_shim import build_oidc_discovery_shim_router
from agent_bom.api.tracing import get_tracer
from agent_bom.firewall import (
    AgentFirewallPolicy,
    FirewallDecision,
    FirewallEvaluation,
    load_firewall_policy_file,
)
from agent_bom.firewall import evaluate as evaluate_firewall_policy
from agent_bom.proxy import parse_jsonrpc
from agent_bom.proxy_policy import (
    DecisionContext,
    GatewayDecision,
    build_policy_ocsf_event,
    deliver_policy_webhook,
    resolve_fail_mode,
    summarize_policy_bundle,
)
from agent_bom.proxy_scanner import ScanConfig, scan_jsonrpc_response
from agent_bom.runtime.correlation_facts import (
    RUNTIME_FACTS_CACHE_INVALIDATING_ERRORS,
    RuntimeFactsBundleError,
    RuntimeFactsPoller,
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
from agent_bom.runtime.gateway_policy_reload import GatewayPolicyReloader, GatewayPolicyState
from agent_bom.runtime.gateway_policy_reload import _load_policy_file as _load_policy_file
from agent_bom.runtime.gateway_relay import GatewayCircuitBreaker as GatewayCircuitBreaker
from agent_bom.runtime.gateway_relay import GatewayCircuitOpenError as GatewayCircuitOpenError
from agent_bom.runtime.gateway_relay import GatewayUpstreamRelay as GatewayUpstreamRelay
from agent_bom.runtime.gateway_relay import _default_upstream_caller as _default_upstream_caller
from agent_bom.runtime.gateway_relay import _post_upstream_jsonrpc as _post_upstream_jsonrpc
from agent_bom.runtime.gateway_relay_contract import MAX_GATEWAY_RELAY_MESSAGE_BYTES
from agent_bom.runtime.gateway_settings import GatewaySettings as GatewaySettings
from agent_bom.runtime.gateway_settings import validate_gateway_security_settings
from agent_bom.runtime.graph_reachability import ReachabilityMap, load_reachability_map
from agent_bom.runtime.trace_metadata import inject_jsonrpc_trace_meta
from agent_bom.security import sanitize_text

logger = logging.getLogger(__name__)
_GATEWAY_TRACER = get_tracer("agent_bom.gateway")
_MAX_GATEWAY_MESSAGE_BYTES = MAX_GATEWAY_RELAY_MESSAGE_BYTES


# Lazy singleton so disabled deploys don't pay the import cost of the
# visual detector (Pillow/pytesseract). Built on first use when
# ``enable_visual_leak_detection`` is True.
_visual_detector_singleton: Any = None
_visual_detector_lock = threading.Lock()


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
    validate_gateway_security_settings(settings)
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

    relay_runtime = RelayRuntime(
        settings=settings,
        policy_reload=policy_reload,
        firewall_reload=firewall_reload,
        fail_closed=fail_closed,
        runtime_profile_mode=runtime_profile_mode,
        rate_limit_store=rate_limit_store,
        reachability_map=reachability_map,
        runtime_facts_poller=runtime_facts_poller,
        runtime_facts_configured=runtime_facts_configured,
        runtime_facts_config_error=runtime_facts_config_error,
        dlp_config=dlp_config,
        upstream_caller=upstream_caller,
        audit_unavailable=_audit_unavailable_response,
        bind_audit_tenant=_bind_authenticated_audit_tenant,
        emit_policy_interop=_emit_policy_interop_event,
        visual_detector=lambda: _get_visual_leak_detector(),
        response_scanner=lambda message, config: scan_jsonrpc_response(message, config),
        tracer=_GATEWAY_TRACER,
    )

    @app.post("/mcp/{server_name}")
    async def relay(server_name: str, request: Request) -> JSONResponse:
        """Route an MCP JSON-RPC request to the named upstream after policy + audit."""
        return await run_relay(relay_runtime, server_name, request)

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
