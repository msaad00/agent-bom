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
import hashlib
import ipaddress
import json
import logging
import os
import threading
import time
from contextlib import asynccontextmanager, nullcontext
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from agent_bom.a2a_auth_posture import evaluate_inline_mutual_auth
from agent_bom.agent_identity import (
    ANONYMOUS,
    check_caller_identity,
    extract_identity_token,
    identity_token_scopes,
    scopes_from_claims,
)
from agent_bom.api.auth import Role, get_key_store
from agent_bom.api.forwarded_identity import resolve_forwarded_client_ip
from agent_bom.api.metrics import record_gateway_relay, record_rate_limit_hit
from agent_bom.api.middleware import InMemoryRateLimitStore, PostgresRateLimitStore
from agent_bom.api.oauth_as import OAuthAuthorizationServer, build_oauth_as_router
from agent_bom.api.oidc_discovery_shim import OIDCDiscoveryShimConfig, build_oidc_discovery_shim_router
from agent_bom.api.tracing import get_tracer, inject_trace_headers, make_request_trace
from agent_bom.firewall import (
    AgentFirewallPolicy,
    FirewallDecision,
    FirewallEvaluation,
    FirewallPolicyError,
    load_firewall_policy_file,
)
from agent_bom.firewall import evaluate as evaluate_firewall_policy
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry
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
from agent_bom.proxy_scanner import ScanConfig, redact_pii, scan_tool_call, scan_tool_response
from agent_bom.runtime.audit_delivery import (
    AuditDeliveryController,
    AuditDeliveryState,
    AuditSpilloverClaim,
    AuditSpilloverStore,
    audit_delivery_paths,
    canonical_runtime_state_path,
)
from agent_bom.runtime.correlation_facts import (
    RUNTIME_FACTS_CACHE_INVALIDATING_ERRORS,
    RuntimeFactsBundleError,
    RuntimeFactsPoller,
    VerifiedRuntimeFacts,
)
from agent_bom.runtime.fail_mode import gateway_fail_mode_matrix
from agent_bom.runtime.gateway_events import (
    GatewayRuntimeEventType,
    build_gateway_runtime_event,
    canonicalize_gateway_enforcement_event,
    ensure_gateway_event_identity,
)
from agent_bom.runtime.gateway_relay_contract import (
    MAX_GATEWAY_RELAY_MESSAGE_BYTES,
    RelayForwardRequest,
    build_gateway_relay_transport,
    relay_upstream_from_config,
)
from agent_bom.runtime.graph_reachability import ReachabilityMap, load_reachability_map
from agent_bom.runtime.profile_resolution import ProfileResolutionCode
from agent_bom.security import sanitize_error, sanitize_sensitive_payload, sanitize_text

logger = logging.getLogger(__name__)
_GATEWAY_TRACER = get_tracer("agent_bom.gateway")
_MAX_GATEWAY_MESSAGE_BYTES = MAX_GATEWAY_RELAY_MESSAGE_BYTES
_GATEWAY_RELAY_SCOPE = "gateway:relay"

AuditSink = Callable[[dict[str, Any]], Awaitable[None]]
GatewayAuditSender = Callable[[dict[str, Any], dict[str, str]], Awaitable[dict[str, Any]]]
UpstreamCaller = Callable[[UpstreamConfig, dict[str, Any], dict[str, str]], Awaitable[dict[str, Any]]]

_GATEWAY_AUDIT_SPILLOVER_BYTES = 8 * 1024 * 1024
_GATEWAY_AUDIT_DLQ_BYTES = 64 * 1024 * 1024
_GATEWAY_AUDIT_MAX_TENANT_SINKS = 256
_GATEWAY_AUDIT_TENANT_MARKER_MAX_BYTES = 4096
_GATEWAY_AUDIT_TENANT_ID_MAX_BYTES = 512


class GatewayAuditDeliveryUnavailableError(RuntimeError):
    """The gateway could not durably retain a runtime audit event."""


# Lazy singleton so disabled deploys don't pay the import cost of the
# visual detector (Pillow/pytesseract). Built on first use when
# ``enable_visual_leak_detection`` is True.
_visual_detector_singleton: Any = None
_visual_detector_lock = threading.Lock()


def _sanitize_for_log(value: Any) -> str:
    """Return a single-line representation safe for plain-text logs."""
    return sanitize_text(value).replace("\r", "").replace("\n", "")


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
    # Graph-derived reachability enforcement (consume direction). Static report
    # mode remains compatible; signed correlation bundles add opt-in polling and
    # last-valid caching. The global default stays off. Missing evidence allows by
    # default, while an operator can explicitly select deny for a strict lab.
    graph_reachability_path: Path | None = None
    graph_reachability_enforcement_mode: str = "off"
    graph_reachability_failure_mode: str = "allow"
    graph_reachability_bundle_url: str = ""
    graph_reachability_bundle_tenant_id: str = "default"
    graph_reachability_bundle_signing_key: bytes | None = None
    graph_reachability_bundle_bearer_token: str = ""
    graph_reachability_bundle_poll_interval_seconds: float = 30.0
    graph_reachability_bundle_fetcher: Callable[[], Awaitable[Mapping[str, Any]]] | None = None
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
    # Canonical managed client-profile resolution. Off preserves compatibility;
    # warn records unsanctioned callers without blocking; enforce denies before
    # upstream routing. This environment is operator-controlled, never caller-
    # declared X-Agent-Environment metadata.
    runtime_profile_enforcement_mode: str = "off"
    runtime_profile_environment: str = ""
    runtime_profile_issuer: str = "agent-bom"
    # The sole enforcement bypass is explicit *and* loopback-only. Merely
    # binding to loopback does not bypass canonical profile validation.
    allow_runtime_profile_dev_bypass: bool = False
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
    # or under-review agent without touching per-tool policy.
    #
    # Defaults to "enforce": quarantine is an explicit operator action, and the
    # minted deny GatewayPolicy only reaches the relay on the control-plane
    # polling path (proxy.py), never on this one — so "off" made the documented
    # one-click containment a no-op here. The check fails open on store error, so
    # a fleet-store outage cannot become a fleet-wide outage. Opt out with
    # ``--fleet-enforcement off`` / AGENT_BOM_GATEWAY_FLEET_ENFORCEMENT=off.
    fleet_enforcement_mode: str = "enforce"
    # Fail-closed posture for the policy engine. "closed" (the secure default,
    # used when the env var is unset) makes a missing/unloadable policy or an
    # evaluation error DENY so a security-conscious operator never silently runs
    # unprotected. "open" opts back into legacy default-allow on those paths.
    # Resolved by ``resolve_fail_mode`` from AGENT_BOM_GATEWAY_FAIL_MODE when
    # left at the sentinel ``None`` (unset env → "closed").
    fail_mode: str | None = None
    # SIEM/SOAR webhook for deny/quarantine OCSF events. Unset (default) is a
    # no-op; when set, every DENY/QUARANTINE POSTs a normalized OCSF event with
    # an idempotency key. Webhook failures NEVER block the relay (bounded
    # retries + drop-with-warning). Resolved from AGENT_BOM_POLICY_WEBHOOK_URL /
    # AGENT_BOM_POLICY_WEBHOOK_TOKEN when left as ``None``.
    policy_webhook_url: str | None = None
    policy_webhook_token: str | None = None
    # OAuth 2.1 Authorization Server (broker AS). When set, the gateway mounts
    # the RFC 8414 metadata / RFC 7591 registration / PKCE authorize+token /
    # JWKS endpoints so standard MCP clients can auto-authenticate, and accepts
    # AS-issued access tokens (Authorization: Bearer or _meta.agent_identity) as
    # the caller's verified agent identity. None = AS disabled (no behaviour
    # change). The OAuth scopes carried in the token feed ``tool_scope_map``.
    oauth_as: OAuthAuthorizationServer | None = None
    # Static OIDC discovery shim for legacy IdPs that do not publish
    # /.well-known/openid-configuration. Serves public metadata only; tokens
    # still come from the upstream IdP endpoints declared in the config.
    oidc_discovery_shim: OIDCDiscoveryShimConfig | None = None
    # A2A inline mutual-auth enforcement. "off" (default) keeps the existing
    # identity posture; "warn" audits weak (anonymous / unverified / invalid)
    # inter-agent / agent-MCP edges; "enforce" rejects them inline at the relay.
    # An edge is mutually authenticated only when the caller presents a
    # cryptographically-verified identity (AS token, JWKS-verified JWT, or an
    # agent-bom-issued managed token).
    a2a_mutual_auth_enforcement_mode: str = "off"
    # Per-tool-call OAuth scope mapping. ``{tool_name: [required_scope, ...]}``;
    # a "*" key applies to every tool. A tool call is denied when the caller's
    # token scopes do not include every required scope for that tool. Empty map
    # = no scope gating (no behaviour change).
    tool_scope_map: dict[str, list[str]] = field(default_factory=dict)
    # Data-loss prevention on tool-call arguments and tool results. Off by
    # default. "audit" flags sensitive-data matches; "enforce" blocks the call
    # (secrets / payload-vuln / injection) and redacts PII in arguments and
    # results before they cross the relay. Reuses the inline proxy scanner.
    dlp_enabled: bool = False
    dlp_mode: str = "audit"  # "audit" | "enforce"
    dlp_pii_action: str = "redact"  # "redact" | "block"
    dlp_scanners: list[str] = field(default_factory=lambda: ["injection", "pii", "secrets", "payload_vuln"])


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


def _agent_cost_anomaly(tenant_id: str, source_agent: str) -> tuple[bool, str]:
    """Return (anomalous, reason) if ``source_agent`` currently has a cost-spike
    anomaly vs the tenant fleet. Cached upstream; fail-open on any store error."""
    if not source_agent:
        return False, ""
    try:
        from agent_bom.api.anomaly import cost_anomalous_agents

        flagged = cost_anomalous_agents(tenant_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("gateway anomaly check failed: %s", sanitize_text(_sanitize_for_log(exc)))
        return False, ""
    info = flagged.get(source_agent)
    if info:
        return True, (f"agent '{source_agent}' has anomalous spend (z={info.get('z_score')}) vs the tenant fleet baseline")
    return False, ""


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


def _agent_is_quarantined(tenant_id: str, source_agent: str) -> bool:
    """Return True when ``source_agent`` is quarantined in this tenant's fleet.

    Resolves one agent through an indexed lookup rather than paging the roster:
    this runs on every relay call, so its cost must not scale with fleet size.
    Fail-open: fleet-store errors are logged and never block the relay.

    Blocking I/O — call it off the event loop.
    """
    if not source_agent:
        return False
    try:
        from agent_bom.api.fleet_store import FleetLifecycleState, find_fleet_agent
        from agent_bom.api.stores import _get_fleet_store

        agent = find_fleet_agent(_get_fleet_store(), tenant_id, source_agent)
    except Exception as exc:  # noqa: BLE001
        logger.warning("gateway fleet check failed: %s", sanitize_text(_sanitize_for_log(exc)))
        return False
    if agent is None:
        return False
    return bool(getattr(agent, "lifecycle_state", None) == FleetLifecycleState.QUARANTINED)


def _agent_identity_revoked(tenant_id: str, source_agent: str) -> tuple[bool, bool, bool]:
    """Return ``(revoked, lookup_incomplete, lookup_failed)`` for a caller with
    no managed token.

    ``identity_for_token`` only matches an agent-bom-issued ``abi_`` token, so a
    JWKS/OIDC JWT or an opaque ``policy.agent_tokens`` caller previously bypassed
    identity revocation entirely.

    The two failure signals are deliberately distinct because they warrant
    different verdicts:

    * ``lookup_incomplete`` — the store answered, but with a result it knows is
      partial. A revoked row may be sitting in the untraversed tail, so the
      answer is unusable and the relay denies unconditionally.
    * ``lookup_failed`` — the store did not answer at all. Fail-open, gated on
      posture, so an identity-store outage never becomes a fleet-wide outage.

    Blocking I/O — call it off the event loop.
    """
    if not source_agent or source_agent == ANONYMOUS:
        return False, False, False
    try:
        from agent_bom.api.agent_identity_store import agent_identity_revoked, get_agent_identity_store

        revoked, lookup_incomplete = agent_identity_revoked(get_agent_identity_store(), tenant_id, source_agent)
        return revoked, lookup_incomplete, False
    except Exception as exc:  # noqa: BLE001
        logger.warning("gateway agent identity revocation check failed: %s", sanitize_text(_sanitize_for_log(exc)))
        return False, False, True


# Upper bound on open incidents fetched per drift enforcement check. When a
# tenant has more open incidents than this, we cannot rule out a violation in the
# untraversed tail, so the lookup returns ``unavailable`` (honest partial signal)
# rather than silently under-enforcing on the capped result.
_DRIFT_INCIDENT_LOOKUP_CAP = 200


@dataclass(frozen=True)
class _DriftLookup:
    violates: bool = False
    unavailable: bool = False
    reason: str = ""


def _open_drift_violates_tool(tenant_id: str, blueprint_id: str, tool_name: str) -> _DriftLookup:
    """Look up a tool violation for a caller's resolved role blueprint.

    Drift incidents are keyed by ``blueprint_id``.  They are never keyed by an
    agent id, so callers must resolve the managed identity -> blueprint binding
    before invoking this function.  Store unavailability is returned explicitly
    so secured enforce-mode callers can fail closed while development/audit
    modes can remain observable without silently inventing a match.
    """
    if not blueprint_id or not tool_name:
        return _DriftLookup()
    try:
        from agent_bom.api.drift_incident_store import get_drift_incident_store

        incidents = get_drift_incident_store().list(tenant_id, include_resolved=False, limit=_DRIFT_INCIDENT_LOOKUP_CAP)
    except Exception as exc:  # noqa: BLE001
        logger.warning("gateway drift check failed: %s", sanitize_text(_sanitize_for_log(exc)))
        return _DriftLookup(unavailable=True, reason="drift incident store unavailable")
    blueprint_key = blueprint_id.strip().lower().replace("-", "_")
    for incident in incidents:
        incident_blueprint = (getattr(incident, "blueprint_id", "") or "").strip().lower().replace("-", "_")
        if incident_blueprint != blueprint_key:
            continue
        drifted_tools = {
            str(v.get("tool_name", "")).strip() for v in (getattr(incident, "top_violations", None) or []) if isinstance(v, dict)
        }
        if tool_name in drifted_tools:
            return _DriftLookup(
                violates=True,
                reason=f"tool '{tool_name}' is outside role blueprint '{blueprint_id}'",
            )
    if len(incidents) >= _DRIFT_INCIDENT_LOOKUP_CAP:
        # The open-incident set was capped, so a violation may exist in the tail
        # we never inspected. Surface this as unavailable (partial) instead of a
        # clean pass, so enforce-mode callers fail closed rather than silently
        # under-enforce for the tenant's tail incidents.
        logger.warning(
            "gateway drift check truncated at %d open incidents for tenant; enforcement coverage is partial",
            _DRIFT_INCIDENT_LOOKUP_CAP,
        )
        return _DriftLookup(
            unavailable=True,
            reason=f"open drift incidents exceed lookup cap ({_DRIFT_INCIDENT_LOOKUP_CAP}); enforcement coverage partial",
        )
    return _DriftLookup()


def _validate_gateway_rule_patterns(policies: list[Any]) -> tuple[bool, str]:
    """Fail closed when a control-plane rule carries an invalid regex pattern."""
    import re

    for policy in policies:
        for rule in policy.rules:
            if rule.tool_name_pattern:
                try:
                    re.compile(rule.tool_name_pattern)
                except re.error:
                    logger.error(
                        "gateway control-plane bundle: invalid tool_name_pattern in rule %s (policy %s); failing closed",
                        rule.id,
                        policy.policy_id,
                    )
                    return False, "control-plane policy malformed"
            for arg_name, arg_regex in (rule.arg_pattern or {}).items():
                try:
                    re.compile(arg_regex)
                except re.error:
                    logger.error(
                        "gateway control-plane bundle: invalid arg_pattern for %s in rule %s (policy %s); failing closed",
                        arg_name,
                        rule.id,
                        policy.policy_id,
                    )
                    return False, "control-plane policy malformed"
    return True, ""


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
        from agent_bom.gateway import evaluate_gateway_policy_bundle

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
            logger.error(
                "gateway control-plane bundle: %d policy/policies failed to parse; failing closed",
                parse_errors,
            )
            return False, "control-plane policy malformed"
        patterns_ok, pattern_reason = _validate_gateway_rule_patterns(policies)
        if not patterns_ok:
            return False, pattern_reason
        return evaluate_gateway_policy_bundle(policies, source_agent, tool_name, arguments)
    except Exception as exc:  # noqa: BLE001
        # Fail closed: a bundle that cannot be evaluated must not silently pass.
        logger.warning("gateway control-plane bundle evaluation failed: %s", sanitize_text(_sanitize_for_log(exc)))
        return False, "control-plane policy evaluation error"


def _request_source_ip(request: Request) -> str:
    """Resolve the caller IP for conditional-access CIDR conditions.

    The transport peer is authoritative unless the deployment declares both a
    bounded proxy depth and trusted transport-peer CIDRs.  This prevents a
    direct caller from satisfying an allowlisted CIDR by spoofing
    ``X-Forwarded-For``.
    """
    client = getattr(request, "client", None)
    return resolve_forwarded_client_ip(
        peer_host=getattr(client, "host", "") or "",
        forwarded_for=request.headers.get("x-forwarded-for", ""),
    )


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


def _request_device_id(request: Request) -> str:
    """Resolve the caller device/workstation id for device ABAC conditions.

    Read from the ``x-agent-device-id`` header (set by the endpoint agent / MDM
    posture broker). Empty when unset, in which case a device condition simply
    fails closed for policies that require one.
    """
    return (request.headers.get("x-agent-device-id", "") or "").strip()[:200]


def _request_groups(request: Request) -> list[str]:
    """Resolve the caller's directory groups for group ABAC conditions.

    Groups arrive comma-separated in the ``x-agent-groups`` header (asserted by
    the IdP / trust proxy after authentication). Bounded and de-duplicated.
    """
    raw = (request.headers.get("x-agent-groups", "") or "").strip()
    if not raw:
        return []
    seen: list[str] = []
    for part in raw.split(","):
        value = part.strip()[:120]
        if value and value not in seen:
            seen.append(value)
        if len(seen) >= 64:
            break
    return seen


def _request_client_id(request: Request) -> str:
    """Resolve the MCP client application id for client ABAC conditions.

    Read from the ``x-agent-client-id`` header (the client app making the call).
    Empty when unset; a client condition fails closed for policies requiring one.
    """
    return (request.headers.get("x-agent-client-id", "") or "").strip()[:200]


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


_CONDITIONAL_ACCESS_EVAL_FAILED = "conditional access evaluation failed"


def _conditional_access_fail_closed(tenant_id: str) -> tuple[bool, str, str]:
    """Decide the conditional-access outcome after an evaluation error, fail-closed.

    The primary evaluation (``evaluate_conditional_access_for_request``) raised, so
    we cannot trust its verdict. A conditional-access ``deny``/``require`` policy
    that would otherwise block the call MUST NOT be silently bypassed (§7 fail
    closed). But we also must not turn a flaky store into a blanket outage for
    tenants that never configured the feature.

    Resolution:
    - Re-read the tenant's active conditional-access policies with a cheap,
      independent lookup. If that read succeeds and finds **no** policies, there
      is no gate to bypass → allow.
    - If the tenant HAS one or more active conditional-access policies → deny.
    - If we cannot even determine whether policies exist (the lookup also
      raised — e.g. the store is unavailable), we cannot prove the gate is empty,
      so deny. Only a positively-confirmed empty policy set opens the gate.

    Returns ``(allowed, reason, policy_id)`` matching the primary evaluator.
    """
    try:
        from agent_bom.api.agent_identity_store import get_agent_identity_store

        policies = get_agent_identity_store().list_conditional_policies(tenant_id, include_disabled=False, limit=1)
    except Exception:  # noqa: BLE001 — cannot confirm an empty gate → fail closed
        return False, _CONDITIONAL_ACCESS_EVAL_FAILED, ""
    if not policies:
        return True, "", ""
    return False, _CONDITIONAL_ACCESS_EVAL_FAILED, ""


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
        self._clients: dict[bool, Any] = {}
        self._client_lock = asyncio.Lock()
        self._breaker = GatewayCircuitBreaker(
            failure_threshold=settings.upstream_failure_threshold,
            cooldown_seconds=settings.upstream_circuit_cooldown_seconds,
        )

    async def aclose(self) -> None:
        async with self._client_lock:
            clients = list(self._clients.values())
            self._clients.clear()
            for client in clients:
                await client.aclose()

    async def _client_for_call(self, *, allow_private_networks: bool) -> Any:
        client = self._clients.get(allow_private_networks)
        if client is not None:
            return client
        async with self._client_lock:
            client = self._clients.get(allow_private_networks)
            if client is None:
                import httpx

                from agent_bom.runtime.egress_transport import build_pinned_async_client

                client = build_pinned_async_client(
                    allow_private_networks=allow_private_networks,
                    timeout=httpx.Timeout(self._timeout_seconds),
                    limits=httpx.Limits(
                        max_connections=self._max_connections,
                        max_keepalive_connections=self._max_keepalive_connections,
                    ),
                )
                self._clients[allow_private_networks] = client
            return client

    async def __call__(
        self,
        upstream: UpstreamConfig,
        message: dict[str, Any],
        extra_headers: dict[str, str],
    ) -> dict[str, Any]:
        circuit_key = _upstream_circuit_key(upstream)
        await self._breaker.before_call(circuit_key, upstream.name)
        try:
            allow_private = upstream.private_network_approved
            response = await _post_upstream_jsonrpc(
                upstream,
                message,
                extra_headers,
                client=await self._client_for_call(allow_private_networks=allow_private),
            )
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
        logger.warning("Gateway key store status unavailable: %s", sanitize_text(_sanitize_for_log(exc)))
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


def _validate_runtime_profile_posture(settings: GatewaySettings) -> str:
    """Validate and return the canonical profile-enforcement mode."""
    mode = settings.runtime_profile_enforcement_mode.strip().lower()
    if mode not in {"off", "warn", "enforce"}:
        raise RuntimeError("runtime profile enforcement mode must be off, warn, or enforce")
    if mode != "off" and not settings.runtime_profile_environment.strip():
        raise RuntimeError("runtime profile enforcement requires an operator-controlled profile environment")
    if mode != "off" and not settings.runtime_profile_issuer.strip():
        raise RuntimeError("runtime profile enforcement requires a trusted profile issuer")
    if settings.allow_runtime_profile_dev_bypass and not _is_loopback_host(settings.listener_host):
        raise RuntimeError("runtime profile development bypass is permitted only on a loopback listener")
    return mode


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


def _configured_gateway_tenant_id() -> str:
    return os.environ.get("AGENT_BOM_TENANT_ID", "default").strip() or "default"


def _authenticate_gateway_request(request: Request, settings: GatewaySettings) -> tuple[str, str]:
    raw_token = _extract_request_token(request)
    if settings.bearer_token:
        if not raw_token or not _request_has_expected_token(request, settings.bearer_token):
            raise HTTPException(status_code=401, detail="gateway authentication required")
        return _configured_gateway_tenant_id(), "static_gateway_token"

    # OAuth 2.1 broker: a standard MCP client presenting an AS-issued access
    # token in the Authorization header satisfies transport auth (the AS already
    # authenticated the client + bound the token via PKCE). Only AS-signed,
    # unexpired tokens pass; any other bearer falls through to API-key auth.
    if settings.oauth_as is not None and raw_token:
        claims = settings.oauth_as.validate_token(raw_token)
        if claims is not None:
            return _configured_gateway_tenant_id(), "oauth_as"

    try:
        store = get_key_store()
        has_keys = store.has_keys()
    except Exception as exc:
        logger.warning("Gateway key store unavailable: %s", sanitize_text(_sanitize_for_log(exc)))
        raise HTTPException(status_code=503, detail="gateway authentication unavailable") from exc

    if has_keys:
        try:
            api_key = store.verify(raw_token) if raw_token else None
        except Exception as exc:
            logger.warning("Gateway key verification unavailable: %s", sanitize_text(_sanitize_for_log(exc)))
            raise HTTPException(status_code=503, detail="gateway authentication unavailable") from exc
        if api_key is None:
            raise HTTPException(status_code=401, detail="gateway authentication required")
        allowed, reason = _api_key_allows_gateway_relay(api_key)
        if not allowed:
            raise HTTPException(status_code=403, detail=reason)
        return api_key.tenant_id or "default", "api_key"

    return _configured_gateway_tenant_id(), "none"


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


def _strip_gateway_identity_metadata(message: dict[str, Any]) -> dict[str, Any]:
    """Remove the gateway caller credential before crossing the upstream boundary."""
    params = message.get("params")
    if not isinstance(params, dict):
        return message
    raw_meta = params.get("_meta")
    if not isinstance(raw_meta, dict) or "agent_identity" not in raw_meta:
        return message
    forwarded = dict(message)
    forwarded_params = dict(params)
    forwarded_meta = dict(raw_meta)
    forwarded_meta.pop("agent_identity", None)
    if forwarded_meta:
        forwarded_params["_meta"] = forwarded_meta
    else:
        forwarded_params.pop("_meta", None)
    forwarded["params"] = forwarded_params
    return forwarded


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

    from agent_bom.runtime.egress_transport import build_pinned_async_client

    allow_private = upstream.private_network_approved
    async with build_pinned_async_client(
        allow_private_networks=allow_private,
        timeout=httpx.Timeout(30.0),
    ) as client:
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
    """Forward via the pure-relay contract (Python in-process or Go sidecar).

    Backend selected by ``AGENT_BOM_GATEWAY_RELAY_BACKEND`` (default ``python``).
    When ``go``, the shared httpx client talks to the sidecar ``/v1/forward``;
    the sidecar then POSTs to the upstream URL.
    """
    auth_headers = await upstream.resolve_auth_headers()
    target = relay_upstream_from_config(upstream)
    transport = build_gateway_relay_transport(client, max_bytes=_MAX_GATEWAY_MESSAGE_BYTES)
    result = await transport.forward(
        RelayForwardRequest(
            upstream=target,
            message=message,
            headers={**auth_headers, **extra_headers},
        )
    )
    return result.message


async def _read_bounded_gateway_body(request: Any) -> bytes:
    """Read a gateway request without buffering past the JSON-RPC limit."""
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > _MAX_GATEWAY_MESSAGE_BYTES:
            raise HTTPException(status_code=413, detail="gateway request exceeds maximum JSON-RPC message size")
        body.extend(chunk)
    return bytes(body)


async def _send_gateway_audit_batch(
    audit_url: str,
    payload: dict[str, Any],
    headers: dict[str, str],
) -> dict[str, Any]:
    """POST one already-redacted backlog batch to the control plane."""

    import httpx

    async with httpx.AsyncClient(timeout=httpx.Timeout(connect=5.0, read=10.0, write=10.0, pool=5.0)) as client:
        response = await client.post(audit_url, json=payload, headers=headers)
        response.raise_for_status()
        body = response.json()
    if not isinstance(body, dict):
        raise RuntimeError("control-plane audit acknowledgement is not an object")
    return body


class _GatewayAuditTenantRegistry:
    """Secret-free durable discovery markers for tenant audit backlogs."""

    def __init__(self, state_dir: Path, *, source_id: str, audit_url: str) -> None:
        router_identity = f"{source_id}\0{audit_url}"
        router_digest = hashlib.sha256(router_identity.encode("utf-8")).hexdigest()[:20]
        self._root = canonical_runtime_state_path(state_dir) / "runtime-audit"
        self._prefix = f"gateway-router-{router_digest}-"

    @staticmethod
    def _normalize_tenant_id(tenant_id: str) -> str:
        normalized = tenant_id.strip()
        encoded = normalized.encode("utf-8")
        if not normalized or len(encoded) > _GATEWAY_AUDIT_TENANT_ID_MAX_BYTES or any(ord(character) < 32 for character in normalized):
            raise ValueError("gateway audit tenant id is invalid")
        return normalized

    def _marker_name(self, tenant_id: str) -> str:
        normalized = self._normalize_tenant_id(tenant_id)
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:20]
        return f"{self._prefix}{digest}.tenant.json"

    def _parent_fd(self) -> int:
        return AuditSpilloverStore._safe_parent_fd(self._root / ".tenant-registry")

    def register(self, tenant_id: str) -> None:
        """Atomically persist one tenant identity without its credential."""

        normalized = self._normalize_tenant_id(tenant_id)
        marker_name = self._marker_name(normalized)
        content = json.dumps(
            {"schema_version": 1, "tenant_id": normalized},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if len(content) > _GATEWAY_AUDIT_TENANT_MARKER_MAX_BYTES:
            raise ValueError("gateway audit tenant marker is too large")
        parent_fd = self._parent_fd()
        temp_name = f".{marker_name}.tmp-{os.urandom(8).hex()}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        fd = -1
        try:
            try:
                existing = os.stat(marker_name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                AuditSpilloverStore._validate_single_link_regular(existing)
            fd = os.open(temp_name, flags, 0o600, dir_fd=parent_fd)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, marker_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            os.close(parent_fd)

    def discover(self) -> list[str]:
        """Load and validate every marker for this control-plane route."""

        parent_fd = self._parent_fd()
        tenants: set[str] = set()
        read_flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            read_flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            read_flags |= os.O_CLOEXEC
        try:
            names = sorted(name for name in os.listdir(parent_fd) if name.startswith(self._prefix) and name.endswith(".tenant.json"))
            for name in names:
                fd = os.open(name, read_flags, dir_fd=parent_fd)
                try:
                    file_stat = os.fstat(fd)
                    AuditSpilloverStore._validate_single_link_regular(file_stat)
                    if file_stat.st_mode & 0o077:
                        raise ValueError("gateway audit tenant marker permissions must be owner-only")
                    if file_stat.st_size > _GATEWAY_AUDIT_TENANT_MARKER_MAX_BYTES:
                        raise ValueError("gateway audit tenant marker is too large")
                    with os.fdopen(fd, "rb") as handle:
                        fd = -1
                        raw = handle.read(_GATEWAY_AUDIT_TENANT_MARKER_MAX_BYTES + 1)
                finally:
                    if fd >= 0:
                        os.close(fd)
                payload = json.loads(raw.decode("utf-8"))
                if not isinstance(payload, dict) or payload.get("schema_version") != 1:
                    raise ValueError("gateway audit tenant marker schema is invalid")
                tenant_id = self._normalize_tenant_id(str(payload.get("tenant_id") or ""))
                if name != self._marker_name(tenant_id):
                    raise ValueError("gateway audit tenant marker identity is invalid")
                tenants.add(tenant_id)
        finally:
            os.close(parent_fd)
        return sorted(tenants)

    def unregister(self, tenant_id: str) -> None:
        """Remove a marker only after its durable backlog is empty."""

        marker_name = self._marker_name(tenant_id)
        parent_fd = self._parent_fd()
        try:
            try:
                existing = os.stat(marker_name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return
            AuditSpilloverStore._validate_single_link_regular(existing)
            os.unlink(marker_name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)


def _audit_health_has_pending_state(health: dict[str, str | int | bool]) -> bool:
    """Return whether a tenant marker must remain for unresolved audit state."""

    return (
        not bool(health.get("backlog_observable", False))
        or int(health.get("backlog_bytes", 0)) > 0
        or int(health.get("dlq_bytes", 0)) > 0
        or int(health.get("dropped_events", 0)) > 0
    )


class ControlPlaneAuditSink:
    """Durably queue and retry standalone-gateway audit delivery.

    A remote outage is fail-safe while the bounded local backlog accepts the
    event: the relay may continue and health reports degraded. If neither the
    spill file nor its finite DLQ can retain the event, ``__call__`` raises and
    the gateway fails closed instead of acknowledging an unaudited decision.
    """

    def __init__(
        self,
        *,
        base_url: str,
        token: str | None,
        tenant_id: str,
        source_id: str,
        session_id: str,
        delivery_state: AuditDeliveryState,
        sender: GatewayAuditSender,
        tenant_registry: _GatewayAuditTenantRegistry | None = None,
        tenant_routing_enabled: bool = True,
        max_tenant_sinks: int = _GATEWAY_AUDIT_MAX_TENANT_SINKS,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._tenant_id = tenant_id
        self._source_id = source_id
        self._session_id = session_id
        self._delivery_state = delivery_state
        self._sender = sender
        self._tenant_registry = tenant_registry
        self._tenant_registry_available = True
        self._lock = asyncio.Lock()
        self._worker: asyncio.Task[None] | None = None
        self._closed = False
        self._persistence_available = True
        self._remote_ack_available = True
        self._tenant_routing_enabled = tenant_routing_enabled
        self._max_tenant_sinks = max_tenant_sinks
        self._tenant_sinks: dict[str, ControlPlaneAuditSink] = {}
        self._tenant_sinks_lock = asyncio.Lock()

    async def bind_authenticated_tenant(self, tenant_id: str, token: str | None) -> None:
        """Bind one verified request credential to an isolated tenant queue."""

        normalized_tenant = tenant_id.strip()
        if not normalized_tenant:
            raise GatewayAuditDeliveryUnavailableError("authenticated audit tenant is unavailable")
        if self._tenant_registry is not None and not self._tenant_registry_available:
            raise GatewayAuditDeliveryUnavailableError("tenant audit routing registry is unavailable")
        if normalized_tenant == self._tenant_id:
            if token:
                self._token = token
            return
        if not self._tenant_routing_enabled or not token:
            raise GatewayAuditDeliveryUnavailableError("no tenant-bound audit credential is available")
        async with self._tenant_sinks_lock:
            sink = self._tenant_sinks.get(normalized_tenant)
            if sink is None:
                if len(self._tenant_sinks) >= self._max_tenant_sinks:
                    raise GatewayAuditDeliveryUnavailableError("tenant audit routing capacity is unavailable")
                if self._tenant_registry is None:
                    raise GatewayAuditDeliveryUnavailableError("tenant audit routing registry is unavailable")
                try:
                    self._tenant_registry.register(normalized_tenant)
                except Exception as exc:  # noqa: BLE001 - registry integrity is fail-closed
                    self._tenant_registry_available = False
                    logger.error("Gateway audit tenant registry unavailable (error_type=%s)", type(exc).__name__)
                    raise GatewayAuditDeliveryUnavailableError("tenant audit routing registry is unavailable") from None
                sink = build_control_plane_audit_sink(
                    self._base_url,
                    token,
                    tenant_id=normalized_tenant,
                    source_id=self._source_id,
                    sender=self._sender,
                    tenant_routing_enabled=False,
                    max_tenant_sinks=0,
                )
                self._tenant_sinks[normalized_tenant] = sink
                await sink.start()
            else:
                sink._token = token
                sink._remote_ack_available = True
                await sink.start()

    async def _recover_tenant_sinks(self) -> None:
        """Reconstruct unbound child queues so restart health remains truthful."""

        if self._tenant_registry is None or self._tenant_sinks:
            return
        try:
            tenant_ids = self._tenant_registry.discover()
            for tenant_id in tenant_ids:
                if tenant_id == self._tenant_id:
                    self._tenant_registry.unregister(tenant_id)
                    continue
                if len(self._tenant_sinks) >= self._max_tenant_sinks:
                    raise ValueError("gateway audit tenant registry exceeds configured capacity")
                sink = build_control_plane_audit_sink(
                    self._base_url,
                    None,
                    tenant_id=tenant_id,
                    source_id=self._source_id,
                    sender=self._sender,
                    tenant_routing_enabled=False,
                    max_tenant_sinks=0,
                )
                child_health = sink._own_health()
                if not _audit_health_has_pending_state(child_health):
                    self._tenant_registry.unregister(tenant_id)
                    continue
                sink._remote_ack_available = False
                self._tenant_sinks[tenant_id] = sink
        except Exception as exc:  # noqa: BLE001 - undiscoverable durable state is fail-closed
            self._tenant_registry_available = False
            logger.error("Gateway audit tenant registry recovery failed (error_type=%s)", type(exc).__name__)

    def _sink_for_event(self, event: dict[str, Any]) -> ControlPlaneAuditSink:
        if self._tenant_registry is not None and not self._tenant_registry_available:
            raise GatewayAuditDeliveryUnavailableError("tenant audit routing registry is unavailable")
        event_tenant = str(event.get("tenant_id") or "")
        if event_tenant == self._tenant_id:
            return self
        sink = self._tenant_sinks.get(event_tenant)
        if sink is None:
            raise GatewayAuditDeliveryUnavailableError("no tenant-bound audit credential is available")
        return sink

    @staticmethod
    def _batch_idempotency_key(session_id: str, events: list[dict[str, Any]]) -> str:
        event_identities = [
            str(event.get("event_id"))
            if event.get("event_id")
            else hashlib.sha256(json.dumps(event, separators=(",", ":"), sort_keys=True, ensure_ascii=True).encode("utf-8")).hexdigest()
            for event in events
        ]
        material = json.dumps([session_id, event_identities], separators=(",", ":"), ensure_ascii=True)
        return "gateway-audit-" + hashlib.sha256(material.encode("utf-8")).hexdigest()

    @staticmethod
    def _validate_acknowledgement(events: list[dict[str, Any]], response: dict[str, Any]) -> None:
        from agent_bom.runtime.gateway_events import GATEWAY_CANONICAL_EVENT_TYPES

        canonical_count = sum(str(event.get("event_type") or "") in GATEWAY_CANONICAL_EVENT_TYPES for event in events)
        durable_count = int(response.get("durable_accepted_count") or 0) + int(response.get("durable_duplicate_count") or 0)
        conflict_count = int(response.get("durable_conflict_count") or 0)
        accepted_count = int(response.get("accepted_alert_count") or 0) + int(response.get("duplicate_alert_count") or 0)
        if conflict_count or durable_count < canonical_count:
            raise RuntimeError("control plane did not durably acknowledge canonical gateway activity")
        if accepted_count < len(events):
            raise RuntimeError("control plane did not acknowledge the complete gateway audit batch")

    def _payload(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "source_id": self._source_id,
            "session_id": self._session_id,
            "idempotency_key": self._batch_idempotency_key(self._session_id, events),
            "alerts": events,
        }

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    async def _persist_and_flush(self, event: dict[str, Any], *, require_remote_ack: bool) -> None:
        async with self._lock:
            try:
                if not self._persistence_available:
                    raise GatewayAuditDeliveryUnavailableError("durable audit backlog is unavailable")
                event = canonicalize_gateway_enforcement_event(ensure_gateway_event_identity(event))
                event_tenant = str(event.get("tenant_id") or "")
                if event_tenant != self._tenant_id:
                    raise GatewayAuditDeliveryUnavailableError("audit credential is not bound to the event tenant")
                if self._delivery_state.store.dlq_size_bytes() or self._delivery_state.store.dropped_events:
                    self._persistence_available = False
                    raise GatewayAuditDeliveryUnavailableError("durable audit backlog is full")
                destination = self._delivery_state.store.append_events([event])
            except GatewayAuditDeliveryUnavailableError:
                raise
            except Exception as exc:  # noqa: BLE001 - local durability failure is fail-closed
                self._persistence_available = False
                logger.error("Gateway audit persistence unavailable (error_type=%s)", type(exc).__name__)
                raise GatewayAuditDeliveryUnavailableError("durable audit backlog is unavailable") from None
            if destination in {"dlq", "dropped"}:
                self._persistence_available = False
                raise GatewayAuditDeliveryUnavailableError("durable audit backlog is full")
            self._persistence_available = True
            flushed = False
            if not self._delivery_state.controller.is_circuit_open():
                flushed = await self._flush_locked()
            if not flushed and not self._persistence_available:
                raise GatewayAuditDeliveryUnavailableError("durable audit backlog is unavailable")
            if require_remote_ack and not flushed:
                raise GatewayAuditDeliveryUnavailableError("control-plane durable acknowledgement is unavailable")

    async def __call__(self, event: dict[str, Any]) -> None:
        sink = self._sink_for_event(event)
        if sink is not self:
            await sink(event)
            return
        await self._persist_and_flush(event, require_remote_ack=False)

    async def admit_before_tool_execution(self, event: dict[str, Any]) -> None:
        """Require the control plane to durably acknowledge before execution."""

        sink = self._sink_for_event(event)
        if sink is not self:
            await sink.admit_before_tool_execution(event)
            return
        await self._persist_and_flush(event, require_remote_ack=True)

    async def _flush_locked(self) -> bool:
        try:
            claim = self._delivery_state.store.claim_spillover()
        except Exception as exc:  # noqa: BLE001 - health must report local durability failure
            self._persistence_available = False
            logger.error("Gateway audit persistence unavailable during retry (error_type=%s)", type(exc).__name__)
            return False
        if claim is None:
            self._persistence_available = True
            return True
        if not claim.events:
            self._delivery_state.store.acknowledge_claim(claim)
            return True
        active_claim: AuditSpilloverClaim | None = claim
        try:
            while active_claim is not None:
                events = active_claim.events[:500]
                response = await self._sender(self._payload(events), self._headers())
                self._validate_acknowledgement(events, response)
                active_claim = self._delivery_state.store.acknowledge_claim_prefix(active_claim, len(events))
        except asyncio.CancelledError:
            if active_claim is not None:
                self._delivery_state.store.restore_claim(active_claim)
            raise
        except Exception as exc:  # noqa: BLE001 - retained backlog is retried
            try:
                if active_claim is not None:
                    self._delivery_state.store.restore_claim(active_claim)
            except Exception:  # noqa: BLE001 - do not leak persistence exception details
                self._persistence_available = False
                logger.error("Gateway audit persistence unavailable while retaining a failed delivery")
            self._delivery_state.controller.record_failure()
            self._remote_ack_available = False
            logger.warning("Gateway audit push failed; retained for retry (error_type=%s)", type(exc).__name__)
            return False
        self._persistence_available = True
        self._remote_ack_available = True
        self._delivery_state.controller.record_success()
        return True

    async def flush_once(self) -> bool:
        """Attempt one serialized backlog delivery, primarily for startup/tests."""

        async with self._lock:
            if self._delivery_state.controller.is_circuit_open():
                return False
            return await self._flush_locked()

    async def _retry_loop(self) -> None:
        while True:
            await asyncio.sleep(self._delivery_state.controller.current_backoff_seconds())
            await self.flush_once()

    async def start(self) -> None:
        """Recover a prior spill immediately, then maintain bounded retries."""

        if self._worker is not None:
            return
        self._closed = False
        await self._recover_tenant_sinks()
        await self.flush_once()
        self._worker = asyncio.create_task(self._retry_loop(), name="gateway-audit-delivery")

    async def aclose(self) -> None:
        self._closed = True
        children = list(self._tenant_sinks.items())
        for _tenant_id, child in children:
            await child.aclose()
        if self._tenant_registry is not None:
            for tenant_id, child in children:
                try:
                    child_health = child._own_health()
                    if not _audit_health_has_pending_state(child_health):
                        self._tenant_registry.unregister(tenant_id)
                except Exception as exc:  # noqa: BLE001 - shutdown remains secret-free
                    self._tenant_registry_available = False
                    logger.error("Gateway audit tenant registry cleanup failed (error_type=%s)", type(exc).__name__)
        if self._worker is None:
            return
        self._worker.cancel()
        try:
            await self._worker
        except asyncio.CancelledError:
            pass
        self._worker = None

    def _own_health(self) -> dict[str, str | int | bool]:
        try:
            health = self._delivery_state.health(buffer_bytes=0)
            backlog_observable = True
        except Exception:  # noqa: BLE001 - health remains secret-free and available
            self._persistence_available = False
            controller = self._delivery_state.controller
            health = {
                "status": "degraded",
                "buffer_bytes": 0,
                "spillover_bytes": 0,
                "dlq_bytes": 0,
                "backlog_bytes": 0,
                "consecutive_failures": controller.consecutive_failures,
                "backoff_seconds": controller.current_backoff_seconds(),
                "circuit_open": controller.is_circuit_open(),
                "dropped_events": self._delivery_state.store.dropped_events,
            }
            backlog_observable = False
        accepting_events = (
            self._persistence_available
            and self._remote_ack_available
            and not bool(health["dlq_bytes"])
            and not bool(health["dropped_events"])
        )
        if not accepting_events:
            health["status"] = "degraded"
        result: dict[str, str | int | bool] = {
            "configured": True,
            "durable": self._persistence_available and backlog_observable,
            "accepting_events": accepting_events,
            "backlog_observable": backlog_observable,
            "remote_acknowledgement_available": self._remote_ack_available,
            "retry_worker_running": self._worker is not None and not self._worker.done() and not self._closed,
            **health,
        }
        result["pending_audit_state"] = _audit_health_has_pending_state(result)
        return result

    def health(self) -> dict[str, str | int | bool]:
        health = self._own_health()
        child_health = [sink._own_health() for sink in self._tenant_sinks.values()]
        if child_health:
            all_health = [health, *child_health]
            health.update(
                {
                    "status": "degraded" if any(item["status"] != "healthy" for item in all_health) else "healthy",
                    "durable": all(bool(item["durable"]) for item in all_health),
                    "accepting_events": all(bool(item["accepting_events"]) for item in all_health),
                    "backlog_observable": all(bool(item["backlog_observable"]) for item in all_health),
                    "remote_acknowledgement_available": all(bool(item["remote_acknowledgement_available"]) for item in all_health),
                    "retry_worker_running": all(bool(item["retry_worker_running"]) for item in all_health),
                    "buffer_bytes": sum(int(item["buffer_bytes"]) for item in all_health),
                    "spillover_bytes": sum(int(item["spillover_bytes"]) for item in all_health),
                    "dlq_bytes": sum(int(item["dlq_bytes"]) for item in all_health),
                    "backlog_bytes": sum(int(item["backlog_bytes"]) for item in all_health),
                    "consecutive_failures": sum(int(item["consecutive_failures"]) for item in all_health),
                    "backoff_seconds": max(int(item["backoff_seconds"]) for item in all_health),
                    "circuit_open": any(bool(item["circuit_open"]) for item in all_health),
                    "dropped_events": sum(int(item["dropped_events"]) for item in all_health),
                    "pending_audit_state": any(_audit_health_has_pending_state(item) for item in all_health),
                    "tenant_sink_count": len(child_health) + 1,
                    "tenant_sink_capacity": self._max_tenant_sinks + 1,
                }
            )
        if self._tenant_registry is not None:
            health["tenant_registry_available"] = self._tenant_registry_available
            if not self._tenant_registry_available:
                health.update(
                    {
                        "status": "degraded",
                        "durable": False,
                        "accepting_events": False,
                        "backlog_observable": False,
                    }
                )
        return health


class LocalGatewayAuditSink:
    """HMAC-chained local durability for gateways without a control plane."""

    def __init__(self, db_path: Path) -> None:
        from agent_bom.api.audit_log import SQLiteAuditLog

        db_path = canonical_runtime_state_path(db_path)
        parent_fd = AuditSpilloverStore._safe_parent_fd(db_path)
        os.close(parent_fd)
        AuditSpilloverStore._validate_existing_path(db_path)
        self._hmac_key = self.load_key(db_path, create=not db_path.exists())
        self._store = SQLiteAuditLog(str(db_path), hmac_key=self._hmac_key)
        self._available = True
        self.db_path = db_path

    @staticmethod
    def load_key(db_path: Path, *, create: bool = False) -> bytes:
        return AuditSpilloverStore.load_or_create_private_key(
            canonical_runtime_state_path(db_path).with_suffix(".hmac.key"),
            create=create,
        )

    async def __call__(self, event: dict[str, Any]) -> None:
        from agent_bom.api.audit_log import AuditEntry, sanitize_audit_details

        if not self._available:
            raise GatewayAuditDeliveryUnavailableError("local durable audit store is unavailable")
        identified = canonicalize_gateway_enforcement_event(ensure_gateway_event_identity(event))
        sanitized = sanitize_sensitive_payload(identified)
        if not isinstance(sanitized, dict):
            self._available = False
            raise GatewayAuditDeliveryUnavailableError("local durable audit event is invalid")
        action = str(sanitized.get("action") or sanitized.get("event_type") or "gateway.runtime")[:256]
        upstream = str(sanitized.get("upstream") or "gateway")[:200]
        entry = AuditEntry(
            action=action,
            actor="gateway",
            resource=f"upstream/{upstream}",
            details=sanitize_audit_details(sanitized),
        )
        try:
            await asyncio.to_thread(self._store.append, entry)
        except Exception as exc:  # noqa: BLE001 - local audit failure is fail-closed
            self._available = False
            logger.error("Gateway local audit persistence unavailable (error_type=%s)", type(exc).__name__)
            raise GatewayAuditDeliveryUnavailableError("local durable audit store is unavailable") from None

    async def admit_before_tool_execution(self, event: dict[str, Any]) -> None:
        await self(event)

    def health(self) -> dict[str, str | int | bool]:
        return {
            "configured": True,
            "mode": "local_hmac_sqlite",
            "status": "healthy" if self._available else "degraded",
            "durable": self._available,
            "accepting_events": self._available,
            "backlog_observable": True,
            "retry_worker_running": False,
            "backlog_bytes": 0,
            "dropped_events": 0,
        }


class UnavailableGatewayAuditSink:
    """Fail-closed health surface retained when local audit setup fails."""

    async def __call__(self, _event: dict[str, Any]) -> None:
        raise GatewayAuditDeliveryUnavailableError("local durable audit store is unavailable")

    async def admit_before_tool_execution(self, event: dict[str, Any]) -> None:
        await self(event)

    @staticmethod
    def health() -> dict[str, str | int | bool]:
        return {
            "configured": True,
            "mode": "unavailable",
            "status": "degraded",
            "durable": False,
            "accepting_events": False,
            "backlog_observable": False,
            "retry_worker_running": False,
            "backlog_bytes": 0,
            "dropped_events": 0,
        }


def build_local_gateway_audit_sink(*, state_dir: Path | None = None) -> LocalGatewayAuditSink:
    """Build the default durable audit path for a standalone local gateway."""

    root = state_dir or Path(os.environ.get("AGENT_BOM_STATE_DIR", Path.home() / ".agent-bom")).expanduser()
    return LocalGatewayAuditSink(root / "runtime-audit" / "gateway-local-audit.db")


def build_control_plane_audit_sink(
    base_url: str,
    token: str | None,
    *,
    tenant_id: str = "default",
    source_id: str = "gateway",
    session_id: str | None = None,
    spill_path: Path | None = None,
    dlq_path: Path | None = None,
    max_spillover_bytes: int = _GATEWAY_AUDIT_SPILLOVER_BYTES,
    max_dlq_bytes: int = _GATEWAY_AUDIT_DLQ_BYTES,
    sender: GatewayAuditSender | None = None,
    tenant_routing_enabled: bool = True,
    max_tenant_sinks: int = _GATEWAY_AUDIT_MAX_TENANT_SINKS,
) -> ControlPlaneAuditSink:
    """Build the gateway's shared bounded control-plane audit delivery sink."""

    audit_url = base_url.rstrip("/") + "/v1/proxy/audit"
    normalized_tenant_id = tenant_id.strip()
    if not normalized_tenant_id:
        raise ValueError("gateway audit tenant_id must not be empty")
    if max_tenant_sinks < 0:
        raise ValueError("gateway audit max_tenant_sinks must not be negative")
    delivery_identity = f"{source_id}\0{audit_url}\0{normalized_tenant_id}"
    active_session_id = session_id or "gateway-" + hashlib.sha256(delivery_identity.encode("utf-8")).hexdigest()[:20]
    state_dir = Path(os.environ.get("AGENT_BOM_STATE_DIR", Path.home() / ".agent-bom")).expanduser()
    stable_paths = audit_delivery_paths(
        state_dir,
        surface="gateway",
        identity=delivery_identity,
    )
    active_spill_path = spill_path or stable_paths.spill_path
    active_dlq_path = dlq_path or stable_paths.dlq_path
    tenant_registry = (
        _GatewayAuditTenantRegistry(state_dir, source_id=source_id, audit_url=audit_url)
        if tenant_routing_enabled and max_tenant_sinks > 0
        else None
    )
    controller = AuditDeliveryController()
    store = AuditSpilloverStore(
        spill_path=active_spill_path,
        dlq_path=active_dlq_path,
        max_spillover_bytes=max_spillover_bytes,
        max_dlq_bytes=max_dlq_bytes,
    )

    active_sender: GatewayAuditSender
    if sender is None:

        async def _sender(payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
            return await _send_gateway_audit_batch(audit_url, payload, headers)

        active_sender = _sender
    else:
        active_sender = sender
    return ControlPlaneAuditSink(
        base_url=base_url,
        token=token,
        tenant_id=normalized_tenant_id,
        source_id=source_id,
        session_id=active_session_id,
        delivery_state=AuditDeliveryState(controller=controller, store=store),
        sender=active_sender,
        tenant_registry=tenant_registry,
        tenant_routing_enabled=tenant_routing_enabled,
        max_tenant_sinks=max_tenant_sinks,
    )


def _warn_on_quarantined_agents(settings: GatewaySettings) -> None:
    """Name the agents that fleet enforcement will block, once, at boot.

    ``fleet_enforcement_mode`` now defaults to ``enforce``. An operator upgrading
    with a stale QUARANTINED row would otherwise discover the new behaviour as
    unexplained traffic loss — especially likely because releasing an agent did
    not disable its deny policy until this release. Best-effort and silent on
    error: this is an advisory log, never a boot gate.
    """
    if settings.fleet_enforcement_mode != "enforce":
        return
    try:
        from agent_bom.api.fleet_store import FleetLifecycleState
        from agent_bom.api.stores import _get_fleet_store

        # The relay resolves a tenant per request; at boot only the default
        # tenant is knowable, which is the single-tenant self-host shape this
        # warning exists for.
        quarantined = [
            (getattr(a, "name", "") or getattr(a, "agent_id", ""))
            for a in _get_fleet_store().list_by_tenant("default")
            if getattr(a, "lifecycle_state", None) == FleetLifecycleState.QUARANTINED
        ]
    except Exception:  # noqa: BLE001
        return
    if quarantined:
        logger.warning(
            "fleet enforcement is active: %d quarantined agent(s) will be blocked at this gateway: %s "
            "(opt out with --fleet-enforcement off)",
            len(quarantined),
            ", ".join(sorted(_sanitize_for_log(name) for name in quarantined)[:20]),
        )


def create_gateway_app(settings: GatewaySettings) -> FastAPI:
    """Build the FastAPI app for `agent-bom gateway serve`.

    Separating app construction from CLI entry point keeps the server
    testable end-to-end via ``TestClient(create_gateway_app(settings))``.
    """
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
                policy_state["last_error"] = sanitize_error(exc)
                logger.warning("gateway policy reload failed for %s: %s", settings.policy_path, sanitize_text(_sanitize_for_log(exc)))
                return False
            except Exception as exc:  # noqa: BLE001
                policy_state["last_error"] = sanitize_error(exc)
                logger.warning("gateway policy reload failed for %s: %s", settings.policy_path, sanitize_text(_sanitize_for_log(exc)))
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
        "load_failed": settings.firewall_policy_path is not None,
    }
    firewall_lock = asyncio.Lock()
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
                firewall_state["last_error"] = sanitize_error(exc)
                firewall_state["load_failed"] = True
                logger.warning(
                    "gateway firewall policy reload failed for %s: %s",
                    settings.firewall_policy_path,
                    sanitize_text(_sanitize_for_log(exc)),
                )
                return False
            except Exception as exc:  # noqa: BLE001
                firewall_state["last_error"] = sanitize_error(exc)
                firewall_state["load_failed"] = True
                logger.warning(
                    "gateway firewall policy reload failed for %s: %s",
                    settings.firewall_policy_path,
                    sanitize_text(_sanitize_for_log(exc)),
                )
                return False

            firewall_state["policy"] = next_policy
            firewall_state["last_loaded_at"] = time.time()
            firewall_state["last_error"] = None
            firewall_state["last_mtime"] = mtime
            firewall_state["load_failed"] = False
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
        nonlocal runtime_facts_task
        try:
            if isinstance(settings.audit_sink, ControlPlaneAuditSink):
                await settings.audit_sink.start()
            if settings.policy_path is not None:
                await _reload_policy_if_changed(force=True)
                if settings.policy_reload_interval_seconds > 0:
                    reload_task = asyncio.create_task(_policy_reload_loop())
            if settings.firewall_policy_path is not None:
                await _reload_firewall_policy_if_changed(force=True)
                if settings.firewall_policy_reload_interval_seconds > 0:
                    firewall_reload_task = asyncio.create_task(_firewall_reload_loop())
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

    app = FastAPI(title="agent-bom gateway", version="1", lifespan=_lifespan)

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

    # OAuth 2.1 Authorization Server (broker AS): mount the unauthenticated
    # discovery/registration/PKCE/token/JWKS endpoints so standard MCP clients
    # can auto-authenticate to brokered MCPs. These deliberately sit outside the
    # gateway transport-auth gate — they ARE the auth bootstrap.
    if settings.oauth_as is not None:
        app.include_router(build_oauth_as_router(settings.oauth_as))
        if settings.oauth_as.signing_key.ephemeral:
            logger.warning("gateway OAuth AS enabled with an ephemeral signing key; set AGENT_BOM_OAUTH_AS_PRIVATE_KEY_PEM for production")
    if settings.oidc_discovery_shim is not None:
        app.include_router(build_oidc_discovery_shim_router(settings.oidc_discovery_shim))

    dlp_config = _gateway_dlp_config(settings)

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
                "load_failed": bool(firewall_state.get("load_failed")),
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
                "oauth_as_enabled": settings.oauth_as is not None,
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
            policy: AgentFirewallPolicy = firewall_state["policy"]
            policy_source = firewall_state["source"]
            policy_loaded_at = firewall_state["last_loaded_at"]
            policy_load_failed = bool(firewall_state.get("load_failed"))
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
        # An OAuth-2.1 AS access token (broker mode) is a cryptographically
        # verified identity: validate it in-process (no self-HTTP) and prefer it
        # over the _meta channel. Standard MCP clients present it in the
        # Authorization header; we also accept it in _meta.agent_identity. The
        # ``scope`` claim drives per-tool-call scope enforcement below.
        identity_token = extract_identity_token(message)
        as_claims: dict[str, Any] | None = None
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
        if settings.oauth_as is not None:
            for candidate in (identity_token, _extract_request_token(request)):
                if candidate:
                    as_claims = settings.oauth_as.validate_token(candidate)
                    if as_claims is not None:
                        identity_token = candidate
                        break

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
        elif as_claims is not None:
            source_agent = str(as_claims.get("sub") or "").strip() or ANONYMOUS
            token_present = True
            identity_invalid_reason = None
            identity_verified = source_agent != ANONYMOUS
            token_scopes = scopes_from_claims(as_claims)
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
                fw_policy: AgentFirewallPolicy = firewall_state["policy"]
                fw_load_failed = bool(firewall_state.get("load_failed"))
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
        # Off by default; fails open on a fleet-store error.
        if settings.fleet_enforcement_mode in ("warn", "enforce") and await asyncio.to_thread(
            _agent_is_quarantined, tenant_id, source_agent
        ):
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

        # DLP pass on the tool RESULT. Scans the serialized result for the same
        # sensitive-data classes as the argument pass. In enforce mode a blocked
        # finding (secrets/payload/injection) replaces the result with a DLP
        # error so the data never reaches the caller; otherwise PII is redacted
        # in-place when pii_action=redact. Audit-only in audit mode.
        if dlp_config.enabled and isinstance(upstream_response, dict) and "result" in upstream_response:
            tool_name_for_dlp = message.get("params", {}).get("name", "") if is_tools_call(message) else str(message.get("method", ""))
            try:
                result_text = json.dumps(upstream_response.get("result"), default=str)
            except (TypeError, ValueError):
                result_text = str(upstream_response.get("result"))
            resp_findings = scan_tool_response(result_text, dlp_config)
            result_blocked = dlp_config.mode == "enforce" and any(f.blocked for f in resp_findings)
            result_redacted = (
                dlp_config.mode == "enforce" and dlp_config.pii_action == "redact" and bool(resp_findings) and not result_blocked
            )
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
                first = next(f for f in resp_findings if f.blocked)
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
            if result_redacted:
                upstream_response["result"] = _redact_obj_pii(upstream_response.get("result"))

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
