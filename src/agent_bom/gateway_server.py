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

from agent_bom.a2a_auth_posture import evaluate_inline_mutual_auth
from agent_bom.agent_identity import (
    ANONYMOUS,
    check_caller_identity,
    extract_identity_token,
    identity_token_scopes,
    scopes_from_claims,
)
from agent_bom.api.auth import Role, get_key_store
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
from agent_bom.proxy_scanner import ScanConfig, redact_pii, scan_tool_call, scan_tool_response
from agent_bom.runtime.fail_mode import gateway_fail_mode_matrix
from agent_bom.runtime.gateway_events import GatewayRuntimeEventType, build_gateway_runtime_event
from agent_bom.runtime.graph_reachability import ReachabilityMap, load_reachability_map
from agent_bom.security import sanitize_error, sanitize_text

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
        logger.warning("gateway drift check failed: %s", _sanitize_for_log(exc))
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
            response = await _post_upstream_jsonrpc(
                upstream,
                message,
                extra_headers,
                client=await self._client_for_call(allow_private_networks=upstream.private_network_approved),
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

    # OAuth 2.1 broker: a standard MCP client presenting an AS-issued access
    # token in the Authorization header satisfies transport auth (the AS already
    # authenticated the client + bound the token via PKCE). Only AS-signed,
    # unexpired tokens pass; any other bearer falls through to API-key auth.
    if settings.oauth_as is not None and raw_token:
        claims = settings.oauth_as.validate_token(raw_token)
        if claims is not None:
            return "default", "oauth_as"

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

    from agent_bom.runtime.egress_transport import build_pinned_async_client

    async with build_pinned_async_client(
        allow_private_networks=upstream.private_network_approved,
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
    auth_headers = await upstream.resolve_auth_headers()
    headers = {"Content-Type": "application/json", **auth_headers, **extra_headers}
    async with client.stream("POST", upstream.url, json=message, headers=headers) as response:
        response.raise_for_status()
        content_length = response.headers.get("content-length")
        if content_length:
            try:
                declared_size = int(content_length)
            except ValueError:
                declared_size = 0
            if declared_size > _MAX_GATEWAY_MESSAGE_BYTES:
                raise ValueError(f"upstream response exceeded {_MAX_GATEWAY_MESSAGE_BYTES} bytes")

        body = bytearray()
        async for chunk in response.aiter_bytes():
            if len(body) + len(chunk) > _MAX_GATEWAY_MESSAGE_BYTES:
                raise ValueError(f"upstream response exceeded {_MAX_GATEWAY_MESSAGE_BYTES} bytes")
            body.extend(chunk)

        raw_body = bytes(body)
        if response.headers.get("content-type", "").startswith("application/json"):
            return json.loads(raw_body)
        # Some upstreams return text/event-stream; MVP treats non-JSON as an
        # opaque body wrapped in a success envelope so policy + audit still fire.
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"raw": raw_body.decode("utf-8", errors="replace")},
        }


async def _read_bounded_gateway_body(request: Any) -> bytes:
    """Read a gateway request without buffering past the JSON-RPC limit."""
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > _MAX_GATEWAY_MESSAGE_BYTES:
            raise HTTPException(status_code=413, detail="gateway request exceeds maximum JSON-RPC message size")
        body.extend(chunk)
    return bytes(body)


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
                logger.warning("gateway policy reload failed for %s: %s", settings.policy_path, _sanitize_for_log(exc))
                return False
            except Exception as exc:  # noqa: BLE001
                policy_state["last_error"] = sanitize_error(exc)
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
        "load_failed": settings.firewall_policy_path is not None,
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
                firewall_state["last_error"] = sanitize_error(exc)
                firewall_state["load_failed"] = True
                logger.warning(
                    "gateway firewall policy reload failed for %s: %s",
                    settings.firewall_policy_path,
                    _sanitize_for_log(exc),
                )
                return False
            except Exception as exc:  # noqa: BLE001
                firewall_state["last_error"] = sanitize_error(exc)
                firewall_state["load_failed"] = True
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
            policy_load_failed = bool(firewall_state.get("load_failed"))
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

        raw_body = await _read_bounded_gateway_body(request)

        try:
            body = json.loads(raw_body)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"body is not valid JSON: {sanitize_error(exc)}") from exc

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
        if identity_token:
            try:
                from agent_bom.api.agent_identity_store import get_agent_identity_store, identity_for_token

                scoped_identity = identity_for_token(get_agent_identity_store(), identity_token)
            except Exception as exc:  # noqa: BLE001
                managed_identity_lookup_unavailable = True
                logger.warning("gateway managed identity lookup failed: %s", _sanitize_for_log(exc))
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
            elif (
                not scoped_identity.blueprint_id
                and settings.drift_enforcement_mode == "enforce"
                and not _gateway_allows_anonymous_agents(settings)
            ):
                identity_invalid_reason = "managed identity has no role blueprint binding"
        elif as_claims is not None:
            source_agent = str(as_claims.get("sub") or "").strip() or ANONYMOUS
            token_present = True
            identity_invalid_reason = None
            identity_verified = source_agent != ANONYMOUS
            token_scopes = scopes_from_claims(as_claims)
        else:
            source_agent, token_present, identity_invalid_reason = check_caller_identity(message, current_policy)
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

        profile_id = str(getattr(scoped_identity, "blueprint_id", "") or "")
        event_tool = str((message.get("params") or {}).get("name") or message.get("method") or "")

        def _typed_runtime_event(
            event_type: GatewayRuntimeEventType,
            *,
            decision: str,
            policy_source: str,
            tool: str = event_tool,
            data_action: str = "",
            policy_id: str = "",
            evidence_id: str = "",
        ) -> dict[str, Any]:
            return build_gateway_runtime_event(
                event_type,
                tenant_id=tenant_id,
                agent_id=source_agent,
                profile_id=profile_id,
                upstream=upstream.name,
                tool=tool,
                decision=decision,
                policy_source=policy_source,
                trace_id=str(trace_meta["trace_id"]),
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
            logger.warning("gateway owner budget check failed: %s", _sanitize_for_log(exc))
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
            if (
                allowed
                and scoped_identity is None
                and managed_identity_lookup_unavailable
                and (identity_token or "").startswith("abi_")
            ):
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
                    logger.warning("gateway conditional-rules evaluation error: %s", _sanitize_for_log(exc))
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
                    logger.warning("gateway plugin evaluation error: %s", _sanitize_for_log(exc))
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
                        "error": _public_gateway_error(exc),
                    }
                )
            raise HTTPException(status_code=502, detail=f"upstream error: {_public_gateway_error(exc)}") from exc

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
                await settings.audit_sink(
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
                    headers=rate_limit_headers or None,
                )
            if result_redacted:
                upstream_response["result"] = _redact_obj_pii(upstream_response.get("result"))

        if settings.audit_sink is not None:
            _forward_is_tool_call = is_tools_call(message)
            forward_audit_event: dict[str, Any] = {
                "action": "gateway.tool_call" if _forward_is_tool_call else "gateway.message",
                "upstream": upstream.name,
                "tenant_id": tenant_id,
                "method": message.get("method"),
                "tool": message.get("params", {}).get("name") if _forward_is_tool_call else None,
            }
            # Only an actual tools/call is an authorized tool invocation. JSON-RPC
            # handshake / discovery traffic (initialize, tools/list, notifications)
            # is forwarded too but must not be tagged TOOL_CALL_ALLOWED, or the live
            # feed would inflate calls_today / tool_calls_authorized with
            # non-invocation messages.
            if _forward_is_tool_call:
                forward_audit_event.update(
                    _typed_runtime_event(
                        GatewayRuntimeEventType.TOOL_CALL_ALLOWED,
                        decision="allow",
                        policy_source=resolved_policy_source,
                        tool=str(message.get("params", {}).get("name") or ""),
                    )
                )
            await settings.audit_sink(forward_audit_event)
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
