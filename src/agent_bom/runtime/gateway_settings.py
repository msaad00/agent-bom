"""Gateway composition settings; construction does not read environment values."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping

from agent_bom.api.oauth_as import OAuthAuthorizationServer
from agent_bom.api.oidc_discovery_shim import OIDCDiscoveryShimConfig
from agent_bom.gateway_upstreams import UpstreamRegistry
from agent_bom.runtime.gateway_contracts import AuditSink, UpstreamCaller


@dataclass
class GatewaySettings:
    """Runtime configuration the caller wires in."""

    registry: UpstreamRegistry = field(repr=False)
    policy: dict[str, Any] = field(repr=False)  # dict passed to check_policy — same shape proxy uses
    audit_sink: AuditSink | None = None
    upstream_caller: UpstreamCaller | None = None  # injectable for tests
    bearer_token: str | None = field(default=None, repr=False)
    bearer_token_expires_at: str | None = None
    _bearer_token_deadline: datetime | None = field(default=None, init=False, repr=False)
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
    graph_reachability_bundle_url: str = field(default="", repr=False)
    graph_reachability_bundle_tenant_id: str = "default"
    graph_reachability_bundle_signing_key: bytes | None = field(default=None, repr=False)
    graph_reachability_bundle_bearer_token: str = field(default="", repr=False)
    graph_reachability_bundle_poll_interval_seconds: float = 30.0
    graph_reachability_bundle_fetcher: Callable[[], Awaitable[Mapping[str, Any]]] | None = None
    upstream_failure_threshold: int = 3
    upstream_circuit_cooldown_seconds: float = 30.0
    upstream_http_timeout_seconds: float = 30.0
    upstream_http_max_connections: int = 100
    upstream_http_max_keepalive_connections: int = 20
    listener_host: str = "127.0.0.1"
    allow_insecure_no_auth: bool = False
    # None resolves the environment at app startup; () explicitly disables trust.
    trusted_context_proxy_cidrs: tuple[str, ...] | None = None
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
    control_plane_policies: list[dict[str, Any]] = field(default_factory=list, repr=False)
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
    # one-click containment a no-op here. Store lookup errors block in enforce
    # mode and remain visible in warn mode. Opt out with
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
    policy_webhook_url: str | None = field(default=None, repr=False)
    policy_webhook_token: str | None = field(default=None, repr=False)
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


def validate_gateway_security_settings(settings: GatewaySettings) -> None:
    """Normalize explicit configuration and reject unsafe values before I/O.

    No environment reads: CLI/env precedence and lazy optional imports remain
    owned by their existing composition paths. Errors never echo input values.
    """
    if settings.oauth_as is not None:
        raise ValueError(
            "Embedded OAuth AS is unavailable until trusted client authorization is implemented; "
            "use configured bearer or API-key authentication"
        )
    modes = {
        "fleet_enforcement_mode": {"off", "warn", "enforce"},
        "drift_enforcement_mode": {"off", "warn", "enforce"},
        "anomaly_enforcement_mode": {"off", "warn", "enforce"},
        "a2a_mutual_auth_enforcement_mode": {"off", "warn", "enforce"},
        "graph_reachability_enforcement_mode": {"off", "warn", "enforce"},
        "graph_reachability_failure_mode": {"allow", "deny"},
        "dlp_mode": {"audit", "enforce"},
        "dlp_pii_action": {"redact", "block"},
    }
    for name, allowed in modes.items():
        value = getattr(settings, name)
        normalized = value.strip().lower() if isinstance(value, str) else None
        if normalized not in allowed:
            raise ValueError(f"{name} must be one of {', '.join(sorted(allowed))}")
        setattr(settings, name, normalized)
    minimums = {
        "runtime_rate_limit_per_tenant_per_minute": 0,
        "policy_reload_interval_seconds": 0,
        "firewall_policy_reload_interval_seconds": 0,
        "upstream_failure_threshold": 1,
        "upstream_circuit_cooldown_seconds": 0,
        "upstream_http_timeout_seconds": 0.001,
        "upstream_http_max_connections": 1,
        "upstream_http_max_keepalive_connections": 0,
        "graph_reachability_bundle_poll_interval_seconds": 0,
    }
    integer_fields = {
        "runtime_rate_limit_per_tenant_per_minute",
        "policy_reload_interval_seconds",
        "firewall_policy_reload_interval_seconds",
        "upstream_failure_threshold",
        "upstream_http_max_connections",
        "upstream_http_max_keepalive_connections",
    }
    for name, minimum in minimums.items():
        value = getattr(settings, name)
        if name in integer_fields and type(value) is not int:
            raise ValueError(f"{name} must be an integer")
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < minimum:
            raise ValueError(f"{name} must be finite and at least {minimum}")
    if settings.upstream_http_max_keepalive_connections > settings.upstream_http_max_connections:
        raise ValueError("upstream_http_max_keepalive_connections must not exceed upstream_http_max_connections")
