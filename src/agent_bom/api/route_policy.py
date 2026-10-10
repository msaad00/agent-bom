"""One route policy for API enforcement and the operator scope catalog.

Rules match path segments, never similarly named sibling routes. Specific
subpaths win. HEAD shares GET policy. Authentication remains the middleware's
responsibility; unclassified protected operations fail closed after authentication.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class RoutePolicy:
    method: str
    path_prefix: str
    minimum_role: Literal["admin", "analyst", "viewer"]
    scope: str | None = None
    exact: bool = False


# Public access is an operation contract, never permission for every future
# method mounted at a health/login path. Login/logout handlers retain their
# credential, state and CSRF checks; HEAD shares the public GET disposition.
PUBLIC_OPERATIONS: frozenset[tuple[str, str]] = frozenset(
    [
        ("GET", path)
        for path in (
            "/",
            "/health",
            "/healthz",
            "/livez",
            "/ping",
            "/readyz",
            "/version",
            "/brand/mark.svg",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/v1/auth/oidc/login",
            "/v1/auth/oidc/callback",
            "/v1/auth/snowflake/login",
            "/v1/auth/snowflake/callback",
            "/v1/auth/saml/metadata",
        )
    ]
    + [
        ("POST", path)
        for path in (
            "/v1/auth/dev-session",
            "/v1/auth/session",
            "/v1/auth/trial/oidc/start",
            "/v1/auth/trial/oidc/start-form",
            "/v1/auth/saml/relay-state",
            "/v1/auth/saml/login",
        )
    ]
    + [("DELETE", "/v1/auth/session")]
)


def public_operation(method: str, path: str) -> bool:
    """Whether this exact operation is intentionally anonymous."""
    return (_method(method), path) in PUBLIC_OPERATIONS


ROUTE_POLICIES: tuple[RoutePolicy, ...] = (
    RoutePolicy("GET", "/v1/observability/adoption", "admin", "audit:read"),
    RoutePolicy("POST", "/v1/observability/adoption/events", "analyst", "scan:write"),
    RoutePolicy("GET", "/v1/compliance", "viewer", "compliance:read"),
    RoutePolicy("GET", "/v1/posture/backpressure", "viewer", "posture:read"),
    RoutePolicy("GET", "/v1/posture/webhooks/", "analyst", "posture:read"),
    RoutePolicy("GET", "/v1/posture", "viewer", "posture:read"),
    RoutePolicy("GET", "/v1/auth/debug", "viewer", "auth:read"),
    RoutePolicy("GET", "/v1/auth/me", "viewer", None),
    RoutePolicy("GET", "/v1/auth/policy", "admin", "auth:read"),
    RoutePolicy("GET", "/v1/auth/scopes", "admin", "auth:read"),
    RoutePolicy("GET", "/v1/auth/secrets/lifecycle", "admin", "auth.secrets:read"),
    RoutePolicy("GET", "/v1/auth/secrets/rotation-plan", "admin", "auth.secrets:read"),
    RoutePolicy("GET", "/v1/auth/secrets/credential-expiry", "admin", "auth.secrets:read"),
    RoutePolicy("GET", "/v1/auth/scim/config", "admin", "auth.scim:read"),
    RoutePolicy("GET", "/v1/entitlements", "admin", "config:read"),
    RoutePolicy("GET", "/v1/credentials", "viewer", "source:read"),
    RoutePolicy("GET", "/v1/evaluations", "viewer", "eval:read"),
    RoutePolicy("POST", "/v1/intel/match", "viewer", "intel:read"),
    RoutePolicy("POST", "/v1/intel/daily-brief", "viewer", "intel:read"),
    RoutePolicy("POST", "/v1/runtime/profiles/evaluate", "viewer", "runtime:read"),
    RoutePolicy("POST", "/v1/graph/query", "viewer", "graph:read"),
    RoutePolicy("POST", "/v1/graph/compromise", "viewer", "graph:read"),
    RoutePolicy("POST", "/v1/graph/should-i-deploy", "viewer", "graph:read"),
    RoutePolicy("GET", "/v1/graph/scenarios", "viewer", "graph:read"),
    RoutePolicy("POST", "/v1/graph/scenarios", "analyst", "scan:write"),
    RoutePolicy("PUT", "/v1/graph/scenarios/", "analyst", "scan:write"),
    RoutePolicy("DELETE", "/v1/graph/scenarios/", "admin", "config:write"),
    RoutePolicy("POST", "/v1/audit/export/verify", "viewer", "audit:read"),
    RoutePolicy("POST", "/v1/traces/attack-paths", "viewer", "runtime:read"),
    RoutePolicy("GET", "/v1/audit", "analyst", "audit:read"),
    RoutePolicy("GET", "/v1/audit/", "analyst", "audit:read"),
    RoutePolicy("GET", "/scim/v2", "admin", "auth.scim:read"),
    RoutePolicy("POST", "/scim/v2", "admin", "auth.scim:write"),
    RoutePolicy("PATCH", "/scim/v2", "admin", "auth.scim:write"),
    RoutePolicy("PUT", "/scim/v2", "admin", "auth.scim:write"),
    RoutePolicy("DELETE", "/scim/v2", "admin", "auth.scim:write"),
    RoutePolicy("GET", "/v1/auth/quota", "admin", "auth.quota:read"),
    RoutePolicy("GET", "/v1/auth/trial-tenants/", "admin", "auth.invitations:read"),
    RoutePolicy("GET", "/v1/auth/keys", "admin", "auth.keys:read"),
    RoutePolicy("GET", "/v1/tenant/", "admin", "privacy.data:read"),
    RoutePolicy("PUT", "/v1/auth/quota", "admin", "auth.quota:write"),
    RoutePolicy("POST", "/v1/auth/invitations", "admin", "auth.keys:write"),
    RoutePolicy("POST", "/v1/auth/trial-invitations", "admin", "auth.invitations:write"),
    RoutePolicy("POST", "/v1/auth/trial-tenants/", "admin", "auth.invitations:write"),
    RoutePolicy("POST", "/v1/auth/keys", "admin", "auth.keys:write"),
    RoutePolicy("POST", "/v1/auth/keys/", "admin", "auth.keys:write"),
    RoutePolicy("DELETE", "/v1/auth/quota", "admin", "auth.quota:write"),
    RoutePolicy("DELETE", "/v1/auth/keys/", "admin", "auth.keys:write"),
    RoutePolicy("DELETE", "/v1/credentials/", "admin", "source:write"),
    RoutePolicy("DELETE", "/v1/tenant/", "admin", "privacy.data:delete"),
    RoutePolicy("POST", "/v1/gateway/policies", "admin", "gateway.policy:write"),
    RoutePolicy("POST", "/v1/posture/webhooks/", "admin", "posture:write"),
    RoutePolicy("PUT", "/v1/gateway/policies/", "admin", "gateway.policy:write"),
    RoutePolicy("DELETE", "/v1/gateway/policies/", "admin", "gateway.policy:write"),
    RoutePolicy("POST", "/v1/fleet/sync", "admin", "fleet:write"),
    RoutePolicy("DELETE", "/v1/sources/", "admin", "source:write"),
    RoutePolicy("PUT", "/v1/fleet/", "admin", "fleet:write"),
    RoutePolicy("PUT", "/v1/exceptions/", "admin", "exception:write"),
    RoutePolicy("DELETE", "/v1/exceptions/", "admin", "exception:write"),
    RoutePolicy("POST", "/v1/siem/test", "admin", "siem:write"),
    RoutePolicy("POST", "/v1/shield/start", "admin", "shield:write"),
    RoutePolicy("POST", "/v1/shield/unblock", "admin", "shield:write"),
    RoutePolicy("POST", "/v1/shield/break-glass", "admin", "shield:write"),
    RoutePolicy("DELETE", "/v1/scan/", "admin", "scan:delete"),
    RoutePolicy("POST", "/v1/exceptions", "analyst", "exception:write"),
    RoutePolicy("POST", "/v1/findings/bulk", "analyst", "finding:write"),
    RoutePolicy("POST", "/v1/reports", "analyst", "report:write"),
    RoutePolicy("GET", "/v1/reports/", "analyst", "report:read"),
    RoutePolicy("POST", "/v1/findings/false-positive", "analyst", "finding:write"),
    RoutePolicy("POST", "/v1/findings/feedback", "analyst", "finding:write"),
    RoutePolicy("DELETE", "/v1/findings/false-positive/", "analyst", "finding:write"),
    RoutePolicy("DELETE", "/v1/findings/feedback/", "analyst", "finding:write"),
    RoutePolicy("POST", "/v1/scan", "analyst", "scan:write"),
    RoutePolicy("POST", "/v1/credentials", "analyst", "source:write"),
    RoutePolicy("POST", "/v1/credentials/", "analyst", "source:write"),
    RoutePolicy("POST", "/v1/datasets/", "analyst", "eval:write"),
    RoutePolicy("POST", "/v1/evaluations", "analyst", "eval:write"),
    RoutePolicy("POST", "/v1/gateway/evaluate", "analyst", "gateway:write"),
    RoutePolicy("POST", "/v1/firewall/check", "analyst", "gateway.firewall:write"),
    RoutePolicy("POST", "/v1/proxy/audit", "analyst", "runtime:write"),
    RoutePolicy("POST", "/v1/traces", "analyst", "runtime:write"),
    RoutePolicy("POST", "/v1/ocsf/ingest", "analyst", "runtime:write"),
    RoutePolicy("POST", "/v1/results/push", "analyst", "scan:write"),
    RoutePolicy("POST", "/v1/schedules", "analyst", "schedule:write"),
    RoutePolicy("POST", "/v1/sources", "analyst", "source:write"),
    RoutePolicy("POST", "/v1/sources/", "analyst", "source:write"),
    RoutePolicy("POST", "/v1/baseline/compare", "analyst", "scan:write"),
    RoutePolicy("POST", "/v1/graph/presets", "analyst", "graph.preset:write"),
    RoutePolicy("POST", "/v1/graph/correlations", "analyst", "scan:write"),
    RoutePolicy("POST", "/v1/model-keys/providers/", "analyst", "model.key:write"),
    RoutePolicy("POST", "/v1/model-keys/virtual-keys/", "analyst", "model.key:write"),
    RoutePolicy("POST", "/v1/model-keys/authorize", "analyst", "model.key:write"),
    RoutePolicy("DELETE", "/v1/schedules/", "analyst", "schedule:write"),
    RoutePolicy("DELETE", "/v1/graph/presets/", "analyst", "graph.preset:write"),
    RoutePolicy("PUT", "/v1/schedules/", "analyst", "schedule:write"),
    RoutePolicy("PUT", "/v1/credentials/", "analyst", "source:write"),
    RoutePolicy("PUT", "/v1/sources/", "analyst", "source:write"),
    RoutePolicy("GET", "/v1/endpoint-connectors", "viewer", "connectors:read"),
    RoutePolicy("POST", "/v1/endpoint-connectors", "admin", "connectors:write"),
    RoutePolicy("PATCH", "/v1/endpoint-connectors/", "admin", "connectors:write"),
    RoutePolicy("PUT", "/v1/endpoint-connectors/", "admin", "connectors:write"),
    RoutePolicy("GET", "/v1/cloud/connections", "viewer", "cloud.connection:read"),
    # The route additionally binds the exact source id and credential lifetime.
    RoutePolicy("POST", "/v1/cloud/runtime-evidence/ingest", "admin", "runtime:ingest:*", exact=True),
    RoutePolicy("POST", "/v1/cloud/connections", "admin", "cloud.connection:write"),
    RoutePolicy("PATCH", "/v1/cloud/connections/", "admin", "cloud.connection:write"),
    RoutePolicy("DELETE", "/v1/cloud/connections/", "admin", "cloud.connection:write"),
    RoutePolicy("GET", "/v1/findings", "viewer", "finding:read"),
    RoutePolicy("GET", "/v1/graph", "viewer", "graph:read"),
    RoutePolicy("GET", "/v1/intel", "viewer", "intel:read"),
    RoutePolicy("GET", "/v1/gateway/policies", "viewer", "gateway.policy:read"),
    RoutePolicy("GET", "/v1/gateway/audit", "viewer", "audit:read"),
    RoutePolicy("POST", "/v1/sources/run-cohort", "analyst", "scan:write"),
    # Explicit resource families for previously unclassified operations.
    RoutePolicy("DELETE", "/v1/compliance", "admin", "compliance:write"),
    RoutePolicy("DELETE", "/v1/exports", "admin", "export:write"),
    RoutePolicy("DELETE", "/v1/model-keys", "admin", "model.key:write"),
    RoutePolicy("DELETE", "/v1/overview", "admin", "posture:write"),
    RoutePolicy("DELETE", "/v1/ticketing", "admin", "ticketing:write"),
    RoutePolicy("DELETE", "/v1/webhooks", "admin", "webhook:write"),
    RoutePolicy("GET", "/metrics", "viewer", "observability:read"),
    RoutePolicy("GET", "/status", "viewer", "observability:read"),
    RoutePolicy("GET", "/v1/activity", "viewer", "runtime:read"),
    RoutePolicy("GET", "/v1/agent-bom", "viewer", "inventory:read"),
    RoutePolicy("GET", "/v1/agent-lifecycle", "viewer", "lifecycle:read"),
    RoutePolicy("GET", "/v1/agents", "viewer", "inventory:read"),
    RoutePolicy("GET", "/v1/assets", "viewer", "inventory:read"),
    RoutePolicy("GET", "/v1/campaigns", "viewer", "finding:read"),
    RoutePolicy("GET", "/v1/cis", "viewer", "compliance:read"),
    RoutePolicy("GET", "/v1/cloud", "viewer", "cloud:read"),
    RoutePolicy("GET", "/v1/conditional-access-policies", "viewer", "identity.policy:read"),
    RoutePolicy("GET", "/v1/connectors", "viewer", "connectors:read"),
    RoutePolicy("GET", "/v1/cortex", "viewer", "runtime:read"),
    RoutePolicy("GET", "/v1/datasets", "viewer", "eval:read"),
    RoutePolicy("GET", "/v1/demo-estate", "viewer", "inventory:read"),
    RoutePolicy("GET", "/v1/device-posture", "viewer", "posture:read"),
    RoutePolicy("GET", "/v1/discovery", "viewer", "inventory:read"),
    RoutePolicy("GET", "/v1/estate", "viewer", "graph:read"),
    RoutePolicy("GET", "/v1/exceptions", "viewer", "exception:read"),
    RoutePolicy("GET", "/v1/exports", "viewer", "export:read"),
    RoutePolicy("GET", "/v1/firewall", "viewer", "gateway.firewall:read"),
    RoutePolicy("GET", "/v1/fleet", "viewer", "fleet:read"),
    RoutePolicy("GET", "/v1/frameworks", "viewer", "compliance:read"),
    RoutePolicy("GET", "/v1/gateway", "viewer", "gateway:read"),
    RoutePolicy("GET", "/v1/governance", "viewer", "governance:read"),
    RoutePolicy("GET", "/v1/identities", "viewer", "identity:read"),
    RoutePolicy("GET", "/v1/identity-jit-grants", "viewer", "identity.grant:read"),
    RoutePolicy("GET", "/v1/inventory", "viewer", "inventory:read"),
    RoutePolicy("GET", "/v1/jobs", "viewer", "scan:read"),
    RoutePolicy("GET", "/v1/kspm", "viewer", "posture:read"),
    RoutePolicy("GET", "/v1/malicious", "viewer", "intel:read"),
    RoutePolicy("GET", "/v1/mcp-config", "viewer", "mcp.config:read"),
    RoutePolicy("GET", "/v1/mitre", "viewer", "compliance:read"),
    RoutePolicy("GET", "/v1/model-keys", "viewer", "model.key:read"),
    RoutePolicy("GET", "/v1/observability", "viewer", "observability:read"),
    RoutePolicy("GET", "/v1/overview", "viewer", "posture:read"),
    RoutePolicy("GET", "/v1/plugins", "viewer", "config:read"),
    RoutePolicy("GET", "/v1/proxy", "viewer", "runtime:read"),
    RoutePolicy("GET", "/v1/registry", "viewer", "intel:read"),
    RoutePolicy("GET", "/v1/runtime", "viewer", "runtime:read"),
    RoutePolicy("GET", "/v1/scan", "viewer", "scan:read"),
    RoutePolicy("GET", "/v1/schedules", "viewer", "schedule:read"),
    RoutePolicy("GET", "/v1/scorecard", "viewer", "intel:read"),
    RoutePolicy("GET", "/v1/self-posture", "viewer", "posture:read"),
    RoutePolicy("GET", "/v1/shield", "viewer", "shield:read"),
    RoutePolicy("GET", "/v1/siem", "viewer", "siem:read"),
    RoutePolicy("GET", "/v1/skills", "viewer", "scan:read"),
    RoutePolicy("GET", "/v1/sources", "viewer", "source:read"),
    RoutePolicy("GET", "/v1/system", "viewer", "observability:read"),
    RoutePolicy("GET", "/v1/ticketing", "viewer", "ticketing:read"),
    RoutePolicy("GET", "/v1/traces", "viewer", "runtime:read"),
    RoutePolicy("GET", "/v1/trends", "viewer", "finding:read"),
    RoutePolicy("GET", "/v1/webhooks", "viewer", "webhook:read"),
    RoutePolicy("PATCH", "/v1/campaigns", "admin", "finding:write"),
    RoutePolicy("POST", "/v1/agent-lifecycle", "admin", "lifecycle:write"),
    RoutePolicy("POST", "/v1/campaigns", "admin", "finding:write"),
    RoutePolicy("POST", "/v1/cloud", "admin", "cloud:write"),
    RoutePolicy("POST", "/v1/compliance", "admin", "compliance:write"),
    RoutePolicy("POST", "/v1/conditional-access-policies", "admin", "identity.policy:write"),
    RoutePolicy("POST", "/v1/delegations", "admin", "identity.delegation:write"),
    RoutePolicy("POST", "/v1/device-posture", "admin", "posture:write"),
    RoutePolicy("POST", "/v1/exports", "admin", "export:write"),
    RoutePolicy("POST", "/v1/findings", "admin", "finding:write"),
    RoutePolicy("POST", "/v1/fleet", "admin", "fleet:write"),
    RoutePolicy("POST", "/v1/governance", "admin", "governance:write"),
    RoutePolicy("POST", "/v1/identities", "admin", "identity:write"),
    RoutePolicy("POST", "/v1/identity-jit-grants", "admin", "identity.grant:write"),
    RoutePolicy("POST", "/v1/kspm", "admin", "posture:write"),
    RoutePolicy("POST", "/v1/mcp-config", "admin", "mcp.config:write"),
    RoutePolicy("POST", "/v1/model-keys", "admin", "model.key:write"),
    RoutePolicy("POST", "/v1/runtime", "admin", "runtime:write"),
    RoutePolicy("POST", "/v1/skills", "admin", "scan:write"),
    RoutePolicy("POST", "/v1/ticketing", "admin", "ticketing:write"),
    RoutePolicy("POST", "/v1/ui", "admin", "observability:write"),
    RoutePolicy("POST", "/v1/webhooks", "admin", "webhook:write"),
    RoutePolicy("PUT", "/v1/exports", "admin", "export:write"),
    RoutePolicy("PUT", "/v1/findings", "admin", "finding:write"),
    RoutePolicy("PUT", "/v1/integrations", "admin", "integration:write"),
    RoutePolicy("PUT", "/v1/mcp-config", "admin", "mcp.config:write"),
    RoutePolicy("PUT", "/v1/observability", "admin", "observability:write"),
    RoutePolicy("PUT", "/v1/overview", "admin", "posture:write"),
)


def _method(method: str) -> str:
    normalized = method.upper()
    return "GET" if normalized == "HEAD" else normalized


def _matches(path: str, prefix: str) -> bool:
    return path.startswith(prefix) if prefix.endswith("/") else path == prefix or path.startswith(prefix + "/")


def route_policy(method: str, path: str) -> RoutePolicy | None:
    normalized_method = _method(method)
    candidates = (
        rule
        for rule in ROUTE_POLICIES
        if rule.method == normalized_method and _matches(path, rule.path_prefix) and (not rule.exact or path == rule.path_prefix)
    )
    return max(candidates, key=lambda rule: len(rule.path_prefix), default=None)


def required_role(method: str, path: str) -> str:
    rule = route_policy(method, path)
    if rule is not None:
        return rule.minimum_role
    if _method(method) in {"POST", "PUT", "PATCH", "DELETE"} and (path in {"/v1", "/scim"} or path.startswith(("/v1/", "/scim/"))):
        return "admin"
    return "viewer"


def required_scope(method: str, path: str) -> str | None:
    rule = route_policy(method, path)
    return rule.scope if rule else None


def request_scopes_allow(scopes: list[str], method: str, path: str) -> bool:
    """Fail closed when no operation policy is defined.

    Empty scopes and ``*`` retain unrestricted access to classified operations. The exact
    self-identity read needs no resource grant; similarly named paths do not.
    Role, tenant and credential-lifecycle checks still apply independently.
    """
    from agent_bom.api.auth import scopes_allow

    if route_policy(method, path) is None:
        return False
    if not scopes or "*" in scopes:
        return True
    if _method(method) == "GET" and path == "/v1/auth/me":
        return True
    scope = required_scope(method, path)
    if scope == "runtime:ingest:*":
        # Admission only: the handler checks the exact encoded source grant,
        # registered tenant/provider/account, revocation and one-hour lifetime.
        return any(value.startswith("runtime:ingest:") and value.removeprefix("runtime:ingest:") for value in scopes)
    return scope is not None and scopes_allow(scopes, scope)


def scope_catalog() -> list[dict[str, str]]:
    """Expose the same role and scope decision used during requests."""
    catalog = []
    for rule in ROUTE_POLICIES:
        if not rule.scope:
            continue
        family, _, action = rule.scope.rpartition(":")
        catalog.append(
            {
                "scope": rule.scope,
                "family": family or rule.scope,
                "action": action or "access",
                "method": rule.method,
                "path_prefix": rule.path_prefix,
                "required_role": required_role(rule.method, rule.path_prefix),
            }
        )
    return sorted(catalog, key=lambda row: (row["scope"], row["method"], row["path_prefix"]))


# Compatibility views for consumers that inspect middleware rules. There is
# only one policy table; these views cannot drift from enforcement.
ROLE_RULES = tuple((rule.method, rule.path_prefix, rule.minimum_role) for rule in ROUTE_POLICIES)
SCOPE_RULES = tuple((rule.method, rule.path_prefix, rule.scope) for rule in ROUTE_POLICIES if rule.scope)
