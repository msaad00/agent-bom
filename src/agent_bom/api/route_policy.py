"""One route policy for API enforcement and the operator scope catalog.

Rules match path segments, never similarly named sibling routes. Specific
subpaths win. HEAD shares GET policy. Authentication remains the middleware's
responsibility; unclassified mutations retain the administrative role floor.
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


ROUTE_POLICIES: tuple[RoutePolicy, ...] = (
    RoutePolicy("GET", "/v1/observability/adoption", "admin", "audit:read"),
    RoutePolicy("POST", "/v1/observability/adoption/events", "analyst", "scan:write"),
    RoutePolicy("GET", "/v1/compliance", "viewer", None),
    RoutePolicy("GET", "/v1/posture/backpressure", "viewer", None),
    RoutePolicy("GET", "/v1/posture/webhooks/", "analyst", None),
    RoutePolicy("GET", "/v1/posture", "viewer", None),
    RoutePolicy("GET", "/v1/auth/debug", "viewer", None),
    RoutePolicy("GET", "/v1/auth/me", "viewer", None),
    RoutePolicy("GET", "/v1/auth/policy", "admin", None),
    RoutePolicy("GET", "/v1/auth/scopes", "admin", None),
    RoutePolicy("GET", "/v1/auth/secrets/lifecycle", "admin", "auth.secrets:read"),
    RoutePolicy("GET", "/v1/auth/secrets/rotation-plan", "admin", "auth.secrets:read"),
    RoutePolicy("GET", "/v1/auth/secrets/credential-expiry", "admin", "auth.secrets:read"),
    RoutePolicy("GET", "/v1/auth/scim/config", "admin", "auth.scim:read"),
    RoutePolicy("GET", "/v1/entitlements", "admin", None),
    RoutePolicy("GET", "/v1/credentials", "viewer", "source:read"),
    RoutePolicy("GET", "/v1/evaluations", "viewer", "eval:read"),
    RoutePolicy("POST", "/v1/intel/match", "viewer", "intel:read"),
    RoutePolicy("POST", "/v1/intel/daily-brief", "viewer", "intel:read"),
    RoutePolicy("POST", "/v1/runtime/profiles/evaluate", "viewer", None),
    RoutePolicy("POST", "/v1/graph/query", "viewer", "graph:read"),
    RoutePolicy("POST", "/v1/graph/should-i-deploy", "viewer", "graph:read"),
    RoutePolicy("GET", "/v1/graph/scenarios", "viewer", "graph:read"),
    RoutePolicy("POST", "/v1/graph/scenarios", "analyst", "scan:write"),
    RoutePolicy("PUT", "/v1/graph/scenarios/", "analyst", "scan:write"),
    RoutePolicy("DELETE", "/v1/graph/scenarios/", "admin", "config:write"),
    RoutePolicy("POST", "/v1/audit/export/verify", "viewer", None),
    RoutePolicy("POST", "/v1/traces/attack-paths", "viewer", None),
    RoutePolicy("GET", "/v1/audit", "analyst", None),
    RoutePolicy("GET", "/v1/audit/", "analyst", None),
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
    RoutePolicy("POST", "/v1/posture/webhooks/", "admin", None),
    RoutePolicy("PUT", "/v1/gateway/policies/", "admin", "gateway.policy:write"),
    RoutePolicy("DELETE", "/v1/gateway/policies/", "admin", "gateway.policy:write"),
    RoutePolicy("POST", "/v1/fleet/sync", "admin", "fleet:write"),
    RoutePolicy("DELETE", "/v1/sources/", "admin", None),
    RoutePolicy("PUT", "/v1/fleet/", "admin", None),
    RoutePolicy("PUT", "/v1/exceptions/", "admin", "exception:write"),
    RoutePolicy("DELETE", "/v1/exceptions/", "admin", "exception:write"),
    RoutePolicy("POST", "/v1/siem/test", "admin", None),
    RoutePolicy("POST", "/v1/shield/start", "admin", "shield:write"),
    RoutePolicy("POST", "/v1/shield/unblock", "admin", "shield:write"),
    RoutePolicy("POST", "/v1/shield/break-glass", "admin", "shield:write"),
    RoutePolicy("DELETE", "/v1/scan/", "admin", "scan:delete"),
    RoutePolicy("POST", "/v1/exceptions", "analyst", "exception:write"),
    RoutePolicy("POST", "/v1/findings/bulk", "analyst", None),
    RoutePolicy("POST", "/v1/reports", "analyst", None),
    RoutePolicy("GET", "/v1/reports/", "analyst", None),
    RoutePolicy("POST", "/v1/findings/false-positive", "analyst", None),
    RoutePolicy("POST", "/v1/findings/feedback", "analyst", None),
    RoutePolicy("DELETE", "/v1/findings/false-positive/", "analyst", None),
    RoutePolicy("DELETE", "/v1/findings/feedback/", "analyst", None),
    RoutePolicy("POST", "/v1/scan", "analyst", "scan:write"),
    RoutePolicy("POST", "/v1/credentials", "analyst", "source:write"),
    RoutePolicy("POST", "/v1/credentials/", "analyst", "source:write"),
    RoutePolicy("POST", "/v1/datasets/", "analyst", None),
    RoutePolicy("POST", "/v1/evaluations", "analyst", "eval:write"),
    RoutePolicy("POST", "/v1/gateway/evaluate", "analyst", None),
    RoutePolicy("POST", "/v1/firewall/check", "analyst", "gateway.firewall:write"),
    RoutePolicy("POST", "/v1/proxy/audit", "analyst", None),
    RoutePolicy("POST", "/v1/traces", "analyst", None),
    RoutePolicy("POST", "/v1/ocsf/ingest", "analyst", None),
    RoutePolicy("POST", "/v1/results/push", "analyst", None),
    RoutePolicy("POST", "/v1/schedules", "analyst", "schedule:write"),
    RoutePolicy("POST", "/v1/sources", "analyst", None),
    RoutePolicy("POST", "/v1/sources/", "analyst", None),
    RoutePolicy("POST", "/v1/baseline/compare", "analyst", None),
    RoutePolicy("POST", "/v1/graph/presets", "analyst", "graph.preset:write"),
    RoutePolicy("POST", "/v1/graph/correlations", "analyst", "scan:write"),
    RoutePolicy("POST", "/v1/model-keys/providers/", "analyst", None),
    RoutePolicy("POST", "/v1/model-keys/virtual-keys/", "analyst", None),
    RoutePolicy("POST", "/v1/model-keys/authorize", "analyst", None),
    RoutePolicy("DELETE", "/v1/schedules/", "analyst", "schedule:write"),
    RoutePolicy("DELETE", "/v1/graph/presets/", "analyst", "graph.preset:write"),
    RoutePolicy("PUT", "/v1/schedules/", "analyst", "schedule:write"),
    RoutePolicy("PUT", "/v1/credentials/", "analyst", "source:write"),
    RoutePolicy("PUT", "/v1/sources/", "analyst", None),
    RoutePolicy("GET", "/v1/endpoint-connectors", "viewer", "connectors:read"),
    RoutePolicy("POST", "/v1/endpoint-connectors", "admin", "connectors:write"),
    RoutePolicy("PATCH", "/v1/endpoint-connectors/", "admin", "connectors:write"),
    RoutePolicy("PUT", "/v1/endpoint-connectors/", "admin", "connectors:write"),
    RoutePolicy("GET", "/v1/cloud/connections", "viewer", "cloud.connection:read"),
    RoutePolicy("POST", "/v1/cloud/connections", "admin", "cloud.connection:write"),
    RoutePolicy("PATCH", "/v1/cloud/connections/", "admin", "cloud.connection:write"),
    RoutePolicy("DELETE", "/v1/cloud/connections/", "admin", "cloud.connection:write"),
    RoutePolicy("GET", "/v1/findings", "viewer", "finding:read"),
    RoutePolicy("GET", "/v1/graph", "viewer", "graph:read"),
    RoutePolicy("GET", "/v1/intel", "viewer", "intel:read"),
    RoutePolicy("GET", "/v1/gateway/policies", "viewer", "gateway.policy:read"),
    RoutePolicy("GET", "/v1/gateway/audit", "viewer", "audit:read"),
    RoutePolicy("POST", "/v1/sources/run-cohort", "analyst", "scan:write"),
)


def _method(method: str) -> str:
    normalized = method.upper()
    return "GET" if normalized == "HEAD" else normalized


def _matches(path: str, prefix: str) -> bool:
    return path.startswith(prefix) if prefix.endswith("/") else path == prefix or path.startswith(prefix + "/")


def route_policy(method: str, path: str) -> RoutePolicy | None:
    normalized_method = _method(method)
    candidates = (rule for rule in ROUTE_POLICIES if rule.method == normalized_method and _matches(path, rule.path_prefix))
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
