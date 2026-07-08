#!/usr/bin/env python3
"""Guard the shared control-plane contract across product surfaces.

The API owns auth, tenant scope, quotas, SCIM, fleet, graph, policy, and audit.
The UI, MCP runtime surfaces, Helm examples, Docker Hub copy, and CI workflows
should reference that same contract instead of drifting into parallel models.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _require_text(path: str, needles: list[str], failures: list[str]) -> None:
    text = _text(path)
    for needle in needles:
        if needle not in text:
            failures.append(f"{path}: missing {needle!r}")


def _require_v1_routes(path: str, routes: list[tuple[str, str]], failures: list[str]) -> None:
    """Require route decorators for full /v1 paths after shared-prefix mounting."""
    text = _text(path)
    prefix = "/v1"
    for method, full_path in routes:
        if not full_path.startswith(prefix):
            failures.append(f"{path}: expected v1 route path, got {full_path!r}")
            continue
        route_path = full_path.removeprefix(prefix) or "/"
        needle = f'@router.{method.lower()}("{route_path}"'
        if needle not in text:
            failures.append(f"{path}: missing {needle!r} for {method.upper()} {full_path}")


def main() -> int:
    failures: list[str] = []

    _require_text(
        "src/agent_bom/api/versioning.py",
        [
            'API_V1_PREFIX = "/v1"',
            "create_v1_api_router",
        ],
        failures,
    )
    _require_v1_routes(
        "src/agent_bom/api/routes/enterprise.py",
        [
            ("GET", "/v1/auth/policy"),
            ("GET", "/v1/auth/scim/config"),
            ("GET", "/v1/auth/secrets/lifecycle"),
            ("GET", "/v1/auth/secrets/rotation-plan"),
            ("GET", "/v1/auth/secrets/credential-expiry"),
            ("GET", "/v1/auth/quota"),
            ("PUT", "/v1/auth/quota"),
        ],
        failures,
    )
    _require_text(
        "src/agent_bom/api/routes/enterprise.py",
        [
            "tenant_quota_runtime",
            "configured_modes",
            "audit_hmac",
            "secret_lifecycle",
            "scim",
        ],
        failures,
    )
    _require_text(
        "src/agent_bom/api/middleware.py",
        [
            '("GET", "/v1/auth/policy", "admin")',
            '("GET", "/v1/auth/scim/config", "admin")',
            '("GET", "/v1/auth/secrets/lifecycle", "admin")',
            '("GET", "/v1/auth/secrets/rotation-plan", "admin")',
            '("GET", "/v1/auth/secrets/credential-expiry", "admin")',
            '("GET", "/v1/auth/quota", "admin")',
            '("POST", "/v1/fleet/sync", "admin")',
            '("GET", "/v1/auth/scim/config", "auth.scim:read")',
            '("GET", "/v1/auth/secrets/lifecycle", "auth.secrets:read")',
            '("GET", "/v1/auth/secrets/rotation-plan", "auth.secrets:read")',
            '("GET", "/v1/auth/secrets/credential-expiry", "auth.secrets:read")',
            '("PUT", "/v1/auth/quota", "auth.quota:write")',
            '("POST", "/v1/fleet/sync", "fleet:write")',
        ],
        failures,
    )
    _require_text(
        "src/agent_bom/api/routes/scim.py",
        [
            '@router.get("/ServiceProviderConfig"',
            '@router.get("/Schemas"',
            '@router.get("/ResourceTypes"',
            '@router.get("/Users"',
            '@router.post("/Users"',
            '@router.get("/Groups"',
            '@router.post("/Groups"',
            "SCIM bearer token required",
        ],
        failures,
    )
    _require_v1_routes(
        "src/agent_bom/api/routes/fleet.py",
        [
            ("GET", "/v1/fleet"),
            ("GET", "/v1/fleet/stats"),
            ("GET", "/v1/fleet/{agent_id}"),
            ("POST", "/v1/fleet/sync"),
        ],
        failures,
    )
    _require_text(
        "src/agent_bom/api/routes/fleet.py",
        [
            "limit: int",
            "offset: int",
        ],
        failures,
    )
    _require_v1_routes(
        "src/agent_bom/api/routes/graph.py",
        [
            ("GET", "/v1/graph"),
            ("GET", "/v1/graph/agents"),
            ("GET", "/v1/graph/search"),
            ("GET", "/v1/graph/node/{node_id}"),
        ],
        failures,
    )
    _require_text(
        "src/agent_bom/api/routes/graph.py",
        [
            "limit: int",
            "offset: int",
        ],
        failures,
    )

    _require_text(
        "ui/lib/api.ts",
        [
            'getAuthPolicy: () => get<AuthPolicyResponse>("/v1/auth/policy")',
            'getTenantQuota: () => get<AuthPolicyResponse["tenant_quota_runtime"]>("/v1/auth/quota")',
            'put<AuthPolicyResponse["tenant_quota_runtime"]>("/v1/auth/quota", body)',
            'del("/v1/auth/quota")',
            'return get<GraphAgentsResponse>(`/v1/graph/agents${qs ? `?${qs}` : ""}`)',
            'return get<FleetResponse>(`/v1/fleet${qs ? `?${qs}` : ""}`)',
        ],
        failures,
    )
    _require_text(
        "ui/components/key-lifecycle-panel.tsx",
        [
            "tenant_quota_runtime",
            "fleet_agents",
            "Active scan jobs",
            "Retained scan jobs",
            "Schedules",
        ],
        failures,
    )

    _require_text(
        "deploy/helm/agent-bom/examples/eks-production-values.yaml",
        [
            "AGENT_BOM_REQUIRE_SHARED_SCIM_STORE",
            "AGENT_BOM_SCIM_BEARER_TOKEN",
            "AGENT_BOM_SCIM_TENANT_ID",
            "AGENT_BOM_BROWSER_SESSION_SIGNING_KEY",
            "AGENT_BOM_BROWSER_SESSION_SIGNING_KEY_LAST_ROTATED",
            "AGENT_BOM_OIDC_ISSUER",
            "AGENT_BOM_AUDIT_HMAC_KEY",
            "aws-secrets-manager",
        ],
        failures,
    )
    _require_text(
        "deploy/helm/agent-bom/values.yaml",
        [
            "api:",
            "ui:",
            "gateway:",
            "requireSharedRateLimit",
            "prometheusRule:",
        ],
        failures,
    )

    _require_text(
        "DOCKER_HUB_README.md",
        [
            "one product with two deployable container images",
            "agentbom/agent-bom",
            "agentbom/agent-bom-ui",
            "Control-Plane Contract",
            "API is the source of truth",
            "UI displays that posture",
            "MCP Gateway consumes the same tenant",
            "secret-manager",
            "CLI and local MCP",
            "modes stay low-friction",
        ],
        failures,
    )
    _require_text(
        "DOCKER_HUB_UI_README.md",
        [
            "not a separate product",
            "Control-Plane Contract",
            "/v1/auth/policy",
            "/v1/auth/quota",
            "secret lifecycle",
            "/v1/graph/agents",
            "/v1/fleet",
        ],
        failures,
    )
    _require_text(
        "docs/MCP_SERVER.md",
        [
            "fails closed",
            "AGENT_BOM_MCP_BEARER_TOKEN",
            "Enterprise Control-Plane Contract",
            "tenant",
            "policy",
            "audit",
        ],
        failures,
    )
    _require_text(
        "site-docs/deployment/proxy-vs-gateway-vs-fleet.md",
        [
            "tenant-aware auth",
            "shared tenant rate limiting",
            "audit logging",
            "environment-backed tokens",
            "control plane",
        ],
        failures,
    )

    _require_text(
        ".github/workflows/ci.yml",
        [
            "merge_group:",
            "python scripts/check_release_consistency.py",
            "python scripts/check_product_surface_contract.py",
            "Test (Python ${{ matrix.python-version }})",
            "python-version: ['3.11', '3.13', '3.14']",
        ],
        failures,
    )
    _require_text(".github/workflows/pr-security-gate.yml", ["merge_group:", "agent-bom self-scan on PR"], failures)
    _require_text(".github/workflows/codeql.yml", ["merge_group:", "Analyze"], failures)
    _require_text(".github/workflows/release.yml", ["python scripts/check_release_consistency.py"], failures)

    if failures:
        print("Product surface contract check failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("Product surface contract check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
