"""Surface-parity tests for cloud scanning.

Covers the two gaps a consistency audit found:
  1. Cloud scanning reachable over REST (it was CLI + MCP only).
  2. MCP write/destructive tools enforced by role/scope at the dispatch layer
     (the ``destructiveHint`` metadata previously only hinted).

The REST result shape is asserted to match the MCP ``cloud_inventory`` /
``cis_benchmark`` tools so REST / CLI / MCP report the same fields and counts.
"""

from __future__ import annotations

import asyncio
import json
import os

from starlette.testclient import TestClient

from agent_bom.api.server import app, configure_api

PROXY_SECRET = "test-proxy-secret-with-32-plus-bytes"


def _proxy_headers(role: str = "admin", tenant: str = "tenant-alpha") -> dict[str, str]:
    return {
        "X-Agent-Bom-Role": role,
        "X-Agent-Bom-Tenant-ID": tenant,
        "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
    }


def setup_module() -> None:
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH"] = "1"
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH_SECRET"] = PROXY_SECRET


def teardown_module() -> None:
    os.environ.pop("AGENT_BOM_TRUST_PROXY_AUTH", None)
    os.environ.pop("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", None)


# --------------------------------------------------------------------------- #
# REST cloud endpoints — auth + role + data
# --------------------------------------------------------------------------- #


def test_cloud_inventory_requires_authenticated_context(monkeypatch) -> None:
    # The shared harness enables the anonymous opt-in by default; this contract
    # asserts fail-closed auth, so disable it and rebuild the middleware.
    monkeypatch.delenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", raising=False)
    configure_api(api_key=None)
    client = TestClient(app)
    resp = client.get("/v1/cloud/aws/inventory")
    assert resp.status_code == 401


def test_cloud_cis_requires_authenticated_context(monkeypatch) -> None:
    # The shared harness enables the anonymous opt-in by default; this contract
    # asserts fail-closed auth, so disable it and rebuild the middleware.
    monkeypatch.delenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", raising=False)
    configure_api(api_key=None)
    client = TestClient(app)
    resp = client.get("/v1/cloud/aws/cis-benchmark")
    assert resp.status_code == 401


def test_cloud_inventory_rejects_underprivileged_role() -> None:
    client = TestClient(app)
    resp = client.get("/v1/cloud/aws/inventory", headers=_proxy_headers(role="viewer"))
    assert resp.status_code == 403


def test_cloud_cis_rejects_underprivileged_role() -> None:
    client = TestClient(app)
    resp = client.get("/v1/cloud/aws/cis-benchmark", headers=_proxy_headers(role="viewer"))
    assert resp.status_code == 403


def test_cloud_inventory_allows_admin_role() -> None:
    client = TestClient(app)
    resp = client.get("/v1/cloud/aws/inventory", headers=_proxy_headers(role="admin"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["schema_version"] == "cloud.inventory.summary.v1"
    assert body["tenant_id"] == "tenant-alpha"
    assert {"total_resources", "total_identities", "providers", "audit_metadata"} <= set(body)
    assert body["audit_metadata"]["read_only"] is True
    assert body["audit_metadata"]["writes_performed"] is False
    assert [p["provider"] for p in body["providers"]] == ["aws"]


def test_cloud_inventory_allows_analyst_role() -> None:
    client = TestClient(app)
    resp = client.get("/v1/cloud/aws/inventory", headers=_proxy_headers(role="analyst"))
    assert resp.status_code == 200


def test_cloud_inventory_all_providers() -> None:
    client = TestClient(app)
    resp = client.get("/v1/cloud/all/inventory", headers=_proxy_headers())
    assert resp.status_code == 200
    providers = [p["provider"] for p in resp.json()["providers"]]
    assert providers == ["aws", "azure", "gcp"]


def test_cloud_inventory_unknown_provider_404() -> None:
    client = TestClient(app)
    resp = client.get("/v1/cloud/bogus/inventory", headers=_proxy_headers())
    assert resp.status_code == 404


def test_cloud_inventory_bad_region_400() -> None:
    client = TestClient(app)
    resp = client.get("/v1/cloud/aws/inventory?region=not a region", headers=_proxy_headers())
    assert resp.status_code == 400


def test_cloud_cis_allows_admin_role() -> None:
    client = TestClient(app)
    resp = client.get("/v1/cloud/aws/cis-benchmark", headers=_proxy_headers())
    # Authorized: 200 whether or not the cloud SDK is installed. With the SDK it
    # returns a full report; without it, a graceful error envelope (never 500).
    assert resp.status_code == 200
    body = resp.json()
    if "error" in body:
        assert body["status"] == "unavailable"
    else:
        assert body["audit_metadata"]["read_only"] is True
        assert "checks" in body or "summary" in body


def test_cloud_cis_unknown_provider_404() -> None:
    client = TestClient(app)
    resp = client.get("/v1/cloud/bogus/cis-benchmark", headers=_proxy_headers())
    assert resp.status_code == 404


def test_cloud_cis_snowflake_is_wired_not_404() -> None:
    # Snowflake CIS is a real benchmark (snowflake_cis_benchmark.run_benchmark);
    # it must not 404 like an unknown provider. Without the snowflake connector /
    # credentials in the test env it degrades to the shared "unavailable"
    # envelope (HTTP 200), exactly like the other providers — never 404, never 500.
    client = TestClient(app)
    resp = client.get("/v1/cloud/snowflake/cis-benchmark", headers=_proxy_headers())
    assert resp.status_code == 200
    body = resp.json()
    if "error" in body:
        assert body["status"] == "unavailable"
        assert body["provider"] == "snowflake"
    else:
        assert body["audit_metadata"]["read_only"] is True
        assert "checks" in body or "summary" in body


def test_cloud_cis_snowflake_rejects_underprivileged_role() -> None:
    client = TestClient(app)
    resp = client.get("/v1/cloud/snowflake/cis-benchmark", headers=_proxy_headers(role="viewer"))
    assert resp.status_code == 403


def test_cloud_cis_bad_region_400() -> None:
    client = TestClient(app)
    resp = client.get("/v1/cloud/aws/cis-benchmark?region=BAD", headers=_proxy_headers())
    assert resp.status_code == 400


# --------------------------------------------------------------------------- #
# Shape parity — REST == MCP for the same capability
# --------------------------------------------------------------------------- #


def _truncate(value: str) -> str:
    return value


def test_rest_inventory_shape_matches_mcp_tool() -> None:
    from agent_bom.mcp_tools.posture import cloud_inventory_impl

    mcp_payload = json.loads(
        asyncio.run(cloud_inventory_impl(providers="aws", region="", tenant_id="tenant-alpha", _truncate_response=_truncate))
    )
    client = TestClient(app)
    rest_payload = client.get("/v1/cloud/aws/inventory", headers=_proxy_headers()).json()

    # Same schema + provider-summary fields the CLI/MCP surface emit.
    assert rest_payload["schema_version"] == mcp_payload["schema_version"]
    assert [p["provider"] for p in rest_payload["providers"]] == [p["provider"] for p in mcp_payload["providers"]]
    rest_aws = rest_payload["providers"][0]
    mcp_aws = mcp_payload["providers"][0]
    assert set(rest_aws) == set(mcp_aws)
    assert rest_aws["resource_count"] == mcp_aws["resource_count"]
    assert rest_aws["identity_count"] == mcp_aws["identity_count"]
    assert rest_aws["node_summary"] == mcp_aws["node_summary"]


def test_rest_cis_shape_matches_mcp_tool() -> None:
    from agent_bom.mcp_tools.compliance import cis_benchmark_impl

    mcp_payload = json.loads(asyncio.run(cis_benchmark_impl(provider="aws", _truncate_response=_truncate)))
    client = TestClient(app)
    rest_payload = client.get("/v1/cloud/aws/cis-benchmark", headers=_proxy_headers()).json()

    if "error" in mcp_payload:
        # No cloud SDK installed: both surfaces degrade to an error envelope, no 500.
        assert "error" in rest_payload
    else:
        # REST returns the same report.to_dict() shape, plus additive metadata.
        mcp_keys = set(mcp_payload)
        rest_keys = set(rest_payload) - {"audit_metadata", "tenant_id"}
        assert rest_keys == mcp_keys


# --------------------------------------------------------------------------- #
# MCP write-tool role enforcement at the dispatch layer
# --------------------------------------------------------------------------- #


def test_authorize_destructive_blocks_non_admin() -> None:
    from agent_bom.mcp_server_runtime import authorize_destructive_tool

    denial = authorize_destructive_tool(
        "shield_start", operator_role="viewer", operator_scopes="shield:write", required_scope="shield:write"
    )
    assert denial is not None
    assert denial["status"] == "blocked"
    assert denial["required_role"] == "admin"


def test_authorize_destructive_blocks_missing_scope() -> None:
    from agent_bom.mcp_server_runtime import authorize_destructive_tool

    denial = authorize_destructive_tool(
        "identity_issue",
        operator_role="admin",
        operator_scopes="identity:write",
        auth_scopes="admin",
        required_scope="identity:write",
    )
    assert denial is not None
    assert denial["required_scope"] == "identity:write"


def test_authorize_destructive_blocks_self_asserted_admin_without_operator_token() -> None:
    from agent_bom.mcp_server_runtime import authorize_destructive_tool

    denial = authorize_destructive_tool(
        "identity_issue",
        operator_role="admin",
        operator_scopes="identity:write",
        auth_scopes="",
        required_scope="identity:write",
    )
    assert denial is not None
    assert denial["status"] == "blocked"
    assert "authenticated operator token" in denial["error"]


def test_authorize_destructive_allows_admin_with_scope() -> None:
    from agent_bom.mcp_server_runtime import authorize_destructive_tool

    assert (
        authorize_destructive_tool(
            "identity_issue",
            operator_role="admin",
            operator_scopes="identity:write",
            auth_scopes="admin,identity:write",
            required_scope="identity:write",
        )
        is None
    )
    # Wildcard scope is accepted.
    assert (
        authorize_destructive_tool(
            "identity_issue",
            operator_role="admin",
            operator_scopes="",
            auth_scopes="admin,*",
            required_scope="identity:write",
        )
        is None
    )


def test_dispatch_blocks_destructive_tool_for_low_role() -> None:
    from agent_bom import mcp_server

    async def handler(**_kwargs: object) -> str:
        return "HANDLER_RAN"

    out = asyncio.run(
        mcp_server._execute_tool_async(
            "shield_start",
            handler,
            destructive=True,
            required_scope="shield:write",
            operator_role="viewer",
            operator_scopes="shield:write",
        )
    )
    assert "HANDLER_RAN" not in out
    assert json.loads(out)["status"] == "blocked"


def test_dispatch_blocks_self_asserted_admin_without_operator_token() -> None:
    from agent_bom import mcp_server

    async def handler(**_kwargs: object) -> str:
        return "HANDLER_RAN"

    out = asyncio.run(
        mcp_server._execute_tool_async(
            "shield_start",
            handler,
            destructive=True,
            required_scope="shield:write",
            operator_role="admin",
            operator_scopes="shield:write",
        )
    )
    assert "HANDLER_RAN" not in out
    assert "authenticated operator token" in json.loads(out)["error"]


def test_authorize_destructive_allows_authenticated_operator_without_self_asserted_role() -> None:
    from agent_bom.mcp_server_runtime import authorize_destructive_tool

    assert (
        authorize_destructive_tool(
            "identity_issue",
            operator_role="viewer",
            operator_scopes="",
            auth_scopes="admin,identity:write",
            required_scope="identity:write",
        )
        is None
    )


def test_dispatch_allows_destructive_tool_with_default_viewer_role_when_operator_token(
    monkeypatch,
) -> None:
    from agent_bom import mcp_server

    async def handler(**_kwargs: object) -> str:
        return "HANDLER_RAN"

    monkeypatch.setattr(
        mcp_server,
        "_current_tool_request",
        lambda: {
            "caller": "operator",
            "client_id": "agent-bom-operator-token",
            "request_id": "req-2",
            "auth_scopes": "admin,shield:write",
        },
    )

    out = asyncio.run(
        mcp_server._execute_tool_async(
            "shield_start",
            handler,
            destructive=True,
            required_scope="shield:write",
            operator_role="viewer",
            operator_scopes="",
            reason="legitimate operator audit reason",
        )
    )
    assert out == "HANDLER_RAN"


def test_dispatch_allows_destructive_tool_for_authenticated_operator(monkeypatch) -> None:
    from agent_bom import mcp_server

    async def handler(**_kwargs: object) -> str:
        return "HANDLER_RAN"

    monkeypatch.setattr(
        mcp_server,
        "_current_tool_request",
        lambda: {
            "caller": "operator",
            "client_id": "agent-bom-operator-token",
            "request_id": "req-1",
            "auth_scopes": "admin,shield:write",
        },
    )

    out = asyncio.run(
        mcp_server._execute_tool_async(
            "shield_start",
            handler,
            destructive=True,
            required_scope="shield:write",
            operator_role="admin",
            operator_scopes="shield:write",
        )
    )
    assert out == "HANDLER_RAN"


def test_dispatch_never_gates_read_only_tools() -> None:
    from agent_bom import mcp_server

    async def handler(**_kwargs: object) -> str:
        return "HANDLER_RAN"

    out = asyncio.run(mcp_server._execute_tool_async("scan", handler, destructive=False))
    assert out == "HANDLER_RAN"


# --------------------------------------------------------------------------- #
# Audit metadata must never surface exception-derived text (py/stack-trace).
# --------------------------------------------------------------------------- #


def test_audit_metadata_drops_exception_derived_text() -> None:
    from agent_bom.api.routes.cloud import _audit_metadata

    out = _audit_metadata(
        [
            {
                "discovery_envelope": {
                    "permissions_used": [
                        "ec2:DescribeInstances",
                        "compute.instances.list",
                        "Traceback (most recent call last): boom",
                        "token with spaces",
                    ],
                    "discovery_scope": [
                        "us-east-1",
                        "arn:aws:s3:::bucket",
                        "line 154\n  raise RuntimeError('x')",
                    ],
                    "redaction_status": "redacted",
                    "scan_mode": "read_only",
                },
                "warnings": ["AccessDenied: arn:... could not assume role: <stack>"],
            }
        ]
    )

    # well-formed IAM identifiers survive
    assert "ec2:DescribeInstances" in out["permissions_used"]
    assert "compute.instances.list" in out["permissions_used"]
    assert "arn:aws:s3:::bucket" in out["discovery_scope"]
    assert "us-east-1" in out["discovery_scope"]
    assert out["redaction_status"] == ["redacted"]
    assert out["scan_modes"] == ["read_only"]

    # any value carrying whitespace / a stack fragment is dropped
    flat = out["permissions_used"] + out["discovery_scope"]
    assert all(" " not in tok and "\n" not in tok for tok in flat)
    assert not any("Traceback" in tok or "raise" in tok for tok in flat)
