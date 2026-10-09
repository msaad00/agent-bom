"""Gateway routing, policy and audit retain one explicit tenant authority."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from starlette.testclient import TestClient

import agent_bom.api.gateway_relay_identity as relay_identity
import agent_bom.gateway_server as gateway
from agent_bom.api.auth import Role
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry


@pytest.mark.parametrize("tenant", [None, "", " \t", 123, [], {}])
@pytest.mark.parametrize("endpoint", ["/mcp/shared", "/v1/firewall/check", "/metrics"])
def test_verified_key_without_explicit_tenant_fails_before_resources(monkeypatch, tenant, endpoint):
    key = SimpleNamespace(tenant_id=tenant, role=Role.ANALYST, has_scope=lambda _: True)
    monkeypatch.setattr("agent_bom.api.gateway_auth.get_key_store", lambda: SimpleNamespace(has_keys=lambda: True, verify=lambda _: key))
    registry = UpstreamRegistry([UpstreamConfig(name="shared", url="https://upstream.example/mcp", tenant_id="default")])
    lookup = Mock(wraps=registry.get)
    monkeypatch.setattr(registry, "get", lookup)
    upstream = AsyncMock(return_value={"jsonrpc": "2.0", "id": 1, "result": {}})
    audit = AsyncMock()
    client = TestClient(
        gateway.create_gateway_app(gateway.GatewaySettings(registry=registry, policy={}, upstream_caller=upstream, audit_sink=audit)),
        raise_server_exceptions=False,
    )
    response = client.request(
        "GET" if endpoint == "/metrics" else "POST",
        endpoint,
        headers={"X-API-Key": "synthetic-key"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "gateway authentication required"}
    lookup.assert_not_called()
    upstream.assert_not_awaited()
    audit.assert_not_awaited()


@pytest.mark.parametrize("tenant", ["default", "tenant-a"])
@pytest.mark.parametrize("auth_mode", ["none", "key", "static"])
def test_selected_tenant_reaches_routing_policy_and_audit(monkeypatch, tenant, auth_mode):
    monkeypatch.setenv("AGENT_BOM_TENANT_ID", tenant)
    key = SimpleNamespace(tenant_id=tenant, role=Role.ANALYST, has_scope=lambda _: True)
    monkeypatch.setattr(
        "agent_bom.api.gateway_auth.get_key_store", lambda: SimpleNamespace(has_keys=lambda: auth_mode == "key", verify=lambda _: key)
    )
    registry = UpstreamRegistry([UpstreamConfig(name="shared", url="https://upstream.example/mcp", tenant_id=tenant)])
    seen = []

    def evaluate(resolved_tenant, source_agent):
        seen.append(resolved_tenant)
        return True, False, False

    monkeypatch.setattr(relay_identity, "_agent_identity_revoked", evaluate)
    monkeypatch.setattr(relay_identity, "check_caller_identity", lambda *_: ("agent-one", True, None))
    upstream = AsyncMock(return_value={"jsonrpc": "2.0", "id": 1, "result": {}})
    audit = AsyncMock()
    settings = gateway.GatewaySettings(registry=registry, policy={}, upstream_caller=upstream, audit_sink=audit)
    if auth_mode == "static":
        from datetime import datetime, timedelta, timezone

        settings.bearer_token = "synthetic-key"
        settings.bearer_token_expires_at = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    client = TestClient(gateway.create_gateway_app(settings))
    response = client.post(
        "/mcp/shared",
        headers={"X-API-Key": "synthetic-key"} if auth_mode != "none" else {},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read"}},
    )
    assert response.status_code == 200
    assert "error" in response.json()
    assert seen == [tenant]
    upstream.assert_not_awaited()
    assert audit.await_count > 0
    assert all(call.args[0]["tenant_id"] == tenant for call in audit.await_args_list)
