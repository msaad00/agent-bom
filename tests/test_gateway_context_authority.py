"""Unverified transport metadata must not satisfy gateway access constraints."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from starlette.testclient import TestClient

from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry
from agent_bom.proxy_policy import context_from_now, evaluate_conditions


def app_config(conditions):
    upstream = AsyncMock(return_value={"jsonrpc": "2.0", "id": 1, "result": {"ok": True}})
    config = GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="fixture", url="https://fixture.invalid/mcp")]),
        policy={"rules": [{"id": "context-required", "action": "block", "conditions": conditions}]},
        bearer_token="synthetic-context-test-token",
        bearer_token_expires_at=(datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(),
        listener_host="0.0.0.0",
        allow_anonymous_agents=True,
        upstream_caller=upstream,
        audit_sink=AsyncMock(),
    )
    return config, upstream


CASES = [
    ({"required_attributes": {"mfa": "true"}}, {"x-agent-ctx-mfa": "true"}),
    ({"allowed_devices": ["managed-device"]}, {"x-agent-device-id": "managed-device"}),
    ({"allowed_groups": ["privileged"]}, {"x-agent-groups": "privileged"}),
    ({"allowed_clients": ["approved-client"]}, {"x-agent-client-id": "approved-client"}),
    ({"max_risk_score": 0.5}, {"x-agent-risk-score": "0.1"}),
]


@pytest.mark.parametrize("conditions,forged", CASES)
def test_direct_authenticated_client_cannot_self_assert_access_context(conditions, forged):
    config, upstream = app_config(conditions)
    with TestClient(create_gateway_app(config), client=("198.51.100.21", 7777)) as client:
        response = client.post(
            "/mcp/fixture",
            headers={
                "Authorization": "Bearer synthetic-context-test-token",
                "x-forwarded-for": "127.0.0.1",
                **forged,
            },
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read"}},
        )
    assert response.status_code == 200
    assert response.json().get("error", {}).get("data", {}).get("policy_source") == "conditional_access"
    upstream.assert_not_awaited()


@pytest.mark.parametrize("risk", [None, float("nan"), float("inf"), float("-inf"), True])
@pytest.mark.parametrize("bound", ["min_risk_score", "max_risk_score"])
def test_risk_constraints_require_finite_evidence(risk, bound):
    allowed, _ = evaluate_conditions({bound: 0.5}, context_from_now(now=1781517600, risk_score=risk))
    assert not allowed


@pytest.mark.parametrize("conditions,asserted", CASES)
@pytest.mark.parametrize(
    "peer,cidrs,allowed",
    [
        ("192.0.2.9", ("192.0.2.9/32",), True),
        ("198.51.100.21", ("192.0.2.9/32",), False),
        ("2001:db8::9", ("2001:db8::/64",), True),
    ],
)
def test_only_explicit_proxy_peer_can_supply_access_context(conditions, asserted, peer, cidrs, allowed):
    config, upstream = app_config(conditions)
    config.trusted_context_proxy_cidrs = cidrs
    with TestClient(create_gateway_app(config), client=(peer, 7777)) as client:
        response = client.post(
            "/mcp/fixture",
            headers={
                "Authorization": "Bearer synthetic-context-test-token",
                "x-forwarded-for": "192.0.2.9",
                **asserted,
            },
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read"}},
        )
    if allowed:
        assert response.json().get("result") == {"ok": True}
        upstream.assert_awaited_once()
    else:
        assert response.json().get("error", {}).get("data", {}).get("policy_source") == "conditional_access"
        upstream.assert_not_awaited()


@pytest.mark.parametrize("cidrs", [("bad-network",), ("0.0.0.0/0",), ("::/0",), ("",), ("127.0.0.1/32",) * 33])
def test_invalid_proxy_trust_configuration_refuses_startup(cidrs):
    config, _ = app_config({})
    config.trusted_context_proxy_cidrs = cidrs
    with pytest.raises(ValueError, match="Gateway trusted context proxy CIDRs"):
        create_gateway_app(config)


def test_explicit_empty_setting_overrides_environment(monkeypatch):
    from agent_bom.api.gateway_context import trusted_context_networks

    config, _ = app_config({})
    monkeypatch.setenv("AGENT_BOM_GATEWAY_TRUSTED_CONTEXT_PROXY_CIDRS", "192.0.2.9/32,2001:db8::/64")
    assert [str(network) for network in trusted_context_networks(config)] == ["192.0.2.9/32", "2001:db8::/64"]
    config.trusted_context_proxy_cidrs = ()
    assert trusted_context_networks(config) == ()


@pytest.mark.parametrize("bound", [float("nan"), float("inf"), None, True, "0.5"])
def test_malformed_risk_configuration_is_denied(bound):
    assert not evaluate_conditions({"max_risk_score": bound}, context_from_now(now=0, risk_score=0.1))[0]


def test_context_trust_is_fixed_at_app_startup(monkeypatch):
    config, upstream = app_config({"required_attributes": {"mfa": "true"}})
    monkeypatch.setenv("AGENT_BOM_GATEWAY_TRUSTED_CONTEXT_PROXY_CIDRS", "127.0.0.1/32")
    trusted_app = create_gateway_app(config)
    monkeypatch.setenv("AGENT_BOM_GATEWAY_TRUSTED_CONTEXT_PROXY_CIDRS", "")
    config.trusted_context_proxy_cidrs = ()
    untrusted_app = create_gateway_app(config)
    for app, allowed in ((trusted_app, True), (untrusted_app, False)):
        with TestClient(app, client=("127.0.0.1", 7777)) as client:
            response = client.post(
                "/mcp/fixture",
                headers={"Authorization": "Bearer synthetic-context-test-token", "x-agent-ctx-mfa": "true"},
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read"}},
            )
        assert ("result" in response.json()) is allowed
    upstream.assert_awaited_once()


def test_forwarded_ip_trust_does_not_enable_assertion_trust(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_TRUSTED_PROXY_CIDRS", "198.51.100.21/32")
    monkeypatch.setenv("AGENT_BOM_TRUSTED_PROXY_HOPS", "1")
    test_direct_authenticated_client_cannot_self_assert_access_context(*CASES[0])
