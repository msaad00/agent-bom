"""Invalid gateway settings must not silently weaken protection."""

from unittest.mock import Mock

import pytest
from starlette.testclient import TestClient

from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry

MODES = (
    "fleet_enforcement_mode",
    "drift_enforcement_mode",
    "anomaly_enforcement_mode",
    "a2a_mutual_auth_enforcement_mode",
    "graph_reachability_enforcement_mode",
    "graph_reachability_failure_mode",
    "dlp_mode",
    "dlp_pii_action",
)


def settings(**kwargs):
    return GatewaySettings(registry=UpstreamRegistry([UpstreamConfig(name="upstream", url="http://upstream.invalid")]), policy={}, **kwargs)


@pytest.mark.parametrize("field", MODES)
def test_invalid_security_mode_rejected_before_startup_side_effects(monkeypatch, field):
    audit = Mock()
    monkeypatch.setattr("agent_bom.gateway_server.build_local_gateway_audit_sink", audit)
    with pytest.raises(ValueError, match=field) as error:
        create_gateway_app(settings(**{field: "typo-secret-value"}))
    assert "typo-secret-value" not in str(error.value)
    audit.assert_not_called()


def test_normalized_fleet_mode_still_blocks_quarantined_identity(monkeypatch):
    from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState, InMemoryFleetStore

    store = InMemoryFleetStore()
    store.put(
        FleetAgent(
            agent_id="agent-a", name="agent-a", agent_type="custom", tenant_id="default", lifecycle_state=FleetLifecycleState.QUARANTINED
        )
    )
    monkeypatch.setattr("agent_bom.api.stores._get_fleet_store", lambda: store)
    calls = []

    async def upstream(*args):
        calls.append(args)
        return {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}

    config = settings(fleet_enforcement_mode=" ENFORCE ", upstream_caller=upstream)
    config.policy = {"agent_tokens": {"synthetic-token": "agent-a"}}
    response = TestClient(create_gateway_app(config)).post(
        "/mcp/upstream",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {}, "_meta": {"agent_identity": "synthetic-token"}},
        },
    )
    assert response.json()["error"]["data"]["policy_source"] == "fleet_quarantine"
    assert calls == []


def test_settings_repr_does_not_expose_credentials_or_policy():
    config = settings(
        bearer_token="bearer-secret",
        graph_reachability_bundle_bearer_token="bundle-secret",
        graph_reachability_bundle_signing_key=b"signing-secret",
        policy_webhook_token="webhook-secret",
    )
    config.policy = {"agent_tokens": {"policy-secret": "agent-a"}}
    config.control_plane_policies = [{"secret": "control-secret"}]
    rendered = repr(config)
    for secret in ("bearer-secret", "bundle-secret", "signing-secret", "webhook-secret", "policy-secret", "control-secret"):
        assert secret not in rendered


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("upstream_http_timeout_seconds", float("nan")),
        ("upstream_http_timeout_seconds", float("inf")),
        ("upstream_http_timeout_seconds", 0),
        ("upstream_http_max_connections", 0),
        ("upstream_http_max_connections", 1.5),
        ("upstream_failure_threshold", True),
        ("runtime_rate_limit_per_tenant_per_minute", -1),
        ("graph_reachability_bundle_poll_interval_seconds", -1),
    ],
)
def test_invalid_resource_bounds_rejected_before_audit(monkeypatch, field, value):
    audit = Mock()
    monkeypatch.setattr("agent_bom.gateway_server.build_local_gateway_audit_sink", audit)
    with pytest.raises(ValueError, match=field):
        create_gateway_app(settings(**{field: value}))
    audit.assert_not_called()


def test_keepalive_cannot_exceed_total_pool():
    with pytest.raises(ValueError, match="must not exceed"):
        create_gateway_app(settings(upstream_http_max_connections=1, upstream_http_max_keepalive_connections=2))


@pytest.mark.parametrize("mode", ["off", "warn", "enforce"])
def test_explicit_modes_preserved(mode):
    from agent_bom.runtime.gateway_settings import validate_gateway_security_settings

    config = settings(fleet_enforcement_mode=mode)
    validate_gateway_security_settings(config)
    assert config.fleet_enforcement_mode == mode
