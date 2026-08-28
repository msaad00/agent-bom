"""Canonical managed-client profile enforcement at the gateway decision point."""

from __future__ import annotations

from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom import agent_identity
from agent_bom.api.agent_identity_store import (
    InMemoryAgentIdentityStore,
    issue_identity,
    set_agent_identity_store,
    verify_token,
)
from agent_bom.api.mcp_config_store import (
    InMemoryMcpConfigStore,
    McpClientConfigAssignment,
    set_mcp_config_store,
)
from agent_bom.gateway_server import GatewayAuditDeliveryUnavailableError, GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry


def _call(token: str, *, tool: str = "read_file", method: str = "tools/call") -> dict[str, Any]:
    params: dict[str, Any] = {"_meta": {"agent_identity": token}}
    if method == "tools/call":
        params.update({"name": tool, "arguments": {"path": "/safe"}})
    return {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}


def _assignment(identity_id: str, **overrides: object) -> McpClientConfigAssignment:
    values: dict[str, object] = {
        "config_id": "client-profile-finance-prod",
        "tenant_id": "default",
        "name": "Finance production client",
        "profile_id": "finance",
        "identity_id": identity_id,
        "connector_ids": ["filesystem"],
        "connection_ids": ["credential-ref-must-not-emit"],
        "issuer": "agent-bom",
        "environment": "prod",
        "allowed_tools": ["read_file"],
        "required_scopes": [],
        "policy_ids": ["policy-finance@7"],
        "owner": "finance-security",
        "status": "active",
        "revision": 3,
        "expires_at": "2030-01-01T00:00:00+00:00",
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-07-17T00:00:00+00:00",
    }
    values.update(overrides)
    return McpClientConfigAssignment(**values)  # type: ignore[arg-type]


def _managed_identity() -> tuple[str, str]:
    store = InMemoryAgentIdentityStore()
    identity, token = issue_identity(
        store,
        agent_id="agent-finance-prod",
        tenant_id="default",
        blueprint_id="finance",
        allowed_tools=["read_file", "run_report"],
        owner="finance-platform",
    )
    set_agent_identity_store(store)
    agent_identity.set_local_identity_verifier(lambda raw: verify_token(store, raw))
    return identity.identity_id, token


def _settings(
    calls: list[dict[str, Any]],
    audits: list[dict[str, Any]],
    *,
    listener_host: str = "0.0.0.0",
    mode: str = "enforce",
    environment: str = "prod",
    allow_loopback_bypass: bool = False,
    policy: dict[str, Any] | None = None,
) -> GatewaySettings:
    async def _caller(upstream, message, extra_headers):
        calls.append({"upstream": upstream.name, "message": message})
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    async def _sink(event: dict[str, Any]) -> None:
        audits.append(event)

    return GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://fs.local:8100")]),
        policy=policy or {},
        upstream_caller=_caller,
        audit_sink=_sink,
        listener_host=listener_host,
        bearer_token="gateway-transport-token" if listener_host != "127.0.0.1" else None,
        runtime_profile_enforcement_mode=mode,
        runtime_profile_environment=environment,
        allow_runtime_profile_dev_bypass=allow_loopback_bypass,
    )


def _relay(
    token: str,
    calls: list[dict[str, Any]],
    audits: list[dict[str, Any]],
    **settings_overrides: Any,
):
    settings = _settings(calls, audits, **settings_overrides)
    headers = {"X-Agent-Environment": "prod"}
    if settings.listener_host != "127.0.0.1":
        headers["Authorization"] = "Bearer gateway-transport-token"
    return TestClient(create_gateway_app(settings)).post(
        "/mcp/filesystem",
        headers=headers,
        json=_call(token),
    )


@pytest.mark.parametrize("mode", ["warn", "enforce"])
def test_profile_audit_outage_fails_closed_before_upstream(mode: str) -> None:
    calls: list[dict[str, Any]] = []
    settings = _settings(calls, [], listener_host="127.0.0.1", mode=mode)

    async def unavailable_audit(_event: dict[str, Any]) -> None:
        raise GatewayAuditDeliveryUnavailableError("hostile audit detail /private/profile.db")

    settings.audit_sink = unavailable_audit
    with TestClient(create_gateway_app(settings), raise_server_exceptions=False) as client:
        response = client.post("/mcp/filesystem", json=_call(""))

    assert response.status_code == 503
    assert response.json()["error"]["code"] == -32003
    assert response.json()["id"] == 1
    assert "/private/profile.db" not in response.text
    assert calls == []


@pytest.fixture(autouse=True)
def _reset_stores():
    yield
    set_agent_identity_store(None)
    set_mcp_config_store(None)
    agent_identity.set_local_identity_verifier(None)


def test_secured_gateway_resolves_profile_and_strips_caller_credential_before_relay() -> None:
    identity_id, token = _managed_identity()
    profile_store = InMemoryMcpConfigStore()
    profile_store.put(_assignment(identity_id))
    set_mcp_config_store(profile_store)
    calls: list[dict[str, Any]] = []
    audits: list[dict[str, Any]] = []

    response = _relay(token, calls, audits)

    assert response.status_code == 200
    assert response.json()["result"] == {"ok": True}
    assert [call["upstream"] for call in calls] == ["filesystem"]
    assert token not in repr(calls)
    assert calls[0]["message"]["params"].get("_meta", {}).get("agent_identity") is None
    allowed = [event for event in audits if event.get("event_type") == "gateway.tool_call.allowed"]
    assert len(allowed) == 1
    event = allowed[0]
    assert event["agent_id"] == "agent-finance-prod"
    assert event["profile_id"] == "client-profile-finance-prod"
    assert event["profile_id"] not in {event["agent_id"], "finance"}
    assert event["profile_revision"] == 3
    assert event["blueprint_id"] == "finance"
    assert event["blueprint_revision"] == 1
    assert event["policy_ids"] == ["policy-finance@7"]
    assert "policy_id" not in event
    assert event["decision_id"] == event["event_id"]
    assert event["decision_id"].startswith("gw_")
    serialized = repr(audits)
    assert token not in serialized
    assert "credential-ref-must-not-emit" not in serialized
    assert "arguments" not in serialized


@pytest.mark.parametrize(
    ("assignment_overrides", "reason_code"),
    [
        ({"revoked": True}, "profile_revoked"),
        ({"status": "disabled"}, "profile_disabled"),
        ({"expires_at": "2020-01-01T00:00:00+00:00"}, "profile_expired"),
        ({"tenant_id": "tenant-b"}, "profile_not_found"),
        ({"profile_id": "unknown-role"}, "blueprint_unknown"),
        ({"connector_ids": ["jira"]}, "upstream_not_allowed"),
        ({"allowed_tools": ["run_report"]}, "tool_not_allowed"),
        ({"allowed_tools": ["write_file"]}, "tool_constraint_conflict"),
        ({"required_scopes": ["tools:read"]}, "insufficient_scope"),
        ({"profile_id": "developer"}, "blueprint_mismatch"),
    ],
)
def test_secured_gateway_denies_unsanctioned_profile_before_upstream(
    assignment_overrides: dict[str, object],
    reason_code: str,
) -> None:
    identity_id, token = _managed_identity()
    profile_store = InMemoryMcpConfigStore()
    profile_store.put(_assignment(identity_id, **assignment_overrides))
    set_mcp_config_store(profile_store)
    calls: list[dict[str, Any]] = []
    audits: list[dict[str, Any]] = []

    response = _relay(token, calls, audits)

    assert response.status_code == 200
    assert response.json()["error"]["data"] == {
        "reason": "Runtime client profile validation blocked this request",
        "policy_source": "runtime_profile",
        "reason_code": reason_code,
    }
    assert calls == []
    blocked = [event for event in audits if event.get("event_type") == "gateway.tool_call.blocked"]
    assert len(blocked) == 1
    assert blocked[0]["policy_source"] == "runtime_profile"
    assert blocked[0]["reason_code"] == reason_code
    assert blocked[0]["decision_id"] == blocked[0]["event_id"]
    assert "agent_identity" not in repr(blocked[0])


def test_upstream_restriction_applies_to_non_tool_jsonrpc_messages() -> None:
    identity_id, token = _managed_identity()
    profile_store = InMemoryMcpConfigStore()
    profile_store.put(_assignment(identity_id, connector_ids=["jira"]))
    set_mcp_config_store(profile_store)
    calls: list[dict[str, Any]] = []
    audits: list[dict[str, Any]] = []
    settings = _settings(calls, audits)
    client = TestClient(create_gateway_app(settings))

    response = client.post(
        "/mcp/filesystem",
        headers={"Authorization": "Bearer gateway-transport-token"},
        json=_call(token, method="initialize"),
    )

    assert response.json()["error"]["data"]["reason_code"] == "upstream_not_allowed"
    assert calls == []
    assert all(event.get("event_type") != "gateway.tool_call.blocked" for event in audits)
    profile_blocked = [event for event in audits if event.get("event_type") == "gateway.runtime_profile.blocked"]
    assert len(profile_blocked) == 1
    assert profile_blocked[0]["decision"] == "deny"


def test_caller_environment_header_cannot_satisfy_operator_profile_environment() -> None:
    identity_id, token = _managed_identity()
    profile_store = InMemoryMcpConfigStore()
    profile_store.put(_assignment(identity_id, environment="prod"))
    set_mcp_config_store(profile_store)
    calls: list[dict[str, Any]] = []
    audits: list[dict[str, Any]] = []

    response = _relay(token, calls, audits, environment="staging")

    assert response.json()["error"]["data"]["reason_code"] == "environment_mismatch"
    assert calls == []


def test_loopback_profile_bypass_requires_explicit_flag_and_is_audited() -> None:
    _identity_id, token = _managed_identity()
    set_mcp_config_store(InMemoryMcpConfigStore())
    calls: list[dict[str, Any]] = []
    audits: list[dict[str, Any]] = []

    denied = _relay(token, calls, audits, listener_host="127.0.0.1")
    assert denied.json()["error"]["data"]["reason_code"] == "profile_not_found"
    assert calls == []

    allowed = _relay(
        token,
        calls,
        audits,
        listener_host="127.0.0.1",
        allow_loopback_bypass=True,
    )
    assert allowed.json()["result"] == {"ok": True}
    assert len(calls) == 1
    bypass = [event for event in audits if event.get("action") == "gateway.runtime_profile_dev_bypass"]
    assert len(bypass) == 1
    assert bypass[0]["event_type"] == "gateway.runtime_profile.dev_bypass"
    assert bypass[0]["decision"] == "allow"
    assert bypass[0]["decision_id"] == bypass[0]["event_id"]
    assert bypass[0]["reason_code"] == "profile_not_found"
    assert bypass[0]["development_mode"] is True
    allowed_events = [event for event in audits if event.get("event_type") == "gateway.tool_call.allowed"]
    assert allowed_events[-1]["profile_id"] == ""


def test_profile_store_failure_is_fail_closed_and_secret_free(caplog: pytest.LogCaptureFixture) -> None:
    class _UnavailableProfileStore(InMemoryMcpConfigStore):
        def get_active_for_identity(self, tenant_id: str, identity_id: str):
            raise RuntimeError("postgresql://runtime:secret@db.internal/profile")

    _identity_id, token = _managed_identity()
    set_mcp_config_store(_UnavailableProfileStore())
    calls: list[dict[str, Any]] = []
    audits: list[dict[str, Any]] = []

    response = _relay(token, calls, audits)

    assert response.json()["error"]["data"]["reason_code"] == "profile_store_unavailable"
    assert calls == []
    assert "secret@db.internal" not in response.text
    assert "secret@db.internal" not in repr(audits)
    assert "secret@db.internal" not in caplog.text


def test_warn_mode_audits_unsanctioned_profile_without_claiming_profile_attribution() -> None:
    _identity_id, token = _managed_identity()
    set_mcp_config_store(InMemoryMcpConfigStore())
    calls: list[dict[str, Any]] = []
    audits: list[dict[str, Any]] = []

    response = _relay(token, calls, audits, mode="warn")

    assert response.json()["result"] == {"ok": True}
    assert len(calls) == 1
    warned = [event for event in audits if event.get("action") == "gateway.runtime_profile_warned"]
    assert len(warned) == 1
    assert warned[0]["event_type"] == "gateway.runtime_profile.warned"
    assert warned[0]["decision"] == "allow"
    assert warned[0]["decision_id"] == warned[0]["event_id"]
    assert warned[0]["reason_code"] == "profile_not_found"
    allowed = [event for event in audits if event.get("event_type") == "gateway.tool_call.allowed"]
    assert allowed[0]["profile_id"] == ""


def test_enforce_mode_rejects_legacy_identity_without_managed_relation() -> None:
    set_agent_identity_store(InMemoryAgentIdentityStore())
    set_mcp_config_store(InMemoryMcpConfigStore())
    calls: list[dict[str, Any]] = []
    audits: list[dict[str, Any]] = []

    response = _relay(
        "legacy-token",
        calls,
        audits,
        policy={"agent_tokens": {"legacy-token": "agent-legacy"}},
    )

    assert response.json()["error"]["data"] == {
        "reason": "Runtime client profile validation blocked this request",
        "policy_source": "runtime_profile",
        "reason_code": "managed_identity_required",
    }
    assert calls == []
