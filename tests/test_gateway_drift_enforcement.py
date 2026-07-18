"""Gateway acts on open behavioral-drift incidents (detection → enforcement).

Drift incidents are keyed by role blueprint, while runtime calls are attributed
to managed agent identities.  These tests prove the gateway resolves that
binding before selecting incidents and never treats a role blueprint id as an
agent id.
"""

from __future__ import annotations

from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom import agent_identity
from agent_bom.api.agent_identity_store import (
    InMemoryAgentIdentityStore,
    get_agent_identity_store,
    issue_identity,
    revoke_identity,
    set_agent_identity_store,
    verify_token,
)
from agent_bom.api.drift_incident_store import (
    DriftIncident,
    InMemoryDriftIncidentStore,
    set_drift_incident_store,
)
from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry


def _registry() -> UpstreamRegistry:
    return UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://fs.local:8100")])


def _call(token: str = "token-a", tool: str = "run_shell") -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": {}, "_meta": {"agent_identity": token}},
    }


async def _ok_caller(upstream, message, extra_headers):
    return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}


def _settings(
    mode: str,
    audit: list[dict[str, Any]] | None = None,
    *,
    listener_host: str = "127.0.0.1",
) -> GatewaySettings:
    async def _sink(event: dict[str, Any]) -> None:
        if audit is not None:
            audit.append(event)

    return GatewaySettings(
        registry=_registry(),
        policy={"agent_tokens": {"token-a": "agent-a", "token-b": "agent-b"}},
        upstream_caller=_ok_caller,
        audit_sink=_sink if audit is not None else None,
        drift_enforcement_mode=mode,
        listener_host=listener_host,
        bearer_token="gateway-transport-token" if listener_host != "127.0.0.1" else None,
    )


def _seed_drift(*, blueprint_id: str = "finance", tool: str = "run_shell") -> None:
    store = InMemoryDriftIncidentStore()
    store.upsert(
        DriftIncident(
            incident_id="d1",
            tenant_id="default",
            blueprint_id=blueprint_id,
            status="drift_detected",
            drift_score=0.8,
            violation_count=1,
            warning_count=0,
            top_violations=[{"tool_name": tool}],
            first_detected_at="2026-06-05T00:00:00Z",
            last_detected_at="2026-06-05T00:00:00Z",
        )
    )
    set_drift_incident_store(store)


def _managed_identity(*, agent_id: str = "agent-a", tenant_id: str = "default", blueprint_id: str = "finance") -> tuple[str, str]:
    store = InMemoryAgentIdentityStore()
    identity, token = issue_identity(
        store,
        agent_id=agent_id,
        tenant_id=tenant_id,
        blueprint_id=blueprint_id,
        owner="security-team",
    )
    set_agent_identity_store(store)
    agent_identity.set_local_identity_verifier(lambda raw: verify_token(store, raw))
    return identity.identity_id, token


def _is_blocked(resp) -> bool:
    body = resp.json()
    return resp.status_code == 200 and isinstance(body.get("error"), dict) and body["error"].get("code") == -32001


@pytest.fixture(autouse=True)
def _reset_store():
    yield
    set_drift_incident_store(None)
    set_agent_identity_store(None)
    agent_identity.set_local_identity_verifier(None)


def test_enforce_blocks_tool_for_callers_managed_blueprint():
    _identity_id, token = _managed_identity(blueprint_id="finance")
    _seed_drift(tool="run_shell")
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call(token=token, tool="run_shell"))
    assert _is_blocked(resp), resp.text
    assert resp.json()["error"]["data"] == {
        "reason": "Drift enforcement blocked this request",
        "policy_source": "drift_enforcement",
    }


def test_enforce_allows_non_drifted_tool():
    _identity_id, token = _managed_identity(blueprint_id="finance")
    _seed_drift(tool="run_shell")  # only run_shell is in violation
    audit: list[dict[str, Any]] = []
    client = TestClient(create_gateway_app(_settings("enforce", audit=audit)))
    resp = client.post("/mcp/filesystem", json=_call(token=token, tool="read_file"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}
    allowed = [event for event in audit if event.get("event_type") == "gateway.tool_call.allowed"]
    assert len(allowed) == 1
    assert allowed[0]["tenant_id"] == "default"
    assert allowed[0]["agent_id"] == "agent-a"
    assert allowed[0]["profile_id"] == "finance"
    assert allowed[0]["upstream"] == "filesystem"
    assert allowed[0]["tool"] == "read_file"
    assert allowed[0]["policy_source"] == "file"


def test_enforce_scopes_incident_to_the_bound_blueprint():
    _identity_id, token = _managed_identity(agent_id="agent-b", blueprint_id="developer")
    _seed_drift(blueprint_id="finance", tool="run_shell")
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call(token=token, tool="run_shell"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}


def test_enforce_ignores_legacy_incident_that_stored_agent_id_as_blueprint_id():
    _identity_id, token = _managed_identity(agent_id="agent-a", blueprint_id="finance")
    _seed_drift(blueprint_id="agent-a", tool="run_shell")
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call(token=token, tool="run_shell"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}


def test_warn_audits_but_does_not_block():
    _identity_id, token = _managed_identity(blueprint_id="finance")
    _seed_drift(tool="run_shell")
    audit: list[dict[str, Any]] = []
    client = TestClient(create_gateway_app(_settings("warn", audit=audit)))
    resp = client.post("/mcp/filesystem", json=_call(token=token, tool="run_shell"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}
    assert any(e.get("action") == "gateway.drift_warned" for e in audit)


def test_off_is_advisory_no_block():
    _identity_id, token = _managed_identity(blueprint_id="finance")
    _seed_drift(tool="run_shell")
    client = TestClient(create_gateway_app(_settings("off")))
    resp = client.post("/mcp/filesystem", json=_call(token=token, tool="run_shell"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}


def test_secured_enforce_fails_closed_when_drift_store_is_unavailable():
    class _Boom:
        def list(self, *a, **k):
            raise RuntimeError("store down")

    _identity_id, token = _managed_identity(blueprint_id="finance")
    set_drift_incident_store(_Boom())  # type: ignore[arg-type]
    client = TestClient(create_gateway_app(_settings("enforce", listener_host="0.0.0.0")))
    resp = client.post(
        "/mcp/filesystem",
        headers={"Authorization": "Bearer gateway-transport-token"},
        json=_call(token=token, tool="run_shell"),
    )
    assert _is_blocked(resp), resp.text
    assert resp.json()["error"]["data"]["policy_source"] == "drift_enforcement"


def test_secured_enforce_fails_closed_without_managed_profile_binding():
    client = TestClient(create_gateway_app(_settings("enforce", listener_host="0.0.0.0")))
    resp = client.post(
        "/mcp/filesystem",
        headers={"Authorization": "Bearer gateway-transport-token"},
        json=_call(token="token-a", tool="run_shell"),
    )
    assert _is_blocked(resp), resp.text
    assert resp.json()["error"]["data"]["policy_source"] == "drift_enforcement"


def test_managed_identity_from_another_tenant_fails_closed():
    _identity_id, token = _managed_identity(tenant_id="tenant-b", blueprint_id="finance")
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call(token=token, tool="run_shell"))
    assert _is_blocked(resp), resp.text


def test_revoked_managed_identity_fails_closed_before_drift_lookup():
    identity_id, token = _managed_identity(blueprint_id="finance")
    revoke_identity(get_agent_identity_store(), identity_id, tenant_id="default", reason="compromised")
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call(token=token, tool="run_shell"))
    assert _is_blocked(resp), resp.text
    assert resp.json()["error"]["message"] == "Blocked by agent-bom gateway identity policy"


def test_loopback_enforce_allows_legacy_unbound_identity_for_development():
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call(token="token-a", tool="run_shell"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}


# ── Open-incident lookup cap must not silently under-enforce (honest partial) ──


def _seed_many_open_incidents(count: int, *, blueprint_id: str = "unrelated", tenant_id: str = "default") -> None:
    """Seed more open incidents than the lookup cap, none matching the caller."""
    store = InMemoryDriftIncidentStore()
    for i in range(count):
        store.upsert(
            DriftIncident(
                incident_id=f"bulk-{i}",
                tenant_id=tenant_id,
                blueprint_id=f"{blueprint_id}-{i}",
                status="drift_detected",
                drift_score=0.5,
                violation_count=1,
                warning_count=0,
                top_violations=[{"tool_name": "some_other_tool"}],
                first_detected_at="2026-06-05T00:00:00Z",
                last_detected_at=f"2026-06-05T00:{i % 60:02d}:00Z",
            )
        )
    set_drift_incident_store(store)


def test_lookup_over_cap_returns_unavailable_not_clean_pass():
    from agent_bom.gateway_server import _DRIFT_INCIDENT_LOOKUP_CAP, _open_drift_violates_tool

    _seed_many_open_incidents(_DRIFT_INCIDENT_LOOKUP_CAP + 5)
    result = _open_drift_violates_tool("default", "finance", "run_shell")
    assert result.unavailable is True
    assert result.violates is False
    assert str(_DRIFT_INCIDENT_LOOKUP_CAP) in result.reason


def test_lookup_under_cap_returns_clean_pass():
    from agent_bom.gateway_server import _DRIFT_INCIDENT_LOOKUP_CAP, _open_drift_violates_tool

    _seed_many_open_incidents(_DRIFT_INCIDENT_LOOKUP_CAP - 5)
    result = _open_drift_violates_tool("default", "finance", "run_shell")
    assert result.unavailable is False
    assert result.violates is False


def test_secured_enforce_fails_closed_when_open_incidents_exceed_cap():
    from agent_bom.gateway_server import _DRIFT_INCIDENT_LOOKUP_CAP

    _identity_id, token = _managed_identity(blueprint_id="finance")
    _seed_many_open_incidents(_DRIFT_INCIDENT_LOOKUP_CAP + 5)
    client = TestClient(create_gateway_app(_settings("enforce", listener_host="0.0.0.0")))
    resp = client.post(
        "/mcp/filesystem",
        headers={"Authorization": "Bearer gateway-transport-token"},
        json=_call(token=token, tool="run_shell"),
    )
    assert _is_blocked(resp), resp.text
    assert resp.json()["error"]["data"]["policy_source"] == "drift_enforcement"


def test_observable_enforce_audits_partial_coverage_when_over_cap():
    from agent_bom.gateway_server import _DRIFT_INCIDENT_LOOKUP_CAP

    _identity_id, token = _managed_identity(blueprint_id="finance")
    _seed_many_open_incidents(_DRIFT_INCIDENT_LOOKUP_CAP + 5)
    audit: list[dict[str, Any]] = []
    client = TestClient(create_gateway_app(_settings("enforce", audit=audit)))
    resp = client.post("/mcp/filesystem", json=_call(token=token, tool="run_shell"))
    # Loopback/observable enforce does not block, but the partial-coverage gap is
    # surfaced as an explicit audit signal rather than a silent clean pass.
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}
    assert any(e.get("action") == "gateway.drift_binding_unavailable" for e in audit)
