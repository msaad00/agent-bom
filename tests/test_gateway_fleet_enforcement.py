"""Gateway isolates quarantined fleet agents (detection → enforcement).

The fleet roster's QUARANTINED lifecycle state was advisory-only — an operator
could quarantine a compromised or under-review agent but it kept relaying. These
tests cover the opt-in enforcement: `enforce` blocks every call from a
quarantined agent, `warn` audits it, `off` stays advisory, and a fleet-store
failure fails open.
"""

from __future__ import annotations

from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState, InMemoryFleetStore
from agent_bom.api.stores import set_fleet_store
from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry


def _registry() -> UpstreamRegistry:
    return UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://fs.local:8100")])


def _call(token: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/tmp/x"}, "_meta": {"agent_identity": token}},
    }


async def _ok_caller(upstream, message, extra_headers):
    return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}


def _settings(mode: str, audit: list[dict[str, Any]] | None = None) -> GatewaySettings:
    async def _sink(event: dict[str, Any]) -> None:
        if audit is not None:
            audit.append(event)

    return GatewaySettings(
        registry=_registry(),
        policy={"agent_tokens": {"token-a": "agent-a", "token-b": "agent-b"}},
        upstream_caller=_ok_caller,
        audit_sink=_sink if audit is not None else None,
        fleet_enforcement_mode=mode,
    )


def _seed_fleet() -> None:
    store = InMemoryFleetStore()
    store.put(
        FleetAgent(
            agent_id="agent-a",
            name="agent-a",
            agent_type="custom",
            tenant_id="default",
            lifecycle_state=FleetLifecycleState.QUARANTINED,
        )
    )
    store.put(
        FleetAgent(
            agent_id="agent-b",
            name="agent-b",
            agent_type="custom",
            tenant_id="default",
            lifecycle_state=FleetLifecycleState.APPROVED,
        )
    )
    set_fleet_store(store)


def _is_blocked(resp) -> bool:
    body = resp.json()
    return resp.status_code == 200 and isinstance(body.get("error"), dict) and body["error"].get("code") == -32001


@pytest.fixture(autouse=True)
def _reset():
    yield
    set_fleet_store(None)


def test_enforce_blocks_quarantined_agent():
    _seed_fleet()
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call("token-a"))
    assert _is_blocked(resp), resp.text
    assert resp.json()["error"]["data"]["policy_source"] == "fleet_quarantine"


def test_enforce_allows_approved_agent():
    _seed_fleet()
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call("token-b"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}


def test_warn_audits_but_does_not_block():
    _seed_fleet()
    audit: list[dict[str, Any]] = []
    client = TestClient(create_gateway_app(_settings("warn", audit=audit)))
    resp = client.post("/mcp/filesystem", json=_call("token-a"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}
    assert any(e.get("action") == "gateway.fleet_warned" for e in audit)


def test_off_is_advisory_no_block():
    _seed_fleet()
    client = TestClient(create_gateway_app(_settings("off")))
    resp = client.post("/mcp/filesystem", json=_call("token-a"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}


def test_fleet_store_failure_fails_open():
    class _Boom:
        def list_by_tenant(self, *a, **k):
            raise RuntimeError("store down")

    set_fleet_store(_Boom())
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call("token-a"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}


# ── Identity revocation for non-managed callers (JWT / opaque tokens) ──────────
#
# The gateway resolves a managed (``abi_``) token through ``identity_for_token``,
# which consults ``AgentIdentity.status`` on every call. A JWKS/OIDC JWT or an
# opaque ``policy.agent_tokens`` mapping never touches the identity store, so the
# agent's revocation was a runtime no-op for exactly the deployments most likely
# to use a real IdP.


def _identity(agent_id: str, status: str):
    from agent_bom.api.agent_identity_store import AgentIdentity

    return AgentIdentity(
        identity_id=f"id-{agent_id}-{status}",
        agent_id=agent_id,
        tenant_id="default",
        token_hash=f"hash-{agent_id}-{status}",
        token_prefix="abi_test",
        role="agent",
        blueprint_id="",
        status=status,
        issued_at="2026-01-01T00:00:00Z",
        expires_at="",
    )


def _seed_identities(*identities) -> None:
    from agent_bom.api.agent_identity_store import InMemoryAgentIdentityStore, set_agent_identity_store

    store = InMemoryAgentIdentityStore()
    for identity in identities:
        store.put(identity)
    set_agent_identity_store(store)


@pytest.fixture(autouse=True)
def _reset_identity_store():
    yield
    from agent_bom.api.agent_identity_store import set_agent_identity_store

    set_agent_identity_store(None)


def test_opaque_caller_with_revoked_identity_is_denied():
    """The bypass proof: an opaque-token caller whose identity was revoked."""
    _seed_fleet()
    _seed_identities(_identity("agent-b", "revoked"))
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call("token-b"))
    assert _is_blocked(resp), resp.text


def test_opaque_caller_with_live_identity_is_allowed():
    _seed_fleet()
    _seed_identities(_identity("agent-b", "active"))
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call("token-b"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}


def test_caller_with_no_managed_identity_record_is_unaffected():
    """Deployments that never issued a managed identity must not start failing."""
    _seed_fleet()
    _seed_identities()  # empty store
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call("token-b"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}


def test_agent_with_one_live_identity_among_revoked_is_allowed():
    """Rotation leaves revoked rows behind; only an agent with NO live identity is dead."""
    _seed_fleet()
    _seed_identities(_identity("agent-b", "revoked"), _identity("agent-b", "active"))
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call("token-b"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}


def test_revocation_blocks_non_tool_methods():
    """Pins the check ABOVE the tool-call branch.

    ``allowed_tools`` and the JIT-grant path only run for ``tools/call``. If the
    revocation check were placed there, a revoked caller could still run
    ``tools/list``, ``initialize`` and ``resources/read``.
    """
    _seed_fleet()
    _seed_identities(_identity("agent-b", "revoked"))
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post(
        "/mcp/filesystem",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {"_meta": {"agent_identity": "token-b"}},
        },
    )
    assert _is_blocked(resp), resp.text


def test_identity_store_failure_fails_open_for_unsecured_posture():
    """An identity-store outage must not become a fleet-wide outage.

    Only the revocation lookup is broken here. Breaking the whole store would
    also take out conditional access, which fails *closed* by design — that
    would test the wrong subsystem.
    """
    from agent_bom.api.agent_identity_store import InMemoryAgentIdentityStore, set_agent_identity_store

    class _RevocationLookupDown(InMemoryAgentIdentityStore):
        def list(self, *a, **k):
            raise RuntimeError("identity store down")

    _seed_fleet()
    set_agent_identity_store(_RevocationLookupDown())
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call("token-b"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}


def test_identity_store_failure_fails_closed_when_identity_is_required():
    """Under a secured posture an unprovable revocation status must deny."""
    from agent_bom.api.agent_identity_store import InMemoryAgentIdentityStore, set_agent_identity_store

    class _RevocationLookupDown(InMemoryAgentIdentityStore):
        def list(self, *a, **k):
            raise RuntimeError("identity store down")

    _seed_fleet()
    set_agent_identity_store(_RevocationLookupDown())
    settings = _settings("enforce")
    settings.policy["require_agent_identity"] = True
    client = TestClient(create_gateway_app(settings))
    resp = client.post("/mcp/filesystem", json=_call("token-b"))
    assert _is_blocked(resp), resp.text


def test_fleet_enforcement_defaults_to_enforce():
    """Quarantine is an explicit operator action; 'off' made it a no-op."""
    settings = GatewaySettings(registry=_registry(), policy={}, upstream_caller=_ok_caller)
    assert settings.fleet_enforcement_mode == "enforce"


def test_boot_warns_and_names_agents_that_enforcement_will_block(caplog):
    """The default flip must not be a silent behaviour change on upgrade."""
    import logging

    _seed_fleet()
    with caplog.at_level(logging.WARNING, logger="agent_bom.gateway_server"):
        create_gateway_app(_settings("enforce"))
    warnings = [r.getMessage() for r in caplog.records if "fleet enforcement is active" in r.getMessage()]
    assert warnings, "operators must be told which agents will now be blocked"
    assert "agent-a" in warnings[0]
    assert "--fleet-enforcement off" in warnings[0]


def test_boot_is_silent_when_enforcement_is_opted_out(caplog):
    import logging

    _seed_fleet()
    with caplog.at_level(logging.WARNING, logger="agent_bom.gateway_server"):
        create_gateway_app(_settings("off"))
    assert not [r for r in caplog.records if "fleet enforcement is active" in r.getMessage()]
