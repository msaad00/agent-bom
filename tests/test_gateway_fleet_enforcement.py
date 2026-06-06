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
