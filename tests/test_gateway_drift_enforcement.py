"""Gateway acts on open behavioral-drift incidents (detection → enforcement).

Drift incidents were advisory-only: the control plane recorded that an agent had
drifted out of its declared blueprint but never blocked the drifted tool calls.
These tests cover the opt-in enforcement: `enforce` blocks the named tool, `warn`
audits it without blocking, `off` stays advisory, and a drift-store failure
fails open (never breaks the relay).
"""

from __future__ import annotations

from typing import Any

import pytest
from starlette.testclient import TestClient

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


def _settings(mode: str, audit: list[dict[str, Any]] | None = None) -> GatewaySettings:
    async def _sink(event: dict[str, Any]) -> None:
        if audit is not None:
            audit.append(event)

    return GatewaySettings(
        registry=_registry(),
        policy={"agent_tokens": {"token-a": "agent-a", "token-b": "agent-b"}},
        upstream_caller=_ok_caller,
        audit_sink=_sink if audit is not None else None,
        drift_enforcement_mode=mode,
    )


def _seed_drift(*, agent: str = "agent-a", tool: str = "run_shell") -> None:
    store = InMemoryDriftIncidentStore()
    store.upsert(
        DriftIncident(
            incident_id="d1",
            tenant_id="default",
            blueprint_id=agent,
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


def _is_blocked(resp) -> bool:
    body = resp.json()
    return resp.status_code == 200 and isinstance(body.get("error"), dict) and body["error"].get("code") == -32001


@pytest.fixture(autouse=True)
def _reset_store():
    yield
    set_drift_incident_store(None)


def test_enforce_blocks_drifted_tool():
    _seed_drift(tool="run_shell")
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call(tool="run_shell"))
    assert _is_blocked(resp), resp.text
    assert resp.json()["error"]["data"] == {
        "reason": "Drift enforcement blocked this request",
        "policy_source": "drift_enforcement",
    }


def test_enforce_allows_non_drifted_tool():
    _seed_drift(tool="run_shell")  # only run_shell is in violation
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call(tool="read_file"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}


def test_enforce_scoped_to_the_drifted_agent_only():
    _seed_drift(agent="agent-a", tool="run_shell")
    client = TestClient(create_gateway_app(_settings("enforce")))
    # agent-b has no drift incident -> relays normally even for the same tool.
    resp = client.post("/mcp/filesystem", json=_call(token="token-b", tool="run_shell"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}


def test_warn_audits_but_does_not_block():
    _seed_drift(tool="run_shell")
    audit: list[dict[str, Any]] = []
    client = TestClient(create_gateway_app(_settings("warn", audit=audit)))
    resp = client.post("/mcp/filesystem", json=_call(tool="run_shell"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}
    assert any(e.get("action") == "gateway.drift_warned" for e in audit)


def test_off_is_advisory_no_block():
    _seed_drift(tool="run_shell")
    client = TestClient(create_gateway_app(_settings("off")))
    resp = client.post("/mcp/filesystem", json=_call(tool="run_shell"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}


def test_drift_store_failure_fails_open():
    class _Boom:
        def list(self, *a, **k):
            raise RuntimeError("store down")

    set_drift_incident_store(_Boom())  # type: ignore[arg-type]
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call(tool="run_shell"))
    # store error must never block the relay
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}
