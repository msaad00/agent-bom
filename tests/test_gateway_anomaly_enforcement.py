"""Gateway acts on cost-spike anomalies (detection → enforcement).

Cost anomalies were advisory-only: a runaway agent spending far above the fleet
baseline was flagged in the observability API but kept relaying. These tests
cover the opt-in enforcement — `enforce` blocks the anomalous agent, `warn`
audits it, `off` stays advisory — and that a cost-store failure fails open.
"""

from __future__ import annotations

from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom.api import anomaly as anomaly_mod
from agent_bom.api.cost_store import LLMCostRecord, set_cost_store
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
        # agent-a is the runaway spender; agent-b is normal.
        policy={"agent_tokens": {"token-a": "agent-a", "token-b": "agent-b"}},
        upstream_caller=_ok_caller,
        audit_sink=_sink if audit is not None else None,
        anomaly_enforcement_mode=mode,
    )


class _InMemoryCostStore:
    def __init__(self, records: list[LLMCostRecord]) -> None:
        self._records = records

    def list_records(self, tenant_id: str, *, limit: int = 1000) -> list[LLMCostRecord]:
        return [r for r in self._records if r.tenant_id == tenant_id][:limit]

    # Unused-by-this-path protocol members.
    def record_cost(self, record: LLMCostRecord) -> None:  # pragma: no cover
        self._records.append(record)

    def total_spend(self, tenant_id: str, *, agent: str | None = None) -> float:  # pragma: no cover
        return sum(r.cost_usd for r in self._records if r.tenant_id == tenant_id and (agent is None or r.agent == agent))

    def get_budget(self, tenant_id: str, agent: str = "") -> None:  # pragma: no cover
        return None


def _rec(agent: str, cost: float) -> LLMCostRecord:
    return LLMCostRecord(
        tenant_id="default",
        call_id=f"c-{agent}",
        agent=agent,
        session_id=f"s-{agent}",
        provider="openai",
        model="gpt-4o",
        input_tokens=1,
        output_tokens=1,
        cost_usd=cost,
        priced=True,
        observed_at="2026-06-05T00:00:00Z",
    )


def _seed_runaway() -> None:
    # Five baseline agents at $1, one runaway at $1000 → runaway is an outlier.
    records = [_rec(f"agent-{i}", 1.0) for i in range(5)] + [_rec("agent-a", 1000.0)]
    set_cost_store(_InMemoryCostStore(records))  # type: ignore[arg-type]


def _is_blocked(resp) -> bool:
    body = resp.json()
    return resp.status_code == 200 and isinstance(body.get("error"), dict) and body["error"].get("code") == -32001


@pytest.fixture(autouse=True)
def _reset():
    anomaly_mod.clear_cost_anomaly_cache()
    yield
    set_cost_store(None)
    anomaly_mod.clear_cost_anomaly_cache()


def test_enforce_blocks_anomalous_agent():
    _seed_runaway()
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call("token-a"))
    assert _is_blocked(resp), resp.text
    assert "anomalous" in resp.json()["error"]["data"]["reason"].lower()


def test_enforce_allows_normal_agent():
    _seed_runaway()
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call("token-b"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}


def test_warn_audits_but_does_not_block():
    _seed_runaway()
    audit: list[dict[str, Any]] = []
    client = TestClient(create_gateway_app(_settings("warn", audit=audit)))
    resp = client.post("/mcp/filesystem", json=_call("token-a"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}
    assert any(e.get("action") == "gateway.anomaly_warned" for e in audit)


def test_off_is_advisory_no_block():
    _seed_runaway()
    client = TestClient(create_gateway_app(_settings("off")))
    resp = client.post("/mcp/filesystem", json=_call("token-a"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}


def test_cost_store_failure_fails_open():
    class _Boom:
        def list_records(self, *a, **k):
            raise RuntimeError("store down")

    set_cost_store(_Boom())  # type: ignore[arg-type]
    client = TestClient(create_gateway_app(_settings("enforce")))
    resp = client.post("/mcp/filesystem", json=_call("token-a"))
    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}
