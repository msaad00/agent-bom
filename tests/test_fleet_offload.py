"""Fleet read handlers offload sync store work off the event loop.

Pre-release scale hardening: list_fleet / fleet_stats / get_fleet_agent ran
synchronous psycopg reads directly on the loop. They now route through
``_store_call`` (asyncio.to_thread under backpressure).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from agent_bom.api.routes import fleet


class _FakeAgent:
    def __init__(self, agent_id="a1"):
        self.agent_id = agent_id
        self.lifecycle_state = SimpleNamespace(value="active")
        self.environment = "prod"
        self.trust_score = 90.0

    def model_dump(self):
        return {"agent_id": self.agent_id}


class _FakeStore:
    def __init__(self):
        self.calls: list[str] = []

    def query_by_tenant(self, tenant_id, **kwargs):
        self.calls.append("query_by_tenant")
        return ([_FakeAgent()], 1)

    def list_by_tenant(self, tenant_id):
        self.calls.append("list_by_tenant")
        return [_FakeAgent()]

    def get(self, agent_id, tenant_id):
        self.calls.append("get")
        return _FakeAgent(agent_id)


@pytest.fixture()
def offload_spy(monkeypatch):
    store = _FakeStore()
    monkeypatch.setattr(fleet, "_get_fleet_store", lambda: store)
    monkeypatch.setattr(fleet, "require_request_tenant_id", lambda request: "acme")

    offloaded: list[object] = []
    real_to_thread = asyncio.to_thread

    async def _spy(fn, /, *args, **kwargs):
        offloaded.append(fn)
        return await real_to_thread(fn, *args, **kwargs)

    monkeypatch.setattr(fleet.asyncio, "to_thread", _spy)
    return store, offloaded


def test_list_fleet_offloads(offload_spy):
    store, offloaded = offload_spy
    result = asyncio.run(fleet.list_fleet(request=object()))
    assert result["count"] == 1
    assert offloaded, "list_fleet must offload the store read"
    assert "query_by_tenant" in store.calls


def test_fleet_stats_offloads(offload_spy):
    store, offloaded = offload_spy
    result = asyncio.run(fleet.fleet_stats(request=object()))
    assert result["total"] == 1
    assert offloaded, "fleet_stats must offload the store read"
    assert "list_by_tenant" in store.calls


def test_get_fleet_agent_offloads(offload_spy):
    store, offloaded = offload_spy
    result = asyncio.run(fleet.get_fleet_agent(request=object(), agent_id="a1"))
    assert result["agent_id"] == "a1"
    assert offloaded, "get_fleet_agent must offload the store read"
    assert "get" in store.calls
