"""The relay must not stop the world while it reads the fleet and identity stores.

``_agent_is_quarantined`` (an unbounded ``list_by_tenant``) and
``_agent_identity_revoked`` were called synchronously from ``async def relay``.
Both scale with the tenant's roster, so on a large fleet every relay call froze
the whole gateway process — health checks, other tenants, background tasks —
not merely its own request. Same defect class as the live-feed fix; that one
was repaired on the feed and not on the relay.

Measured on 20k fleet agents / 5k identities before the fix: mean relay 181 ms,
worst event-loop stall 3.8 s across 20 concurrent calls.
"""

from __future__ import annotations

import asyncio
import time

import httpx
import pytest

from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState, InMemoryFleetStore
from agent_bom.api.stores import set_fleet_store
from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry

# Each store read is made to cost this much wall-clock. Long enough that a
# blocking call is unmistakable, short enough to keep the test quick.
STORE_LATENCY = 0.25


@pytest.fixture(autouse=True)
def _reset():
    yield
    set_fleet_store(None)
    from agent_bom.api.agent_identity_store import set_agent_identity_store

    set_agent_identity_store(None)


class _SlowFleetStore(InMemoryFleetStore):
    """Stands in for a large roster: every read costs real wall-clock time."""

    def list_by_tenant(self, tenant_id: str):
        time.sleep(STORE_LATENCY)
        return super().list_by_tenant(tenant_id)

    def find_by_identifier(self, tenant_id: str, identifier: str):
        time.sleep(STORE_LATENCY)
        return super().find_by_identifier(tenant_id, identifier)


def _slow_identity_store():
    from agent_bom.api.agent_identity_store import InMemoryAgentIdentityStore

    class _SlowIdentityStore(InMemoryAgentIdentityStore):
        def list(self, *a, **k):
            time.sleep(STORE_LATENCY)
            return super().list(*a, **k)

        def list_by_agent(self, *a, **k):
            time.sleep(STORE_LATENCY)
            return super().list_by_agent(*a, **k)

    return _SlowIdentityStore()


def _app():
    async def _ok_caller(upstream, message, extra_headers):
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    return create_gateway_app(
        GatewaySettings(
            registry=UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://fs.local:8100")]),
            policy={"agent_tokens": {"token-b": "agent-b"}},
            upstream_caller=_ok_caller,
            fleet_enforcement_mode="enforce",
        )
    )


def _seed() -> None:
    fleet = _SlowFleetStore()
    fleet.put(
        FleetAgent(
            agent_id="agent-b",
            name="agent-b",
            agent_type="custom",
            tenant_id="default",
            lifecycle_state=FleetLifecycleState.APPROVED,
        )
    )
    set_fleet_store(fleet)

    from agent_bom.api.agent_identity_store import set_agent_identity_store

    set_agent_identity_store(_slow_identity_store())


_CALL = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "read_file", "arguments": {"path": "/tmp/x"}, "_meta": {"agent_identity": "token-b"}},
}


async def _worst_stall_while(work, *, tick: float = 0.005) -> tuple[object, float]:
    """Run *work*, sampling the longest the loop ever went without a tick."""
    worst = 0.0
    stop = False

    async def _heartbeat() -> None:
        nonlocal worst
        last = time.perf_counter()
        while not stop:
            await asyncio.sleep(tick)
            now = time.perf_counter()
            worst = max(worst, now - last)
            last = now

    beat = asyncio.create_task(_heartbeat())
    # Let the heartbeat actually start. Without this it is merely scheduled,
    # never runs, and a fully blocking call measures as zero stall — the
    # instrument would exonerate the bug.
    for _ in range(5):
        await asyncio.sleep(tick)
    try:
        result = await work
    finally:
        stop = True
        await asyncio.sleep(0)
        beat.cancel()
    return result, worst


def test_relay_does_not_block_the_event_loop_on_store_reads():
    _seed()
    app = _app()

    async def _drive():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://gw") as client:
            await client.post("/mcp/filesystem", json=_CALL)  # warm caches

            async def _one():
                return await client.post("/mcp/filesystem", json=_CALL)

            return await _worst_stall_while(_one())

    resp, worst_stall = asyncio.run(_drive())

    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}
    # Both store reads happen off-loop, so the loop keeps servicing ticks while
    # they run. Blocking calls parked it for at least STORE_LATENCY.
    assert worst_stall < STORE_LATENCY, f"event loop stalled {worst_stall * 1000:.0f} ms on one relay call"


def test_concurrent_relays_do_not_serialize_on_the_loop():
    """The user-visible symptom: one slow tenant freezing every other caller."""
    _seed()
    app = _app()
    calls = 8

    async def _drive():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://gw") as client:
            await client.post("/mcp/filesystem", json=_CALL)
            started = time.perf_counter()
            responses = await asyncio.gather(*[client.post("/mcp/filesystem", json=_CALL) for _ in range(calls)])
            return responses, time.perf_counter() - started

    responses, elapsed = asyncio.run(_drive())

    assert all(r.status_code == 200 for r in responses)
    # Serialized on the loop this is calls * 2 * STORE_LATENCY (4.0 s at these
    # settings). Off-loop the reads overlap in the worker pool.
    assert elapsed < calls * STORE_LATENCY, f"{calls} concurrent relays took {elapsed:.2f}s — they serialized"
