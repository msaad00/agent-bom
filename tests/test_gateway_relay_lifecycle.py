"""Characterize pooled relay isolation, failure recovery and transport lifecycle."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

import agent_bom.gateway_server as gateway
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry


@pytest.mark.asyncio
async def test_relay_pools_clients_by_private_egress_approval_and_closes_them(monkeypatch):
    from agent_bom.runtime import egress_transport

    made = []

    def build_client(**options):
        client = AsyncMock()
        made.append((options, client))
        return client

    monkeypatch.setattr(egress_transport, "build_pinned_async_client", build_client)
    relay = gateway.GatewayUpstreamRelay(
        gateway.GatewaySettings(
            registry=UpstreamRegistry([]),
            policy={},
            upstream_http_timeout_seconds=7,
            upstream_http_max_connections=9,
            upstream_http_max_keepalive_connections=3,
        )
    )
    public = await relay._client_for_call(allow_private_networks=False)
    private = await relay._client_for_call(allow_private_networks=True)
    assert public is not private
    assert await relay._client_for_call(allow_private_networks=False) is public
    assert await relay._client_for_call(allow_private_networks=True) is private
    assert [options["allow_private_networks"] for options, _ in made] == [False, True]
    for options, _ in made:
        assert options["timeout"].read == 7
        assert options["limits"].max_connections == 9
        assert options["limits"].max_keepalive_connections == 3
    await relay.aclose()
    await relay.aclose()
    public.aclose.assert_awaited_once()
    private.aclose.assert_awaited_once()
    assert relay._clients == {}


@pytest.mark.asyncio
async def test_relay_failure_isolated_by_tenant_and_success_resets_circuit(monkeypatch):
    from agent_bom.runtime import gateway_relay_contract

    now = [100.0]
    monkeypatch.setattr(gateway, "time", SimpleNamespace(monotonic=lambda: now[0]))
    attempts = []
    failing = True

    class Transport:
        async def forward(self, request):
            attempts.append(request)
            if failing and request.upstream.tenant_id == "tenant-a":
                raise RuntimeError("upstream unavailable")
            return gateway_relay_contract.RelayForwardResult(
                message={"jsonrpc": "2.0", "id": 7, "result": {"ok": True}}, upstream_name=request.upstream.name, bytes_read=0
            )

    monkeypatch.setattr(gateway, "build_gateway_relay_transport", lambda *_args, **_kwargs: Transport())
    relay = gateway.GatewayUpstreamRelay(
        gateway.GatewaySettings(
            registry=UpstreamRegistry([]),
            policy={},
            upstream_failure_threshold=1,
            upstream_circuit_cooldown_seconds=10,
        )
    )
    relay._clients[False] = AsyncMock()
    a = UpstreamConfig(name="shared", url="https://upstream.example/mcp", tenant_id="tenant-a", headers={"X-Upstream": "a"})
    b = UpstreamConfig(name="shared", url="https://upstream.example/mcp", tenant_id="tenant-b", headers={"X-Upstream": "b"})
    message = {"jsonrpc": "2.0", "id": 7, "method": "tools/list"}
    with pytest.raises(RuntimeError, match="upstream unavailable"):
        await relay(a, message, {"X-Trace": "trace-a"})
    with pytest.raises(gateway.GatewayCircuitOpenError):
        await relay(a, message, {})
    assert (await relay(b, message, {"X-Trace": "trace-b"}))["result"] == {"ok": True}
    assert len(attempts) == 2
    assert attempts[0].headers == {"X-Upstream": "a", "X-Trace": "trace-a"}
    assert attempts[1].headers == {"X-Upstream": "b", "X-Trace": "trace-b"}
    failing = False
    now[0] += 11
    assert (await relay(a, message, {}))["result"] == {"ok": True}
    failing = True
    with pytest.raises(RuntimeError, match="upstream unavailable"):
        await relay(a, message, {})
    assert len(attempts) == 4
    await relay.aclose()
