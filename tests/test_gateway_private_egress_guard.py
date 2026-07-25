"""Private-network egress stays gated by upstream provenance.

``private_network_approved`` is an operator-authored provenance bit: only YAML
an operator wrote may unlock the private-capable transport. No runtime switch —
relay backend, sidecar, or otherwise — may widen it, because the pinned
transport is what keeps metadata/link-local destinations unreachable.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

import pytest

from agent_bom.gateway_upstreams import UpstreamConfig


@asynccontextmanager
async def _dummy_client(*_args: Any, **_kwargs: Any):
    yield object()


def _capture_allow_private(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Patch the egress client factory and record the flag it is called with."""
    seen: dict[str, Any] = {}

    from agent_bom.runtime import egress_transport

    def _fake_builder(**kwargs: Any):
        seen["allow_private_networks"] = kwargs.get("allow_private_networks")
        return _dummy_client()

    monkeypatch.setattr(egress_transport, "build_pinned_async_client", _fake_builder)

    import agent_bom.gateway_server as gateway_server

    async def _fake_post(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "result": {}}

    monkeypatch.setattr(gateway_server, "_post_upstream_jsonrpc", _fake_post)
    return seen


@pytest.mark.asyncio
@pytest.mark.parametrize("backend", ["python", "go", "golang", "GO", ""])
async def test_unapproved_upstream_never_reaches_private_networks(monkeypatch: pytest.MonkeyPatch, backend: str) -> None:
    """No backend value may unlock private egress for an unapproved upstream."""
    monkeypatch.setenv("AGENT_BOM_GATEWAY_RELAY_BACKEND", backend)
    seen = _capture_allow_private(monkeypatch)

    from agent_bom.gateway_server import _default_upstream_caller

    upstream = UpstreamConfig(name="u", url="https://example.test/mcp")
    assert upstream.private_network_approved is False

    await _default_upstream_caller(upstream, {"jsonrpc": "2.0", "method": "ping"}, {})

    assert seen["allow_private_networks"] is False, f"backend={backend!r} unlocked private-network egress for an unapproved upstream"


@pytest.mark.asyncio
async def test_operator_approved_upstream_still_reaches_private_networks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The operator-authored provenance bit remains the one way in."""
    monkeypatch.delenv("AGENT_BOM_GATEWAY_RELAY_BACKEND", raising=False)
    seen = _capture_allow_private(monkeypatch)

    from agent_bom.gateway_server import _default_upstream_caller

    upstream = UpstreamConfig(name="u", url="https://example.test/mcp")
    object.__setattr__(upstream, "private_network_approved", True)

    await _default_upstream_caller(upstream, {"jsonrpc": "2.0", "method": "ping"}, {})

    assert seen["allow_private_networks"] is True
