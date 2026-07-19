from __future__ import annotations

import socket
from typing import Any

import pytest


class _Delegate:
    def __init__(self) -> None:
        self.hosts: list[str] = []

    async def connect_tcp(self, host: str, port: int, **kwargs: Any) -> object:
        self.hosts.append(host)
        return object()

    async def connect_unix_socket(self, path: str, **kwargs: Any) -> object:
        raise AssertionError("unix sockets are not used by the gateway transport")

    async def sleep(self, seconds: float) -> None:
        return None


@pytest.mark.asyncio
async def test_backend_pins_public_dns_answer_at_connect_time() -> None:
    from agent_bom.runtime.egress_transport import PinnedDNSNetworkBackend

    delegate = _Delegate()

    async def resolve(host: str, port: int) -> list[tuple[Any, ...]]:
        assert host == "mcp.example.com"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    backend = PinnedDNSNetworkBackend(delegate=delegate, resolver=resolve)
    await backend.connect_tcp("mcp.example.com", 443)

    assert delegate.hosts == ["93.184.216.34"]


@pytest.mark.asyncio
async def test_backend_rejects_mixed_public_private_dns_answers() -> None:
    from agent_bom.runtime.egress_transport import PinnedDNSNetworkBackend, UnsafeDestinationError

    delegate = _Delegate()

    async def resolve(host: str, port: int) -> list[tuple[Any, ...]]:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
        ]

    backend = PinnedDNSNetworkBackend(delegate=delegate, resolver=resolve)
    with pytest.raises(UnsafeDestinationError, match="non-public"):
        await backend.connect_tcp("mcp.example.com", 443)

    assert delegate.hosts == []


@pytest.mark.asyncio
async def test_backend_operator_private_mode_never_allows_cloud_metadata() -> None:
    from agent_bom.runtime.egress_transport import PinnedDNSNetworkBackend, UnsafeDestinationError

    delegate = _Delegate()
    backend = PinnedDNSNetworkBackend(delegate=delegate, allow_private_networks=True)

    with pytest.raises(UnsafeDestinationError, match="metadata"):
        await backend.connect_tcp("169.254.169.254", 80)

    assert delegate.hosts == []


@pytest.mark.asyncio
async def test_backend_operator_private_mode_allows_loopback() -> None:
    from agent_bom.runtime.egress_transport import PinnedDNSNetworkBackend

    delegate = _Delegate()
    backend = PinnedDNSNetworkBackend(delegate=delegate, allow_private_networks=True)
    await backend.connect_tcp("127.0.0.1", 8080)

    assert delegate.hosts == ["127.0.0.1"]

    await backend.connect_tcp("::1", 8080)
    assert delegate.hosts == ["127.0.0.1", "::1"]
