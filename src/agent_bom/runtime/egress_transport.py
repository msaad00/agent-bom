"""Connect-time destination enforcement for gateway HTTP egress.

The request URL remains hostname-based so HTTP Host, TLS SNI, and certificate
verification retain their normal semantics.  Only the socket destination is
replaced with an address resolved and validated immediately before connect.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Awaitable, Callable, Iterable
from typing import Any

import anyio
import httpcore
import httpx

Resolver = Callable[[str, int], Awaitable[list[tuple[Any, ...]]]]

_METADATA_HOSTS = frozenset({"metadata.google.internal", "metadata.goog"})
_METADATA_IPS = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("fd00:ec2::254"),
    }
)


class UnsafeDestinationError(httpcore.ConnectError):
    """Raised before connect when a destination violates egress policy."""


async def _resolve(host: str, port: int) -> list[tuple[Any, ...]]:
    return list(await anyio.getaddrinfo(host, port, type=socket.SOCK_STREAM))


class PinnedDNSNetworkBackend(httpcore.AsyncNetworkBackend):
    """Resolve, validate, and pin every new TCP socket to an approved IP."""

    def __init__(
        self,
        *,
        allow_private_networks: bool = False,
        delegate: Any | None = None,
        resolver: Resolver = _resolve,
    ) -> None:
        self._allow_private_networks = allow_private_networks
        self._delegate = delegate or httpcore.AnyIOBackend()
        self._resolver = resolver

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        normalized_host = host.rstrip(".").lower()
        if normalized_host in _METADATA_HOSTS:
            raise UnsafeDestinationError("cloud metadata destinations are forbidden")

        try:
            literal = ipaddress.ip_address(normalized_host)
        except ValueError:
            try:
                answers = await self._resolver(host, port)
            except OSError as exc:
                raise UnsafeDestinationError("gateway destination could not be resolved") from exc
            addresses = self._addresses_from_answers(answers)
        else:
            addresses = [literal]

        if not addresses:
            raise UnsafeDestinationError("gateway destination returned no usable addresses")
        for address in addresses:
            self._validate_address(address)

        last_error: Exception | None = None
        for address in addresses:
            try:
                return await self._delegate.connect_tcp(
                    str(address),
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except Exception as exc:  # httpcore backends expose backend-specific connect errors
                last_error = exc
        assert last_error is not None
        raise last_error

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise UnsafeDestinationError("gateway egress does not allow Unix sockets")

    async def sleep(self, seconds: float) -> None:
        await self._delegate.sleep(seconds)

    @staticmethod
    def _addresses_from_answers(answers: list[tuple[Any, ...]]) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        seen: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        for answer in answers:
            if len(answer) < 5 or not answer[4]:
                continue
            address = ipaddress.ip_address(str(answer[4][0]))
            if address not in seen:
                seen.add(address)
                addresses.append(address)
        return addresses

    def _validate_address(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
        if address in _METADATA_IPS:
            raise UnsafeDestinationError("cloud metadata destinations are forbidden")
        if address.is_link_local or address.is_multicast or address.is_unspecified:
            raise UnsafeDestinationError("gateway destination resolved to a forbidden address")
        if self._allow_private_networks and (address.is_private or address.is_loopback):
            return
        if address.is_reserved:
            raise UnsafeDestinationError("gateway destination resolved to a forbidden address")
        if not self._allow_private_networks and not address.is_global:
            raise UnsafeDestinationError("gateway destination resolved to a non-public address")


class _AsyncResponseStream(httpx.AsyncByteStream):
    def __init__(self, stream: Any) -> None:
        self._stream = stream

    async def __aiter__(self):
        async for chunk in self._stream:
            yield chunk

    async def aclose(self) -> None:
        await self._stream.aclose()


class PinnedDNSAsyncTransport(httpx.AsyncBaseTransport):
    """HTTPX transport backed by the connect-time validating network backend."""

    def __init__(self, *, allow_private_networks: bool, limits: httpx.Limits) -> None:
        ssl_context = httpx.create_ssl_context(verify=True, trust_env=False)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            max_connections=limits.max_connections,
            max_keepalive_connections=limits.max_keepalive_connections,
            keepalive_expiry=limits.keepalive_expiry,
            network_backend=PinnedDNSNetworkBackend(allow_private_networks=allow_private_networks),
            retries=0,
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        response = await self._pool.handle_async_request(core_request)
        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=_AsyncResponseStream(response.stream),
            extensions=response.extensions,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()


def build_pinned_async_client(
    *,
    allow_private_networks: bool,
    timeout: httpx.Timeout | float,
    limits: httpx.Limits | None = None,
) -> httpx.AsyncClient:
    """Return a no-proxy, no-redirect client with connect-time DNS pinning."""
    resolved_limits = limits or httpx.Limits()
    return httpx.AsyncClient(
        timeout=timeout,
        limits=resolved_limits,
        transport=PinnedDNSAsyncTransport(
            allow_private_networks=allow_private_networks,
            limits=resolved_limits,
        ),
        trust_env=False,
        follow_redirects=False,
    )


__all__ = [
    "PinnedDNSAsyncTransport",
    "PinnedDNSNetworkBackend",
    "UnsafeDestinationError",
    "build_pinned_async_client",
]
