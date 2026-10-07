"""Connect-time destination enforcement for gateway and delivery HTTP egress.

The request URL remains hostname-based so HTTP Host, TLS SNI, and certificate
verification retain their normal semantics.  Only the socket destination is
replaced with an address resolved and validated immediately before connect.
"""

from __future__ import annotations

import ipaddress
import socket
import time
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
        ipaddress.ip_address("100.100.100.200"),
        ipaddress.ip_address("fd00:ec2::254"),
    }
)


class UnsafeDestinationError(httpcore.ConnectError):
    """Raised before connect when a destination violates egress policy."""


def validate_destination_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address, *, allow_private_networks: bool = False) -> None:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if address in _METADATA_IPS:
        raise UnsafeDestinationError("cloud metadata destinations are forbidden")
    if address.is_link_local or address.is_multicast or address.is_unspecified:
        raise UnsafeDestinationError("gateway destination resolved to a forbidden address")
    if allow_private_networks and (address.is_private or address.is_loopback):
        return
    if address.is_reserved:
        raise UnsafeDestinationError("gateway destination resolved to a forbidden address")
    if not allow_private_networks and not address.is_global:
        raise UnsafeDestinationError("gateway destination resolved to a non-public address")


def validate_literal_destination(host: str, *, allow_private_networks: bool = False) -> None:
    """Reject forbidden literals/names; DNS answers are checked at connect time."""
    normalized = host.rstrip(".").lower()
    if normalized in _METADATA_HOSTS:
        raise UnsafeDestinationError("cloud metadata destinations are forbidden")
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return
    validate_destination_address(address, allow_private_networks=allow_private_networks)


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
            validate_destination_address(address, allow_private_networks=self._allow_private_networks)

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


class PinnedDNSSyncNetworkBackend(httpcore.NetworkBackend):
    """Resolve once per socket and connect only to the validated numeric address."""

    def __init__(self, *, allow_private_networks: bool = False) -> None:
        self._allow_private_networks = allow_private_networks
        self._delegate = httpcore.SyncBackend()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        validate_literal_destination(host, allow_private_networks=self._allow_private_networks)
        try:
            addresses = [ipaddress.ip_address(host)]
        except ValueError:
            try:
                answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            except OSError as exc:
                raise UnsafeDestinationError("delivery destination could not be resolved") from exc
            addresses = PinnedDNSNetworkBackend._addresses_from_answers(answers)
        if not addresses:
            raise UnsafeDestinationError("delivery destination returned no usable addresses")
        for address in addresses:
            validate_destination_address(address, allow_private_networks=self._allow_private_networks)
        last_error: Exception | None = None
        for address in addresses:
            try:
                return self._delegate.connect_tcp(
                    str(address), port, timeout=timeout, local_address=local_address, socket_options=socket_options
                )
            except Exception as exc:
                last_error = exc
        assert last_error is not None
        raise last_error

    def connect_unix_socket(
        self, path: str, timeout: float | None = None, socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None
    ) -> httpcore.NetworkStream:
        raise UnsafeDestinationError("delivery egress does not allow Unix sockets")

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


class _SyncResponseStream(httpx.SyncByteStream):
    def __init__(self, stream: Any) -> None:
        self._stream = stream

    def __iter__(self):
        yield from self._stream

    def close(self) -> None:
        self._stream.close()


class PinnedDNSSyncTransport(httpx.BaseTransport):
    """Synchronous delivery transport sharing the gateway's destination policy."""

    def __init__(self, *, allow_private_networks: bool) -> None:
        self._pool = httpcore.ConnectionPool(
            ssl_context=httpx.create_ssl_context(verify=True, trust_env=False),
            network_backend=PinnedDNSSyncNetworkBackend(allow_private_networks=allow_private_networks),
            retries=0,
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        response = self._pool.handle_request(
            httpcore.Request(
                method=request.method,
                url=httpcore.URL(
                    scheme=request.url.raw_scheme, host=request.url.raw_host, port=request.url.port, target=request.url.raw_path
                ),
                headers=request.headers.raw,
                content=request.stream,
                extensions=request.extensions,
            )
        )
        return httpx.Response(
            response.status, headers=response.headers, stream=_SyncResponseStream(response.stream), extensions=response.extensions
        )

    def close(self) -> None:
        self._pool.close()


def build_pinned_sync_client(*, allow_private_networks: bool, timeout: float) -> httpx.Client:
    """No ambient proxy or redirects: validate the target immediately before connect."""
    return httpx.Client(
        timeout=timeout,
        trust_env=False,
        follow_redirects=False,
        transport=PinnedDNSSyncTransport(allow_private_networks=allow_private_networks),
    )
