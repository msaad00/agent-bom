"""Pooled upstream relay and circuit lifecycle, independent of the HTTP app."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Protocol

from agent_bom.gateway_upstreams import UpstreamConfig
from agent_bom.runtime.gateway_relay_contract import (
    MAX_GATEWAY_RELAY_MESSAGE_BYTES,
    RelayForwardRequest,
    build_gateway_relay_transport,
    relay_upstream_from_config,
)

_MAX_GATEWAY_MESSAGE_BYTES = MAX_GATEWAY_RELAY_MESSAGE_BYTES


class RelaySettings(Protocol):
    """Only transport limits are needed by the managed upstream relay."""

    upstream_http_timeout_seconds: float
    upstream_http_max_connections: int
    upstream_http_max_keepalive_connections: int
    upstream_failure_threshold: int
    upstream_circuit_cooldown_seconds: float


class GatewayCircuitOpenError(RuntimeError):
    """Raised when an upstream circuit is open and calls should fail fast."""

    def __init__(self, upstream_name: str, retry_after_seconds: float) -> None:
        self.upstream_name = upstream_name
        self.retry_after_seconds = max(1.0, retry_after_seconds)
        super().__init__(f"upstream {upstream_name!r} circuit open; retry after {int(self.retry_after_seconds)}s")


@dataclass
class _CircuitState:
    failures: int = 0
    opened_until: float = 0.0


class GatewayCircuitBreaker:
    """Small per-upstream circuit breaker for gateway relay calls."""

    def __init__(self, *, failure_threshold: int, cooldown_seconds: float) -> None:
        self.failure_threshold = max(1, failure_threshold)
        self.cooldown_seconds = max(1.0, cooldown_seconds)
        self._states: dict[str, _CircuitState] = {}
        self._lock = asyncio.Lock()

    async def before_call(self, key: str, upstream_name: str) -> None:
        now = time.monotonic()
        async with self._lock:
            state = self._states.get(key)
            if state is None or state.opened_until <= 0:
                return
            if state.opened_until > now:
                raise GatewayCircuitOpenError(upstream_name, state.opened_until - now)
            # Half-open: allow one trial request and reset on success/failure path.
            state.opened_until = 0.0

    async def record_success(self, key: str) -> None:
        async with self._lock:
            self._states.pop(key, None)

    async def record_failure(self, key: str) -> None:
        now = time.monotonic()
        async with self._lock:
            state = self._states.setdefault(key, _CircuitState())
            state.failures += 1
            if state.failures >= self.failure_threshold:
                state.opened_until = now + self.cooldown_seconds


class GatewayUpstreamRelay:
    """Lifecycle-managed upstream relay with connection pooling and breakers."""

    def __init__(self, settings: RelaySettings) -> None:
        self._timeout_seconds = max(1.0, settings.upstream_http_timeout_seconds)
        self._max_connections = max(1, settings.upstream_http_max_connections)
        self._max_keepalive_connections = max(1, settings.upstream_http_max_keepalive_connections)
        self._clients: dict[bool, Any] = {}
        self._client_lock = asyncio.Lock()
        self._breaker = GatewayCircuitBreaker(
            failure_threshold=settings.upstream_failure_threshold,
            cooldown_seconds=settings.upstream_circuit_cooldown_seconds,
        )

    async def aclose(self) -> None:
        async with self._client_lock:
            clients = list(self._clients.values())
            self._clients.clear()
            for client in clients:
                await client.aclose()

    async def _client_for_call(self, *, allow_private_networks: bool) -> Any:
        client = self._clients.get(allow_private_networks)
        if client is not None:
            return client
        async with self._client_lock:
            client = self._clients.get(allow_private_networks)
            if client is None:
                import httpx

                from agent_bom.runtime.egress_transport import build_pinned_async_client

                client = build_pinned_async_client(
                    allow_private_networks=allow_private_networks,
                    timeout=httpx.Timeout(self._timeout_seconds),
                    limits=httpx.Limits(
                        max_connections=self._max_connections,
                        max_keepalive_connections=self._max_keepalive_connections,
                    ),
                )
                self._clients[allow_private_networks] = client
            return client

    async def __call__(
        self,
        upstream: UpstreamConfig,
        message: dict[str, Any],
        extra_headers: dict[str, str],
    ) -> dict[str, Any]:
        circuit_key = _upstream_circuit_key(upstream)
        await self._breaker.before_call(circuit_key, upstream.name)
        try:
            allow_private = upstream.private_network_approved
            response = await _post_upstream_jsonrpc(
                upstream,
                message,
                extra_headers,
                client=await self._client_for_call(allow_private_networks=allow_private),
            )
        except Exception:
            await self._breaker.record_failure(circuit_key)
            raise
        await self._breaker.record_success(circuit_key)
        return response


async def _default_upstream_caller(
    upstream: UpstreamConfig,
    message: dict[str, Any],
    extra_headers: dict[str, str],
) -> dict[str, Any]:
    """Forward a JSON-RPC message to an upstream MCP server via HTTP POST.

    Resolves per-upstream auth (bearer + OAuth2 client-credentials) via
    ``upstream.resolve_auth_headers`` so OAuth tokens are fetched + cached
    correctly instead of failing at send time.
    """
    import httpx

    from agent_bom.runtime.egress_transport import build_pinned_async_client

    allow_private = upstream.private_network_approved
    async with build_pinned_async_client(
        allow_private_networks=allow_private,
        timeout=httpx.Timeout(30.0),
    ) as client:
        return await _post_upstream_jsonrpc(upstream, message, extra_headers, client=client)


def _upstream_circuit_key(upstream: UpstreamConfig) -> str:
    return f"{upstream.tenant_id or 'global'}:{upstream.name}:{upstream.url}"


async def _post_upstream_jsonrpc(
    upstream: UpstreamConfig,
    message: dict[str, Any],
    extra_headers: dict[str, str],
    *,
    client: Any,
) -> dict[str, Any]:
    """Forward via the pure-relay contract (Python in-process or Go sidecar).

    Backend selected by ``AGENT_BOM_GATEWAY_RELAY_BACKEND`` (default ``python``).
    When ``go``, the shared httpx client talks to the sidecar ``/v1/forward``;
    the sidecar then POSTs to the upstream URL.
    """
    auth_headers = await upstream.resolve_auth_headers()
    target = relay_upstream_from_config(upstream)
    transport = build_gateway_relay_transport(client, max_bytes=_MAX_GATEWAY_MESSAGE_BYTES)
    result = await transport.forward(
        RelayForwardRequest(
            upstream=target,
            message=message,
            headers={**auth_headers, **extra_headers},
        )
    )
    return result.message
