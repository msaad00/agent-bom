"""Gateway pure-relay contract (Python reference; future Go sidecar target).

ADR-009 allows an optional Go sidecar only for proven hot paths. Phase 2 of the
Go-workload plan extracts the **pure HTTP JSON-RPC forward** surface from
policy / detector / audit orchestration so a sidecar can replace the relay loop
without forking product semantics.

This module is the Python-owned contract:

* transport: streamable-http ``POST`` of a JSON-RPC object to an upstream URL
* max body: ``MAX_GATEWAY_RELAY_MESSAGE_BYTES``
* auth headers: resolved by the caller (Python registry today) and passed in
* policy / DLP / firewall / identity: **not** in this contract — stay in the
  Python gateway process (or a future HTTP callback), then call ``forward``

See ``docs/design/GATEWAY_RELAY_CONTRACT.md``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

# Shared with gateway_server request/response caps (2 MiB).
MAX_GATEWAY_RELAY_MESSAGE_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class RelayUpstreamTarget:
    """Minimal upstream identity needed to forward one JSON-RPC call.

    Intentionally narrower than ``UpstreamConfig`` so a future sidecar can take
    a JSON snapshot without importing the full Python registry model.
    """

    name: str
    url: str
    tenant_id: str = ""
    private_network_approved: bool = False


@dataclass(frozen=True, slots=True)
class RelayForwardRequest:
    """One already-authorized JSON-RPC forward.

    The Python gateway applies policy/identity **before** constructing this
    request. A sidecar must treat presence of this object as "forward allowed".
    """

    upstream: RelayUpstreamTarget
    message: dict[str, Any]
    headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RelayForwardResult:
    """Normalized upstream response envelope."""

    message: dict[str, Any]
    upstream_name: str
    bytes_read: int


@dataclass(frozen=True, slots=True)
class RelayAuditHint:
    """Metadata-only audit hint the control plane already understands.

    Raw tool arguments / results must never be attached here — reuse
    ``build_gateway_runtime_event`` for durable events.
    """

    action: str
    upstream: str
    tenant_id: str
    outcome: str  # forwarded | blocked | upstream_error | upstream_timeout | circuit_open
    tool: str = ""
    reason: str = ""


@runtime_checkable
class GatewayRelayTransport(Protocol):
    """Pure relay backend: forward one authorized JSON-RPC message upstream."""

    async def forward(self, request: RelayForwardRequest) -> RelayForwardResult:
        """POST ``request.message`` to ``request.upstream.url``.

        Must raise on transport / HTTP / oversized-body failures so the Python
        orchestration layer can map them to circuit-breaker + audit outcomes.
        """


def relay_upstream_from_config(upstream: Any) -> RelayUpstreamTarget:
    """Adapt a gateway ``UpstreamConfig`` (duck-typed) to the contract snapshot."""
    return RelayUpstreamTarget(
        name=str(getattr(upstream, "name", "") or ""),
        url=str(getattr(upstream, "url", "") or ""),
        tenant_id=str(getattr(upstream, "tenant_id", "") or ""),
        private_network_approved=bool(getattr(upstream, "private_network_approved", False)),
    )


async def forward_jsonrpc_http(
    *,
    upstream_url: str,
    message: dict[str, Any],
    headers: dict[str, str],
    client: Any,
    upstream_name: str = "",
    max_bytes: int = MAX_GATEWAY_RELAY_MESSAGE_BYTES,
) -> RelayForwardResult:
    """Python reference implementation of the pure HTTP JSON-RPC forward.

    ``client`` is an httpx-like async client that supports ``stream("POST", ...)``.
    Auth / Content-Type headers are caller-supplied (registry resolves bearer /
    OAuth before this call).
    """
    merged = {"Content-Type": "application/json", **headers}
    async with client.stream("POST", upstream_url, json=message, headers=merged) as response:
        response.raise_for_status()
        content_length = response.headers.get("content-length")
        if content_length:
            try:
                declared_size = int(content_length)
            except ValueError:
                declared_size = 0
            if declared_size > max_bytes:
                raise ValueError(f"upstream response exceeded {max_bytes} bytes")

        body = bytearray()
        async for chunk in response.aiter_bytes():
            if len(body) + len(chunk) > max_bytes:
                raise ValueError(f"upstream response exceeded {max_bytes} bytes")
            body.extend(chunk)

        raw_body = bytes(body)
        if response.headers.get("content-type", "").startswith("application/json"):
            parsed: dict[str, Any] = json.loads(raw_body)
        else:
            # Non-JSON upstreams (e.g. text/event-stream) stay opaque so policy
            # + audit in the Python plane can still observe a success envelope.
            parsed = {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "result": {"raw": raw_body.decode("utf-8", errors="replace")},
            }
        return RelayForwardResult(message=parsed, upstream_name=upstream_name, bytes_read=len(raw_body))


class PythonHttpRelayTransport:
    """Reference ``GatewayRelayTransport`` using a shared httpx async client."""

    def __init__(self, client: Any, *, max_bytes: int = MAX_GATEWAY_RELAY_MESSAGE_BYTES) -> None:
        self._client = client
        self._max_bytes = max_bytes

    async def forward(self, request: RelayForwardRequest) -> RelayForwardResult:
        return await forward_jsonrpc_http(
            upstream_url=request.upstream.url,
            message=request.message,
            headers=request.headers,
            client=self._client,
            upstream_name=request.upstream.name,
            max_bytes=self._max_bytes,
        )



def gateway_relay_backend() -> str:
    """Return ``python`` (default) or ``go`` from ``AGENT_BOM_GATEWAY_RELAY_BACKEND``."""
    import os

    raw = (os.environ.get("AGENT_BOM_GATEWAY_RELAY_BACKEND") or "python").strip().lower()
    if raw in {"go", "golang"}:
        return "go"
    return "python"


def gateway_relay_go_url() -> str:
    """Sidecar base URL for the Go relay (no trailing slash)."""
    import os

    return (os.environ.get("AGENT_BOM_GATEWAY_RELAY_GO_URL") or "http://127.0.0.1:8091").rstrip("/")


class GoHttpRelayTransport:
    """``GatewayRelayTransport`` that POSTs to a Go sidecar ``/v1/forward``.

    Enabled when ``AGENT_BOM_GATEWAY_RELAY_BACKEND=go``. The Python gateway still
    owns policy / auth header resolution; the sidecar only performs the HTTP
    forward under the shared contract.
    """

    def __init__(
        self,
        client: Any,
        *,
        base_url: str | None = None,
        max_bytes: int = MAX_GATEWAY_RELAY_MESSAGE_BYTES,
    ) -> None:
        self._client = client
        self._base_url = (base_url or gateway_relay_go_url()).rstrip("/")
        self._max_bytes = max_bytes

    async def forward(self, request: RelayForwardRequest) -> RelayForwardResult:
        payload = {
            "upstream": {
                "name": request.upstream.name,
                "url": request.upstream.url,
                "tenant_id": request.upstream.tenant_id,
                "private_network_approved": request.upstream.private_network_approved,
            },
            "message": request.message,
            "headers": dict(request.headers),
        }
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if len(encoded) > self._max_bytes:
            raise ValueError(f"relay request exceeded {self._max_bytes} bytes")

        url = f"{self._base_url}/v1/forward"
        response = await self._client.post(
            url,
            content=encoded,
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()
        raw = response.content
        if len(raw) > self._max_bytes:
            raise ValueError(f"relay response exceeded {self._max_bytes} bytes")
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError("Go relay returned non-object JSON")
        message = data.get("message")
        if not isinstance(message, dict):
            raise ValueError("Go relay result missing message object")
        upstream_name = str(data.get("upstream_name") or request.upstream.name)
        bytes_read = int(data.get("bytes_read") or len(raw))
        return RelayForwardResult(message=message, upstream_name=upstream_name, bytes_read=bytes_read)


def build_gateway_relay_transport(client: Any, *, max_bytes: int = MAX_GATEWAY_RELAY_MESSAGE_BYTES) -> GatewayRelayTransport:
    """Select Python or Go transport from ``AGENT_BOM_GATEWAY_RELAY_BACKEND``."""
    if gateway_relay_backend() == "go":
        return GoHttpRelayTransport(client, max_bytes=max_bytes)
    return PythonHttpRelayTransport(client, max_bytes=max_bytes)


__all__ = [
    "MAX_GATEWAY_RELAY_MESSAGE_BYTES",
    "GatewayRelayTransport",
    "GoHttpRelayTransport",
    "PythonHttpRelayTransport",
    "RelayAuditHint",
    "RelayForwardRequest",
    "RelayForwardResult",
    "RelayUpstreamTarget",
    "build_gateway_relay_transport",
    "forward_jsonrpc_http",
    "gateway_relay_backend",
    "gateway_relay_go_url",
    "relay_upstream_from_config",
]
