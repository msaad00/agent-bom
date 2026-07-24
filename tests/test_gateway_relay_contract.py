"""Contract tests for the pure gateway relay transport (Phase 2 / ADR-009)."""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from agent_bom.runtime.gateway_relay_contract import (
    MAX_GATEWAY_RELAY_MESSAGE_BYTES,
    GatewayRelayTransport,
    PythonHttpRelayTransport,
    RelayForwardRequest,
    RelayUpstreamTarget,
    forward_jsonrpc_http,
)

ROOT = Path(__file__).resolve().parents[1]
MOCK = ROOT / "scripts" / "perf" / "mock_mcp_upstream.py"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="module")
def mock_upstream_url() -> str:
    if not MOCK.exists():
        pytest.skip("mock upstream script not present on this branch")
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, str(MOCK), "--host", "127.0.0.1", "--port", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 15.0
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            httpx.get(f"{url}/healthz", timeout=0.5).raise_for_status()
            break
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            time.sleep(0.05)
    else:
        proc.kill()
        raise RuntimeError(f"mock upstream failed to start: {last_err}")
    try:
        yield f"{url}/mcp"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_protocol_runtime_checkable() -> None:
    class _Stub:
        async def forward(self, request: RelayForwardRequest):  # noqa: ANN001
            raise NotImplementedError

    assert isinstance(_Stub(), GatewayRelayTransport)


def test_forward_jsonrpc_http_echo(mock_upstream_url: str) -> None:
    message = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": "echo", "arguments": {"x": 1}},
    }

    async def _run() -> None:
        async with httpx.AsyncClient(timeout=5.0) as client:
            result = await forward_jsonrpc_http(
                upstream_url=mock_upstream_url,
                message=message,
                headers={},
                client=client,
                upstream_name="echo",
            )
            assert result.upstream_name == "echo"
            assert result.bytes_read > 0
            assert result.message["jsonrpc"] == "2.0"
            assert result.message["id"] == 7
            assert "result" in result.message
            assert "error" not in result.message

    asyncio.run(_run())


def test_python_transport_forward(mock_upstream_url: str) -> None:
    request = RelayForwardRequest(
        upstream=RelayUpstreamTarget(
            name="echo",
            url=mock_upstream_url,
            private_network_approved=True,
        ),
        message={
            "jsonrpc": "2.0",
            "id": "abc",
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {}},
        },
    )

    async def _run() -> None:
        async with httpx.AsyncClient(timeout=5.0) as client:
            transport = PythonHttpRelayTransport(client)
            assert isinstance(transport, GatewayRelayTransport)
            result = await transport.forward(request)
            assert result.message["id"] == "abc"
            assert "result" in result.message

    asyncio.run(_run())


def test_oversized_response_rejected(mock_upstream_url: str) -> None:
    """Contract: bodies above the shared cap must raise (fail closed)."""

    async def _run() -> None:
        # Build a fake client that streams an oversize JSON body.
        class _Resp:
            status_code = 200
            headers = {"content-type": "application/json", "content-length": str(MAX_GATEWAY_RELAY_MESSAGE_BYTES + 1)}

            def raise_for_status(self) -> None:
                return None

            async def aiter_bytes(self):
                yield b"{" + (b"a" * (MAX_GATEWAY_RELAY_MESSAGE_BYTES + 1)) + b"}"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):  # noqa: ANN002
                return False

        class _Client:
            def stream(self, *args, **kwargs):  # noqa: ANN002, ANN003
                return _Resp()

        with pytest.raises(ValueError, match="exceeded"):
            await forward_jsonrpc_http(
                upstream_url=mock_upstream_url,
                message={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}},
                headers={},
                client=_Client(),
                max_bytes=MAX_GATEWAY_RELAY_MESSAGE_BYTES,
            )

    asyncio.run(_run())


def test_relay_request_json_roundtrip_shape() -> None:
    target = RelayUpstreamTarget(name="jira", url="https://example.invalid/mcp", tenant_id="t1")
    req = RelayForwardRequest(
        upstream=target,
        message={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        headers={"Authorization": "Bearer redacted"},
    )
    payload = {
        "upstream": {
            "name": req.upstream.name,
            "url": req.upstream.url,
            "tenant_id": req.upstream.tenant_id,
            "private_network_approved": req.upstream.private_network_approved,
        },
        "message": req.message,
        "headers": req.headers,
    }
    # Sidecar I/O must be JSON-serializable without Python-only types.
    encoded = json.dumps(payload)
    decoded = json.loads(encoded)
    assert decoded["upstream"]["name"] == "jira"
    assert decoded["message"]["method"] == "tools/list"
