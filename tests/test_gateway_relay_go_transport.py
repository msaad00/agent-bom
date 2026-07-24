"""Behavioral parity checks for the Go gateway-relay sidecar (Phase 3)."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from agent_bom.runtime.gateway_relay_contract import (
    MAX_GATEWAY_RELAY_MESSAGE_BYTES,
    GoHttpRelayTransport,
    RelayForwardRequest,
    RelayUpstreamTarget,
    gateway_relay_backend,
)

ROOT = Path(__file__).resolve().parents[1]
GO_MOD = ROOT / "runtime" / "gateway-relay"
MOCK = ROOT / "scripts" / "perf" / "mock_mcp_upstream.py"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _go_available() -> bool:
    return shutil.which("go") is not None and GO_MOD.is_dir()


@pytest.mark.skipif(not _go_available(), reason="go toolchain or runtime/gateway-relay missing")
def test_go_module_unit_tests() -> None:
    proc = subprocess.run(
        ["go", "test", "./..."],
        cwd=str(GO_MOD),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.fixture(scope="module")
def mock_upstream_url() -> str:
    if not MOCK.exists():
        pytest.skip("mock upstream script not present")
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


@pytest.fixture(scope="module")
def go_relay_base() -> str:
    if not _go_available():
        pytest.skip("go toolchain or runtime/gateway-relay missing")
    port = _free_port()
    listen = f"127.0.0.1:{port}"
    bin_dir = GO_MOD / "bin"
    bin_dir.mkdir(exist_ok=True)
    binary = bin_dir / "gateway-relay"
    build = subprocess.run(
        ["go", "build", "-o", str(binary), "./cmd/gateway-relay"],
        cwd=str(GO_MOD),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if build.returncode != 0:
        pytest.skip(f"go build failed: {build.stderr}")
    proc = subprocess.Popen(
        [str(binary), "-listen", listen],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    base = f"http://{listen}"
    deadline = time.monotonic() + 15.0
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            httpx.get(f"{base}/healthz", timeout=0.5).raise_for_status()
            break
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            time.sleep(0.05)
    else:
        proc.kill()
        raise RuntimeError(f"go relay failed to start: {last_err}")
    try:
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_gateway_relay_backend_default_python(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_GATEWAY_RELAY_BACKEND", raising=False)
    assert gateway_relay_backend() == "python"
    monkeypatch.setenv("AGENT_BOM_GATEWAY_RELAY_BACKEND", "go")
    assert gateway_relay_backend() == "go"


@pytest.mark.skipif(not _go_available(), reason="go toolchain or runtime/gateway-relay missing")
def test_go_transport_forward_echo(mock_upstream_url: str, go_relay_base: str) -> None:
    request = RelayForwardRequest(
        upstream=RelayUpstreamTarget(
            name="echo",
            url=mock_upstream_url,
            private_network_approved=True,
        ),
        message={
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"k": "v"}},
        },
        headers={},
    )

    async def _run() -> None:
        async with httpx.AsyncClient(timeout=10.0) as client:
            transport = GoHttpRelayTransport(client, base_url=go_relay_base)
            result = await transport.forward(request)
            assert result.upstream_name == "echo"
            assert result.bytes_read > 0
            assert result.message["id"] == 99
            assert "result" in result.message

    asyncio.run(_run())


@pytest.mark.skipif(not _go_available(), reason="go toolchain or runtime/gateway-relay missing")
def test_go_relay_rejects_oversized_request_body(go_relay_base: str) -> None:
    huge = {"upstream": {"name": "x", "url": "http://127.0.0.1:9/"}, "message": {"pad": "x" * (MAX_GATEWAY_RELAY_MESSAGE_BYTES)}}
    raw = json.dumps(huge).encode()
    assert len(raw) > MAX_GATEWAY_RELAY_MESSAGE_BYTES
    resp = httpx.post(f"{go_relay_base}/v1/forward", content=raw, headers={"Content-Type": "application/json"}, timeout=10.0)
    assert resp.status_code in {400, 413}
