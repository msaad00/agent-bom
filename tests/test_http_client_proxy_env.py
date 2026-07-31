"""``HTTP(S)_PROXY`` must be honoured — a silently ignored proxy fails open.

httpx only builds its environment proxy mounts when ``transport`` is left unset
(``allow_env_proxies = trust_env and transport is None``, httpx 0.28.1
``_client.py``). Passing our retrying transport therefore emptied every proxy
mount, so an operator who believed egress was pinned through an inspecting
proxy had no such control — disqualifying for a regulated self-host.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpcore
import httpx
import pytest

from agent_bom.http_client import create_client, create_sync_client

PROXY_PORT = 8874
PROXY_ENV_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy")


class _ProxyHandler(BaseHTTPRequestHandler):
    """Answers any absolute-URI request with a marker status."""

    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler contract
        body = self.path.encode()
        self.send_response(418)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        return


@pytest.fixture
def proxy_server(monkeypatch):
    for name in PROXY_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), _ProxyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{PROXY_PORT}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_sync_client_routes_through_the_configured_proxy(proxy_server, monkeypatch) -> None:
    monkeypatch.setenv("HTTP_PROXY", proxy_server)

    with create_sync_client(timeout=5) as client:
        response = client.get("http://blocked.example/resource")

    # The marker status can only come from the proxy: blocked.example does not
    # resolve, so a direct connection could not have produced a response.
    assert response.status_code == 418
    assert response.text == "http://blocked.example/resource"


@pytest.mark.asyncio
async def test_async_client_routes_through_the_configured_proxy(proxy_server, monkeypatch) -> None:
    monkeypatch.setenv("HTTP_PROXY", proxy_server)

    async with create_client(timeout=5) as client:
        response = await client.get("http://blocked.example/resource")

    assert response.status_code == 418


def test_no_proxy_exclusions_are_still_honoured(proxy_server, monkeypatch) -> None:
    """A ``NO_PROXY`` host must bypass the proxy, not be forced through it."""
    monkeypatch.setenv("HTTP_PROXY", proxy_server)
    monkeypatch.setenv("NO_PROXY", "blocked.example")

    # The proxy answers every absolute-URI request with 418, so reaching it at
    # all would mean NO_PROXY was ignored. Going direct is what must happen,
    # and the host does not resolve — but the exact exception depends on the
    # resolver: httpx wraps httpcore's error on some paths and lets it through
    # on others, so a CI runner and a laptop raise different types for the same
    # correct behaviour. Assert the property, not the type.
    with create_sync_client(timeout=5) as client:
        with pytest.raises((httpx.TransportError, httpcore.NetworkError)) as excinfo:
            client.get("http://blocked.example/resource")
    assert not isinstance(excinfo.value, httpx.HTTPStatusError)


def test_connection_retries_stay_enabled_without_a_proxy(monkeypatch) -> None:
    """The retrying transport is only stood down when a proxy is configured."""
    for name in PROXY_ENV_VARS:
        monkeypatch.delenv(name, raising=False)

    with create_sync_client(timeout=5) as client:
        assert isinstance(client._transport, httpx.HTTPTransport)
        assert client._transport._pool._retries == 2
