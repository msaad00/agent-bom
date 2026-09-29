"""Live credentials bound SSE and WebSocket access after the handshake."""

from __future__ import annotations

import asyncio
import threading
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from starlette.applications import Starlette
from starlette.datastructures import Headers, QueryParams
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from agent_bom.api import auth, stream_authorization, websocket_auth
from agent_bom.api.routes import proxy


@pytest.mark.asyncio
@pytest.mark.parametrize("restriction", ["revoked", "scope", "tenant", "expired", "unavailable"])
async def test_open_metrics_stream_stops_after_key_restriction(monkeypatch, restriction):
    monkeypatch.setattr(stream_authorization, "STREAM_RECHECK_SECONDS", 0.0)
    store = auth.KeyStore()
    raw, key = auth.create_api_key(name="stream-fixture", role=auth.Role.ADMIN, scopes=["runtime:read"], tenant_id="tenant-a")
    store.add(key)
    monkeypatch.setattr(auth, "get_key_store", lambda: store)
    monkeypatch.setattr(websocket_auth, "_ws_auth_required", lambda: True)
    monkeypatch.setattr(websocket_auth, "_ws_handshake_within_rate_limit", AsyncMock(return_value=True))
    monkeypatch.setattr(proxy, "_runtime_metrics_for_tenant", lambda _: {})

    class Socket:
        headers = Headers({"Authorization": f"Bearer {raw}"})
        query_params = QueryParams()
        client = SimpleNamespace(host="127.0.0.1")
        frames = []
        close_code = None

        async def accept(self):
            pass

        async def send_json(self, data):
            self.frames.append(data)
            if len(self.frames) > 1:
                raise WebSocketDisconnect()
            if restriction == "revoked":
                key.revoked_at = datetime.now(timezone.utc).isoformat()
            elif restriction == "expired":
                key.expires_at = "2000-01-01T00:00:00+00:00"
            elif restriction == "scope":
                key.scopes = ["scan:read"]
            elif restriction == "tenant":
                key.tenant_id = "tenant-b"
            else:

                def unavailable(*args):
                    raise RuntimeError("private database details")

                monkeypatch.setattr(store, "verify", unavailable)

        async def close(self, code):
            self.close_code = code

    socket = Socket()
    await proxy.ws_proxy_metrics(socket)
    assert len(socket.frames) == 1
    assert socket.close_code == 4001


@pytest.mark.asyncio
async def test_idle_alert_stream_closes_when_key_is_revoked(scoped_store, monkeypatch):
    raw, key = auth.create_api_key(name="idle-stream", role=auth.Role.VIEWER, scopes=["runtime:read"])
    scoped_store.add(key)
    monkeypatch.setattr(websocket_auth, "_ws_auth_required", lambda: True)
    monkeypatch.setattr(websocket_auth, "_ws_handshake_within_rate_limit", AsyncMock(return_value=True))

    class Socket:
        headers = Headers({"Authorization": f"Bearer {raw}"})
        query_params = QueryParams()
        close_code = None

        async def accept(self):
            key.revoked_at = datetime.now(timezone.utc).isoformat()

        async def send_json(self, data):
            pytest.fail("Revoked idle stream must not deliver alerts")

        async def close(self, code):
            self.close_code = code

    socket = Socket()
    await asyncio.wait_for(proxy.ws_proxy_alerts(socket), timeout=1)
    assert socket.close_code == 4001


@pytest.mark.parametrize("transport", ["header", "first-message"])
@pytest.mark.parametrize("role", list(auth.Role))
def test_startup_seeded_env_keys_retain_store_identity(scoped_store, monkeypatch, transport, role):
    from agent_bom.api import server

    raw, _ = auth.create_api_key(name="seed-input", role=role)
    monkeypatch.setenv("AGENT_BOM_API_KEYS", f"{raw}:{role.value}")
    monkeypatch.setattr(server, "_env_api_keys_seeded", False)
    seeded = server._seed_api_key_store_from_env()
    assert seeded
    key = scoped_store.verify(raw)
    assert key is not None
    context = websocket_auth._ws_auth_from_token(raw, bearer=transport == "header")
    assert context is not None
    assert (context.key_id, context.tenant_id, context.role) == (key.key_id, key.tenant_id, role.value)


@pytest.mark.parametrize("transport", ["header", "first-message"])
@pytest.mark.parametrize("restriction", ["revoked", "expired", "rotation-ended", "unseeded"])
def test_env_key_cannot_bypass_store_lifecycle(scoped_store, monkeypatch, transport, restriction):
    raw, key = auth.create_api_key(name="env-stream", role=auth.Role.ADMIN, scopes=["runtime:read"])
    monkeypatch.setenv("AGENT_BOM_API_KEYS", f"{raw}:admin")
    if restriction != "unseeded":
        scoped_store.add(key)
        assert websocket_auth._ws_auth_from_token(raw) is not None
    if restriction == "revoked":
        scoped_store.remove(key.key_id)
    elif restriction == "expired":
        key.expires_at = "2000-01-01T00:00:00+00:00"
    elif restriction == "rotation-ended":
        key.replacement_key_id = "replacement-key"
        key.rotation_overlap_until = "2000-01-01T00:00:00+00:00"
    assert websocket_auth._ws_auth_from_token(raw, bearer=transport == "header") is None


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", [proxy.ws_proxy_metrics, proxy.ws_proxy_alerts])
@pytest.mark.parametrize("transport", ["header", "first-message"])
async def test_revoked_env_key_handshake_never_reads_or_sends_runtime_data(scoped_store, monkeypatch, endpoint, transport):
    raw, key = auth.create_api_key(name="env-reconnect", role=auth.Role.ADMIN)
    scoped_store.add(key)
    monkeypatch.setenv("AGENT_BOM_API_KEYS", f"{raw}:admin")
    scoped_store.remove(key.key_id)
    monkeypatch.setattr(websocket_auth, "_ws_auth_required", lambda: True)
    monkeypatch.setattr(websocket_auth, "_ws_handshake_within_rate_limit", AsyncMock(return_value=True))
    monkeypatch.setattr(proxy, "_runtime_metrics_for_tenant", lambda _: pytest.fail("Denied handshake read runtime metrics"))
    socket = SimpleNamespace(
        headers=Headers({"Authorization": f"Bearer {raw}"} if transport == "header" else {}),
        query_params=QueryParams(),
        accept=AsyncMock(),
        receive_json=AsyncMock(return_value={"type": "auth", "token": raw}),
        send_json=AsyncMock(side_effect=AssertionError("Denied handshake sent a frame")),
        close=AsyncMock(),
    )
    await asyncio.wait_for(endpoint(socket), timeout=1)
    socket.close.assert_awaited_once_with(code=4001)
    socket.send_json.assert_not_awaited()


@pytest.fixture
def scoped_store(monkeypatch):
    for name in ("AGENT_BOM_API_KEY", "AGENT_BOM_OIDC_ISSUER", "AGENT_BOM_TRUST_PROXY_AUTH", "AGENT_BOM_DEMO_ESTATE"):
        monkeypatch.delenv(name, raising=False)
    original = auth.get_key_store()
    store = auth.KeyStore()
    auth.set_key_store(store)
    monkeypatch.setattr(stream_authorization, "STREAM_RECHECK_SECONDS", 0.0)
    yield store
    auth.set_key_store(original)


@pytest.mark.asyncio
@pytest.mark.parametrize("credential", ["key", "session"])
@pytest.mark.parametrize("restriction", ["revoked", "scope", "tenant", "expired", "role", "unavailable"])
async def test_http_stream_rechecks_credentials_with_fresh_state(scoped_store, monkeypatch, credential, restriction):
    from agent_bom.api.browser_session import SESSION_COOKIE_NAME, create_browser_session_token
    from agent_bom.api.middleware import APIKeyMiddleware

    captured = []

    async def endpoint(request):
        captured.append(request)
        return Response(status_code=204)

    path = "/v1/scan/fixture/stream"
    app = Starlette(routes=[Route(path, endpoint)])
    app.add_middleware(APIKeyMiddleware, api_key="")
    raw, key = auth.create_api_key(name="stream-test", role=auth.Role.ADMIN, scopes=["scan:read"], tenant_id="tenant-a")
    scoped_store.add(key)
    with TestClient(app) as client:
        if credential == "key":
            client.headers["X-API-Key"] = raw
        else:
            token, _ = create_browser_session_token(
                subject=key.name,
                role=key.role.value,
                tenant_id=key.tenant_id,
                auth_method="api_key",
                key_id=key.key_id,
                scopes=key.scopes,
                max_age_seconds=300,
            )
            client.cookies.set(SESSION_COOKIE_NAME, token)
        assert client.get(path).status_code == 204
    lease = captured[0].state.stream_authorization
    assert await lease.allowed()
    if restriction == "revoked":
        key.revoked_at = datetime.now(timezone.utc).isoformat()
    elif restriction == "expired":
        key.expires_at = "2000-01-01T00:00:00+00:00"
    elif restriction == "scope":
        key.scopes = ["runtime:read"]
    elif restriction == "tenant":
        key.tenant_id = "tenant-b"
    elif restriction == "role":
        key.role = auth.Role.VIEWER
    else:

        def unavailable(*args):
            raise RuntimeError("private database details")

        monkeypatch.setattr(scoped_store, "get" if credential == "session" else "verify", unavailable)
    assert not await lease.allowed()
    # A failure is terminal even if credentials become usable again.
    key.scopes = ["scan:read"]
    assert not await lease.allowed()
    assert len(captured) == 1, "Revalidation must never execute the endpoint again"


@pytest.mark.asyncio
async def test_idle_sse_rechecks_and_cancels_pending_source(monkeypatch):
    monkeypatch.setattr(stream_authorization, "STREAM_RECHECK_SECONDS", 0.01)
    active = True
    closed = asyncio.Event()

    async def check():
        return active

    async def source():
        try:
            yield {"data": "first"}
            await asyncio.Event().wait()
        finally:
            closed.set()

    request = Request({"type": "http", "state": {"stream_authorization": stream_authorization.StreamAuthorization(check)}})
    events = stream_authorization.authorized_events(request, source())
    assert await anext(events) == {"data": "first"}
    active = False
    assert (await asyncio.wait_for(anext(events), timeout=1))["event"] == "reconnect"
    with pytest.raises(StopAsyncIteration):
        await anext(events)
    assert closed.is_set()


@pytest.mark.asyncio
async def test_stream_lease_bounds_check_frequency(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(stream_authorization.time, "monotonic", lambda: now[0])
    check = AsyncMock(return_value=True)
    lease = stream_authorization.StreamAuthorization(check)
    for _ in range(100):
        assert await lease.allowed()
    check.assert_not_called()
    now[0] += stream_authorization.STREAM_RECHECK_SECONDS
    assert await lease.allowed()
    check.assert_awaited_once()


@pytest.mark.asyncio
async def test_stream_lease_fails_closed_on_timeout(monkeypatch):
    monkeypatch.setattr(stream_authorization, "STREAM_RECHECK_SECONDS", 0.0)
    monkeypatch.setattr(stream_authorization, "_CHECK_TIMEOUT_SECONDS", 0.01)

    async def stalled():
        await asyncio.Event().wait()
        return True

    lease = stream_authorization.StreamAuthorization(stalled)
    assert not await asyncio.wait_for(lease.allowed(), timeout=1)


@pytest.mark.asyncio
async def test_stream_without_authenticator_never_starts_source():
    started = False

    async def source():
        nonlocal started
        started = True
        yield {"data": "private"}

    events = stream_authorization.authorized_events(Request({"type": "http"}), source())
    assert [event async for event in events] == [{"event": "reconnect", "data": '{"reason":"reauthenticate"}'}]
    assert not started


@pytest.mark.asyncio
async def test_stalled_websocket_consumer_is_closed(monkeypatch):
    monkeypatch.setattr(websocket_auth, "_STREAM_SEND_TIMEOUT_SECONDS", 0.01)
    lease = stream_authorization.StreamAuthorization(AsyncMock(return_value=True))
    context = websocket_auth._WebSocketAuthContext(authorization=lease)

    class Socket:
        close_code = None

        async def send_json(self, data):
            await asyncio.Event().wait()

        async def close(self, code):
            self.close_code = code

    socket = Socket()
    assert not await asyncio.wait_for(websocket_auth.send_stream_json(socket, context, {}), timeout=1)
    assert socket.close_code == 1013


@pytest.mark.asyncio
async def test_stalled_sse_consumer_cancels_source(monkeypatch):
    from sse_starlette.sse import SendTimeoutError

    from agent_bom.api import sse_authorization

    monkeypatch.setattr(sse_authorization, "_STREAM_SEND_TIMEOUT_SECONDS", 0.01)
    closed = asyncio.Event()

    async def source():
        try:
            yield {"data": "first"}
        finally:
            closed.set()

    async def send(message):
        if message["type"] == "http.response.body":
            await asyncio.Event().wait()

    async def receive():
        await asyncio.Event().wait()

    lease = stream_authorization.StreamAuthorization(AsyncMock(return_value=True))
    response = sse_authorization.AuthorizedEventSourceResponse(source())
    with pytest.raises((SendTimeoutError, BaseExceptionGroup)) as error:
        await asyncio.wait_for(response({"type": "http", "state": {"stream_authorization": lease}}, receive, send), timeout=1)
    if isinstance(error.value, BaseExceptionGroup):
        assert error.value.subgroup(SendTimeoutError) is not None
    assert closed.is_set()


@pytest.mark.asyncio
async def test_session_backing_key_revalidation_runs_off_event_loop(scoped_store, monkeypatch):
    from agent_bom.api.session_authorization import authorize_browser_session_async

    _, key = auth.create_api_key(name="worker-fixture", role=auth.Role.VIEWER, scopes=["scan:read"])
    scoped_store.add(key)
    loop_thread = threading.get_ident()
    original = scoped_store.get
    threads = []

    def lookup(key_id):
        threads.append(threading.get_ident())
        return original(key_id)

    monkeypatch.setattr(scoped_store, "get", lookup)
    role, scopes = await authorize_browser_session_async(
        role=key.role,
        scopes=key.scopes,
        tenant_id=key.tenant_id,
        key_id=key.key_id,
        auth_method="api_key",
        method="GET",
        path="/v1/scan/fixture/stream",
    )
    assert role == key.role and scopes == key.scopes
    assert threads and all(thread != loop_thread for thread in threads)


@pytest.mark.asyncio
async def test_session_nonce_and_scim_rechecks_run_off_event_loop(scoped_store, monkeypatch):
    from agent_bom.api import middleware
    from agent_bom.api.browser_session import SESSION_COOKIE_NAME, create_browser_session_token

    token, _ = create_browser_session_token(
        subject="stream-user",
        role="viewer",
        tenant_id="tenant-a",
        auth_method="oidc",
        max_age_seconds=300,
    )
    loop_thread = threading.get_ident()
    nonce_threads, role_threads = [], []
    verify = middleware.verify_browser_session_token

    def verify_nonce(value):
        nonce_threads.append(threading.get_ident())
        return verify(value)

    def resolve_role(*args):
        role_threads.append(threading.get_ident())
        return auth.SCIMRoleResolution(matched=False, active=False)

    monkeypatch.setattr(middleware, "verify_browser_session_token", verify_nonce)
    monkeypatch.setattr(auth, "resolve_scim_user_role", resolve_role)
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/v1/scan/fixture/stream",
            "scheme": "http",
            "headers": [(b"cookie", f"{SESSION_COOKIE_NAME}={token}".encode())],
        }
    )
    auth_middleware = middleware.APIKeyMiddleware(Starlette(), api_key="")

    async def endpoint(_):
        return Response(status_code=204)

    assert (await auth_middleware.dispatch(request, endpoint)).status_code == 204
    assert await request.state.stream_authorization.allowed()
    assert len(nonce_threads) == len(role_threads) == 2
    assert all(thread != loop_thread for thread in nonce_threads + role_threads)
