"""Key-backed cookies obey live records on memory and real PostgreSQL stores."""

from __future__ import annotations

import os
from uuid import uuid4

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from agent_bom.api.auth import KeyStore, Role, create_api_key, get_key_store, set_key_store
from agent_bom.api.browser_session import SESSION_COOKIE_NAME, create_browser_session_token
from agent_bom.api.middleware import APIKeyMiddleware
from agent_bom.api.postgres_common import _current_tenant
from agent_bom.api.tenant_worker import run_tenant_bound


def test_session_key_lookup_binds_verified_tenant_and_restores_context():
    from agent_bom.api.session_authorization import authorize_browser_session

    class ContextCheckingKeys(KeyStore):
        def get(self, key_id):
            assert _current_tenant.get() == "signed-session-tenant"
            return super().get(key_id)

    original = get_key_store()
    store = ContextCheckingKeys()
    set_key_store(store)
    _, key = create_api_key("reader", Role.VIEWER, tenant_id="signed-session-tenant", scopes=["scan:read"])
    store.add(key)
    before = _current_tenant.get()
    try:
        role, scopes = authorize_browser_session(
            role=key.role,
            scopes=key.scopes,
            tenant_id=key.tenant_id,
            key_id=key.key_id,
            auth_method="api_key",
            method="GET",
            path="/v1/scan/job",
        )
        assert (role, scopes) == (Role.VIEWER, ["scan:read"])
        assert _current_tenant.get() == before
    finally:
        set_key_store(original)


@pytest.mark.asyncio
@pytest.mark.parametrize("backend", ["memory", "postgres"])
@pytest.mark.parametrize("restriction", ["revoked", "scope"])
async def test_open_stream_rechecks_persisted_session_key(backend, restriction, monkeypatch):
    from agent_bom.api import stream_authorization

    if backend == "postgres":
        if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
            pytest.skip("AGENT_BOM_POSTGRES_URL required for live stream parity")
        from agent_bom.api.postgres_access import PostgresKeyStore

        keys = PostgresKeyStore()
    else:
        keys = KeyStore()
    original = get_key_store()
    set_key_store(keys)
    monkeypatch.setattr(stream_authorization, "STREAM_RECHECK_SECONDS", 0.0)
    tenant = f"stream-{uuid4().hex}"
    _, key = create_api_key("stream-owner", Role.VIEWER, tenant_id=tenant, scopes=["scan:read"])
    keys.provision_tenant_key(key, team_name=tenant)
    captured = []

    async def handler(request):
        captured.append(request.state.stream_authorization)
        return JSONResponse({"tenant": request.state.tenant_id})

    app = Starlette(routes=[Route("/v1/scan/fixture/stream", handler)])
    app.add_middleware(APIKeyMiddleware, api_key="")
    token, _ = create_browser_session_token(
        subject=key.name,
        role=key.role.value,
        tenant_id=tenant,
        key_id=key.key_id,
        auth_method="api_key",
        scopes=key.scopes,
        max_age_seconds=300,
    )
    before = _current_tenant.get()
    try:
        with TestClient(app) as client:
            client.cookies.set(SESSION_COOKIE_NAME, token)
            assert client.get("/v1/scan/fixture/stream").json() == {"tenant": tenant}
        assert await captured[0].allowed()
        if restriction == "scope":
            key.scopes = ["runtime:read"]
        else:
            key.revoked_at = "2026-09-27T00:00:00+00:00"
        if backend == "postgres":
            run_tenant_bound(tenant, keys.add, key)
        assert not await captured[0].allowed()
        assert _current_tenant.get() == before
    finally:
        set_key_store(original)


@pytest.mark.parametrize("backend", ["memory", "postgres"])
def test_cookie_uses_current_persisted_key_authority(backend, monkeypatch):
    if backend == "postgres":
        if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
            pytest.skip("AGENT_BOM_POSTGRES_URL required for live key-store parity")
        from agent_bom.api.postgres_access import PostgresKeyStore

        keys = PostgresKeyStore()
    else:
        keys = KeyStore()
    original = get_key_store()
    set_key_store(keys)
    tenant = f"session-{uuid4().hex}"
    _, key = create_api_key("session-owner", Role.ADMIN, tenant_id=tenant, scopes=["auth.keys:read", "scan:read"])
    keys.provision_tenant_key(key, team_name=tenant)

    async def handler(request):
        return JSONResponse({"role": request.state.api_key_role, "scopes": request.state.api_key_scopes, "tenant": request.state.tenant_id})

    app = Starlette(routes=[Route("/v1/auth/me", handler), Route("/v1/auth/keys", handler)])
    app.add_middleware(APIKeyMiddleware, api_key="")
    client = TestClient(app)

    def cookie(tenant_id):
        token, _ = create_browser_session_token(
            subject=key.name,
            role="admin",
            tenant_id=tenant_id,
            key_id=key.key_id,
            auth_method="api_key",
            scopes=["auth.keys:read", "scan:read"],
            max_age_seconds=300,
        )
        client.cookies.set(SESSION_COOKIE_NAME, token)

    def persist():
        if backend == "postgres":
            run_tenant_bound(tenant, keys.add, key)

    try:
        cookie(tenant)
        assert client.get("/v1/auth/keys").status_code == 200
        key.role = Role.VIEWER
        persist()
        assert client.get("/v1/auth/keys").status_code == 403
        assert client.get("/v1/auth/me").json()["role"] == "viewer"
        key.scopes = ["scan:read"]
        persist()
        assert client.get("/v1/auth/me").json() == {"role": "viewer", "scopes": ["scan:read"], "tenant": tenant}
        cookie(f"foreign-{tenant}")
        assert client.get("/v1/auth/me").status_code == 401
        cookie(tenant)
        key.revoked_at = "2026-09-27T00:00:00+00:00"
        persist()
        assert client.get("/v1/auth/me").status_code == 401
    finally:
        set_key_store(original)
