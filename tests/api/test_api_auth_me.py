"""Tests for GET /v1/auth/me — UI-facing auth/session contract."""

from __future__ import annotations

import asyncio
import json

from starlette.testclient import TestClient

from agent_bom.api.server import app


def test_auth_me_returns_zero_state_without_auth() -> None:
    client = TestClient(app)
    resp = client.get("/v1/auth/me")
    assert resp.status_code == 200
    body = resp.json()
    assert body["authenticated"] is False
    assert body["auth_method"] is None
    assert body["role"] is None
    assert body["tenant_id"] == "default"
    assert body["role_summary"] is None
    assert body["memberships"] == []


def test_auth_me_reports_contributor_capabilities_for_analyst() -> None:
    from agent_bom.api.routes.enterprise import auth_me

    class _FakeState:
        auth_method = "oidc"
        api_key_name = "alice@example.com"
        api_key_role = "analyst"
        tenant_id = "tenant-alpha"
        request_id = "req-123"
        trace_id = "trace-abc"
        span_id = "span-456"
        auth_issuer = "example.com"
        api_key_id = None

    class _FakeRequest:
        state = _FakeState()

    body = asyncio.run(auth_me(_FakeRequest()))  # type: ignore[arg-type]
    assert body["authenticated"] is True
    assert body["role"] == "analyst"
    assert body["tenant_id"] == "tenant-alpha"
    assert body["role_summary"]["ui_role"] == "contributor"
    assert body["role_summary"]["display_name"] == "Contributor"
    assert "scan.run" in body["role_summary"]["capabilities"]
    assert "keys.manage" not in body["role_summary"]["capabilities"]
    assert "Create, rotate, or revoke API keys" in body["role_summary"]["cannot_do"]
    assert body["memberships"] == [
        {
            "tenant_id": "tenant-alpha",
            "role": "analyst",
            "ui_role": "contributor",
            "display_name": "Contributor",
            "active": True,
        }
    ]


def test_auth_me_never_leaks_raw_key_or_token() -> None:
    from agent_bom.api.routes.enterprise import auth_me

    secret = "sk-live-super-secret-123456789"

    class _FakeState:
        auth_method = "api_key"
        api_key_name = "ci-bot"
        api_key_role = "admin"
        tenant_id = "tenant-alpha"
        request_id = "req-123"
        trace_id = "trace-abc"
        span_id = "span-456"
        auth_issuer = None
        api_key_id = "deadbeef01234567"
        raw_api_key = secret
        jwt_token = secret
        api_key_hash = secret

    class _FakeRequest:
        state = _FakeState()

    body = asyncio.run(auth_me(_FakeRequest()))  # type: ignore[arg-type]
    serialized = json.dumps(body)
    assert secret not in serialized


def test_browser_session_accepts_runtime_configured_api_key(monkeypatch) -> None:
    from agent_bom.api import server as api_server
    from agent_bom.api.auth import KeyStore, get_key_store, set_key_store

    original_store = get_key_store()
    set_key_store(KeyStore())
    monkeypatch.setattr(api_server, "_runtime_api_key_seeded", False)

    try:
        api_server.configure_api(api_key="abk_runtime_test_key")
        client = TestClient(app)

        response = client.post("/v1/auth/session", json={"api_key": "abk_runtime_test_key"})
        assert response.status_code == 204

        session = client.get("/v1/auth/me").json()
        assert session["authenticated"] is True
        assert session["auth_method"] == "browser_session"
        assert session["subject"] == "runtime:admin"
        assert session["role"] == "admin"
    finally:
        set_key_store(original_store)
