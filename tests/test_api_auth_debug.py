"""Tests for GET /v1/auth/debug — operator-facing auth introspection.

Covers:
- unauthenticated request returns a safe zero-state response
- auth method + role + tenant reflect the middleware-resolved state
- no raw key / token / hash ever appears in the response
- request-scoped trace IDs are surfaced so operators can correlate logs
"""

from __future__ import annotations

from starlette.testclient import TestClient

from agent_bom.api.server import app


def _set_state(client: TestClient, **attrs) -> TestClient:
    """Install a one-shot ASGI middleware that seeds request.state.

    The API's real middleware stack populates these attributes from a valid
    API key / OIDC token / SAML session. For the debug endpoint contract we
    only care that given some state, the response shape is stable — so we
    inject the state directly and exercise the endpoint handler.
    """
    # Starlette's TestClient shares the app instance; stacking middlewares
    # between tests would leak. Instead, monkey-patch the endpoint's
    # request.state lookups via a scope override.
    raise NotImplementedError  # sentinel to clarify intent — see direct calls below


def test_auth_debug_returns_zero_state_without_auth() -> None:
    """No middleware has run → every auth attribute reports None."""
    client = TestClient(app)
    resp = client.get("/v1/auth/debug")
    # The endpoint itself is not auth-required; it reports the absence.
    assert resp.status_code == 200
    body = resp.json()
    assert body["authenticated"] is False
    assert body["auth_method"] is None
    assert body["subject"] is None
    assert body["role"] is None
    # tenant_id defaults to "default" so clients can always display a value
    assert body["tenant_id"] == "default"


def test_auth_debug_reports_resolved_method_and_role() -> None:
    """When middleware has set auth state, it surfaces on the debug endpoint."""
    from agent_bom.api.routes.enterprise import auth_debug

    class _FakeState:
        auth_method = "api_key"
        api_key_name = "ci-bot"
        api_key_role = "analyst"
        tenant_id = "tenant-alpha"
        request_id = "req-123"
        trace_id = "trace-abc"
        span_id = "span-456"
        auth_issuer = None
        api_key_id = "deadbeef01234567"

    class _FakeRequest:
        state = _FakeState()

    import asyncio

    result = asyncio.run(auth_debug(_FakeRequest()))  # type: ignore[arg-type]
    assert result == {
        "authenticated": True,
        "auth_required": False,
        "configured_modes": [],
        "recommended_ui_mode": "no_auth",
        "auth_method": "api_key",
        "subject": "ci-bot",
        "role": "analyst",
        "tenant_id": "tenant-alpha",
        "oidc_issuer_suffix": None,
        "api_key_id_prefix": "deadbeef",
        "request_id": "req-123",
        "trace_id": "trace-abc",
        "span_id": "span-456",
    }


def test_auth_debug_never_leaks_raw_key_or_token() -> None:
    """Even if a wildly-unsafe key somehow lands in state, it must not escape."""
    from agent_bom.api.routes.enterprise import auth_debug

    secret = "sk-live-super-secret-123456789"

    class _FakeState:
        auth_method = "oidc"
        api_key_name = "alice@example.com"
        api_key_role = "admin"
        tenant_id = "tenant-alpha"
        request_id = "r-1"
        trace_id = "t-1"
        span_id = "s-1"
        auth_issuer = "example.com"
        api_key_id = None
        # Attributes the endpoint explicitly does not read
        raw_api_key = secret
        jwt_token = secret
        api_key_hash = secret

    class _FakeRequest:
        state = _FakeState()

    import asyncio
    import json

    body = asyncio.run(auth_debug(_FakeRequest()))  # type: ignore[arg-type]
    serialized = json.dumps(body)
    assert secret not in serialized, "raw key/token must never appear in /v1/auth/debug output"


def test_auth_debug_distinguishes_saml_from_api_key() -> None:
    """Keys minted via /v1/auth/saml/login are reported as auth_method=saml."""
    from agent_bom.api.routes.enterprise import auth_debug

    class _FakeState:
        auth_method = "saml"
        api_key_name = "saml:alice@example.com"
        api_key_role = "analyst"
        tenant_id = "tenant-alpha"
        request_id = "r-1"
        trace_id = "t-1"
        span_id = "s-1"
        auth_issuer = None
        api_key_id = "cafebabe12345678"

    class _FakeRequest:
        state = _FakeState()

    import asyncio

    result = asyncio.run(auth_debug(_FakeRequest()))  # type: ignore[arg-type]
    assert result["auth_method"] == "saml"
    assert result["subject"].startswith("saml:")


def test_auth_debug_key_id_only_exposes_prefix() -> None:
    """api_key_id_prefix must be 8 chars max to avoid leaking full identifier."""
    from agent_bom.api.routes.enterprise import auth_debug

    class _FakeState:
        auth_method = "api_key"
        api_key_name = "ci-bot"
        api_key_role = "viewer"
        tenant_id = "default"
        request_id = "r-1"
        trace_id = "t-1"
        span_id = "s-1"
        auth_issuer = None
        api_key_id = "0123456789abcdef0123456789abcdef"

    class _FakeRequest:
        state = _FakeState()

    import asyncio

    result = asyncio.run(auth_debug(_FakeRequest()))  # type: ignore[arg-type]
    assert result["api_key_id_prefix"] == "01234567"
    assert len(result["api_key_id_prefix"]) == 8
