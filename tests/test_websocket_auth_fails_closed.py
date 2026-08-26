"""WebSocket streams must fail CLOSED, and must not hand-roll auth detection.

`APIKeyMiddleware` is a `BaseHTTPMiddleware`, so it never runs on websocket
scopes. `/ws/proxy/metrics` and `/ws/proxy/alerts` therefore implement their own
gate, and when that gate says "no auth configured" they accept anonymously into
`_WebSocketAuthContext(tenant_id="default", role="admin")`.

Two defects in that gate, both found by the pre-release security audit:

1. **It failed OPEN on a store error.** `_ws_auth_required()` ended with
   `except Exception: return False`, so a Postgres pool exhaustion — precisely
   when a control plane is already unhealthy — silently turned an admin stream
   anonymous. Observed: HTTP `/v1/findings` returned 500 while both websockets
   kept accepting.

2. **It swept the environment itself and missed a credential source.** The
   hand-rolled sweep never consulted Snowflake OAuth, so a Snowflake-OAuth-only
   deployment served both sockets anonymously while its HTTP surface was
   authenticated.

`derive_auth_posture` is the single env-based derivation every other reader
already consumes. These tests drive real environment variables rather than
patching that function, because the contract under test is "a deployment that
configured *any* credential source gets an authenticated socket" — not which
helper the gate happens to call.

This matters beyond the socket: `/ws/proxy/alerts` streams runtime DLP alerts,
whose excerpts carry the matched secret material.
"""

from __future__ import annotations

import pytest

from agent_bom.api.routes import proxy as proxy_routes

# Every environment variable any credential source reads, cleared before each
# case so one source can be switched on in isolation.
_AUTH_ENV = [
    "AGENT_BOM_API_KEY",
    "AGENT_BOM_API_KEYS",
    "AGENT_BOM_OIDC_ISSUER",
    "AGENT_BOM_OIDC_AUDIENCE",
    "AGENT_BOM_OIDC_JWKS_URL",
    "AGENT_BOM_OIDC_BROWSER_CLIENT_ID",
    "AGENT_BOM_SNOWFLAKE_OAUTH_ACCOUNT_URL",
    "AGENT_BOM_SNOWFLAKE_OAUTH_REDIRECT_URI",
    "AGENT_BOM_SNOWFLAKE_OAUTH_CLIENT_ID",
    "AGENT_BOM_SCIM_BEARER_TOKEN",
    "AGENT_BOM_SAML_IDP_ENTITY_ID",
    "AGENT_BOM_SAML_IDP_SSO_URL",
    "AGENT_BOM_SAML_IDP_X509_CERT",
    "AGENT_BOM_SAML_SP_ENTITY_ID",
    "AGENT_BOM_SAML_SP_ACS_URL",
    "AGENT_BOM_TRUST_PROXY_AUTH",
    "AGENT_BOM_TRUST_PROXY_SECRET",
    "AGENT_BOM_ALLOW_UNAUTHENTICATED_API",
]


@pytest.fixture(autouse=True)
def _clean_auth_env(monkeypatch: pytest.MonkeyPatch):
    for name in _AUTH_ENV:
        monkeypatch.delenv(name, raising=False)
    from agent_bom.api.middleware import apply_auth_posture, derive_auth_posture

    apply_auth_posture(derive_auth_posture(api_key_configured=False, allow_unauthenticated=False))


def _apply_current_posture(*, api_key_configured: bool = False, allow_unauthenticated: bool = False) -> None:
    from agent_bom.api.middleware import apply_auth_posture, derive_auth_posture

    apply_auth_posture(
        derive_auth_posture(
            api_key_configured=api_key_configured,
            allow_unauthenticated=allow_unauthenticated,
        )
    )


def test_default_unconfigured_deployment_matches_http_auth_by_default() -> None:
    """No credentials is not an implicit anonymous opt-in for WebSockets."""
    from agent_bom.api.middleware import apply_auth_posture, derive_auth_posture

    apply_auth_posture(derive_auth_posture(api_key_configured=False, allow_unauthenticated=False))
    assert proxy_routes._ws_auth_required() is True


def test_explicit_anonymous_posture_is_the_only_no_auth_websocket_mode() -> None:
    from agent_bom.api.middleware import apply_auth_posture, derive_auth_posture

    apply_auth_posture(derive_auth_posture(api_key_configured=False, allow_unauthenticated=True))
    assert proxy_routes._ws_auth_required() is False


def test_snowflake_oauth_alone_still_requires_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    """The source the hand-rolled env sweep never consulted."""
    monkeypatch.setenv("AGENT_BOM_SNOWFLAKE_OAUTH_ACCOUNT_URL", "https://acme-prod.snowflakecomputing.com")
    monkeypatch.setenv("AGENT_BOM_SNOWFLAKE_OAUTH_CLIENT_ID", "abom-client")
    monkeypatch.setenv("AGENT_BOM_SNOWFLAKE_OAUTH_REDIRECT_URI", "https://abom.example/oauth/callback")
    _apply_current_posture()
    assert proxy_routes._ws_auth_required() is True


def test_an_api_key_requires_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_API_KEY", "s3cret-key-value")
    _apply_current_posture(api_key_configured=True)
    assert proxy_routes._ws_auth_required() is True


def test_saml_alone_requires_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_SAML_IDP_ENTITY_ID", "https://idp.example/meta")
    monkeypatch.setenv("AGENT_BOM_SAML_IDP_SSO_URL", "https://idp.example/sso")
    monkeypatch.setenv("AGENT_BOM_SAML_IDP_X509_CERT", "MIIC-not-a-real-cert")
    monkeypatch.setenv("AGENT_BOM_SAML_SP_ENTITY_ID", "https://abom.example")
    monkeypatch.setenv("AGENT_BOM_SAML_SP_ACS_URL", "https://abom.example/acs")
    _apply_current_posture()
    assert proxy_routes._ws_auth_required() is True


def test_issued_api_keys_require_auth_even_with_no_env_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keys minted at runtime are a credential source with no env var."""
    _apply_current_posture(api_key_configured=True)
    assert proxy_routes._ws_auth_required() is True


def test_a_key_store_error_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unavailable applied posture must not open an admin stream."""

    import agent_bom.api.middleware as mw

    def _boom() -> object:
        raise RuntimeError("connection pool exhausted")

    monkeypatch.setattr(mw, "get_auth_posture", _boom)
    assert proxy_routes._ws_auth_required() is True


def test_a_posture_derivation_error_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """The applied source of truth is the only posture the socket consumes."""
    import agent_bom.api.middleware as mw

    def _boom(**_kwargs: object) -> object:
        raise RuntimeError("posture derivation failed")

    monkeypatch.setattr(mw, "get_auth_posture", _boom)
    assert proxy_routes._ws_auth_required() is True


@pytest.mark.asyncio
async def test_explicit_anonymous_websocket_uses_no_auth_role(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Socket:
        async def accept(self) -> None:
            return None

    monkeypatch.setattr(proxy_routes, "_ws_auth_required", lambda: False)
    monkeypatch.setenv("AGENT_BOM_NO_AUTH_ROLE", "viewer")
    context = await proxy_routes._ws_accept_and_check_auth(_Socket())  # type: ignore[arg-type]
    assert context is not None
    assert context.role == "viewer"


@pytest.mark.asyncio
async def test_explicit_anonymous_websocket_clamps_role_when_credentials_exist(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Socket:
        async def accept(self) -> None:
            return None

    class _Store:
        @staticmethod
        def has_keys() -> bool:
            return True

    import agent_bom.api.auth as auth_module

    monkeypatch.setattr(proxy_routes, "_ws_auth_required", lambda: False)
    monkeypatch.setattr(auth_module, "get_key_store", lambda: _Store())
    monkeypatch.setenv("AGENT_BOM_NO_AUTH_ROLE", "admin")
    context = await proxy_routes._ws_accept_and_check_auth(_Socket())  # type: ignore[arg-type]
    assert context is not None
    assert context.role == "viewer"


def test_trusted_proxy_intent_requires_auth_even_when_misconfigured(monkeypatch: pytest.MonkeyPatch) -> None:
    """A weak or missing proxy secret is a misconfiguration, not "no auth".

    `AuthPosture.trusted_proxy` reports whether the mode is *usable*, so it is
    false for a weak secret. Treating that as "nothing configured" would hand an
    anonymous admin stream to exactly the deployment that got its auth wrong —
    which `tests/api/test_api_proxy_scorecard.py` already pins over HTTP.
    """
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", "short")
    assert proxy_routes._ws_auth_required() is True


def test_websocket_runtime_role_rejects_inactive_scim_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    import agent_bom.api.auth as auth_module
    from agent_bom.api.auth import SCIMRoleResolution

    monkeypatch.setattr(
        auth_module,
        "resolve_scim_user_role",
        lambda *_args: SCIMRoleResolution(matched=True, active=False, user_id="user-1"),
    )
    assert proxy_routes._ws_runtime_role("tenant-a", "admin", "user@example.com") is None
