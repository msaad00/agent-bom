"""Snowflake OAuth authorization-code + PKCE sign-in tests.

Snowflake's OAuth server is non-standard (no OIDC discovery/JWKS/userinfo); the
endpoint shapes and token-response ``username`` identity are verified against
https://docs.snowflake.com/en/user-guide/oauth-custom.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from agent_bom.api.oidc import OIDCError
from agent_bom.api.oidc_browser import seal_pkce_cookie
from agent_bom.api.routes import enterprise
from agent_bom.api.shared_auth_state import reset_auth_state_for_tests
from agent_bom.api.snowflake_oauth import (
    SnowflakeOAuthConfig,
    build_authorize_url,
    snowflake_oauth_enabled_from_env,
    username_from_token_response,
)


@pytest.fixture(autouse=True)
def _reset_auth_state():
    reset_auth_state_for_tests()
    yield
    reset_auth_state_for_tests()


def _request(path: str = "/v1/auth/snowflake/login", cookies: dict[str, str] | None = None) -> Request:
    headers = []
    if cookies:
        cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
        headers.append((b"cookie", cookie_header.encode("latin-1")))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 12345),
        "server": ("test", 80),
    }
    return Request(scope)


def _configure(monkeypatch: pytest.MonkeyPatch, *, secret: str | None = "sf-secret") -> None:
    monkeypatch.setenv("AGENT_BOM_SNOWFLAKE_OAUTH_ACCOUNT_URL", "https://myorg-acct.snowflakecomputing.com")
    monkeypatch.setenv("AGENT_BOM_SNOWFLAKE_OAUTH_CLIENT_ID", "abom-dashboard")
    monkeypatch.setenv("AGENT_BOM_SNOWFLAKE_OAUTH_REDIRECT_URI", "https://cp.example/v1/auth/snowflake/callback")
    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "test-browser-session-signing-key")
    if secret is None:
        monkeypatch.delenv("AGENT_BOM_SNOWFLAKE_OAUTH_CLIENT_SECRET", raising=False)
    else:
        monkeypatch.setenv("AGENT_BOM_SNOWFLAKE_OAUTH_CLIENT_SECRET", secret)


# ── Config + endpoint shapes (verified against Snowflake docs) ──────────────


def test_config_enabled_and_endpoint_shapes(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch)
    cfg = SnowflakeOAuthConfig.from_env()
    assert cfg.enabled is True
    assert cfg.authorize_endpoint == "https://myorg-acct.snowflakecomputing.com/oauth/authorize"
    assert cfg.token_endpoint == "https://myorg-acct.snowflakecomputing.com/oauth/token-request"
    assert cfg.client_secret == "sf-secret"


def test_config_rejects_non_snowflake_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_SNOWFLAKE_OAUTH_ACCOUNT_URL", "https://evil.example.com")
    monkeypatch.setenv("AGENT_BOM_SNOWFLAKE_OAUTH_CLIENT_ID", "c")
    monkeypatch.setenv("AGENT_BOM_SNOWFLAKE_OAUTH_REDIRECT_URI", "https://cp.example/cb")
    with pytest.raises(OIDCError):
        SnowflakeOAuthConfig.from_env()


def test_config_rejects_http_account_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_SNOWFLAKE_OAUTH_ACCOUNT_URL", "http://myorg-acct.snowflakecomputing.com")
    monkeypatch.setenv("AGENT_BOM_SNOWFLAKE_OAUTH_CLIENT_ID", "c")
    monkeypatch.setenv("AGENT_BOM_SNOWFLAKE_OAUTH_REDIRECT_URI", "https://cp.example/cb")
    with pytest.raises(OIDCError):
        SnowflakeOAuthConfig.from_env()


def test_config_secret_file_missing_raises_oidcerror(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch, secret=None)
    monkeypatch.setenv("AGENT_BOM_SNOWFLAKE_OAUTH_CLIENT_SECRET_FILE", "/nonexistent/sf-secret")
    with pytest.raises(OIDCError):
        SnowflakeOAuthConfig.from_env()
    # enablement probe must not crash startup on a misconfigured secret file.
    assert snowflake_oauth_enabled_from_env() is False


def test_config_secret_from_file(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    _configure(monkeypatch, secret=None)
    secret_file = tmp_path / "sf-secret"
    secret_file.write_text("file-secret\n")
    monkeypatch.setenv("AGENT_BOM_SNOWFLAKE_OAUTH_CLIENT_SECRET_FILE", str(secret_file))
    cfg = SnowflakeOAuthConfig.from_env()
    assert cfg.client_secret == "file-secret"


def test_enabled_from_env_false_when_unconfigured(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "AGENT_BOM_SNOWFLAKE_OAUTH_ACCOUNT_URL",
        "AGENT_BOM_SNOWFLAKE_OAUTH_CLIENT_ID",
        "AGENT_BOM_SNOWFLAKE_OAUTH_REDIRECT_URI",
    ):
        monkeypatch.delenv(var, raising=False)
    assert snowflake_oauth_enabled_from_env() is False


def test_build_authorize_url_has_pkce_and_code_params(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_SNOWFLAKE_OAUTH_SCOPE", "refresh_token")
    cfg = SnowflakeOAuthConfig.from_env()
    with patch("agent_bom.api.snowflake_oauth.validate_url"):
        url = build_authorize_url(cfg, state="state-123", code_challenge="chal-abc")
    assert url.startswith("https://myorg-acct.snowflakecomputing.com/oauth/authorize?")
    assert "response_type=code" in url
    assert "client_id=abom-dashboard" in url
    assert "code_challenge=chal-abc" in url
    assert "code_challenge_method=S256" in url
    assert "state=state-123" in url
    assert "scope=refresh_token" in url


# ── Identity: username from token response, fail closed ─────────────────────


def test_username_from_token_response() -> None:
    assert username_from_token_response({"username": "ANALYST@CO", "access_token": "x"}) == "ANALYST@CO"


def test_username_from_token_response_missing_fails_closed() -> None:
    with pytest.raises(OIDCError):
        username_from_token_response({"access_token": "x"})


# ── Login route ─────────────────────────────────────────────────────────────


def test_login_requires_config(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "AGENT_BOM_SNOWFLAKE_OAUTH_ACCOUNT_URL",
        "AGENT_BOM_SNOWFLAKE_OAUTH_CLIENT_ID",
        "AGENT_BOM_SNOWFLAKE_OAUTH_REDIRECT_URI",
    ):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(enterprise.snowflake_oauth_login(_request()))
    assert exc.value.status_code == 503


def test_login_redirects_with_pkce(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch)
    with patch("agent_bom.api.snowflake_oauth.validate_url"):
        response = asyncio.run(enterprise.snowflake_oauth_login(_request()))
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith("https://myorg-acct.snowflakecomputing.com/oauth/authorize?")
    assert "code_challenge_method=S256" in location
    assert "response_type=code" in location
    cookies = response.headers.getlist("set-cookie")
    assert any("agent_bom_oidc_pkce=" in c for c in cookies)


# ── Callback ────────────────────────────────────────────────────────────────


def test_callback_rejects_bad_state(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch)
    sealed = seal_pkce_cookie(code_verifier="v", nonce="n")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            enterprise.snowflake_oauth_callback(
                _request(path="/v1/auth/snowflake/callback", cookies={"agent_bom_oidc_pkce": sealed}),
                code="abc",
                state="unknown",
            )
        )
    assert exc.value.status_code == 401


def test_callback_missing_pkce_cookie_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch)
    state = enterprise._new_snowflake_login_state()
    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            enterprise.snowflake_oauth_callback(
                _request(path="/v1/auth/snowflake/callback"),
                code="abc",
                state=state,
            )
        )
    assert exc.value.status_code == 401


def test_callback_missing_username_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch)
    state = enterprise._new_snowflake_login_state()
    sealed = seal_pkce_cookie(code_verifier="verifier-value", nonce="n")
    with patch(
        "agent_bom.api.snowflake_oauth.exchange_code_for_tokens",
        return_value={"access_token": "opaque"},  # no username
    ):
        with pytest.raises(HTTPException) as exc:
            asyncio.run(
                enterprise.snowflake_oauth_callback(
                    _request(path="/v1/auth/snowflake/callback", cookies={"agent_bom_oidc_pkce": sealed}),
                    code="auth-code",
                    state=state,
                )
            )
    assert exc.value.status_code == 401


def test_callback_happy_path_mints_session(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch)
    state = enterprise._new_snowflake_login_state()
    sealed = seal_pkce_cookie(code_verifier="verifier-value", nonce="n")
    with patch(
        "agent_bom.api.snowflake_oauth.exchange_code_for_tokens",
        return_value={"access_token": "opaque", "username": "ANALYST@CO"},
    ):
        response = asyncio.run(
            enterprise.snowflake_oauth_callback(
                _request(path="/v1/auth/snowflake/callback", cookies={"agent_bom_oidc_pkce": sealed}),
                code="auth-code",
                state=state,
            )
        )
    assert response.status_code == 302
    assert response.headers["location"] == "/"
    cookies = response.headers.getlist("set-cookie")
    assert any("agent_bom_session=" in c for c in cookies)
    assert any("agent_bom_csrf=" in c for c in cookies)
    assert any("agent_bom_oidc_pkce=" in c and "Max-Age=0" in c for c in cookies)


def test_callback_defaults_to_least_privilege_viewer(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch)
    state = enterprise._new_snowflake_login_state()
    sealed = seal_pkce_cookie(code_verifier="verifier-value", nonce="n")
    captured: dict[str, object] = {}

    def _capture(response, request, **kwargs):  # noqa: ANN001, ANN003
        captured.update(kwargs)

    with (
        patch(
            "agent_bom.api.snowflake_oauth.exchange_code_for_tokens",
            return_value={"access_token": "opaque", "username": "SOME_USER"},
        ),
        patch.object(enterprise, "_set_browser_session_cookie", _capture),
    ):
        asyncio.run(
            enterprise.snowflake_oauth_callback(
                _request(path="/v1/auth/snowflake/callback", cookies={"agent_bom_oidc_pkce": sealed}),
                code="auth-code",
                state=state,
            )
        )
    assert captured["role"] == "viewer"
    assert captured["auth_method"] == "snowflake_oauth"
    assert captured["subject"] == "SOME_USER"


# ── Auth-runtime introspection ──────────────────────────────────────────────


def test_auth_runtime_exposes_snowflake_oauth_mode() -> None:
    from agent_bom.api.middleware import configure_auth_runtime, get_auth_runtime_status

    configure_auth_runtime(
        api_key_configured=True,
        oidc_enabled=False,
        trusted_proxy_enabled=False,
        snowflake_oauth_enabled=True,
    )
    status = get_auth_runtime_status()
    assert "snowflake_oauth" in status["configured_modes"]
    assert status["recommended_ui_mode"] == "snowflake_oauth"
