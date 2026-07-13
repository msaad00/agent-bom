"""OIDC browser auth-code + PKCE foundation tests."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from agent_bom.api.oidc_browser import (
    OIDCBrowserConfig,
    open_pkce_cookie,
    pkce_challenge_s256,
    pkce_verifier,
    seal_pkce_cookie,
    subject_from_claims,
)
from agent_bom.api.routes import enterprise
from agent_bom.api.shared_auth_state import reset_auth_state_for_tests


@pytest.fixture(autouse=True)
def _reset_auth_state():
    reset_auth_state_for_tests()
    yield
    reset_auth_state_for_tests()


def _request(path: str = "/v1/auth/oidc/login", cookies: dict[str, str] | None = None) -> Request:
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


def test_pkce_s256_round_trip() -> None:
    verifier = pkce_verifier()
    challenge = pkce_challenge_s256(verifier)
    assert len(challenge) >= 43
    sealed = seal_pkce_cookie(code_verifier=verifier, nonce="n1")
    opened_v, opened_n, return_to = open_pkce_cookie(sealed)
    assert opened_v == verifier
    assert opened_n == "n1"
    # return_to is no longer carried in the sealed cookie (CodeQL hardening);
    # open_pkce_cookie defaults it to "/".
    assert return_to == "/"


def test_oidc_browser_login_requires_client_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.delenv("AGENT_BOM_OIDC_CLIENT_ID", raising=False)
    monkeypatch.delenv("AGENT_BOM_OIDC_REDIRECT_URI", raising=False)
    import asyncio

    with pytest.raises(HTTPException) as exc:
        asyncio.run(enterprise.oidc_browser_login(_request()))
    assert exc.value.status_code == 503


def test_oidc_browser_login_redirects_with_pkce(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("AGENT_BOM_OIDC_CLIENT_ID", "dashboard-client")
    monkeypatch.setenv("AGENT_BOM_OIDC_REDIRECT_URI", "https://cp.example/v1/auth/oidc/callback")
    monkeypatch.setenv("AGENT_BOM_OIDC_ALLOW_DEFAULT_TENANT", "1")

    with (
        patch(
            "agent_bom.api.oidc_browser.discover_oidc",
            return_value={
                "authorization_endpoint": "https://issuer.example/authorize",
                "jwks_uri": "https://issuer.example/jwks",
            },
        ),
        patch("agent_bom.api.oidc_browser.validate_url"),
    ):
        import asyncio

        response = asyncio.run(enterprise.oidc_browser_login(_request(), return_to="/jobs"))
    assert response.status_code == 302
    location = response.headers["location"]
    assert "code_challenge_method=S256" in location
    assert "client_id=dashboard-client" in location
    assert "response_type=code" in location
    cookies = response.headers.getlist("set-cookie")
    assert any("agent_bom_oidc_pkce=" in c for c in cookies)
    assert not any("agent_bom_oidc_return=" in c for c in cookies)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/jobs?tab=open#recent", "/jobs?tab=open#recent"),
        ("https://evil.example/", "/"),
        ("//evil.example/", "/"),
        ("\\\\evil.example\\share", "/"),
    ],
)
def test_safe_post_login_path_rejects_remote_targets(raw: str, expected: str) -> None:
    assert enterprise._safe_post_login_path(raw) == expected


def test_oidc_callback_rejects_bad_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("AGENT_BOM_OIDC_CLIENT_ID", "dashboard-client")
    monkeypatch.setenv("AGENT_BOM_OIDC_REDIRECT_URI", "https://cp.example/v1/auth/oidc/callback")
    sealed = seal_pkce_cookie(code_verifier="v", nonce="n")
    import asyncio

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            enterprise.oidc_browser_callback(
                _request(path="/v1/auth/oidc/callback", cookies={"agent_bom_oidc_pkce": sealed}),
                code="abc",
                state="unknown",
            )
        )
    assert exc.value.status_code == 401


def test_subject_from_claims_prefers_email() -> None:
    assert subject_from_claims({"email": "a@b.co", "sub": "x"}) == "a@b.co"


def test_oidc_browser_config_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("AGENT_BOM_OIDC_CLIENT_ID", "c")
    monkeypatch.setenv("AGENT_BOM_OIDC_REDIRECT_URI", "https://cp.example/v1/auth/oidc/callback")
    monkeypatch.setenv("AGENT_BOM_OIDC_ALLOW_DEFAULT_TENANT", "1")
    cfg = OIDCBrowserConfig.from_env()
    assert cfg.enabled is True


def test_auth_runtime_exposes_oidc_browser_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api.middleware import configure_auth_runtime, get_auth_runtime_status

    configure_auth_runtime(
        api_key_configured=True,
        oidc_enabled=True,
        oidc_browser_enabled=True,
        trusted_proxy_enabled=False,
    )
    status = get_auth_runtime_status()
    assert "oidc_browser" in status["configured_modes"]
    assert "oidc_bearer" in status["configured_modes"]
    assert status["recommended_ui_mode"] == "oidc_browser"

    configure_auth_runtime(
        api_key_configured=True,
        oidc_enabled=True,
        oidc_browser_enabled=True,
        trusted_proxy_enabled=True,
    )
    status = get_auth_runtime_status()
    assert status["recommended_ui_mode"] == "reverse_proxy_oidc"


def test_oidc_callback_happy_path_mints_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("AGENT_BOM_OIDC_CLIENT_ID", "dashboard-client")
    monkeypatch.setenv("AGENT_BOM_OIDC_REDIRECT_URI", "https://cp.example/v1/auth/oidc/callback")
    monkeypatch.setenv("AGENT_BOM_OIDC_ALLOW_DEFAULT_TENANT", "1")
    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "test-browser-session-signing-key")

    state = enterprise._new_oidc_login_state()
    sealed = seal_pkce_cookie(code_verifier="verifier-value", nonce="nonce-value")
    import asyncio

    with (
        patch(
            "agent_bom.api.oidc_browser.exchange_code_for_tokens",
            return_value={"id_token": "fake.jwt.token"},
        ),
        patch(
            "agent_bom.api.oidc_browser.verify_browser_id_token",
            return_value={
                "email": "analyst@example.com",
                "sub": "oidc-sub-1",
                "agent_bom_role": "analyst",
            },
        ),
    ):
        response = asyncio.run(
            enterprise.oidc_browser_callback(
                _request(path="/v1/auth/oidc/callback", cookies={"agent_bom_oidc_pkce": sealed}),
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
