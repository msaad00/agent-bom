"""Tests for SSO provider brand detection surfaced at the /login sign-in preset."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api.oidc_browser import (
    configured_browser_sso_provider,
    sso_provider_from_issuer,
)
from agent_bom.api.server import app

_BROWSER_ENV = {
    "AGENT_BOM_OIDC_AUDIENCE": "agent-bom",
    "AGENT_BOM_OIDC_CLIENT_ID": "client-123",
    "AGENT_BOM_OIDC_REDIRECT_URI": "https://agent-bom.example/v1/auth/oidc/callback",
    "AGENT_BOM_OIDC_ALLOW_DEFAULT_TENANT": "1",
}


@pytest.mark.parametrize(
    ("issuer", "expected"),
    [
        ("https://acme.okta.com/oauth2/default", "okta"),
        ("https://acme.okta.com", "okta"),
        ("https://acme.oktapreview.com/oauth2/default", "okta"),
        ("https://acme.okta-emea.com", "okta"),
        ("https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0", "entra"),
        ("https://sts.windows.net/00000000-0000-0000-0000-000000000000/", "entra"),
        ("https://accounts.google.com", "google"),
        ("https://idp.your-org.example", "generic"),
        ("https://acme.snowflakecomputing.com", "generic"),
        ("", "generic"),
        ("not-a-url", "generic"),
    ],
)
def test_sso_provider_from_issuer(issuer: str, expected: str) -> None:
    assert sso_provider_from_issuer(issuer) == expected


def test_configured_browser_sso_provider_none_when_browser_oidc_disabled(monkeypatch) -> None:
    for key in _BROWSER_ENV:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.delenv("AGENT_BOM_OIDC_ISSUER", raising=False)
    assert configured_browser_sso_provider() is None


def test_configured_browser_sso_provider_detects_okta(monkeypatch) -> None:
    for key, value in _BROWSER_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("AGENT_BOM_OIDC_ISSUER", "https://acme.okta.com/oauth2/default")
    assert configured_browser_sso_provider() == "okta"


def test_configured_browser_sso_provider_generic_for_unknown_issuer(monkeypatch) -> None:
    for key, value in _BROWSER_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("AGENT_BOM_OIDC_ISSUER", "https://idp.your-org.example")
    assert configured_browser_sso_provider() == "generic"


def test_auth_me_omits_sso_provider_without_browser_oidc(monkeypatch) -> None:
    for key in _BROWSER_ENV:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.delenv("AGENT_BOM_OIDC_ISSUER", raising=False)
    client = TestClient(app)
    body = client.get("/v1/auth/me").json()
    assert body.get("sso_provider") is None


def test_auth_me_reports_sso_provider_when_browser_oidc_configured(monkeypatch) -> None:
    from agent_bom.api import server as api_server

    for key, value in _BROWSER_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("AGENT_BOM_OIDC_ISSUER", "https://acme.okta.com/oauth2/default")
    monkeypatch.setenv("AGENT_BOM_OIDC_JWKS_URI", "https://acme.okta.com/oauth2/default/v1/keys")
    try:
        api_server.configure_api_from_env()
        client = TestClient(app)
        body = client.get("/v1/auth/me").json()
        assert "oidc_browser" in body["configured_modes"]
        assert body["sso_provider"] == "okta"
    finally:
        for key in list(_BROWSER_ENV) + ["AGENT_BOM_OIDC_ISSUER", "AGENT_BOM_OIDC_JWKS_URI"]:
            monkeypatch.delenv(key, raising=False)
        api_server.configure_api_from_env()
