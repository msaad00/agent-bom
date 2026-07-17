"""Atlassian OAuth 2.0 (3LO) helper tests for the Jira ticketing connect flow.

Pure/unit level: the authorize URL builder and the token/cloud-id exchanges with
mocked HTTP. The live browser callback route is a deferred follow-up; these prove
the connect-once, no-typed-token building blocks.
"""

from __future__ import annotations

import httpx
import pytest

from agent_bom.ticketing import oauth


@pytest.fixture(autouse=True)
def _oauth_app(monkeypatch):
    monkeypatch.setenv(oauth.CLIENT_ID_ENV, "client-abc")
    monkeypatch.setenv(oauth.CLIENT_SECRET_ENV, "shh-secret")


def _factory(handler):
    def factory(timeout: float = 15.0):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    return factory


def test_oauth_configured():
    assert oauth.oauth_configured() is True


def test_build_authorize_url_carries_client_state_scope_redirect():
    url = oauth.build_authorize_url(redirect_uri="https://cp/cb", state="xyz")
    assert url.startswith(oauth.AUTHORIZE_URL)
    assert "client_id=client-abc" in url
    assert "state=xyz" in url
    assert "response_type=code" in url
    assert "offline_access" in url  # refresh token for background status sync


def test_build_authorize_url_requires_state():
    with pytest.raises(oauth.TicketingOAuthError):
        oauth.build_authorize_url(redirect_uri="https://cp/cb", state="")


@pytest.mark.asyncio
async def test_exchange_code_returns_token_bundle():
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == oauth.TOKEN_URL
        import json

        body = json.loads(request.content)
        assert body["grant_type"] == "authorization_code"
        assert body["client_secret"] == "shh-secret"
        return httpx.Response(200, json={"access_token": "at", "refresh_token": "rt", "expires_in": 3600})

    bundle = await oauth.exchange_code(code="code-1", redirect_uri="https://cp/cb", client_factory=_factory(handler))
    assert bundle["access_token"] == "at"
    assert bundle["refresh_token"] == "rt"


@pytest.mark.asyncio
async def test_exchange_code_rejects_missing_access_token():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token_type": "bearer"})

    with pytest.raises(oauth.TicketingOAuthError):
        await oauth.exchange_code(code="c", redirect_uri="https://cp/cb", client_factory=_factory(handler))


@pytest.mark.asyncio
async def test_resolve_accessible_resource_picks_cloud_id():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "api.atlassian.com"
        assert request.headers["Authorization"] == "Bearer at"
        return httpx.Response(
            200,
            json=[{"id": "cloud-1", "url": "https://acme.atlassian.net", "name": "acme"}],
        )

    resolved = await oauth.resolve_accessible_resource(access_token="at", client_factory=_factory(handler))
    assert resolved["cloud_id"] == "cloud-1"
    assert resolved["site_url"] == "https://acme.atlassian.net"
