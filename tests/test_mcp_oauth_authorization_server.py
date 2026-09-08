"""MCP bearer auth must not silently enable an unapproved token issuer."""

import asyncio
import time
from datetime import datetime, timedelta, timezone

import pytest
from starlette.testclient import TestClient

from agent_bom.api.oauth_as import OAuthAuthorizationServer
from agent_bom.mcp_server import _StaticBearerTokenVerifier, create_mcp_server


def _deadline():
    return (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()


@pytest.mark.parametrize("profile", ["scan", "full"])
def test_private_mcp_does_not_mount_or_advertise_an_authorization_server(monkeypatch, profile):
    monkeypatch.setenv("AGENT_BOM_MCP_PUBLIC_URL", "http://localhost:8000")
    monkeypatch.setenv("AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT", _deadline())
    server = create_mcp_server(host="127.0.0.1", port=8000, bearer_token="private-token", profile=profile)
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        for path in (
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-authorization-server",
            "/oauth/jwks.json",
            "/oauth/authorize",
        ):
            assert client.get(path).status_code == 404
        for path in ("/oauth/register", "/oauth/token"):
            assert client.post(path, json={}).status_code == 404


def test_static_verifier_rejects_previously_self_issued_tokens():
    issuer = OAuthAuthorizationServer(issuer="https://mcp.example/")
    token = issuer.signing_key.sign(
        {"iss": issuer.resolve_issuer(), "sub": "former-client", "scope": "read", "iat": int(time.time()), "exp": int(time.time()) + 3600}
    )
    verifier = _StaticBearerTokenVerifier("current-token", token_expires_at=_deadline())
    assert asyncio.run(verifier.verify_token(token)) is None
    assert asyncio.run(verifier.verify_token("current-token")) is not None


def test_replaced_static_credential_is_rejected():
    verifier = _StaticBearerTokenVerifier(
        "replacement-read", operator_token="replacement-operator", token_expires_at=_deadline(), operator_token_expires_at=_deadline()
    )
    assert asyncio.run(verifier.verify_token("former-read")) is None
    assert asyncio.run(verifier.verify_token("former-operator")) is None
