"""External MCP access tokens cannot widen the server's authority."""

import json
import time
from unittest.mock import Mock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient

from agent_bom.mcp_tools.oauth import OAuthConfig, OAuthTokenVerifier

ISSUER = "https://identity.example/realms/agent-bom"
AUDIENCE = "https://mcp.example/mcp"


@pytest.fixture
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def verifier(signing_key):
    verifier = OAuthTokenVerifier(OAuthConfig(ISSUER, AUDIENCE, ISSUER + "/certs", frozenset({"approved-user"})))
    verifier.keys = Mock()
    verifier.keys.get_signing_key_from_jwt.return_value.key = signing_key.public_key()
    return verifier


def token(key, **changes):
    now = int(time.time())
    claims = dict(iss=ISSUER, aud=AUDIENCE, sub="approved-user", iat=now, exp=now + 600, scope="read")
    claims.update(changes)
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "first"})


@pytest.mark.asyncio
async def test_approved_token_is_read_only(verifier, signing_key):
    result = await verifier.verify_token(token(signing_key, scope="read admin scan:write", roles=["admin"]))
    assert result is not None
    assert result.scopes == ["read"]
    assert result.client_id == "oauth:approved-user"
    assert result.resource == AUDIENCE


@pytest.mark.parametrize(
    "changes",
    [
        {"iss": "https://other.example"},
        {"aud": "other-api"},
        {"sub": "unapproved"},
        {"scope": "admin"},
        {"scope": ["read"]},
        {"exp": 1},
        lambda: {"exp": int(time.time()) + 7200},
        lambda: {"iat": int(time.time()) + 30},
        {"iat": True},
        {"sub": None},
    ],
)
@pytest.mark.asyncio
async def test_rejects_invalid_claims(verifier, signing_key, changes):
    # Resolve relative timestamps at execution, after potentially slow collection.
    changes = changes() if callable(changes) else changes
    assert await verifier.verify_token(token(signing_key, **changes)) is None


@pytest.mark.asyncio
async def test_rejects_invalid_signature_and_provider_outage(verifier):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert await verifier.verify_token(token(other)) is None
    verifier.keys.get_signing_key_from_jwt.side_effect = OSError("provider unavailable")
    assert await verifier.verify_token(token(other)) is None


@pytest.fixture
def oauth_env(monkeypatch):
    for key, value in {"ISSUER": ISSUER, "AUDIENCE": AUDIENCE, "JWKS_URI": ISSUER + "/certs", "SUBJECTS": "approved-user"}.items():
        monkeypatch.setenv("AGENT_BOM_MCP_OAUTH_" + key, value)
    monkeypatch.setenv("AGENT_BOM_MCP_PUBLIC_URL", "https://mcp.example")
    monkeypatch.delenv("AGENT_BOM_MCP_OPERATOR_TOKEN", raising=False)


def test_incomplete_or_wildcard_configuration_fails(oauth_env, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_MCP_OAUTH_SUBJECTS", "*")
    with pytest.raises(ValueError, match="explicit approved"):
        OAuthConfig.from_env()
    monkeypatch.delenv("AGENT_BOM_MCP_OAUTH_SUBJECTS")
    with pytest.raises(ValueError, match="requires"):
        OAuthConfig.from_env()


def test_metadata_and_actual_transport_authorization(oauth_env, monkeypatch, verifier, signing_key):
    from agent_bom.mcp_server_factory import create_fastmcp_server

    monkeypatch.setattr("agent_bom.mcp_tools.oauth.OAuthTokenVerifier", lambda config: verifier)
    server = create_fastmcp_server(
        host="0.0.0.0", port=8000, bearer_token=None, version="test", token_verifier_factory=Mock(), oauth_enabled=True
    )
    with TestClient(server.streamable_http_app(), base_url="https://mcp.example") as client:
        metadata = client.get("/.well-known/oauth-protected-resource/mcp")
        assert metadata.status_code == 200
        assert metadata.json()["authorization_servers"] == [ISSUER]
        assert metadata.json()["resource"] == AUDIENCE
        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}},
        }
        headers = {"Accept": "application/json, text/event-stream"}
        assert client.post("/mcp", json=message, headers=headers).status_code == 401
        headers["Authorization"] = "Bearer " + token(signing_key)
        initialized = client.post("/mcp", json=message, headers=headers)
        assert initialized.status_code == 200
        headers["mcp-session-id"] = initialized.headers["mcp-session-id"]
        headers["mcp-protocol-version"] = "2025-11-25"
        client.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=headers)
        listing = client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, headers=headers)
        assert listing.status_code == 200
        assert '"tools"' in listing.text
        assert client.post("/oauth/register", json={}).status_code == 404


def test_oauth_configuration_does_not_activate_stdio_or_other_servers(oauth_env):
    from agent_bom.mcp_server_factory import create_fastmcp_server

    server = create_fastmcp_server(host="127.0.0.1", port=8000, bearer_token=None, version="test", token_verifier_factory=Mock())
    assert server.settings.auth is None


@pytest.mark.asyncio
async def test_jwks_rotates_and_new_access_token_works(monkeypatch, signing_key):
    from jwt import PyJWKClient

    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    keys = [
        {**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(k.public_key())), "kid": kid}
        for k, kid in [(signing_key, "first"), (other, "second")]
    ]
    verifier = OAuthTokenVerifier(OAuthConfig(ISSUER, AUDIENCE, ISSUER + "/certs", frozenset({"approved-user"})))
    responses = iter([{"keys": [keys[0]]}, {"keys": keys}])

    def fetch():
        data = next(responses)
        verifier.keys.jwk_set_cache.put(data)
        return data

    monkeypatch.setattr(verifier.keys, "fetch_data", fetch)
    assert isinstance(verifier.keys, PyJWKClient)
    assert await verifier.verify_token(token(signing_key)) is not None
    now = int(time.time())
    renewed = jwt.encode(
        dict(iss=ISSUER, aud=AUDIENCE, sub="approved-user", iat=now, exp=now + 600, scope="read"),
        other,
        algorithm="RS256",
        headers={"kid": "second"},
    )
    assert await verifier.verify_token(renewed) is not None


@pytest.mark.asyncio
async def test_expired_credential_does_not_require_server_restart(verifier, signing_key):
    now = int(time.time())
    assert await verifier.verify_token(token(signing_key, iat=now - 600, exp=now - 1)) is None
    assert await verifier.verify_token(token(signing_key)) is not None


def test_external_and_static_modes_cannot_be_combined(oauth_env):
    from agent_bom.mcp_server_factory import create_fastmcp_server

    with pytest.raises(ValueError, match="not both"):
        create_fastmcp_server(
            host="0.0.0.0",
            port=8000,
            bearer_token="existing",
            version="test",
            token_verifier_factory=Mock(),
            oauth_enabled=True,
        )
