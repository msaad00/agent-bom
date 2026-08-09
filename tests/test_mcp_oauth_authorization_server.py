"""The MCP server must serve the authorization server it advertises.

`/.well-known/oauth-protected-resource` returned 200 naming an authorization
server whose `/.well-known/oauth-authorization-server`, `/authorize` and
`/token` all returned 404. FastMCP mounts `create_auth_routes` only when an
`auth_server_provider` is configured; agent-bom runs as a resource server
(static bearer + token verifier), so discovery resolved and the flow then died.

Smithery's scanner settles as AUTH_REQUIRED because of it, and the public
catalog advertises a fraction of the tools the server actually serves.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlparse

import pytest

from agent_bom.mcp_server_factory import build_mcp_authorization_server


def _pkce() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


@pytest.fixture()
def issuer() -> str:
    # Exactly what pydantic AnyHttpUrl renders for a bare host, trailing slash
    # included — the string the SDK publishes in authorization_servers.
    return "https://agent-bom.example.com/"


def test_metadata_issuer_matches_the_advertised_identifier_exactly(issuer: str) -> None:
    """RFC 8414/9728 compare issuer strings byte-for-byte.

    The SDK advertises us through pydantic ``AnyHttpUrl``, which renders a bare
    host WITH a trailing slash. The AS used to strip it, so the two documents
    disagreed by one character — enough for a strict client to reject the server
    after a successful authorize, and indistinguishable from a working flow on a
    lenient one.
    """
    from mcp.shared.auth import ProtectedResourceMetadata
    from pydantic import AnyHttpUrl, TypeAdapter

    url = TypeAdapter(AnyHttpUrl).validate_python("https://agent-bom.example.com")
    advertised = ProtectedResourceMetadata(resource=url, authorization_servers=[url], scopes_supported=[])
    advertised_issuer = str(advertised.authorization_servers[0])

    metadata = build_mcp_authorization_server(advertised_issuer).metadata()

    assert metadata["issuer"] == advertised_issuer


def test_endpoints_never_double_slash_on_a_slashed_issuer(issuer: str) -> None:
    """Echoing the slash must not leak into the endpoint URLs."""
    metadata = build_mcp_authorization_server(issuer).metadata()

    for key in ("authorization_endpoint", "token_endpoint", "registration_endpoint", "jwks_uri"):
        assert "//" not in metadata[key].removeprefix("https://"), (key, metadata[key])
        assert metadata[key].startswith("https://agent-bom.example.com/oauth/")


def test_a_token_from_the_full_pkce_flow_is_accepted_by_the_mcp_verifier(issuer: str) -> None:
    """The regression that matters: authorize succeeds, then every call 401s.

    A client completing the flow holds a token the static bearer verifier has
    never seen. Mounting the AS without teaching the verifier about its own
    tokens moves the failure one step later instead of fixing it.
    """
    import asyncio

    from agent_bom.mcp_server import _StaticBearerTokenVerifier

    server = build_mcp_authorization_server(issuer)
    verifier = _StaticBearerTokenVerifier("static-token")
    verifier.accept_tokens_issued_by(server)

    registered = server.register_client({"redirect_uris": ["https://client.example/cb"], "client_name": "probe"})
    code_verifier, code_challenge = _pkce()
    location = server.authorize(
        {
            "response_type": "code",
            "client_id": registered["client_id"],
            "redirect_uri": "https://client.example/cb",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": "xyz",
        }
    )
    code = parse_qs(urlparse(location).query)["code"][0]
    issued = server.token(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.example/cb",
            "client_id": registered["client_id"],
            "code_verifier": code_verifier,
        }
    )

    access = asyncio.run(verifier.verify_token(issued["access_token"]))

    assert access is not None, "a token this server itself issued was rejected"
    assert access.scopes == ["read"]


def test_the_static_bearer_token_still_works(issuer: str) -> None:
    """The AS must not displace the configured bearer token."""
    import asyncio

    from agent_bom.mcp_server import _StaticBearerTokenVerifier

    verifier = _StaticBearerTokenVerifier("static-token")
    verifier.accept_tokens_issued_by(build_mcp_authorization_server(issuer))

    assert asyncio.run(verifier.verify_token("static-token")) is not None
    assert asyncio.run(verifier.verify_token("wrong-token")) is None


def test_a_foreign_token_is_not_accepted(issuer: str) -> None:
    """Only tokens signed by THIS server's key may pass."""
    import asyncio

    from agent_bom.mcp_server import _StaticBearerTokenVerifier

    # A second AS with the same issuer but its own ephemeral signing key: the
    # token is well-formed and claims the right issuer, and must still fail.
    other = build_mcp_authorization_server(issuer)
    registered = other.register_client({"redirect_uris": ["https://client.example/cb"]})
    code_verifier, code_challenge = _pkce()
    location = other.authorize(
        {
            "response_type": "code",
            "client_id": registered["client_id"],
            "redirect_uri": "https://client.example/cb",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
    )
    foreign = other.token(
        {
            "grant_type": "authorization_code",
            "code": parse_qs(urlparse(location).query)["code"][0],
            "redirect_uri": "https://client.example/cb",
            "client_id": registered["client_id"],
            "code_verifier": code_verifier,
        }
    )["access_token"]

    verifier = _StaticBearerTokenVerifier("static-token")
    verifier.accept_tokens_issued_by(build_mcp_authorization_server(issuer))

    assert asyncio.run(verifier.verify_token(foreign)) is None, "a token signed by a different key was accepted"


def test_every_advertised_endpoint_is_actually_mounted(monkeypatch: pytest.MonkeyPatch) -> None:
    """The whole defect in one assertion: we advertised routes we did not serve.

    FastMCP only mounts `create_auth_routes` when an `auth_server_provider` is
    configured. agent-bom configures a token verifier instead, so the
    protected-resource document named an authorization server whose endpoints
    all returned 404 — discovery resolved, and the flow died one step later.
    """
    from agent_bom.mcp_server import _StaticBearerTokenVerifier
    from agent_bom.mcp_server_factory import create_fastmcp_server

    monkeypatch.setenv("AGENT_BOM_MCP_PUBLIC_URL", "https://agent-bom.example.com")

    mcp = create_fastmcp_server(
        host="0.0.0.0",
        port=8080,
        bearer_token="secret",
        version="0.99.0",
        token_verifier_factory=lambda token: _StaticBearerTokenVerifier(token),
    )
    mounted = {getattr(route, "path", "") for route in mcp.streamable_http_app().routes}

    assert "/.well-known/oauth-protected-resource" in mounted
    for path in (
        "/.well-known/oauth-authorization-server",
        "/oauth/authorize",
        "/oauth/token",
        "/oauth/register",
        "/oauth/jwks.json",
    ):
        assert path in mounted, f"{path} is advertised but not served"


def test_no_authorization_server_is_mounted_when_auth_is_off(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unauthenticated local server must not sprout an OAuth surface."""
    from agent_bom.mcp_server import _StaticBearerTokenVerifier
    from agent_bom.mcp_server_factory import create_fastmcp_server

    monkeypatch.delenv("AGENT_BOM_MCP_PUBLIC_URL", raising=False)

    mcp = create_fastmcp_server(
        host="127.0.0.1",
        port=8080,
        bearer_token=None,
        version="0.99.0",
        token_verifier_factory=lambda token: _StaticBearerTokenVerifier(token),
    )
    mounted = {getattr(route, "path", "") for route in mcp.streamable_http_app().routes}

    assert "/oauth/token" not in mounted
    assert "/.well-known/oauth-authorization-server" not in mounted


def test_a_malformed_signing_key_degrades_instead_of_crashing(monkeypatch: pytest.MonkeyPatch) -> None:
    """A configuration typo must not crash-loop the MCP server.

    Observed in production: the key was pasted into a hosting dashboard, which
    stored its newlines as literal `\\n`, and `load_pem_private_key` raised on
    boot. Before #12 nothing built a signing key at MCP startup, so this turned
    a bad secret into a total outage the moment the AS was mounted.

    Losing token persistence is recoverable. Losing the server is not.
    """
    from agent_bom.api.oauth_as import OAuthSigningKey

    monkeypatch.setenv("AGENT_BOM_OAUTH_AS_PRIVATE_KEY_PEM", "-----BEGIN PRIVATE KEY-----\\nnot-a-key\\n-----END PRIVATE KEY-----")

    key = OAuthSigningKey()

    assert key.ephemeral is True, "a rejected key must fall back, not be silently trusted"
    assert key.kid


def test_the_server_still_serves_the_as_with_a_malformed_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Degraded means degraded, not absent — discovery must still resolve."""
    from agent_bom.mcp_server import _StaticBearerTokenVerifier
    from agent_bom.mcp_server_factory import create_fastmcp_server

    monkeypatch.setenv("AGENT_BOM_OAUTH_AS_PRIVATE_KEY_PEM", "garbage")
    monkeypatch.setenv("AGENT_BOM_MCP_PUBLIC_URL", "https://agent-bom.example.com")

    mcp = create_fastmcp_server(
        host="0.0.0.0",
        port=8080,
        bearer_token="secret",
        version="0.99.0",
        token_verifier_factory=lambda token: _StaticBearerTokenVerifier(token),
    )
    mounted = {getattr(route, "path", "") for route in mcp.streamable_http_app().routes}

    assert "/oauth/token" in mounted
    assert "/.well-known/oauth-authorization-server" in mounted
