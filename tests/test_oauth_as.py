"""OAuth 2.1 Authorization Server (broker AS) conformance tests.

Exercises the RFC 8414 metadata endpoint, RFC 7591 dynamic client
registration, the PKCE-required authorization-code token flow, the
client_credentials grant, JWKS publication, and token validation — both via the
:class:`OAuthAuthorizationServer` API and the mounted FastAPI router.
"""

from __future__ import annotations

import base64
import hashlib
import secrets

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from agent_bom.api.oauth_as import (
    OAuthAuthorizationServer,
    OAuthError,
    OAuthSigningKey,
    build_oauth_as_router,
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def _server() -> OAuthAuthorizationServer:
    # A stable key so issued tokens validate deterministically within a test.
    return OAuthAuthorizationServer(issuer="https://gw.example", signing_key=OAuthSigningKey())


def _client_app() -> TestClient:
    server = _server()
    app = FastAPI()
    app.include_router(build_oauth_as_router(server))
    client = TestClient(app)
    client.app.state.server = server  # type: ignore[attr-defined]
    return client


# ── RFC 8414 metadata ─────────────────────────────────────────────────────────


def test_metadata_advertises_required_oauth21_endpoints() -> None:
    server = _server()
    meta = server.metadata("https://gw.example")
    assert meta["issuer"] == "https://gw.example"
    assert meta["authorization_endpoint"] == "https://gw.example/oauth/authorize"
    assert meta["token_endpoint"] == "https://gw.example/oauth/token"
    assert meta["registration_endpoint"] == "https://gw.example/oauth/register"
    assert meta["jwks_uri"] == "https://gw.example/oauth/jwks.json"
    # OAuth 2.1 mandates PKCE S256 and forbids the implicit grant.
    assert meta["code_challenge_methods_supported"] == ["S256"]
    assert "token" not in meta["response_types_supported"]
    assert "authorization_code" in meta["grant_types_supported"]


def test_metadata_endpoint_served_over_http() -> None:
    client = _client_app()
    resp = client.get("/.well-known/oauth-authorization-server")
    assert resp.status_code == 200
    body = resp.json()
    assert body["code_challenge_methods_supported"] == ["S256"]
    jwks = client.get("/oauth/jwks.json").json()
    assert jwks["keys"] and jwks["keys"][0]["kty"] == "RSA"


# ── RFC 7591 dynamic client registration ──────────────────────────────────────


def test_dynamic_registration_public_client_pkce() -> None:
    server = _server()
    reg = server.register_client({"redirect_uris": ["https://app.example/cb"], "client_name": "mcp-client"})
    assert reg["client_id"].startswith("abc_")
    # Public client → no secret, PKCE only.
    assert "client_secret" not in reg
    assert reg["token_endpoint_auth_method"] == "none"
    assert reg["grant_types"] == ["authorization_code"]


def test_dynamic_registration_confidential_client_gets_secret() -> None:
    server = _server()
    reg = server.register_client(
        {
            "redirect_uris": ["https://app.example/cb"],
            "grant_types": ["authorization_code", "client_credentials"],
            "token_endpoint_auth_method": "client_secret_basic",
        }
    )
    assert reg["client_secret"]
    assert "client_credentials" in reg["grant_types"]


def test_registration_rejects_non_loopback_http_redirect() -> None:
    server = _server()
    try:
        server.register_client({"redirect_uris": ["http://evil.example/cb"]})
    except OAuthError as exc:
        assert exc.error == "invalid_redirect_uri"
    else:  # pragma: no cover
        raise AssertionError("expected OAuthError for plaintext non-loopback redirect")


def test_registration_endpoint_returns_201() -> None:
    client = _client_app()
    resp = client.post("/oauth/register", json={"redirect_uris": ["https://app.example/cb"]})
    assert resp.status_code == 201
    assert resp.json()["client_id"]


# ── PKCE authorization-code token flow ────────────────────────────────────────


def test_pkce_authorization_code_flow_issues_validatable_token() -> None:
    server = _server()
    reg = server.register_client({"redirect_uris": ["https://app.example/cb"], "scope": "tools:read tools:write"})
    client_id = reg["client_id"]
    verifier, challenge = _pkce_pair()

    location = server.authorize(
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "https://app.example/cb",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "tools:read",
            "state": "xyz",
        }
    )
    assert location.startswith("https://app.example/cb?code=")
    assert "state=xyz" in location
    code = location.split("code=")[1].split("&")[0]

    tokens = server.token(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://app.example/cb",
            "client_id": client_id,
            "code_verifier": verifier,
        }
    )
    assert tokens["token_type"] == "Bearer"
    assert tokens["scope"] == "tools:read"
    claims = server.validate_token(tokens["access_token"])
    assert claims is not None
    assert claims["sub"] == client_id
    assert claims["scope"] == "tools:read"


def test_authorize_requires_pkce_s256() -> None:
    server = _server()
    reg = server.register_client({"redirect_uris": ["https://app.example/cb"]})
    # plain method is forbidden in OAuth 2.1 → redirect error.
    exc_location = None
    try:
        server.authorize(
            {
                "response_type": "code",
                "client_id": reg["client_id"],
                "redirect_uri": "https://app.example/cb",
                "code_challenge": "abc",
                "code_challenge_method": "plain",
            }
        )
    except OAuthError as exc:
        exc_location = exc.redirect_location
    assert exc_location is not None and "error=invalid_request" in exc_location


def test_token_rejects_wrong_pkce_verifier() -> None:
    server = _server()
    reg = server.register_client({"redirect_uris": ["https://app.example/cb"]})
    _verifier, challenge = _pkce_pair()
    location = server.authorize(
        {
            "response_type": "code",
            "client_id": reg["client_id"],
            "redirect_uri": "https://app.example/cb",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    code = location.split("code=")[1].split("&")[0]
    try:
        server.token(
            {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": reg["client_id"],
                "code_verifier": "the-wrong-verifier",
            }
        )
    except OAuthError as exc:
        assert exc.error == "invalid_grant"
    else:  # pragma: no cover
        raise AssertionError("expected PKCE verification failure")


def test_authorization_code_is_single_use() -> None:
    server = _server()
    reg = server.register_client({"redirect_uris": ["https://app.example/cb"]})
    verifier, challenge = _pkce_pair()
    location = server.authorize(
        {
            "response_type": "code",
            "client_id": reg["client_id"],
            "redirect_uri": "https://app.example/cb",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    code = location.split("code=")[1].split("&")[0]
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": reg["client_id"],
        "code_verifier": verifier,
    }
    assert server.token(dict(form))["access_token"]
    try:
        server.token(dict(form))
    except OAuthError as exc:
        assert exc.error == "invalid_grant"
    else:  # pragma: no cover
        raise AssertionError("replayed authorization code must be rejected")


def test_token_endpoint_full_http_flow() -> None:
    client = _client_app()
    reg = client.post("/oauth/register", json={"redirect_uris": ["https://app.example/cb"]}).json()
    verifier, challenge = _pkce_pair()
    authorize = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": reg["client_id"],
            "redirect_uri": "https://app.example/cb",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert authorize.status_code == 302
    code = authorize.headers["location"].split("code=")[1].split("&")[0]
    token_resp = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": reg["client_id"],
            "code_verifier": verifier,
        },
    )
    assert token_resp.status_code == 200
    assert token_resp.headers["cache-control"] == "no-store"
    assert token_resp.json()["access_token"]


# ── client_credentials grant ──────────────────────────────────────────────────


def test_client_credentials_grant_requires_secret() -> None:
    server = _server()
    reg = server.register_client(
        {
            "redirect_uris": ["https://app.example/cb"],
            "grant_types": ["authorization_code", "client_credentials"],
            "token_endpoint_auth_method": "client_secret_post",
            "scope": "tools:read",
        }
    )
    tokens = server.token(
        {
            "grant_type": "client_credentials",
            "client_id": reg["client_id"],
            "client_secret": reg["client_secret"],
        }
    )
    claims = server.validate_token(tokens["access_token"])
    assert claims is not None and claims["scope"] == "tools:read"

    # Wrong secret fails closed.
    try:
        server.token(
            {
                "grant_type": "client_credentials",
                "client_id": reg["client_id"],
                "client_secret": "nope",
            }
        )
    except OAuthError as exc:
        assert exc.error == "invalid_client"
    else:  # pragma: no cover
        raise AssertionError("client_credentials must reject a wrong secret")


def test_requested_scope_outside_client_grant_rejected() -> None:
    server = _server()
    reg = server.register_client({"redirect_uris": ["https://app.example/cb"], "scope": "tools:read"})
    _verifier, challenge = _pkce_pair()
    try:
        server.authorize(
            {
                "response_type": "code",
                "client_id": reg["client_id"],
                "redirect_uri": "https://app.example/cb",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "scope": "tools:admin",
            }
        )
    except OAuthError as exc:
        assert exc.redirect_location and "error=invalid_scope" in exc.redirect_location
    else:  # pragma: no cover
        raise AssertionError("scope outside the client grant must be rejected")


def test_validate_token_rejects_foreign_token() -> None:
    server_a = _server()
    server_b = _server()
    reg = server_a.register_client(
        {
            "redirect_uris": ["https://app.example/cb"],
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "client_secret_post",
        }
    )
    tokens = server_a.token(
        {"grant_type": "client_credentials", "client_id": reg["client_id"], "client_secret": reg["client_secret"]}
    )
    # A token signed by server_a does not validate against server_b's key.
    assert server_b.validate_token(tokens["access_token"]) is None
    assert server_a.validate_token(tokens["access_token"]) is not None


# ── Signing-key source (env / mounted-file resolution) ────────────────────────

_OAUTH_PEM_ENV = "AGENT_BOM_OAUTH_AS_PRIVATE_KEY_PEM"


def _rsa_private_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def test_signing_key_ephemeral_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_OAUTH_PEM_ENV, raising=False)
    monkeypatch.delenv(f"{_OAUTH_PEM_ENV}_FILE", raising=False)
    key = OAuthSigningKey()
    assert key.ephemeral is True


def test_signing_key_loads_from_inline_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(f"{_OAUTH_PEM_ENV}_FILE", raising=False)
    pem = _rsa_private_pem()
    monkeypatch.setenv(_OAUTH_PEM_ENV, pem)
    key = OAuthSigningKey()
    assert key.ephemeral is False


def test_signing_key_loads_from_mounted_file(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    # File-first: `*_FILE` points at a mounted secret; the inline var stays unset.
    monkeypatch.delenv(_OAUTH_PEM_ENV, raising=False)
    pem = _rsa_private_pem()
    pem_file = tmp_path / "oauth_as.pem"
    pem_file.write_text(pem)
    monkeypatch.setenv(f"{_OAUTH_PEM_ENV}_FILE", str(pem_file))
    key = OAuthSigningKey()
    assert key.ephemeral is False


def test_signing_key_file_takes_precedence_over_inline_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    file_pem = _rsa_private_pem()
    inline_pem = _rsa_private_pem()
    pem_file = tmp_path / "oauth_as.pem"
    pem_file.write_text(file_pem)
    monkeypatch.setenv(_OAUTH_PEM_ENV, inline_pem)
    monkeypatch.setenv(f"{_OAUTH_PEM_ENV}_FILE", str(pem_file))
    # The mounted file wins: the loaded key matches the FILE kid, not the inline one.
    file_kid = OAuthSigningKey(private_pem=file_pem).kid
    resolved_kid = OAuthSigningKey().kid
    assert resolved_kid == file_kid


# ── F1: issuer must not be Host-header-influenced when unconfigured ────────────


def test_issuer_derivation_disabled_fails_closed_and_ignores_host() -> None:
    # A server that does not allow host-derived issuers (non-loopback listener
    # without an explicit issuer) must refuse to derive `iss` from the client
    # base URL rather than TOFU-cache an attacker-controlled Host.
    server = OAuthAuthorizationServer(issuer=None, allow_host_derived_issuer=False)
    try:
        server.resolve_issuer("https://evil.example")
        raise AssertionError("expected OAuthError when issuer derivation is disabled")
    except OAuthError as exc:
        assert exc.status == 500
        assert exc.error == "server_error"
    # A second attempt with a different Host is likewise refused — nothing was
    # cached from the first (spoofed) request.
    try:
        server.resolve_issuer("https://also-evil.example")
        raise AssertionError("expected OAuthError on repeat")
    except OAuthError:
        pass


def test_metadata_endpoint_fails_closed_when_issuer_unconfigured_non_loopback() -> None:
    server = OAuthAuthorizationServer(issuer=None, allow_host_derived_issuer=False)
    app = FastAPI()
    app.include_router(build_oauth_as_router(server))
    client = TestClient(app)
    resp = client.get(
        "/.well-known/oauth-authorization-server",
        headers={"Host": "evil.example"},
    )
    assert resp.status_code == 500
    assert resp.json()["error"] == "server_error"


def test_explicit_issuer_is_never_overridden_by_host() -> None:
    server = OAuthAuthorizationServer(issuer="https://gw.example", allow_host_derived_issuer=False)
    assert server.resolve_issuer("https://evil.example") == "https://gw.example"
    assert server.metadata("https://evil.example")["issuer"] == "https://gw.example"


def test_loopback_dev_still_derives_issuer_from_request() -> None:
    # Back-compat: loopback dev keeps deriving (and TOFU-caching) the issuer.
    server = OAuthAuthorizationServer(issuer=None, allow_host_derived_issuer=True)
    assert server.resolve_issuer("http://127.0.0.1:8080") == "http://127.0.0.1:8080"
    # First observed value is stable even if a later request presents another host.
    assert server.resolve_issuer("http://other.host") == "http://127.0.0.1:8080"
