"""Bearer-token reuse and fail-closed role precedence using signed JWTs."""

import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from agent_bom.api.oidc import OIDCConfig, OIDCError, claims_have_role_signal, claims_to_role, verify_oidc_token


@pytest.fixture
def signed_token(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr("agent_bom.api.oidc._validate_jwks_uri", lambda *a, **kw: "https://issuer.example/jwks")
    monkeypatch.setattr(
        jwt, "PyJWKClient", lambda *a, **kw: SimpleNamespace(get_signing_key_from_jwt=lambda token: SimpleNamespace(key=key.public_key()))
    )

    def make(issuer="https://issuer.example", **overrides):
        claims = dict(
            iss=issuer,
            aud="agent-bom",
            sub="user-a",
            iat=int(time.time()),
            exp=int(time.time()) + 600,
            jti="same-id",
            nonce="browser-nonce",
            agent_bom_role="viewer",
            tenant_id="tenant-a",
        )
        claims.update(overrides)
        return jwt.encode(claims, key, algorithm="RS256")

    return make


def test_valid_access_token_can_be_reused(signed_token):
    token = signed_token()
    cfg = OIDCConfig(issuer="https://issuer.example", audience="agent-bom", jwks_uri="https://issuer.example/jwks", require_role_claim=True)
    assert cfg.verify(token)[1] == "viewer"
    assert cfg.verify(token)[1] == "viewer"


@pytest.mark.parametrize("claim", ["viewer", "readonlyuser", "", None, ["admin"], 123])
def test_explicit_role_never_falls_back_to_admin_groups(claim):
    claims = {"custom_role": claim, "groups": ["admin"], "roles": ["admin"]}
    assert claims_to_role(claims, "custom_role") == "viewer"
    assert claims_have_role_signal(claims, "custom_role") is (claim == "viewer")


def test_invalid_explicit_role_fails_required_role_check(signed_token):
    cfg = OIDCConfig(issuer="https://issuer.example", audience="agent-bom", jwks_uri="https://issuer.example/jwks", require_role_claim=True)
    with pytest.raises(OIDCError, match="role claim"):
        cfg.verify(signed_token(agent_bom_role=["admin"], groups=["admin"]))


def test_access_token_reuse_still_checks_expiry(signed_token):
    with pytest.raises(OIDCError, match="JWT verification failed"):
        verify_oidc_token(signed_token(exp=int(time.time()) - 30), "https://issuer.example", "agent-bom", "https://issuer.example/jwks")


def test_id_token_exchange_rejects_replay_but_does_not_consume_another_issuer(signed_token):
    for issuer in ("https://issuer.example", "https://other.example"):
        token = signed_token(issuer=issuer)
        args = (token, issuer, "agent-bom", "https://issuer.example/jwks", "browser-nonce")
        assert verify_oidc_token(*args, single_use=True)["sub"] == "user-a"
        with pytest.raises(OIDCError, match="replay"):
            verify_oidc_token(*args, single_use=True)


def test_browser_verification_enables_single_use(monkeypatch):
    from agent_bom.api.oidc_browser import OIDCBrowserConfig, verify_browser_id_token

    seen = {}

    def verify(*args, **kwargs):
        seen.update(kwargs)
        return {"sub": "user-a"}

    monkeypatch.setattr("agent_bom.api.oidc_browser.verify_oidc_token", verify)
    cfg = OIDCBrowserConfig(
        oidc=OIDCConfig(issuer="https://issuer.example"), client_id="browser", redirect_uri="https://app.example/callback"
    )
    verify_browser_id_token(cfg, "token", nonce="browser-nonce")
    assert seen["single_use"] is True
