"""OIDC-invalid decision for the consolidated resolver chain (PR2 of #4274).

PR1 flagged that an OIDC decode/verify failure fell through to the API-key store
as ``Absent``. PR2 makes a deliberate, tested distinction inside
``_resolve_oidc_bearer``:

* A **JWT-shaped** bearer that fails OIDC verification (bad signature, wrong
  issuer/audience, expired, unconfigured issuer, replay, ...) is a
  *presented-but-invalid OIDC credential* -> ``Invalid`` (hard 401). It must
  NEVER be retried as an API key.
* A bearer that is **not a JWT at all** (a raw opaque API key sent as
  ``Authorization: Bearer``) is ``Absent`` for the OIDC resolver, so it can
  still authenticate downstream as an API key.
"""

import base64
import json

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from agent_bom.api.auth import KeyStore, Role, create_api_key_record, get_key_store, set_key_store
from agent_bom.api.middleware import APIKeyMiddleware
from agent_bom.api.oidc import OIDCConfig, OIDCError, token_is_jwt_shaped


def _jwt_shaped(claims: dict[str, object], *, alg: str = "RS256") -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": alg, "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"{header}.{payload}.c2lnbmF0dXJl"


# ── token_is_jwt_shaped: structural discriminator ────────────────────────────


def test_jwt_shaped_true_for_real_jwt() -> None:
    assert token_is_jwt_shaped(_jwt_shaped({"iss": "https://corp.okta.com", "sub": "u1"})) is True


def test_jwt_shaped_false_for_opaque_api_key() -> None:
    # Real agent-bom API keys are opaque url-safe tokens, never JWTs.
    assert token_is_jwt_shaped("abk_live_Zm9vYmFyYmF6cXV4c2VjcmV0dG9rZW4") is False


def test_jwt_shaped_false_for_two_part_token() -> None:
    assert token_is_jwt_shaped("header.payload") is False


def test_jwt_shaped_false_when_header_has_no_alg() -> None:
    header = base64.urlsafe_b64encode(json.dumps({"typ": "JWT"}).encode()).decode().rstrip("=")
    assert token_is_jwt_shaped(f"{header}.eyJ9.sig") is False


def test_jwt_shaped_false_when_header_is_not_base64_json() -> None:
    assert token_is_jwt_shaped("!!!.???.$$$") is False


def test_jwt_shaped_false_for_empty() -> None:
    assert token_is_jwt_shaped("") is False


# ── middleware: invalid OIDC -> 401, never retried as an API key ─────────────


def _app() -> Starlette:
    async def secure(request):
        return JSONResponse(
            {
                "role": request.state.api_key_role,
                "auth_method": request.state.auth_method,
                "name": request.state.api_key_name,
            }
        )

    app = Starlette(routes=[Route("/v1/test", secure)])
    app.add_middleware(APIKeyMiddleware, api_key=None)
    return app


def test_invalid_signature_oidc_bearer_is_401_and_not_tried_as_key(monkeypatch) -> None:
    """A JWT-shaped bearer that fails OIDC verification is a hard 401.

    Even with a populated key store, the invalid OIDC token must not be handed
    to ``store.verify`` — the presented OIDC credential is terminal.
    """
    # A real key store with one valid key configured (combined OIDC + key mode).
    store = KeyStore()
    store.add(create_api_key_record("valid-standalone-key", "svc:admin", Role.ADMIN))
    original = get_key_store()
    set_key_store(store)

    verify_calls: list[str] = []
    real_verify = store.verify

    def _spy_verify(raw_key: str):
        verify_calls.append(raw_key)
        return real_verify(raw_key)

    monkeypatch.setattr(store, "verify", _spy_verify)

    cfg = OIDCConfig(issuer="https://corp.okta.com", audience="agent-bom", allow_default_tenant=True)
    monkeypatch.setattr("agent_bom.api.oidc.OIDCConfig.from_env", lambda: cfg)
    monkeypatch.setattr(
        "agent_bom.api.oidc.verify_oidc_token",
        lambda *a, **k: (_ for _ in ()).throw(OIDCError("JWT verification failed: signature")),
    )

    bad_jwt = _jwt_shaped({"iss": "https://corp.okta.com", "sub": "attacker"})
    try:
        client = TestClient(_app())
        resp = client.get("/v1/test", headers={"Authorization": f"Bearer {bad_jwt}"})
        assert resp.status_code == 401
        # The invalid OIDC token must never have been offered to the key store.
        assert bad_jwt not in verify_calls
    finally:
        set_key_store(original)


def test_raw_api_key_sent_as_bearer_still_authenticates(monkeypatch) -> None:
    """A non-JWT bearer (a raw API key) stays Absent for OIDC and authenticates.

    OIDC is enabled, but the presented bearer is opaque (not JWT-shaped), so the
    OIDC resolver declines and the API-key resolver authenticates it.
    """
    store = KeyStore()
    store.add(create_api_key_record("abk_live_realopaquekey_1234567890", "svc:analyst", Role.ANALYST))
    original = get_key_store()
    set_key_store(store)

    cfg = OIDCConfig(issuer="https://corp.okta.com", audience="agent-bom", allow_default_tenant=True)
    monkeypatch.setattr("agent_bom.api.oidc.OIDCConfig.from_env", lambda: cfg)
    # An opaque (non-JWT) bearer cannot verify as OIDC. The resolver must decline
    # (Absent), not reject (Invalid), so the key resolver authenticates it.
    monkeypatch.setattr(
        "agent_bom.api.oidc.verify_oidc_token",
        lambda *a, **k: (_ for _ in ()).throw(OIDCError("Failed to resolve signing key")),
    )

    try:
        client = TestClient(_app())
        resp = client.get(
            "/v1/test",
            headers={"Authorization": "Bearer abk_live_realopaquekey_1234567890"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["auth_method"] == "api_key"
        assert body["role"] == "analyst"
    finally:
        set_key_store(original)


def test_valid_oidc_bearer_still_authenticates(monkeypatch) -> None:
    """Regression guard: the OIDC success path is unchanged."""
    original = get_key_store()
    set_key_store(KeyStore())

    cfg = OIDCConfig(issuer="https://corp.okta.com", audience="agent-bom", allow_default_tenant=True)
    monkeypatch.setattr("agent_bom.api.oidc.OIDCConfig.from_env", lambda: cfg)
    monkeypatch.setattr(
        "agent_bom.api.oidc.verify_oidc_token",
        lambda *a, **k: {"sub": "u1", "email": "alice@corp.com", "agent_bom_role": "analyst"},
    )
    good_jwt = _jwt_shaped({"iss": "https://corp.okta.com", "sub": "u1"})
    try:
        client = TestClient(_app())
        resp = client.get("/v1/test", headers={"Authorization": f"Bearer {good_jwt}"})
        assert resp.status_code == 200
        assert resp.json()["auth_method"] == "oidc"
    finally:
        set_key_store(original)
