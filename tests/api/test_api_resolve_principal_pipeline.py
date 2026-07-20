"""Pipeline invariants for the consolidated ``resolve_principal`` resolver chain.

These assert the structural contract of the single authentication decision point
(``APIKeyMiddleware.resolve_principal`` / ``run_resolver_chain``):

* ``Absent`` chains to the next resolver.
* ``Invalid`` is terminal — a presented-but-invalid credential is a hard 401 and
  never falls through to a later resolver or the anonymous fallback.
* the anonymous fallback only activates when explicitly opted in.
* a present-but-invalid credential resolves to 401, never a downgrade to the
  anonymous VIEWER identity.
"""

import asyncio

from starlette.responses import JSONResponse
from starlette.testclient import TestClient

from agent_bom.api.middleware import Absent, Invalid, Resolved, run_resolver_chain
from agent_bom.api.server import app, configure_api

_CREDENTIAL_ENV = (
    "AGENT_BOM_API_KEY",
    "AGENT_BOM_API_KEYS",
    "AGENT_BOM_OIDC_ISSUER",
    "AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON",
    "AGENT_BOM_TRUST_PROXY_AUTH",
    "AGENT_BOM_SCIM_BEARER_TOKEN",
)

# A configured static key puts the middleware in "combined" mode: valid
# credentials authenticate to their role, credential-less callers fall through to
# the anonymous NO_AUTH_ROLE (clamped to VIEWER), and a presented-but-invalid
# credential is still rejected. The pure no-auth mode (nothing configured + opt-in)
# removes the auth middleware entirely, so it cannot exercise these invariants.
_STATIC_KEY = "static-admin-key-for-pipeline-invariants"


def _clear_credential_sources(monkeypatch) -> None:
    for name in _CREDENTIAL_ENV:
        monkeypatch.delenv(name, raising=False)


# --- run_resolver_chain: control-flow invariants (pure, no HTTP) -----------------


def test_absent_chains_to_the_next_resolver() -> None:
    called: list[str] = []

    async def first() -> Absent:
        called.append("first")
        return Absent()

    async def second() -> Resolved:
        called.append("second")
        return Resolved(JSONResponse(status_code=200, content={"who": "second"}))

    async def third() -> Resolved:  # pragma: no cover - must never run
        called.append("third")
        return Resolved(JSONResponse(status_code=200, content={"who": "third"}))

    response = asyncio.run(run_resolver_chain([first, second, third]))

    assert response is not None
    assert response.status_code == 200
    # Absent chained to ``second``; the first non-Absent result won and ``third``
    # was never consulted.
    assert called == ["first", "second"]


def test_invalid_is_terminal_and_never_falls_through() -> None:
    called: list[str] = []

    async def absent_resolver() -> Absent:
        called.append("absent")
        return Absent()

    async def rejecting_resolver() -> Invalid:
        called.append("invalid")
        return Invalid(JSONResponse(status_code=401, content={"detail": "rejected"}))

    async def anonymous_resolver() -> Resolved:  # pragma: no cover - must never run
        called.append("anonymous")
        return Resolved(JSONResponse(status_code=200, content={"detail": "anonymous"}))

    response = asyncio.run(run_resolver_chain([absent_resolver, rejecting_resolver, anonymous_resolver]))

    assert response is not None
    assert response.status_code == 401
    # Invalid stopped the chain: the anonymous fallback after it never ran.
    assert called == ["absent", "invalid"]
    assert "anonymous" not in called


def test_resolved_short_circuits_immediately() -> None:
    called: list[str] = []

    async def resolved_resolver() -> Resolved:
        called.append("resolved")
        return Resolved(JSONResponse(status_code=200, content={"who": "resolved"}))

    async def later() -> Absent:  # pragma: no cover - must never run
        called.append("later")
        return Absent()

    response = asyncio.run(run_resolver_chain([resolved_resolver, later]))

    assert response is not None
    assert response.status_code == 200
    assert called == ["resolved"]


def test_all_absent_returns_none() -> None:
    async def absent_resolver() -> Absent:
        return Absent()

    assert asyncio.run(run_resolver_chain([absent_resolver, absent_resolver])) is None


# --- middleware-level invariants (through the real app) --------------------------


def test_anonymous_served_only_when_opted_in(monkeypatch) -> None:
    _clear_credential_sources(monkeypatch)

    # Opted in (combined mode): a credential-less request is served as the
    # anonymous NO_AUTH_ROLE, clamped to VIEWER because a credential source is
    # configured — so a viewer route is 200 but an admin route is 403 (not 200),
    # proving the anonymous identity is not elevated.
    monkeypatch.setenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "1")
    configure_api(api_key=_STATIC_KEY, allow_unauthenticated=True)
    try:
        client = TestClient(app)
        assert client.get("/v1/auth/me").status_code == 200
        assert client.get("/v1/auth/policy").status_code == 403
    finally:
        configure_api(api_key=None)

    # Opted out: the same credential-less request fails closed with 401.
    monkeypatch.delenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", raising=False)
    configure_api(api_key=_STATIC_KEY, allow_unauthenticated=False)
    try:
        assert TestClient(app).get("/v1/auth/me").status_code == 401
    finally:
        configure_api(api_key=None)


def test_present_but_invalid_credential_is_401_not_anonymous_viewer(monkeypatch) -> None:
    """Anonymous opt-in must not downgrade a rejected credential to VIEWER."""
    _clear_credential_sources(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "1")
    configure_api(api_key=_STATIC_KEY, allow_unauthenticated=True)
    try:
        client = TestClient(app)

        # Baseline: no credential at all -> anonymous VIEWER is served; the valid
        # static key authenticates to its (admin) role.
        assert client.get("/v1/auth/me").status_code == 200
        assert client.get("/v1/auth/me", headers={"Authorization": f"Bearer {_STATIC_KEY}"}).status_code == 200

        # A credential IS presented but cannot resolve to a valid identity. Each
        # must be a hard 401 — never a silent downgrade to the anonymous VIEWER.
        # (a) Non-Bearer Authorization scheme: raw key stays empty, but a
        #     credential is present, so ``_credential_presented`` blocks anonymous.
        assert client.get("/v1/auth/me", headers={"Authorization": "Basic Zm9vOmJhcg=="}).status_code == 401
        # (b) Bearer token that matches no configured credential source.
        assert client.get("/v1/auth/me", headers={"Authorization": "Bearer not-a-real-token"}).status_code == 401
        # (c) X-API-Key that matches no configured key.
        assert client.get("/v1/auth/me", headers={"X-API-Key": "not-a-real-key"}).status_code == 401
    finally:
        configure_api(api_key=None)
