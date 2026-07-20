"""Auth posture contract-test matrix (PR3 of #4274).

This is the consolidated 401/403/200 grid for the single ``resolve_principal``
pipeline (PR1) and the derived ``AuthPosture`` single-source-of-truth (PR2). It
exists to convert "audited fail-closed" into "enforced fail-closed every commit":
if a future change regresses the ordered resolver chain or the posture
derivation, a cell in this table goes red.

It exercises the REAL middleware end to end through ``TestClient`` — the resolver
is never mocked. Only the two boundaries a unit test cannot fake are stubbed: the
OIDC token verifier (no live IdP) and the SCIM/key stores (populated with real
records). Every other decision is the production code path.

Dimensions
----------
* credential source / mode: OIDC bearer, API key (keystore), static key, browser
  session, trusted-proxy headers, anonymous(opt-in), and the multi-mode combos
  that actually coexist — static key + anonymous, OIDC + key, trusted-proxy + key.
* credential state: none presented, invalid/malformed presented, valid presented,
  expired/rotated presented (where the mode has an expiry/revocation concept).
* route authz level: a viewer-level route (``GET /v1/posture``) and an admin-level
  route (``GET /v1/auth/policy``) drawn from the real ``_ROLE_RULES`` — so the
  VIEWER-clamp on anonymous is observable (200 viewer / 403 admin).
* listener scope: loopback vs non-loopback. The request-time middleware is
  listener-invariant by construction (the same resolver runs regardless of bind),
  so listener scope is exercised where it actually changes behaviour — the posture
  derivation, the CLI serve gate, and the loopback dev-key auto-disable — in the
  ``LISTENER_POSTURE_CASES`` grid, not faked into request cells where it is inert.

Pinned epic invariants (each mapped to explicit rows below)
-----------------------------------------------------------
(a) A presented-but-invalid credential is NEVER downgraded to anonymous/VIEWER —
    it is a hard 401. Includes the PR2 OIDC decision: a JWT-shaped-but-bad bearer
    is 401 and never retried as a key, while a raw opaque key sent as Bearer still
    authenticates as a key.
(b) Absent chains to the next resolver; Invalid and Resolved are terminal. Pinned
    at the HTTP boundary (opaque-key-as-bearer falls through OIDC to the key
    resolver; an invalid JWT stops the chain).
(c) Anonymous access is served only when opted in, and only as VIEWER.
(d) The loopback dev-key auto-disables the moment any real credential source is
    configured.
(e) Trusted-proxy is a usable auth path only with its strong attestation secret.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

import click
import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from agent_bom.api.auth import (
    KeyStore,
    Role,
    create_api_key_record,
    get_key_store,
    set_key_store,
)
from agent_bom.api.browser_session import SESSION_COOKIE_NAME, create_browser_session_token
from agent_bom.api.middleware import APIKeyMiddleware, derive_auth_posture
from agent_bom.api.oidc import OIDCConfig, OIDCError
from agent_bom.api.scim_store import InMemorySCIMStore
from agent_bom.api.stores import set_scim_store
from agent_bom.cli._server import _enforce_auth_defaults, _should_auto_generate_dev_key

# ── fixed test material ──────────────────────────────────────────────────────

STATIC_KEY = "static-admin-key-value-abcdefghijklmnop"
OPAQUE_KEY = "abom_opaque_matrix_key_abcdefghijklmnop"  # non-JWT-shaped raw key
GARBAGE_KEY = "abom_not_a_real_key_zzzzzzzzzzzzzzzzzzzz"
PROXY_SECRET = "trusted-proxy-secret-with-32-plus-bytes!"
OIDC_ISSUER = "https://corp.okta.com"
OIDC_AUDIENCE = "agent-bom"

VIEWER_ROUTE = "/v1/posture"  # _ROLE_RULES -> viewer
ADMIN_ROUTE = "/v1/auth/policy"  # _ROLE_RULES -> admin
_ROUTE_PATH = {"viewer": VIEWER_ROUTE, "admin": ADMIN_ROUTE}

_CREDENTIAL_ENV = (
    "AGENT_BOM_API_KEY",
    "AGENT_BOM_API_KEYS",
    "AGENT_BOM_OIDC_ISSUER",
    "AGENT_BOM_OIDC_AUDIENCE",
    "AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON",
    "AGENT_BOM_OIDC_ROLE_CLAIM",
    "AGENT_BOM_TRUST_PROXY_AUTH",
    "AGENT_BOM_TRUST_PROXY_AUTH_SECRET",
    "AGENT_BOM_TRUST_PROXY_AUTH_SECRET_FILE",
    "AGENT_BOM_TRUST_PROXY_AUTH_ISSUER",
    "AGENT_BOM_SCIM_BEARER_TOKEN",
    "AGENT_BOM_SAML_IDP_ENTITY_ID",
    "AGENT_BOM_SAML_IDP_SSO_URL",
    "AGENT_BOM_SAML_IDP_X509_CERT",
    "AGENT_BOM_SAML_SP_ENTITY_ID",
    "AGENT_BOM_SAML_SP_ACS_URL",
    "AGENT_BOM_ALLOW_UNAUTHENTICATED_API",
    "AGENT_BOM_NO_AUTH_ROLE",
    "AGENT_BOM_NO_AUTO_DEV_KEY",
    "AGENT_BOM_DEMO_ESTATE",
)


@pytest.fixture(autouse=True)
def _isolate_auth_state(monkeypatch):
    """Every case starts from a clean auth environment and global store state."""
    for name in _CREDENTIAL_ENV:
        monkeypatch.delenv(name, raising=False)
    original_keys = get_key_store()
    set_key_store(KeyStore())
    set_scim_store(InMemorySCIMStore())
    try:
        yield
    finally:
        set_key_store(original_keys)
        set_scim_store(InMemorySCIMStore())


# ── app under test: real role rules, two authz altitudes ─────────────────────


def _build_client(api_key: str | None, *, allow_unauthenticated: bool = False) -> TestClient:
    async def handler(request):
        return JSONResponse(
            {
                "role": request.state.api_key_role,
                "auth_method": request.state.auth_method,
                "name": request.state.api_key_name,
                "tenant": request.state.tenant_id,
            }
        )

    app = Starlette(
        routes=[
            Route(VIEWER_ROUTE, handler, methods=["GET"]),
            Route(ADMIN_ROUTE, handler, methods=["GET"]),
        ]
    )
    # api_key="" and api_key=None both mean "no static key"; the middleware only
    # enters simple-static mode for a truthy key.
    app.add_middleware(APIKeyMiddleware, api_key=api_key or "", allow_unauthenticated=allow_unauthenticated)
    return TestClient(app)


# ── credential mocks (the only stubbed boundaries) ───────────────────────────


def _jwt_shaped(role: str) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"iss": OIDC_ISSUER, "sub": f"user-{role}"}).encode()).decode().rstrip("=")
    return f"{header}.{payload}.c2ln"


def _mock_oidc(monkeypatch, *, role: str | None, fail: bool) -> None:
    cfg = OIDCConfig(issuer=OIDC_ISSUER, audience=OIDC_AUDIENCE, allow_default_tenant=True)
    monkeypatch.setattr("agent_bom.api.oidc.OIDCConfig.from_env", lambda: cfg)
    if fail:
        monkeypatch.setattr(
            "agent_bom.api.oidc.verify_oidc_token",
            lambda *a, **k: (_ for _ in ()).throw(OIDCError("OIDC verification failed")),
        )
    else:
        monkeypatch.setattr(
            "agent_bom.api.oidc.verify_oidc_token",
            lambda *a, **k: {"sub": "u1", "email": "user@corp.com", "agent_bom_role": role},
        )


def _keystore_with(role: str, raw_key: str, *, revoked: bool = False) -> None:
    store = KeyStore()
    record = create_api_key_record(raw_key, name=f"svc:{role}", role=Role(role))
    if revoked:
        record.revoked_at = datetime.now(timezone.utc).isoformat()
    store.add(record)
    set_key_store(store)


def _proxy_headers(role: str, *, secret: str = PROXY_SECRET) -> dict[str, str]:
    return {
        "X-Agent-Bom-Role": role,
        "X-Agent-Bom-Subject": f"{role}@example.com",
        "X-Agent-Bom-Tenant-ID": "tenant-alpha",
        "X-Agent-Bom-Proxy-Secret": secret,
    }


# ── one row of the grid ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class Case:
    mode: str
    state: str  # none | invalid | valid | expired | mode-specific combo state
    route: str  # viewer | admin
    expected: int
    presented_role: str | None = None
    auth_method: str | None = None  # asserted on a 200
    invariant: str = ""
    note: str = ""

    @property
    def id(self) -> str:
        role = self.presented_role or "-"
        tag = f"[{self.invariant}]" if self.invariant else ""
        return f"{self.mode}:{self.state}:{role}->{self.route}={self.expected}{tag}"


@dataclass
class _Prepared:
    api_key: str | None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    allow_unauthenticated: bool = False


def _prepare(case: Case, monkeypatch) -> _Prepared:
    """Configure env/stores/mocks for a case and return the request material."""
    mode = case.mode
    state = case.state
    role = case.presented_role

    if mode == "oidc":
        _mock_oidc(monkeypatch, role=role, fail=state in {"invalid", "expired"})
        if state == "none":
            return _Prepared(api_key=None)
        return _Prepared(api_key=None, headers={"Authorization": f"Bearer {_jwt_shaped(role or 'viewer')}"})

    if mode == "api_key":
        if state == "valid":
            _keystore_with(role or "viewer", OPAQUE_KEY)
            return _Prepared(api_key=None, headers={"Authorization": f"Bearer {OPAQUE_KEY}"})
        if state == "expired":  # rotated/revoked key still presented
            _keystore_with("admin", OPAQUE_KEY, revoked=True)
            return _Prepared(api_key=None, headers={"Authorization": f"Bearer {OPAQUE_KEY}"})
        if state == "invalid":
            _keystore_with("admin", OPAQUE_KEY)
            return _Prepared(api_key=None, headers={"Authorization": f"Bearer {GARBAGE_KEY}"})
        # none
        _keystore_with("admin", OPAQUE_KEY)
        return _Prepared(api_key=None)

    if mode == "static_key":
        if state == "valid":
            return _Prepared(api_key=STATIC_KEY, headers={"Authorization": f"Bearer {STATIC_KEY}"})
        if state == "invalid":
            return _Prepared(api_key=STATIC_KEY, headers={"Authorization": f"Bearer {GARBAGE_KEY}"})
        return _Prepared(api_key=STATIC_KEY)  # none

    if mode == "browser_session":
        if state == "valid":
            token, _csrf = create_browser_session_token(
                subject=f"{role}@corp.com", role=role or "viewer", tenant_id="default", auth_method="browser_session", max_age_seconds=3600
            )
            return _Prepared(api_key=None, cookies={SESSION_COOKIE_NAME: token})
        if state == "expired":
            token, _csrf = create_browser_session_token(
                subject="stale@corp.com", role="admin", tenant_id="default", auth_method="browser_session", max_age_seconds=-10
            )
            return _Prepared(api_key=None, cookies={SESSION_COOKIE_NAME: token})
        if state == "invalid":
            token, _csrf = create_browser_session_token(
                subject="a@corp.com", role="admin", tenant_id="default", auth_method="browser_session", max_age_seconds=3600
            )
            tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
            return _Prepared(api_key=None, cookies={SESSION_COOKIE_NAME: tampered})
        return _Prepared(api_key=None)  # none

    if mode == "trusted_proxy":
        monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
        if state == "usable_gate":  # flag on, secret NOT configured
            return _Prepared(api_key=None, headers=_proxy_headers(role or "viewer"))
        monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
        if state == "valid":
            return _Prepared(api_key=None, headers=_proxy_headers(role or "viewer"))
        if state == "invalid":
            return _Prepared(api_key=None, headers=_proxy_headers(role or "viewer", secret="wrong-secret"))
        return _Prepared(api_key=None)  # none: no proxy headers

    if mode == "anonymous":
        if state == "invalid":  # a garbage bearer presented under anonymous opt-in
            return _Prepared(api_key=None, headers={"Authorization": f"Bearer {GARBAGE_KEY}"}, allow_unauthenticated=True)
        if state == "invalid_scheme":
            # A credential in a NON-Bearer scheme leaves raw_key empty, so the
            # terminal resolver reaches the ``_credential_presented`` guard: it
            # must still be rejected, never downgraded to the anonymous fallback.
            return _Prepared(api_key=None, headers={"Authorization": "Basic Zm9vOmJhcg=="}, allow_unauthenticated=True)
        return _Prepared(api_key=None, allow_unauthenticated=True)  # none

    if mode == "static_key+anonymous":
        # NO_AUTH_ROLE=admin proves the combined-mode clamp forces VIEWER.
        monkeypatch.setenv("AGENT_BOM_NO_AUTH_ROLE", "admin")
        if state == "valid":
            return _Prepared(api_key=STATIC_KEY, headers={"Authorization": f"Bearer {STATIC_KEY}"}, allow_unauthenticated=True)
        if state == "invalid":
            return _Prepared(api_key=STATIC_KEY, headers={"Authorization": f"Bearer {GARBAGE_KEY}"}, allow_unauthenticated=True)
        return _Prepared(api_key=STATIC_KEY, allow_unauthenticated=True)  # none

    if mode == "oidc+api_key":
        _keystore_with("analyst", OPAQUE_KEY)
        if state == "valid_oidc":
            _mock_oidc(monkeypatch, role="admin", fail=False)
            return _Prepared(api_key=None, headers={"Authorization": f"Bearer {_jwt_shaped('admin')}"})
        if state == "opaque_key":  # not JWT-shaped -> OIDC Absent -> key resolver wins
            _mock_oidc(monkeypatch, role=None, fail=True)
            return _Prepared(api_key=None, headers={"Authorization": f"Bearer {OPAQUE_KEY}"})
        # invalid_jwt -> Invalid terminal, never retried as key
        _mock_oidc(monkeypatch, role=None, fail=True)
        return _Prepared(api_key=None, headers={"Authorization": f"Bearer {_jwt_shaped('admin')}"})

    if mode == "trusted_proxy+api_key":
        monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
        monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
        _keystore_with("admin", OPAQUE_KEY)
        if state == "key":  # a presented key short-circuits the proxy resolver
            return _Prepared(api_key=None, headers={"Authorization": f"Bearer {OPAQUE_KEY}"})
        if state == "proxy":  # no key -> proxy header path
            return _Prepared(api_key=None, headers=_proxy_headers("admin"))
        # invalid_key: key present but bad -> proxy skipped, key rejected
        return _Prepared(api_key=None, headers={"Authorization": f"Bearer {GARBAGE_KEY}"})

    raise AssertionError(f"unhandled mode {mode!r}")


# ── the request grid ─────────────────────────────────────────────────────────


def _role_route_block(mode: str, auth_method: str, roles: tuple[str, ...]) -> list[Case]:
    """Valid credential of each role against both authz altitudes."""
    rows: list[Case] = []
    for prole in roles:
        for route in ("viewer", "admin"):
            if route == "admin":
                expected = 200 if prole == "admin" else 403
            else:
                expected = 200
            rows.append(
                Case(
                    mode=mode,
                    state="valid",
                    route=route,
                    expected=expected,
                    presented_role=prole,
                    auth_method=auth_method if expected == 200 else None,
                )
            )
    return rows


REQUEST_CASES: list[Case] = []

# 1. Valid credential x role x route authz — the 200/403 core, per mode.
REQUEST_CASES += _role_route_block("oidc", "oidc", ("viewer", "analyst", "admin"))
REQUEST_CASES += _role_route_block("api_key", "api_key", ("viewer", "analyst", "admin"))
REQUEST_CASES += _role_route_block("browser_session", "browser_session", ("viewer", "admin"))
REQUEST_CASES += _role_route_block("trusted_proxy", "proxy_header", ("viewer", "admin"))

# 2. Static key always authenticates as admin (no role dimension).
REQUEST_CASES += [
    Case(mode="static_key", state="valid", route="viewer", expected=200, auth_method="static_api_key"),
    Case(mode="static_key", state="valid", route="admin", expected=200, auth_method="static_api_key"),
    Case(mode="static_key", state="invalid", route="viewer", expected=401, invariant="a", note="wrong static key is a hard 401"),
    Case(mode="static_key", state="none", route="viewer", expected=401, note="no credential when required"),
]

# 3. Credential-STATE rows (viewer route): none/invalid/expired must fail closed.
for _mode in ("oidc", "api_key", "browser_session"):
    REQUEST_CASES += [
        Case(mode=_mode, state="none", route="viewer", expected=401, presented_role="viewer", note="absent credential when auth required"),
        Case(
            mode=_mode,
            state="invalid",
            route="viewer",
            expected=401,
            presented_role="viewer",
            invariant="a",
            note="invalid credential is 401, never anonymous",
        ),
        Case(
            mode=_mode,
            state="expired",
            route="viewer",
            expected=401,
            presented_role="viewer",
            invariant="a",
            note="expired/rotated credential is 401",
        ),
    ]

# 4. Trusted-proxy state rows, including the usable-gate invariant (e).
REQUEST_CASES += [
    Case(mode="trusted_proxy", state="none", route="viewer", expected=401, presented_role="viewer", note="no proxy headers when required"),
    Case(
        mode="trusted_proxy",
        state="invalid",
        route="viewer",
        expected=401,
        presented_role="viewer",
        invariant="e",
        note="wrong attestation secret is 401",
    ),
    Case(
        mode="trusted_proxy",
        state="usable_gate",
        route="viewer",
        expected=503,
        presented_role="viewer",
        invariant="e",
        note="proxy flag without secret is not a usable auth path",
    ),
]

# 5. Anonymous (opt-in) — only when opted in, and only VIEWER (invariant c).
REQUEST_CASES += [
    Case(
        mode="anonymous",
        state="none",
        route="viewer",
        expected=200,
        auth_method="anonymous",
        invariant="c",
        note="anonymous served as viewer",
    ),
    Case(mode="anonymous", state="none", route="admin", expected=403, invariant="c", note="anonymous viewer cannot reach admin"),
    Case(
        mode="anonymous",
        state="invalid",
        route="viewer",
        expected=401,
        invariant="a",
        note="invalid bearer is 401 even with anonymous opt-in",
    ),
    Case(
        mode="anonymous",
        state="invalid_scheme",
        route="viewer",
        expected=401,
        invariant="a",
        note="non-Bearer credential is not downgraded to anonymous",
    ),
]

# 6. static key + anonymous — combined-mode VIEWER clamp + no invalid downgrade.
REQUEST_CASES += [
    Case(
        mode="static_key+anonymous",
        state="valid",
        route="admin",
        expected=200,
        auth_method="static_api_key",
        note="static key still elevates to admin",
    ),
    Case(
        mode="static_key+anonymous",
        state="none",
        route="viewer",
        expected=200,
        auth_method="anonymous",
        invariant="c",
        note="anonymous served",
    ),
    Case(
        mode="static_key+anonymous",
        state="none",
        route="admin",
        expected=403,
        invariant="c",
        note="NO_AUTH_ROLE=admin is clamped to viewer when a key source coexists",
    ),
    Case(
        mode="static_key+anonymous",
        state="invalid",
        route="viewer",
        expected=401,
        invariant="a",
        note="invalid key not downgraded to anonymous",
    ),
]

# 7. OIDC + key — Absent chains, Invalid is terminal (invariants a, b).
REQUEST_CASES += [
    Case(mode="oidc+api_key", state="valid_oidc", route="admin", expected=200, auth_method="oidc", note="valid OIDC admin authenticates"),
    Case(
        mode="oidc+api_key",
        state="opaque_key",
        route="viewer",
        expected=200,
        auth_method="api_key",
        invariant="b",
        note="non-JWT bearer falls through OIDC to the key resolver",
    ),
    Case(
        mode="oidc+api_key",
        state="invalid_jwt",
        route="viewer",
        expected=401,
        invariant="a",
        note="invalid JWT is terminal, never retried as a key",
    ),
]

# 8. Trusted-proxy + key — a presented key short-circuits the proxy resolver.
REQUEST_CASES += [
    Case(
        mode="trusted_proxy+api_key",
        state="key",
        route="admin",
        expected=200,
        auth_method="api_key",
        note="presented key wins over proxy headers",
    ),
    Case(
        mode="trusted_proxy+api_key",
        state="proxy",
        route="admin",
        expected=200,
        auth_method="proxy_header",
        note="proxy header path when no key presented",
    ),
    Case(
        mode="trusted_proxy+api_key",
        state="invalid_key",
        route="admin",
        expected=401,
        invariant="a",
        note="bad key skips proxy and is a hard 401",
    ),
]


@pytest.mark.parametrize("case", REQUEST_CASES, ids=[c.id for c in REQUEST_CASES])
def test_auth_request_grid(case: Case, monkeypatch) -> None:
    prepared = _prepare(case, monkeypatch)
    client = _build_client(prepared.api_key, allow_unauthenticated=prepared.allow_unauthenticated)
    if prepared.cookies:
        client.cookies.update(prepared.cookies)

    response = client.get(_ROUTE_PATH[case.route], headers=prepared.headers)

    assert response.status_code == case.expected, f"{case.id}: expected {case.expected}, got {response.status_code} — {response.text}"
    if case.expected == 200 and case.auth_method is not None:
        assert response.json()["auth_method"] == case.auth_method, case.id


# ── listener-scope / posture grid (invariants d + e) ─────────────────────────


@dataclass(frozen=True)
class ListenerCase:
    host: str
    env: dict[str, str]
    api_key_configured: bool
    expect_programmatic_auth: bool
    expect_dev_key: bool
    expect_serve: str  # "pass" | "raise"
    label: str

    @property
    def id(self) -> str:
        return f"{self.label}@{self.host}"


_STRONG_SECRET = "trusted-proxy-secret-material-32-bytes!!"

LISTENER_POSTURE_CASES: list[ListenerCase] = [
    # No credential source configured.
    ListenerCase("127.0.0.1", {}, False, False, True, "pass", "no-source"),
    ListenerCase("::1", {}, False, False, True, "pass", "no-source"),
    ListenerCase("0.0.0.0", {}, False, False, False, "raise", "no-source"),
    ListenerCase("192.168.1.10", {}, False, False, False, "raise", "no-source"),
    # API key source — dev-key auto-disables (invariant d); serve gate satisfied.
    ListenerCase("127.0.0.1", {"AGENT_BOM_API_KEYS": "raw-key:admin"}, True, True, False, "pass", "api-key"),
    ListenerCase("0.0.0.0", {"AGENT_BOM_API_KEYS": "raw-key:admin"}, True, True, False, "pass", "api-key"),
    # OIDC bearer source.
    ListenerCase(
        "127.0.0.1", {"AGENT_BOM_OIDC_ISSUER": OIDC_ISSUER, "AGENT_BOM_OIDC_AUDIENCE": OIDC_AUDIENCE}, False, True, False, "pass", "oidc"
    ),
    ListenerCase(
        "0.0.0.0", {"AGENT_BOM_OIDC_ISSUER": OIDC_ISSUER, "AGENT_BOM_OIDC_AUDIENCE": OIDC_AUDIENCE}, False, True, False, "pass", "oidc"
    ),
    # Trusted proxy: flag WITHOUT a strong secret is not usable (invariant e).
    ListenerCase("0.0.0.0", {"AGENT_BOM_TRUST_PROXY_AUTH": "1"}, False, False, False, "raise", "proxy-no-secret"),
    # Trusted proxy: flag WITH a strong secret is a usable non-loopback auth path.
    ListenerCase(
        "0.0.0.0",
        {"AGENT_BOM_TRUST_PROXY_AUTH": "1", "AGENT_BOM_TRUST_PROXY_AUTH_SECRET": _STRONG_SECRET},
        False,
        True,
        False,
        "pass",
        "proxy-secret",
    ),
    ListenerCase(
        "127.0.0.1",
        {"AGENT_BOM_TRUST_PROXY_AUTH": "1", "AGENT_BOM_TRUST_PROXY_AUTH_SECRET": _STRONG_SECRET},
        False,
        True,
        False,
        "pass",
        "proxy-secret",
    ),
]


@pytest.mark.parametrize("case", LISTENER_POSTURE_CASES, ids=[c.id for c in LISTENER_POSTURE_CASES])
def test_listener_posture_grid(case: ListenerCase, monkeypatch) -> None:
    for key, value in case.env.items():
        monkeypatch.setenv(key, value)

    posture = derive_auth_posture(
        api_key_configured=case.api_key_configured,
        allow_unauthenticated=False,
        listener_host=case.host,
    )
    assert posture.programmatic_auth_configured is case.expect_programmatic_auth, case.id

    # (d) loopback dev-key auto-disables the moment a real source is configured.
    dev_key = _should_auto_generate_dev_key(host=case.host, api_key=None, allow_insecure_no_auth=False)
    assert dev_key is case.expect_dev_key, f"{case.id}: dev-key decision"

    # (e) + serve gate: the CLI refuses a non-loopback bind without a usable path.
    if case.expect_serve == "raise":
        with pytest.raises(click.ClickException):
            _enforce_auth_defaults("serve", case.host, api_key=None, allow_insecure_no_auth=False)
    else:
        _enforce_auth_defaults("serve", case.host, api_key=None, allow_insecure_no_auth=False)


def test_matrix_cell_count_is_meaningful() -> None:
    """Guardrail: the grid must stay comprehensive, not silently shrink."""
    total = len(REQUEST_CASES) + len(LISTENER_POSTURE_CASES)
    assert total >= 55, f"contract matrix shrank to {total} cells"
    # Every pinned invariant must have at least one asserting row.
    invariants = {c.invariant for c in REQUEST_CASES if c.invariant}
    assert {"a", "b", "c", "e"} <= invariants
