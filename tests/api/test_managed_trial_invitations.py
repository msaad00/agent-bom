"""Managed-trial invitation security contracts."""

from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from pydantic import SecretStr
from starlette.requests import Request
from starlette.testclient import TestClient

from agent_bom.api.browser_session import create_browser_session_token, verify_browser_session_token
from agent_bom.api.managed_trial_invitation import (
    InMemoryManagedTrialInvitationStore,
    ManagedTrialInvitationError,
    issue_managed_trial_invitation,
    normalize_invitation_email,
    set_managed_trial_invitation_store_for_tests,
)
from agent_bom.api.oidc_browser import (
    managed_trial_invitation_digest_from_pkce_cookie,
    open_pkce_cookie,
    seal_pkce_cookie,
)
from agent_bom.api.routes import enterprise
from agent_bom.api.shared_auth_state import reset_auth_state_for_tests
from agent_bom.api.tenant_lifecycle import (
    InMemoryTenantLifecycleStore,
    TenantLifecycleState,
    set_tenant_lifecycle_store_for_tests,
)


@pytest.fixture(autouse=True)
def _reset_stores() -> None:
    set_managed_trial_invitation_store_for_tests(None)
    set_tenant_lifecycle_store_for_tests(None)
    reset_auth_state_for_tests()
    yield
    set_managed_trial_invitation_store_for_tests(None)
    set_tenant_lifecycle_store_for_tests(None)
    reset_auth_state_for_tests()


def _request(
    *,
    path: str,
    method: str = "POST",
    cookies: dict[str, str] | None = None,
    tenant_id: str = "default",
) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if cookies:
        headers.append((b"cookie", "; ".join(f"{key}={value}" for key, value in cookies.items()).encode()))
    request = Request(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "https",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": headers,
            "client": ("127.0.0.1", 12345),
            "server": ("trial.example", 443),
        }
    )
    request.state.api_key_name = "synthetic-operator"
    request.state.tenant_id = tenant_id
    return request


def _cookie_value(response, name: str) -> str:
    jar = SimpleCookie()
    for header in response.headers.getlist("set-cookie"):
        jar.load(header)
    return jar[name].value


def test_issue_persists_digest_and_normalized_email_but_never_raw_token() -> None:
    now = datetime(2026, 7, 24, 12, 0, tzinfo=timezone.utc)
    issued = issue_managed_trial_invitation(
        InMemoryManagedTrialInvitationStore(),
        email="  Analyst@Example.COM ",
        tenant_id="trial-example-123",
        team_name="Example Trial",
        now=now,
    )

    assert issued.raw_token.startswith("abti_")
    assert issued.invitation.email == "analyst@example.com"
    assert issued.invitation.expires_at == now + timedelta(hours=48)
    assert issued.invitation.token_digest == hashlib.sha256(issued.raw_token.encode()).hexdigest()
    persisted = asdict(issued.invitation)
    assert "raw_token" not in persisted
    assert issued.raw_token not in repr(issued.invitation)


def test_accept_is_email_bound_single_use_and_fail_closed() -> None:
    now = datetime(2026, 7, 24, 12, 0, tzinfo=timezone.utc)
    store = InMemoryManagedTrialInvitationStore()
    issued = issue_managed_trial_invitation(
        store,
        email="analyst@example.com",
        tenant_id="trial-example-123",
        team_name="Example Trial",
        now=now,
    )
    digest = issued.invitation.token_digest

    with pytest.raises(ManagedTrialInvitationError, match="(?i)invalid or expired"):
        store.accept_digest(digest, verified_email="other@example.com", now=now)
    assert store.get_by_digest(digest, now=now).state == "pending"

    accepted = store.accept_digest(digest, verified_email="ANALYST@example.com", now=now)
    assert accepted.state == "accepted"
    assert accepted.accepted_at == now
    with pytest.raises(ManagedTrialInvitationError, match="(?i)invalid or expired"):
        store.accept_digest(digest, verified_email="analyst@example.com", now=now)


def test_expired_invitation_is_rejected_and_marked_expired() -> None:
    issued_at = datetime(2026, 7, 24, 12, 0, tzinfo=timezone.utc)
    store = InMemoryManagedTrialInvitationStore()
    issued = issue_managed_trial_invitation(
        store,
        email="analyst@example.com",
        tenant_id="trial-example-123",
        team_name="Example Trial",
        now=issued_at,
        ttl=timedelta(seconds=1),
    )

    with pytest.raises(ManagedTrialInvitationError, match="(?i)invalid or expired"):
        store.accept_digest(
            issued.invitation.token_digest,
            verified_email="analyst@example.com",
            now=issued_at + timedelta(seconds=2),
        )
    assert store._records[issued.invitation.token_digest].state == "expired"


@pytest.mark.parametrize("email", ["", "missing-at", "a b@example.com", "@example.com", "a@"])
def test_email_normalization_rejects_invalid_values(email: str) -> None:
    with pytest.raises(ManagedTrialInvitationError):
        normalize_invitation_email(email)


def test_pkce_cookie_carries_only_invitation_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "synthetic-signing-key-for-tests")
    raw_token = "abti_synthetic_raw_token"
    digest = hashlib.sha256(raw_token.encode()).hexdigest()

    sealed = seal_pkce_cookie(
        code_verifier="verifier",
        nonce="nonce",
        managed_trial_invitation_digest=digest,
    )

    assert raw_token not in sealed
    assert open_pkce_cookie(sealed) == ("verifier", "nonce", "/")
    assert managed_trial_invitation_digest_from_pkce_cookie(sealed) == digest


def test_pkce_cookie_rejects_invalid_invitation_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "synthetic-signing-key-for-tests")
    with pytest.raises(ValueError, match="(?i)invitation"):
        seal_pkce_cookie(
            code_verifier="verifier",
            nonce="nonce",
            managed_trial_invitation_digest="not-a-digest",
        )


def test_managed_trial_creation_is_opt_in_and_never_mints_an_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    store = InMemoryManagedTrialInvitationStore()
    set_managed_trial_invitation_store_for_tests(store)
    request = _request(path="/v1/auth/trial-invitations")
    body = enterprise.ManagedTrialInvitationRequest(email="analyst@example.com", organization="Example Trial")

    with pytest.raises(Exception) as disabled:
        asyncio.run(enterprise.create_managed_trial_invitation(request, body))
    assert getattr(disabled.value, "status_code", None) == 404
    assert store._records == {}

    monkeypatch.setenv("AGENT_BOM_MANAGED_TRIAL_INVITATIONS", "1")
    monkeypatch.setenv("AGENT_BOM_HOSTED_INVITE_BASE_URL", "https://trial.example")
    with patch("agent_bom.api.auth.create_api_key", side_effect=AssertionError("must not mint API key")):
        response = asyncio.run(enterprise.create_managed_trial_invitation(request, body))

    assert response["token"].startswith("abti_")
    assert response["role"] == "analyst"
    assert response["login_url"] == "https://trial.example/login"
    assert response["token"] not in response["login_url"]
    invitation = next(iter(store._records.values()))
    assert not hasattr(invitation, "raw_token")


def test_managed_trial_creation_rejects_non_operator_before_generating_or_persisting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_BOM_MANAGED_TRIAL_INVITATIONS", "1")
    monkeypatch.setenv("AGENT_BOM_PLATFORM_OPERATOR_TENANT_ID", "platform-operator")
    request = _request(path="/v1/auth/trial-invitations", tenant_id="customer-tenant")
    body = enterprise.ManagedTrialInvitationRequest(email="analyst@example.com", organization="Example Trial")

    with (
        patch.object(
            enterprise,
            "_new_invited_tenant_id",
            side_effect=AssertionError("tenant id must not be generated"),
        ),
        patch(
            "agent_bom.api.managed_trial_invitation.get_managed_trial_invitation_store",
            side_effect=AssertionError("store must not be resolved"),
        ),
        patch(
            "agent_bom.api.managed_trial_invitation.issue_managed_trial_invitation",
            side_effect=AssertionError("invitation must not be issued"),
        ),
        pytest.raises(Exception) as denied,
    ):
        asyncio.run(enterprise.create_managed_trial_invitation(request, body))

    assert getattr(denied.value, "status_code", None) == 403


@pytest.mark.asyncio
async def test_slow_managed_trial_persistence_keeps_event_loop_responsive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_BOM_MANAGED_TRIAL_INVITATIONS", "1")
    block_seconds = 0.25
    tick_seconds = 0.01
    ticks = 0

    class _SlowInvitationStore(InMemoryManagedTrialInvitationStore):
        def issue(self, invitation, *, team_name: str) -> None:  # type: ignore[no-untyped-def]
            time.sleep(block_seconds)
            super().issue(invitation, team_name=team_name)

    class _SlowLifecycleStore(InMemoryTenantLifecycleStore):
        def transition(self, tenant_id, *, state, now=None):  # type: ignore[no-untyped-def]
            time.sleep(block_seconds)
            return super().transition(tenant_id, state=state, now=now)

    invitation_store = _SlowInvitationStore()
    lifecycle_store = _SlowLifecycleStore()
    now = datetime.now(timezone.utc)
    lifecycle_store.create(
        tenant_id="trial-example-123",
        trial_ends_at=now + timedelta(days=14),
        cleanup_after=now + timedelta(days=21),
        now=now,
    )
    lifecycle_store.transition("trial-example-123", state=TenantLifecycleState.SUSPENDED, now=now)
    set_managed_trial_invitation_store_for_tests(invitation_store)
    set_tenant_lifecycle_store_for_tests(lifecycle_store)

    async def _heartbeat() -> None:
        nonlocal ticks
        while True:
            await asyncio.sleep(tick_seconds)
            ticks += 1

    beat = asyncio.create_task(_heartbeat())
    await asyncio.sleep(tick_seconds * 2)
    try:
        before_issue = ticks
        created = await enterprise.create_managed_trial_invitation(
            _request(path="/v1/auth/trial-invitations"),
            enterprise.ManagedTrialInvitationRequest(email="analyst@example.com", organization="Example Trial"),
        )
        issue_ticks = ticks - before_issue

        before_transition = ticks
        resumed = await enterprise.resume_managed_trial_tenant(
            _request(path="/v1/auth/trial-tenants/trial-example-123/resume"),
            "trial-example-123",
        )
        transition_ticks = ticks - before_transition
    finally:
        beat.cancel()

    assert created["state"] == "pending"
    assert resumed["state"] == "active"
    assert issue_ticks >= 5
    assert transition_ticks >= 5


def test_managed_trial_requires_postgres_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_MANAGED_TRIAL_INVITATIONS", "1")
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.delenv("AGENT_BOM_DB", raising=False)
    request = _request(path="/v1/auth/trial-invitations")
    body = enterprise.ManagedTrialInvitationRequest(email="analyst@example.com", organization="Example Trial")

    with pytest.raises(Exception) as unavailable:
        asyncio.run(enterprise.create_managed_trial_invitation(request, body))
    assert getattr(unavailable.value, "status_code", None) == 503


def test_managed_trial_route_access_contract() -> None:
    from agent_bom.api.middleware import APIKeyMiddleware

    assert "/v1/auth/trial/oidc/start" in APIKeyMiddleware._EXEMPT_PATHS
    assert ("POST", "/v1/auth/trial-invitations", "admin") in APIKeyMiddleware._ROLE_RULES
    assert ("POST", "/v1/auth/trial-invitations", "auth.invitations:write") in APIKeyMiddleware._SCOPE_RULES


def test_managed_trial_oidc_start_uses_posted_secret_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_MANAGED_TRIAL_INVITATIONS", "1")
    monkeypatch.setenv("AGENT_BOM_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("AGENT_BOM_OIDC_CLIENT_ID", "trial-client")
    monkeypatch.setenv("AGENT_BOM_OIDC_REDIRECT_URI", "https://trial.example/v1/auth/oidc/callback")
    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "synthetic-signing-key-for-tests")
    store = InMemoryManagedTrialInvitationStore()
    issued = issue_managed_trial_invitation(
        store,
        email="analyst@example.com",
        tenant_id="trial-example-123",
        team_name="Example Trial",
    )
    set_managed_trial_invitation_store_for_tests(store)
    body = enterprise.ManagedTrialOIDCStartRequest(token=SecretStr(issued.raw_token))

    with (
        patch(
            "agent_bom.api.oidc_browser.discover_oidc",
            return_value={"authorization_endpoint": "https://issuer.example/authorize"},
        ),
        patch("agent_bom.api.oidc_browser.validate_url"),
    ):
        response = asyncio.run(
            enterprise.managed_trial_oidc_start(_request(path="/v1/auth/trial/oidc/start"), body)
        )

    assert issued.raw_token not in response.headers["location"]
    sealed = _cookie_value(response, "agent_bom_oidc_pkce")
    assert issued.raw_token not in sealed
    assert managed_trial_invitation_digest_from_pkce_cookie(sealed) == issued.invitation.token_digest


def test_login_form_adapter_accepts_post_body_and_never_requires_query_token() -> None:
    from starlette.responses import RedirectResponse

    raw_token = "abti_synthetic_form_token"
    body = f"token={raw_token}".encode()
    delivered = False

    async def _receive() -> dict[str, object]:
        nonlocal delivered
        if delivered:
            return {"type": "http.disconnect"}
        delivered = True
        return {"type": "http.request", "body": body, "more_body": False}

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/auth/trial/oidc/start-form",
            "query_string": b"",
            "headers": [(b"content-type", b"application/x-www-form-urlencoded")],
        },
        _receive,
    )
    adapter = AsyncMock(return_value=RedirectResponse("/synthetic", status_code=302))
    with patch.object(enterprise, "managed_trial_oidc_start", adapter):
        response = asyncio.run(enterprise.managed_trial_oidc_start_form(request))

    assert response.status_code == 302
    submitted = adapter.await_args.args[1]
    assert submitted.token.get_secret_value() == raw_token
    assert request.url.query == ""


def test_managed_trial_oidc_callback_binds_verified_subject_and_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_MANAGED_TRIAL_INVITATIONS", "1")
    monkeypatch.setenv("AGENT_BOM_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("AGENT_BOM_OIDC_CLIENT_ID", "trial-client")
    monkeypatch.setenv("AGENT_BOM_OIDC_REDIRECT_URI", "https://trial.example/v1/auth/oidc/callback")
    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "synthetic-signing-key-for-tests")
    store = InMemoryManagedTrialInvitationStore()
    issued = issue_managed_trial_invitation(
        store,
        email="analyst@example.com",
        tenant_id="trial-example-123",
        team_name="Example Trial",
    )
    set_managed_trial_invitation_store_for_tests(store)
    sealed = seal_pkce_cookie(
        code_verifier="verifier",
        nonce="nonce",
        managed_trial_invitation_digest=issued.invitation.token_digest,
    )
    state = enterprise._new_oidc_login_state()

    with (
        patch("agent_bom.api.oidc_browser.exchange_code_for_tokens", return_value={"id_token": "synthetic.jwt"}),
        patch(
            "agent_bom.api.oidc_browser.verify_browser_id_token",
            return_value={"sub": "oidc-subject-123", "email": "Analyst@Example.com", "email_verified": True},
        ),
        patch("agent_bom.api.audit_log.log_action"),
    ):
        response = asyncio.run(
            enterprise.oidc_browser_callback(
                _request(path="/v1/auth/oidc/callback", method="GET", cookies={"agent_bom_oidc_pkce": sealed}),
                code="synthetic-code",
                state=state,
            )
        )

    session = verify_browser_session_token(_cookie_value(response, "agent_bom_session"))
    assert session["sub"] == "oidc-subject-123"
    assert session["tenant_id"] == "trial-example-123"
    assert session["role"] == "analyst"
    assert session["auth_method"] == "managed_trial_oidc"
    assert session["scopes"] == [
        "cloud.connection:read",
        "cloud.connection:write",
        "finding:read",
        "graph:read",
    ]
    accepted = store._records[issued.invitation.token_digest]
    assert accepted.state == "accepted"
    assert accepted.verified_subject == "oidc-subject-123"


def test_managed_trial_session_is_rejected_after_tenant_suspension(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api.middleware import APIKeyMiddleware

    monkeypatch.setenv("AGENT_BOM_MANAGED_TRIAL_MODE", "1")
    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "synthetic-signing-key-for-tests")
    now = datetime.now(timezone.utc)
    lifecycle = InMemoryTenantLifecycleStore()
    lifecycle.create(
        tenant_id="trial-example-123",
        trial_ends_at=now + timedelta(days=14),
        cleanup_after=now + timedelta(days=21),
        now=now,
    )
    lifecycle.transition("trial-example-123", state=TenantLifecycleState.SUSPENDED, now=now)
    set_tenant_lifecycle_store_for_tests(lifecycle)
    token, _csrf = create_browser_session_token(
        subject="oidc-subject-123",
        role="analyst",
        tenant_id="trial-example-123",
        auth_method="managed_trial_oidc",
        scopes=["finding:read"],
        max_age_seconds=3600,
    )
    app = FastAPI()

    @app.get("/v1/findings")
    async def _findings() -> dict[str, bool]:
        return {"reached": True}

    app.add_middleware(APIKeyMiddleware, api_key="")
    client = TestClient(app)
    client.cookies.set("agent_bom_session", token)
    response = client.get("/v1/findings")

    assert response.status_code == 401
    assert response.json()["detail"] == "Unauthorized — managed trial is inactive"


@pytest.mark.parametrize(
    "claims",
    [
        {"sub": "subject", "email": "other@example.com", "email_verified": True},
        {"sub": "subject", "email": "analyst@example.com", "email_verified": False},
        {"email": "analyst@example.com", "email_verified": True},
    ],
)
def test_managed_trial_oidc_callback_rejects_unbound_identity(monkeypatch: pytest.MonkeyPatch, claims: dict) -> None:
    monkeypatch.setenv("AGENT_BOM_MANAGED_TRIAL_INVITATIONS", "1")
    monkeypatch.setenv("AGENT_BOM_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("AGENT_BOM_OIDC_CLIENT_ID", "trial-client")
    monkeypatch.setenv("AGENT_BOM_OIDC_REDIRECT_URI", "https://trial.example/v1/auth/oidc/callback")
    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "synthetic-signing-key-for-tests")
    store = InMemoryManagedTrialInvitationStore()
    issued = issue_managed_trial_invitation(
        store,
        email="analyst@example.com",
        tenant_id="trial-example-123",
        team_name="Example Trial",
    )
    set_managed_trial_invitation_store_for_tests(store)
    sealed = seal_pkce_cookie(
        code_verifier="verifier",
        nonce="nonce",
        managed_trial_invitation_digest=issued.invitation.token_digest,
    )
    state = enterprise._new_oidc_login_state()

    with (
        patch("agent_bom.api.oidc_browser.exchange_code_for_tokens", return_value={"id_token": "synthetic.jwt"}),
        patch("agent_bom.api.oidc_browser.verify_browser_id_token", return_value=claims),
        pytest.raises(Exception) as rejected,
    ):
        asyncio.run(
            enterprise.oidc_browser_callback(
                _request(path="/v1/auth/oidc/callback", method="GET", cookies={"agent_bom_oidc_pkce": sealed}),
                code="synthetic-code",
                state=state,
            )
        )
    assert getattr(rejected.value, "status_code", None) == 401
    assert getattr(rejected.value, "detail", "") == "Invalid or expired managed-trial invitation"
    assert store._records[issued.invitation.token_digest].state == "pending"
