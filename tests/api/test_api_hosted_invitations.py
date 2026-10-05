"""End-to-end tests for the hosted invite/create-tenant endpoint.

Closes the last item of the invite-only authenticated MVP (#3834): a thin,
admin-scoped ``POST /v1/auth/invitations`` that provisions a NEW tenant, mints
a scoped API key for it (reusing the existing key-minting crypto), and returns
a one-time invite payload bounded by the conservative default tenant quotas.

These drive the real middleware (RBAC role + scope gate, tenant isolation) via
TestClient with a seeded KeyStore, so they exercise auth end-to-end rather than
calling the handler in isolation.
"""

from __future__ import annotations

from types import SimpleNamespace
from urllib.parse import urlparse

import pytest
from starlette.testclient import TestClient

from agent_bom.api.auth import KeyStore, Role, create_api_key, get_key_store, set_key_store
from agent_bom.api.server import app, configure_api
from agent_bom.api.stores import _get_tenant_quota_store, set_tenant_quota_store
from agent_bom.api.tenant_quota import default_tenant_quotas
from agent_bom.api.tenant_quota_store import InMemoryTenantQuotaStore

OPERATOR_TENANT = "operator"


@pytest.fixture
def invite_ctx(monkeypatch):
    """Seed an operator KeyStore with admin/analyst/viewer keys and a clean quota store."""
    monkeypatch.setenv("AGENT_BOM_PLATFORM_OPERATOR_TENANT_ID", OPERATOR_TENANT)
    monkeypatch.delenv("AGENT_BOM_HOSTED_INVITE_BASE_URL", raising=False)
    # Hosted invite-only posture: fail closed. The session-wide conftest opt-in
    # would otherwise strip the auth middleware because no env/static key is set.
    monkeypatch.delenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", raising=False)
    original_store = get_key_store()
    original_quota = _get_tenant_quota_store()
    set_tenant_quota_store(InMemoryTenantQuotaStore())
    store = KeyStore()
    set_key_store(store)

    raw_admin, admin_key = create_api_key(name="operator-admin", role=Role.ADMIN, scopes=["*"], tenant_id=OPERATOR_TENANT)
    raw_analyst, analyst_key = create_api_key(name="operator-analyst", role=Role.ANALYST, scopes=["*"], tenant_id=OPERATOR_TENANT)
    raw_viewer, viewer_key = create_api_key(name="operator-viewer", role=Role.VIEWER, scopes=["*"], tenant_id=OPERATOR_TENANT)
    for key in (admin_key, analyst_key, viewer_key):
        store.add(key)

    # Hosted invite-only posture is fail-closed: a missing credential is 401,
    # never the session-wide anonymous fallback the test conftest enables.
    configure_api(api_key=None, allow_unauthenticated=False)
    try:
        yield SimpleNamespace(
            client=TestClient(app),
            store=store,
            raw_admin=raw_admin,
            raw_analyst=raw_analyst,
            raw_viewer=raw_viewer,
            operator_key_ids={admin_key.key_id, analyst_key.key_id, viewer_key.key_id},
        )
    finally:
        set_key_store(original_store)
        set_tenant_quota_store(original_quota)
        configure_api(api_key=None)


def _create_invitation(ctx, raw_key, **body):
    return ctx.client.post("/v1/auth/invitations", json=body, headers={"X-API-Key": raw_key})


# ── happy path: admin mints an invite for a brand-new tenant ─────────────────


def test_admin_invitation_mints_scoped_key_for_new_tenant(invite_ctx):
    resp = _create_invitation(invite_ctx, invite_ctx.raw_admin, organization="Acme Corp", email="owner@acme.example")
    assert resp.status_code == 201, resp.text
    body = resp.json()

    assert body["raw_key"].startswith("abom_")
    assert body["raw_key"] != invite_ctx.raw_admin
    assert body["role"] == "admin"
    assert body["key_id"]
    # A brand-new tenant, never the operator's tenant nor the system default.
    assert body["tenant_id"] not in {OPERATOR_TENANT, "default"}
    assert body["tenant_id"]
    # The applied bounds are the conservative process defaults.
    assert body["quota"] == default_tenant_quotas()
    # One-time raw key material lives only in this body.
    assert "not be shown again" in body["message"].lower()


def test_two_invitations_get_distinct_non_colliding_tenants(invite_ctx):
    first = _create_invitation(invite_ctx, invite_ctx.raw_admin, organization="Acme Corp")
    second = _create_invitation(invite_ctx, invite_ctx.raw_admin, organization="Acme Corp")
    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["tenant_id"] != second.json()["tenant_id"]


# ── the minted key authenticates and is bounded by its default quota ─────────


def test_invited_key_authenticates_and_is_bounded_by_default_quota(invite_ctx):
    body = _create_invitation(invite_ctx, invite_ctx.raw_admin, organization="Acme").json()
    raw_key = body["raw_key"]
    tenant_id = body["tenant_id"]

    me = invite_ctx.client.get("/v1/auth/me", headers={"X-API-Key": raw_key})
    assert me.status_code == 200
    assert me.json()["role"] == "admin"
    assert me.json()["tenant_id"] == tenant_id

    quota = invite_ctx.client.get("/v1/auth/quota", headers={"X-API-Key": raw_key})
    assert quota.status_code == 200
    usage = quota.json()["usage"]
    defaults = default_tenant_quotas()
    for name, limit in defaults.items():
        assert usage[name]["limit"] == limit
        assert usage[name]["current"] == 0


# ── cross-tenant isolation: invited key sees only its own tenant ─────────────


def test_invited_key_cannot_see_operator_or_other_tenant_keys(invite_ctx):
    body = _create_invitation(invite_ctx, invite_ctx.raw_admin, organization="Acme").json()
    raw_key = body["raw_key"]
    tenant_id = body["tenant_id"]

    listed = invite_ctx.client.get("/v1/auth/keys", headers={"X-API-Key": raw_key})
    assert listed.status_code == 200
    keys = listed.json()["keys"]
    assert keys, "the invited tenant should see its own key"
    for key in keys:
        assert key["tenant_id"] == tenant_id
        assert key["key_id"] not in invite_ctx.operator_key_ids


# ── RBAC: only admin may mint invites ────────────────────────────────────────


def test_viewer_cannot_create_invitation(invite_ctx):
    resp = _create_invitation(invite_ctx, invite_ctx.raw_viewer, organization="Nope")
    assert resp.status_code == 403


def test_analyst_cannot_create_invitation(invite_ctx):
    resp = _create_invitation(invite_ctx, invite_ctx.raw_analyst, organization="Nope")
    assert resp.status_code == 403


def test_unauthenticated_invitation_is_rejected(invite_ctx):
    resp = invite_ctx.client.post("/v1/auth/invitations", json={"organization": "Nope"})
    assert resp.status_code == 401


# ── §11: no per-action credential/secret accepted or echoed ──────────────────


def test_invitation_rejects_per_action_secret(invite_ctx):
    before = len(invite_ctx.store.list_keys())
    resp = invite_ctx.client.post(
        "/v1/auth/invitations",
        json={"organization": "Acme", "provider_secret": "sk-live-should-be-rejected"},
        headers={"X-API-Key": invite_ctx.raw_admin},
    )
    # The unknown secret field is rejected outright (extra=forbid), not ignored.
    assert resp.status_code == 422
    assert "extra_forbidden" in resp.text
    assert "provider_secret" in resp.text
    # Nothing was minted for the rejected request — no key, no tenant.
    assert len(invite_ctx.store.list_keys()) == before


# ── invite link is opt-in and never carries the secret ───────────────────────


def test_invite_url_present_only_when_base_configured_and_carries_no_secret(invite_ctx, monkeypatch):
    without = _create_invitation(invite_ctx, invite_ctx.raw_admin, organization="Acme").json()
    assert without["invite_url"] is None

    monkeypatch.setenv("AGENT_BOM_HOSTED_INVITE_BASE_URL", "https://app.example.com")
    body = _create_invitation(invite_ctx, invite_ctx.raw_admin, organization="Acme").json()
    assert body["invite_url"] is not None
    parsed = urlparse(body["invite_url"])
    assert (parsed.scheme, parsed.netloc) == ("https", "app.example.com")
    assert parsed.path == "/login"
    assert body["tenant_id"] in parsed.path + "?" + parsed.query
    assert body["raw_key"] not in body["invite_url"]


@pytest.mark.parametrize("tenant,scopes", [("customer", ["*"]), (OPERATOR_TENANT, ["auth.keys:write"])])
def test_invitation_requires_operator_boundary_and_delegation_ceiling(invite_ctx, tenant, scopes):
    raw, key = create_api_key(name="restricted-admin", role=Role.ADMIN, scopes=scopes, tenant_id=tenant)
    invite_ctx.store.add(key)
    before = {item.key_id for item in invite_ctx.store.list_keys()}
    response = _create_invitation(invite_ctx, raw, organization="NotAuthorized")
    assert response.status_code == 403
    assert {item.key_id for item in invite_ctx.store.list_keys()} == before


def test_invited_admin_cannot_recursively_provision_tenants(invite_ctx):
    first = _create_invitation(invite_ctx, invite_ctx.raw_admin, organization="Customer").json()
    before = len(invite_ctx.store.list_keys())
    denied = _create_invitation(invite_ctx, first["raw_key"], organization="Recursive")
    assert denied.status_code == 403
    assert len(invite_ctx.store.list_keys()) == before


def test_invitation_has_attributable_receipts_in_both_tenants(invite_ctx, monkeypatch):
    from agent_bom.api import audit_log

    calls = []
    monkeypatch.setattr(audit_log, "log_action", lambda action, **kwargs: calls.append({"action": action, **kwargs}))
    response = _create_invitation(invite_ctx, invite_ctx.raw_admin, organization="Customer")
    assert response.status_code == 201
    body = response.json()
    receipts = [entry for entry in calls if entry["action"].startswith("auth.invitation_")]
    assert {entry["tenant_id"] for entry in receipts} == {OPERATOR_TENANT, body["tenant_id"]}
    assert all(entry["actor_tenant_id"] == OPERATOR_TENANT and entry["actor_key_id"] for entry in receipts)
    assert body["raw_key"] not in str(calls)


def test_audit_write_failure_does_not_provision_an_invitation(invite_ctx, monkeypatch):
    from agent_bom.api import audit_log

    before = len(invite_ctx.store.list_keys())

    def unavailable(*args, **kwargs):
        raise RuntimeError("private-connection-secret")

    monkeypatch.setattr(audit_log, "log_action", unavailable)
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post("/v1/auth/invitations", json={"organization": "Customer"}, headers={"X-API-Key": invite_ctx.raw_admin})
    assert response.status_code == 503
    assert "private-connection-secret" not in response.text
    assert len(invite_ctx.store.list_keys()) == before


def test_second_audit_write_failure_leaves_history_but_no_key(invite_ctx, monkeypatch):
    from agent_bom.api import audit_log

    calls = []

    def append(action, **details):
        if calls:
            raise RuntimeError("unavailable")
        calls.append({"action": action, **details})

    monkeypatch.setattr(audit_log, "log_action", append)
    before = len(invite_ctx.store.list_keys())
    response = _create_invitation(invite_ctx, invite_ctx.raw_admin, organization="Customer")
    assert response.status_code == 503
    assert len(invite_ctx.store.list_keys()) == before
    assert len(calls) == 1 and calls[0]["action"] == "auth.invitation_authorized"


def test_sqlite_invitation_audit_survives_restart_without_cross_tenant_reads(invite_ctx, monkeypatch, tmp_path):
    from agent_bom.api import audit_log

    path = str(tmp_path / "audit.sqlite")
    audit = audit_log.SQLiteAuditLog(path, hmac_key=b"isolated-test-key")
    monkeypatch.setattr(audit_log, "get_audit_log", lambda: audit)
    body = _create_invitation(invite_ctx, invite_ctx.raw_admin, organization="Customer").json()
    restarted = audit_log.SQLiteAuditLog(path, hmac_key=b"isolated-test-key")
    for tenant in (OPERATOR_TENANT, body["tenant_id"]):
        entries = restarted.list_entries(action="auth.invitation_authorized", tenant_id=tenant)
        assert len(entries) == 1
        assert entries[0].details["actor_tenant_id"] == OPERATOR_TENANT
        assert entries[0].details["actor_key_id"]
        assert body["raw_key"] not in str(entries[0].details)
    assert restarted.list_entries(tenant_id="unrelated") == []


@pytest.mark.skipif(not __import__("os").environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires isolated live Postgres")
def test_live_postgres_invitation_audit_and_key_persistence(monkeypatch):
    from uuid import uuid4

    from starlette.requests import Request

    from agent_bom.api import audit_log, postgres_common
    from agent_bom.api.invitation_provisioning import provision_invited_key
    from agent_bom.api.postgres_access import PostgresKeyStore
    from agent_bom.api.postgres_audit import PostgresAuditLog

    postgres_common.reset_pool()
    destination = "invited-" + uuid4().hex
    operator = "operator-" + uuid4().hex
    request = Request({"type": "http"})
    request.state.tenant_id = operator
    request.state.api_key_name = "operator-admin"
    request.state.api_key_id = "operator-key"
    raw, key = create_api_key(name="invited-owner", role=Role.ADMIN, scopes=["*"], tenant_id=destination)
    store = PostgresKeyStore()
    audit = PostgresAuditLog()
    monkeypatch.setattr(audit_log, "get_audit_log", lambda: audit)
    monkeypatch.setattr("agent_bom.api.invitation_provisioning.get_key_store", lambda: store)
    token = postgres_common.set_current_tenant(operator)
    try:
        with store._pool.connection() as conn:
            assert conn.execute("SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user").fetchone() == (False, False)
        provision_invited_key(request, key, team_name="Invited")
        postgres_common.reset_pool()
        store = PostgresKeyStore()
        audit = PostgresAuditLog()
        for tenant in (operator, destination):
            receipts = audit.list_entries(action="auth.invitation_authorized", tenant_id=tenant)
            assert len(receipts) == 1 and receipts[0].details["actor_tenant_id"] == operator
            assert receipts[0].details["actor_key_id"] == "operator-key"
            assert raw not in str(receipts)
        with store._pool.connection() as conn:
            conn.execute("SELECT set_config('app.tenant_id', %s, true)", (destination,))
            assert conn.execute("SELECT count(*) FROM api_keys WHERE key_id=%s", (key.key_id,)).fetchone()[0] == 1
            conn.execute("SELECT set_config('app.tenant_id', %s, true)", (operator,))
            assert conn.execute("SELECT count(*) FROM api_keys WHERE key_id=%s", (key.key_id,)).fetchone()[0] == 0
    finally:
        postgres_common.reset_pool()
        postgres_common.reset_current_tenant(token)
