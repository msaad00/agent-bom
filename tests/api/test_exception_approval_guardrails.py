"""Suppression approvals are bounded in time and need a second principal."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores
from agent_bom.api.auth import KeyStore, Role, create_api_key, get_key_store, set_key_store
from agent_bom.api.exception_store import ExceptionStatus, InMemoryExceptionStore, VulnException
from agent_bom.api.server import app, configure_api

FAR_FUTURE = "9999-12-31T00:00:00+00:00"


def _in_days(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


@pytest.fixture
def ctx(monkeypatch):
    for name in ("AGENT_BOM_EXCEPTION_MAX_EXPIRY_DAYS", "AGENT_BOM_EXCEPTION_ALLOW_SELF_APPROVAL", "AGENT_BOM_ALLOW_UNAUTHENTICATED_API"):
        monkeypatch.delenv(name, raising=False)
    old_keys = get_key_store()
    old_exceptions = stores._get_exception_store()
    keys = KeyStore()
    exceptions = InMemoryExceptionStore()
    set_key_store(keys)
    stores.set_exception_store(exceptions)
    raw_alice, alice = create_api_key(name="alice", role=Role.ADMIN, scopes=["*"], tenant_id="tenant-a")
    raw_bob, bob = create_api_key(name="bob", role=Role.ADMIN, scopes=["*"], tenant_id="tenant-a")
    raw_carol, carol = create_api_key(name="carol", role=Role.ADMIN, scopes=["*"], tenant_id="tenant-a")
    for key in (alice, bob, carol):
        keys.add(key)
    configure_api(api_key=None, allow_unauthenticated=False)
    try:
        yield SimpleNamespace(
            client=TestClient(app),
            store=exceptions,
            alice={"X-API-Key": raw_alice},
            bob={"X-API-Key": raw_bob},
            carol={"X-API-Key": raw_carol},
        )
    finally:
        set_key_store(old_keys)
        stores.set_exception_store(old_exceptions)
        configure_api(api_key=None)


def _create(ctx, expires_at: str, headers=None):
    return ctx.client.post(
        "/v1/exceptions",
        json={"vuln_id": "CVE-2024-1", "package_name": "demo", "reason": "accepted risk", "expires_at": expires_at},
        headers=headers or ctx.alice,
    )


def test_create_rejects_expiry_beyond_default_window(ctx):
    response = _create(ctx, FAR_FUTURE)

    assert response.status_code == 422, response.text
    assert "365 days" in response.text
    assert ctx.store.list_all(tenant_id="tenant-a") == []


def test_create_honours_configured_window(ctx, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_EXCEPTION_MAX_EXPIRY_DAYS", "14")

    assert _create(ctx, _in_days(30)).status_code == 422
    assert _create(ctx, _in_days(7)).status_code == 201


@pytest.mark.parametrize(
    "path,body",
    [
        ("findings/feedback", {"vulnerability_id": "CVE-2024-1", "package": "demo", "state": "accepted_risk"}),
        (
            "findings/triage",
            {
                "vulnerability_id": "CVE-2024-1",
                "package": "demo",
                "decision": "not_affected",
                "justification": "vulnerable_code_not_present",
            },
        ),
    ],
)
def test_other_suppression_requests_share_the_window(ctx, path, body):
    response = ctx.client.post("/v1/" + path, json={**body, "expires_at": FAR_FUTURE}, headers=ctx.alice)

    assert response.status_code == 422, response.text
    assert ctx.store.list_all(tenant_id="tenant-a") == []


def test_approve_rejects_expiry_beyond_window(ctx):
    exception_id = _create(ctx, _in_days(30)).json()["exception_id"]

    response = ctx.client.put(f"/v1/exceptions/{exception_id}/approve", json={"expires_at": FAR_FUTURE}, headers=ctx.bob)

    assert response.status_code == 400, response.text
    assert "365 days" in response.json()["detail"]
    stored = ctx.store.get(exception_id, tenant_id="tenant-a")
    assert stored.status is ExceptionStatus.PENDING
    assert not stored.approved_by


def test_approve_rejects_preexisting_row_beyond_window(ctx):
    exc = VulnException(vuln_id="CVE-2024-1", package_name="demo", requested_by="carol", expires_at=FAR_FUTURE, tenant_id="tenant-a")
    ctx.store.put(exc, tenant_id="tenant-a")

    response = ctx.client.put(f"/v1/exceptions/{exc.exception_id}/approve", headers=ctx.bob)

    assert response.status_code == 400, response.text
    assert ctx.store.get(exc.exception_id, tenant_id="tenant-a").status is ExceptionStatus.PENDING


def test_requester_cannot_approve_their_own_exception(ctx):
    exception_id = _create(ctx, _in_days(30)).json()["exception_id"]

    response = ctx.client.put(f"/v1/exceptions/{exception_id}/approve", headers=ctx.alice)

    assert response.status_code == 403, response.text
    assert "different approver" in response.json()["detail"]
    assert ctx.store.get(exception_id, tenant_id="tenant-a").status is ExceptionStatus.PENDING
    approved = ctx.client.put(f"/v1/exceptions/{exception_id}/approve", headers=ctx.bob)
    assert approved.status_code == 200, approved.text
    assert approved.json()["approved_by"] == "bob"
    assert approved.json()["suppression_active"] is True


def test_single_operator_setting_allows_self_approval(ctx, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_EXCEPTION_ALLOW_SELF_APPROVAL", "1")
    exception_id = _create(ctx, _in_days(30)).json()["exception_id"]

    response = ctx.client.put(f"/v1/exceptions/{exception_id}/approve", headers=ctx.alice)

    assert response.status_code == 200, response.text
    assert response.json()["approved_by"] == "alice"


def test_triage_decision_update_shares_the_window(ctx):
    created = ctx.client.post(
        "/v1/findings/triage",
        json={"vulnerability_id": "CVE-2024-1", "package": "demo", "decision": "under_investigation"},
        headers=ctx.alice,
    )
    assert created.status_code == 201, created.text

    response = ctx.client.put(
        f"/v1/findings/triage/{created.json()['id']}/decision",
        json={"decision": "not_affected", "justification": "vulnerable_code_not_present", "expires_at": FAR_FUTURE},
        headers=ctx.alice,
    )

    assert response.status_code == 422, response.text
    assert ctx.store.get(created.json()["id"], tenant_id="tenant-a").expires_at == ""


def _mcp(coro) -> dict:
    return json.loads(asyncio.run(coro))


def test_mcp_surfaces_window_and_four_eyes_errors(ctx, monkeypatch):
    from agent_bom.mcp_tools import exceptions as mcp_exceptions

    monkeypatch.setattr(mcp_exceptions, "resolve_mcp_tool_tenant_id", lambda tenant_id: "tenant-a")
    common = {"_truncate_response": lambda text: text, "_authenticated_actor": "alice"}
    too_far = _mcp(
        mcp_exceptions.request_exception_impl(
            vulnerability_id="CVE-2024-1", package_name="demo", exception_reason="accepted business risk", expires_at=FAR_FUTURE, **common
        )
    )
    assert too_far["status"] == "rejected"
    assert "365 days" in too_far["error"]

    created = _mcp(
        mcp_exceptions.request_exception_impl(
            vulnerability_id="CVE-2024-1", package_name="demo", exception_reason="accepted business risk", expires_at=_in_days(30), **common
        )
    )
    self_approved = _mcp(mcp_exceptions.approve_exception_impl(exception_id=created["exception_id"], **common))
    assert self_approved["status"] == "rejected"
    assert "different approver" in self_approved["error"]

    approved = _mcp(
        mcp_exceptions.approve_exception_impl(
            exception_id=created["exception_id"], _truncate_response=lambda text: text, _authenticated_actor="bob"
        )
    )
    assert approved["approved_by"] == "bob"


def _triage_opened_by_bob(ctx) -> str:
    created = ctx.client.post(
        "/v1/findings/triage",
        json={"vulnerability_id": "CVE-2024-1", "package": "demo", "decision": "under_investigation"},
        headers=ctx.bob,
    )
    assert created.status_code == 201, created.text
    return created.json()["id"]


def _alice_decides_not_affected(ctx, triage_id: str) -> dict:
    decided = ctx.client.put(
        f"/v1/findings/triage/{triage_id}/decision",
        json={"decision": "not_affected", "justification": "vulnerable_code_not_present", "expires_at": _in_days(30)},
        headers=ctx.alice,
    )
    assert decided.status_code == 200, decided.text
    return decided.json()


def test_decision_author_cannot_approve_a_decision_on_another_requesters_item(ctx):
    triage_id = _triage_opened_by_bob(ctx)
    body = _alice_decides_not_affected(ctx, triage_id)
    assert body["created_by"] == "bob"
    assert body["decided_by"] == "alice"
    assert body["approval_required"] is True

    self_approved = ctx.client.put(f"/v1/exceptions/{triage_id}/approve", headers=ctx.alice)

    assert self_approved.status_code == 403, self_approved.text
    assert "different approver" in self_approved.json()["detail"]
    stored = ctx.store.get(triage_id, tenant_id="tenant-a")
    assert stored.status is ExceptionStatus.PENDING
    assert (stored.requested_by, stored.decided_by, stored.approved_by) == ("bob", "alice", "")
    assert ctx.client.put(f"/v1/exceptions/{triage_id}/approve", headers=ctx.bob).status_code == 403

    approved = ctx.client.put(f"/v1/exceptions/{triage_id}/approve", headers=ctx.carol)
    assert approved.status_code == 200, approved.text
    assert approved.json()["approved_by"] == "carol"
    assert approved.json()["decided_by"] == "alice"
    listed = ctx.client.get("/v1/findings/triage", headers=ctx.carol).json()["triage"]
    assert [(row["created_by"], row["decided_by"], row["vex_eligible"]) for row in listed] == [("bob", "alice", True)]


def test_mcp_approval_rejects_the_decision_author(ctx, monkeypatch):
    from agent_bom.mcp_tools import exceptions as mcp_exceptions

    monkeypatch.setattr(mcp_exceptions, "resolve_mcp_tool_tenant_id", lambda tenant_id: "tenant-a")
    triage_id = _triage_opened_by_bob(ctx)
    _alice_decides_not_affected(ctx, triage_id)

    rejected = _mcp(
        mcp_exceptions.approve_exception_impl(exception_id=triage_id, _truncate_response=lambda text: text, _authenticated_actor="alice")
    )

    assert rejected["status"] == "rejected"
    assert "different approver" in rejected["error"]
    assert ctx.store.get(triage_id, tenant_id="tenant-a").status is ExceptionStatus.PENDING
    approved = _mcp(
        mcp_exceptions.approve_exception_impl(exception_id=triage_id, _truncate_response=lambda text: text, _authenticated_actor="carol")
    )
    assert approved["approved_by"] == "carol"


def test_vex_ingest_author_cannot_approve_the_ingested_decision(ctx):
    triage_id = _triage_opened_by_bob(ctx)
    vex = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://example.invalid/vex/1",
        "author": "alice",
        "timestamp": "2026-01-01T00:00:00Z",
        "version": 1,
        "statements": [
            {
                "vulnerability": {"name": "CVE-2024-1"},
                "status": "not_affected",
                "justification": "vulnerable_code_not_present",
                "products": [{"@id": "demo"}],
            }
        ],
    }
    ingested = ctx.client.post("/v1/findings/triage/vex/ingest", json={"vex": vex}, headers=ctx.alice)
    assert ingested.status_code == 201, ingested.text
    assert ingested.json()["applied"] == 1
    stored = ctx.store.get(triage_id, tenant_id="tenant-a")
    assert (stored.requested_by, stored.decided_by) == ("bob", "alice")

    response = ctx.client.put(f"/v1/exceptions/{triage_id}/approve", json={"expires_at": _in_days(30)}, headers=ctx.alice)

    assert response.status_code == 403, response.text
    assert ctx.store.get(triage_id, tenant_id="tenant-a").status is ExceptionStatus.PENDING


def test_sqlite_store_persists_decision_author_and_upgrades_legacy_tables(tmp_path):
    import sqlite3

    from agent_bom.api.exception_store import SQLiteExceptionStore

    db_path = tmp_path / "exceptions.db"
    legacy = sqlite3.connect(db_path)
    legacy.execute(
        "CREATE TABLE exceptions (exception_id TEXT PRIMARY KEY, vuln_id TEXT NOT NULL, package_name TEXT NOT NULL, "
        "server_name TEXT NOT NULL DEFAULT '', reason TEXT NOT NULL DEFAULT '', requested_by TEXT NOT NULL DEFAULT '', "
        "approved_by TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL, "
        "expires_at TEXT NOT NULL DEFAULT '', approved_at TEXT NOT NULL DEFAULT '', revoked_at TEXT NOT NULL DEFAULT '', "
        "tenant_id TEXT NOT NULL DEFAULT 'default', approval_version INTEGER NOT NULL DEFAULT 0)"
    )
    legacy.execute(
        "INSERT INTO exceptions (exception_id, vuln_id, package_name, requested_by, created_at, tenant_id) VALUES (?, ?, ?, ?, ?, ?)",
        ("exc-legacy", "CVE-2024-1", "demo", "bob", "2026-01-01T00:00:00+00:00", "tenant-a"),
    )
    legacy.commit()
    legacy.close()

    store = SQLiteExceptionStore(str(db_path))
    upgraded = store.get("exc-legacy", tenant_id="tenant-a")
    assert (upgraded.requested_by, upgraded.decided_by) == ("bob", "")

    upgraded.decided_by = "alice"
    store.put(upgraded, tenant_id="tenant-a")
    reopened = SQLiteExceptionStore(str(db_path))
    assert reopened.get("exc-legacy", tenant_id="tenant-a").decided_by == "alice"
    assert [row.decided_by for row in reopened.list_all(tenant_id="tenant-a")] == ["alice"]


def test_reset_requires_a_decision_author():
    from agent_bom.api.suppression_approval import reset_suppression_request

    exc = VulnException(vuln_id="CVE-2024-1", package_name="demo", requested_by="bob", tenant_id="tenant-a")
    with pytest.raises(ValueError, match="decision author"):
        reset_suppression_request(exc, decided_by="  ")
