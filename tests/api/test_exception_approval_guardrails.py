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
    keys.add(alice)
    keys.add(bob)
    configure_api(api_key=None, allow_unauthenticated=False)
    try:
        yield SimpleNamespace(client=TestClient(app), store=exceptions, alice={"X-API-Key": raw_alice}, bob={"X-API-Key": raw_bob})
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
