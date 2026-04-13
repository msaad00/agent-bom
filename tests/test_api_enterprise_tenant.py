"""Tenant isolation tests for enterprise auth and exception routes."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from agent_bom.api.auth import KeyStore, Role, create_api_key, get_key_store, set_key_store
from agent_bom.api.exception_store import InMemoryExceptionStore, VulnException
from agent_bom.api.models import CreateKeyRequest
from agent_bom.api.routes import enterprise


def _request(tenant_id: str, api_key_name: str = "tenant-admin") -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(tenant_id=tenant_id, api_key_name=api_key_name))


@pytest.fixture
def isolated_key_store():
    original = get_key_store()
    store = KeyStore()
    set_key_store(store)
    try:
        yield store
    finally:
        set_key_store(original)


@pytest.fixture
def isolated_exception_store(monkeypatch):
    store = InMemoryExceptionStore()
    monkeypatch.setattr(enterprise, "_get_exception_store", lambda: store)
    return store


@pytest.mark.asyncio
async def test_create_key_uses_authenticated_tenant(isolated_key_store):
    created = await enterprise.create_key(
        _request("tenant-alpha"),
        CreateKeyRequest(name="alpha-analyst", role="analyst"),
    )

    assert created["tenant_id"] == "tenant-alpha"
    keys = isolated_key_store.list_keys("tenant-alpha")
    assert len(keys) == 1
    assert keys[0].tenant_id == "tenant-alpha"


@pytest.mark.asyncio
async def test_list_keys_only_returns_current_tenant(isolated_key_store):
    _, alpha = create_api_key("alpha", Role.ADMIN, tenant_id="tenant-alpha")
    _, beta = create_api_key("beta", Role.ADMIN, tenant_id="tenant-beta")
    isolated_key_store.add(alpha)
    isolated_key_store.add(beta)

    result = await enterprise.list_keys(_request("tenant-alpha"))

    assert [k["name"] for k in result["keys"]] == ["alpha"]
    assert result["keys"][0]["tenant_id"] == "tenant-alpha"


@pytest.mark.asyncio
async def test_delete_key_returns_404_for_cross_tenant_key(isolated_key_store):
    _, beta = create_api_key("beta", Role.ADMIN, tenant_id="tenant-beta")
    isolated_key_store.add(beta)

    with pytest.raises(HTTPException) as exc:
        await enterprise.delete_key(_request("tenant-alpha"), beta.key_id)

    assert exc.value.status_code == 404
    assert isolated_key_store.get(beta.key_id) is not None


@pytest.mark.asyncio
async def test_get_exception_returns_404_for_cross_tenant(isolated_exception_store):
    exc = VulnException(vuln_id="CVE-1", package_name="pkg", tenant_id="tenant-beta")
    isolated_exception_store.put(exc)

    with pytest.raises(HTTPException) as error:
        await enterprise.get_exception(_request("tenant-alpha"), exc.exception_id)

    assert error.value.status_code == 404


@pytest.mark.asyncio
async def test_approve_exception_uses_request_actor_and_tenant(isolated_exception_store):
    exc = VulnException(vuln_id="CVE-1", package_name="pkg", tenant_id="tenant-alpha")
    isolated_exception_store.put(exc)

    approved = await enterprise.approve_exception(_request("tenant-alpha", "alice-admin"), exc.exception_id)

    assert approved["approved_by"] == "alice-admin"
    assert approved["status"] == "active"


@pytest.mark.asyncio
async def test_revoke_exception_returns_404_for_cross_tenant(isolated_exception_store):
    exc = VulnException(vuln_id="CVE-1", package_name="pkg", tenant_id="tenant-beta")
    isolated_exception_store.put(exc)

    with pytest.raises(HTTPException) as error:
        await enterprise.revoke_exception(_request("tenant-alpha"), exc.exception_id)

    assert error.value.status_code == 404


@pytest.mark.asyncio
async def test_delete_exception_returns_404_for_cross_tenant(isolated_exception_store):
    exc = VulnException(vuln_id="CVE-1", package_name="pkg", tenant_id="tenant-beta")
    isolated_exception_store.put(exc)

    with pytest.raises(HTTPException) as error:
        await enterprise.delete_exception(_request("tenant-alpha"), exc.exception_id)

    assert error.value.status_code == 404
    assert isolated_exception_store.get(exc.exception_id) is not None


@pytest.mark.asyncio
async def test_create_jira_ticket_requires_header_token(monkeypatch):
    req = enterprise.JiraTicketRequest(
        jira_url="https://example.atlassian.net",
        email="user@example.com",
        project_key="SEC",
        finding={"vulnerability_id": "CVE-1", "package": "pkg"},
    )

    with pytest.raises(HTTPException) as error:
        await enterprise.create_jira_ticket_route(req, jira_api_token=None)

    assert error.value.status_code == 400
    assert "X-Jira-Api-Token" in error.value.detail


@pytest.mark.asyncio
async def test_create_jira_ticket_uses_header_token(monkeypatch):
    req = enterprise.JiraTicketRequest(
        jira_url="https://example.atlassian.net",
        email="user@example.com",
        project_key="SEC",
        finding={"vulnerability_id": "CVE-1", "package": "pkg"},
    )
    captured: dict[str, str] = {}

    async def fake_create_jira_ticket(*, jira_url: str, email: str, api_token: str, project_key: str, finding: dict):
        captured.update(
            {
                "jira_url": jira_url,
                "email": email,
                "api_token": api_token,
                "project_key": project_key,
                "vuln_id": finding["vulnerability_id"],
            }
        )
        return "SEC-42"

    monkeypatch.setattr("agent_bom.integrations.jira.create_jira_ticket", fake_create_jira_ticket)

    result = await enterprise.create_jira_ticket_route(req, jira_api_token="token-abc")

    assert result == {"ticket_key": "SEC-42", "status": "created"}
    assert captured["api_token"] == "token-abc"
    assert captured["project_key"] == "SEC"


@pytest.mark.asyncio
async def test_remove_false_positive_returns_404_for_wrong_tenant(isolated_exception_store):
    exc = VulnException(
        vuln_id="CVE-1",
        package_name="pkg",
        reason="[false_positive] expected noise",
        tenant_id="tenant-beta",
    )
    isolated_exception_store.put(exc)

    with pytest.raises(HTTPException) as error:
        await enterprise.remove_false_positive(_request("tenant-alpha"), exc.exception_id)

    assert error.value.status_code == 404
    assert isolated_exception_store.get(exc.exception_id) is not None
