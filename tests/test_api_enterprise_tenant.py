"""Tenant isolation tests for enterprise auth and exception routes."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from agent_bom.api.audit_log import AuditEntry, InMemoryAuditLog
from agent_bom.api.auth import KeyStore, Role, create_api_key, get_key_store, set_key_store
from agent_bom.api.exception_store import InMemoryExceptionStore, VulnException
from agent_bom.api.models import CreateKeyRequest, JobStatus, RotateKeyRequest, ScanJob, ScanRequest
from agent_bom.api.routes import enterprise
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import _get_store, _get_trend_store, set_job_store, set_trend_store
from agent_bom.baseline import InMemoryTrendStore, TrendPoint


def _request(tenant_id: str, api_key_name: str = "tenant-admin") -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(tenant_id=tenant_id, api_key_name=api_key_name))


@pytest.fixture
def isolated_job_store():
    original = _get_store()
    store = InMemoryJobStore()
    set_job_store(store)
    try:
        yield store
    finally:
        set_job_store(original)


@pytest.fixture
def isolated_trend_store():
    original = _get_trend_store()
    store = InMemoryTrendStore()
    set_trend_store(store)
    try:
        yield store
    finally:
        set_trend_store(original)


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
    assert created["expires_at"]
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
async def test_rotate_key_replaces_old_key_and_revokes_previous(isolated_key_store):
    raw, alpha = create_api_key("alpha", Role.ADMIN, tenant_id="tenant-alpha")
    isolated_key_store.add(alpha)

    result = await enterprise.rotate_key(_request("tenant-alpha", "alice-admin"), alpha.key_id, RotateKeyRequest())

    assert result["replaced_key_id"] == alpha.key_id
    assert result["tenant_id"] == "tenant-alpha"
    assert result["expires_at"]
    assert isolated_key_store.get(alpha.key_id) is None
    assert isolated_key_store.verify(raw) is None
    assert isolated_key_store.verify(result["raw_key"]) is not None


@pytest.mark.asyncio
async def test_rotate_key_returns_404_for_cross_tenant_key(isolated_key_store):
    _, beta = create_api_key("beta", Role.ADMIN, tenant_id="tenant-beta")
    isolated_key_store.add(beta)

    with pytest.raises(HTTPException) as exc:
        await enterprise.rotate_key(_request("tenant-alpha"), beta.key_id, RotateKeyRequest())

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
        await enterprise.create_jira_ticket_route(_request("tenant-alpha"), req, jira_api_token=None)

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

    result = await enterprise.create_jira_ticket_route(_request("tenant-alpha"), req, jira_api_token="token-abc")

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


@pytest.mark.asyncio
async def test_export_audit_entries_returns_signed_json(monkeypatch):
    store = InMemoryAuditLog()
    store.append(AuditEntry(action="scan", actor="alice", resource="job/1", details={"packages": 5, "tenant_id": "tenant-alpha"}))
    store.append(AuditEntry(action="scan", actor="bob", resource="job/2", details={"packages": 7, "tenant_id": "tenant-beta"}))
    monkeypatch.setattr("agent_bom.api.audit_log.get_audit_log", lambda: store)

    response = await enterprise.export_audit_entries(_request("tenant-alpha", "alice-admin"))

    payload = json.loads(response.body.decode())
    assert payload["tenant_id"] == "tenant-alpha"
    assert len(payload["entries"]) == 1
    assert payload["entries"][0]["action"] == "scan"
    assert payload["entries"][0]["details"]["tenant_id"] == "tenant-alpha"
    assert response.headers["x-agent-bom-audit-export-signature"]
    assert response.headers["content-disposition"].endswith('agent-bom-audit-export.json"')


@pytest.mark.asyncio
async def test_export_audit_entries_supports_jsonl(monkeypatch):
    store = InMemoryAuditLog()
    store.append(AuditEntry(action="scan", actor="alice", resource="job/1", details={"tenant_id": "tenant-alpha"}))
    store.append(AuditEntry(action="scan", actor="bob", resource="job/2", details={"tenant_id": "tenant-beta"}))
    monkeypatch.setattr("agent_bom.api.audit_log.get_audit_log", lambda: store)

    response = await enterprise.export_audit_entries(_request("tenant-alpha", "alice-admin"), format="jsonl")

    lines = [line for line in response.body.decode().splitlines() if line]
    assert len(lines) == 1
    assert json.loads(lines[0])["resource"] == "job/1"
    assert response.media_type == "application/x-ndjson"


@pytest.mark.asyncio
async def test_list_audit_entries_and_integrity_are_tenant_scoped(monkeypatch):
    store = InMemoryAuditLog()
    store.append(AuditEntry(action="scan", actor="alice", resource="job/alpha", details={"tenant_id": "tenant-alpha"}))
    store.append(AuditEntry(action="scan", actor="bob", resource="job/beta", details={"tenant_id": "tenant-beta"}))
    monkeypatch.setattr("agent_bom.api.audit_log.get_audit_log", lambda: store)

    listed = await enterprise.list_audit_entries(_request("tenant-alpha"))
    integrity = await enterprise.audit_integrity(_request("tenant-alpha"))

    assert listed["total"] == 1
    assert [entry["resource"] for entry in listed["entries"]] == ["job/alpha"]
    assert integrity == {"verified": 1, "tampered": 0, "checked": 1}


@pytest.mark.asyncio
async def test_export_audit_entries_rejects_unknown_format():
    with pytest.raises(HTTPException) as error:
        await enterprise.export_audit_entries(_request("tenant-alpha"), format="csv")

    assert error.value.status_code == 400


@pytest.mark.asyncio
async def test_compare_baseline_is_tenant_scoped(isolated_job_store):
    alpha_job = ScanJob(
        job_id="job-alpha",
        tenant_id="tenant-alpha",
        status=JobStatus.DONE,
        created_at="2026-04-20T00:00:00Z",
        completed_at="2026-04-20T00:01:00Z",
        request=ScanRequest(),
        result={"blast_radius": [{"vulnerability_id": "CVE-alpha", "package": "alpha@1.0.0", "severity": "high"}]},
    )
    beta_job = ScanJob(
        job_id="job-beta",
        tenant_id="tenant-beta",
        status=JobStatus.DONE,
        created_at="2026-04-20T00:00:00Z",
        completed_at="2026-04-20T00:01:00Z",
        request=ScanRequest(),
        result={"blast_radius": [{"vulnerability_id": "CVE-beta", "package": "beta@1.0.0", "severity": "critical"}]},
    )
    isolated_job_store.put(alpha_job)
    isolated_job_store.put(beta_job)

    diff = await enterprise.compare_baseline(_request("tenant-alpha"), previous_job_id="job-alpha")
    assert diff["persistent_count"] == 0
    assert diff["resolved_count"] == 1

    with pytest.raises(HTTPException) as error:
        await enterprise.compare_baseline(_request("tenant-alpha"), previous_job_id="job-beta")

    assert error.value.status_code == 404


@pytest.mark.asyncio
async def test_get_trends_is_tenant_scoped(isolated_trend_store):
    isolated_trend_store.record(
        TrendPoint(
            timestamp="2026-04-20T00:00:00Z",
            total_vulns=5,
            critical=1,
            high=2,
            medium=1,
            low=1,
            posture_score=72.0,
            posture_grade="C",
            tenant_id="tenant-alpha",
        )
    )
    isolated_trend_store.record(
        TrendPoint(
            timestamp="2026-04-20T01:00:00Z",
            total_vulns=1,
            critical=0,
            high=1,
            medium=0,
            low=0,
            posture_score=91.0,
            posture_grade="A",
            tenant_id="tenant-beta",
        )
    )

    result = await enterprise.get_trends(_request("tenant-alpha"), limit=30)
    assert result["count"] == 1
    assert result["data_points"][0]["total_vulns"] == 5
