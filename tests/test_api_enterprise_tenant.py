"""Tenant isolation tests for enterprise auth and exception routes."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from agent_bom.api.audit_log import AuditEntry, InMemoryAuditLog, get_audit_log, set_audit_log
from agent_bom.api.auth import KeyStore, Role, create_api_key, get_key_store, set_key_store
from agent_bom.api.exception_store import ExceptionStatus, InMemoryExceptionStore, VulnException
from agent_bom.api.models import CreateKeyRequest, FindingFeedbackRequest, JobStatus, RotateKeyRequest, ScanJob, ScanRequest
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


@pytest.fixture
def isolated_audit_log():
    original = get_audit_log()
    store = InMemoryAuditLog()
    set_audit_log(store)
    try:
        yield store
    finally:
        set_audit_log(original)


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
async def test_rotate_key_replaces_old_key_and_preserves_overlap_window(isolated_key_store):
    raw, alpha = create_api_key("alpha", Role.ADMIN, tenant_id="tenant-alpha")
    isolated_key_store.add(alpha)

    result = await enterprise.rotate_key(
        _request("tenant-alpha", "alice-admin"),
        alpha.key_id,
        RotateKeyRequest(overlap_seconds=300),
    )

    assert result["replaced_key_id"] == alpha.key_id
    assert result["tenant_id"] == "tenant-alpha"
    assert result["expires_at"]
    assert result["overlap_seconds"] == 300
    previous = isolated_key_store.get(alpha.key_id)
    assert previous is not None
    assert previous.replacement_key_id == result["key_id"]
    assert isolated_key_store.verify(raw) is not None
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
async def test_revoke_exception_uses_authenticated_actor(isolated_exception_store):
    exc = VulnException(vuln_id="CVE-1", package_name="pkg", tenant_id="tenant-alpha")
    exc.status = ExceptionStatus.ACTIVE
    isolated_exception_store.put(exc)

    revoked = await enterprise.revoke_exception(_request("tenant-alpha", "alice-admin"), exc.exception_id)

    assert revoked["status"] == "revoked"


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
async def test_delete_exception_audit_logs_actor_and_tenant(isolated_exception_store, isolated_audit_log):
    exc = VulnException(vuln_id="CVE-1", package_name="pkg", tenant_id="tenant-alpha")
    isolated_exception_store.put(exc)

    await enterprise.delete_exception(_request("tenant-alpha", "alice-admin"), exc.exception_id)

    entries = isolated_audit_log.list_entries()
    assert entries[0].action == "exception_delete"
    assert entries[0].actor == "alice-admin"
    assert entries[0].details["tenant_id"] == "tenant-alpha"


@pytest.mark.asyncio
async def test_delete_exception_passes_tenant_to_store(monkeypatch):
    class RecordingExceptionStore:
        def __init__(self) -> None:
            self.get_calls: list[tuple[str, str | None]] = []
            self.delete_calls: list[tuple[str, str | None]] = []
            self.exc = VulnException(vuln_id="CVE-1", package_name="pkg", tenant_id="tenant-alpha")

        def put(self, exc: VulnException) -> None:
            self.exc = exc

        def get(self, exception_id: str, tenant_id: str | None = None) -> VulnException | None:
            self.get_calls.append((exception_id, tenant_id))
            if exception_id != self.exc.exception_id or tenant_id != self.exc.tenant_id:
                return None
            return self.exc

        def delete(self, exception_id: str, tenant_id: str | None = None) -> bool:
            self.delete_calls.append((exception_id, tenant_id))
            return exception_id == self.exc.exception_id and tenant_id == self.exc.tenant_id

        def list_all(self, status: str | None = None, tenant_id: str = "default"):
            return []

        def find_matching(self, vuln_id: str, package_name: str, server_name: str = "", tenant_id: str = "default"):
            return None

    store = RecordingExceptionStore()
    monkeypatch.setattr(enterprise, "_get_exception_store", lambda: store)

    await enterprise.delete_exception(_request("tenant-alpha", "alice-admin"), store.exc.exception_id)

    assert store.get_calls == [(store.exc.exception_id, "tenant-alpha")]
    assert store.delete_calls == [(store.exc.exception_id, "tenant-alpha")]


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
async def test_siem_test_logs_attempt(monkeypatch, isolated_audit_log):
    class _FakeConnector:
        def health_check(self):
            return True

    monkeypatch.setattr("agent_bom.security.validate_url", lambda url: None)
    monkeypatch.setattr("agent_bom.siem.create_connector", lambda *args, **kwargs: _FakeConnector())

    result = await enterprise.test_siem_connection(
        _request("tenant-alpha", "alice-admin"),
        siem_type="splunk",
        url="https://siem.example.com",
        token="secret",
    )

    assert result == {"siem_type": "splunk", "healthy": True}
    entries = isolated_audit_log.list_entries()
    assert entries[0].action == "siem.test"
    assert entries[0].actor == "alice-admin"
    assert entries[0].details["tenant_id"] == "tenant-alpha"


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
async def test_finding_feedback_uses_authenticated_actor_and_tenant(isolated_exception_store, isolated_audit_log):
    result = await enterprise.create_finding_feedback(
        _request("tenant-alpha", "alice-admin"),
        FindingFeedbackRequest(
            vulnerability_id="CVE-2026-0001",
            package="requests",
            state="accepted_risk",
            reason="compensating control",
            expires_at="2026-12-31T00:00:00Z",
        ),
    )

    assert result["state"] == "accepted_risk"
    assert result["marked_by"] == "alice-admin"
    assert result["tenant_id"] == "tenant-alpha"
    stored = isolated_exception_store.get(result["id"], tenant_id="tenant-alpha")
    assert stored is not None
    assert stored.requested_by == "alice-admin"
    assert stored.reason.startswith("[finding_feedback:accepted_risk]")

    entries = isolated_audit_log.list_entries()
    assert entries[0].action == "findings.feedback_recorded"
    assert entries[0].actor == "alice-admin"
    assert entries[0].details["state"] == "accepted_risk"
    assert entries[0].details["tenant_id"] == "tenant-alpha"


@pytest.mark.asyncio
async def test_finding_feedback_list_is_tenant_scoped(isolated_exception_store):
    alpha = VulnException(
        vuln_id="CVE-2026-0001",
        package_name="requests",
        reason="[finding_feedback:false_positive] scanner noise",
        requested_by="alice",
        tenant_id="tenant-alpha",
    )
    beta = VulnException(
        vuln_id="CVE-2026-0002",
        package_name="django",
        reason="[finding_feedback:false_positive] beta only",
        requested_by="bob",
        tenant_id="tenant-beta",
    )
    isolated_exception_store.put(alpha)
    isolated_exception_store.put(beta)

    result = await enterprise.list_finding_feedback(_request("tenant-alpha"), state="false_positive")

    assert result["total"] == 1
    assert result["feedback"][0]["id"] == alpha.exception_id
    assert result["feedback"][0]["tenant_id"] == "tenant-alpha"


@pytest.mark.asyncio
async def test_remove_finding_feedback_returns_404_for_wrong_tenant(isolated_exception_store):
    feedback = VulnException(
        vuln_id="CVE-2026-0001",
        package_name="requests",
        reason="[finding_feedback:not_applicable] beta only",
        tenant_id="tenant-beta",
    )
    isolated_exception_store.put(feedback)

    with pytest.raises(HTTPException) as error:
        await enterprise.remove_finding_feedback(_request("tenant-alpha"), feedback.exception_id)

    assert error.value.status_code == 404
    assert isolated_exception_store.get(feedback.exception_id) is not None


@pytest.mark.asyncio
async def test_false_positive_ignores_client_marked_by(isolated_exception_store):
    result = await enterprise.mark_false_positive(
        _request("tenant-alpha", "alice-admin"),
        enterprise.FalsePositiveRequest(
            vulnerability_id="CVE-2026-0001",
            package="requests",
            reason="scanner noise",
            marked_by="mallory",
        ),
    )

    assert result["marked_by"] == "alice-admin"
    stored = isolated_exception_store.get(result["id"], tenant_id="tenant-alpha")
    assert stored is not None
    assert stored.requested_by == "alice-admin"


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
async def test_verify_audit_export_accepts_signed_json(monkeypatch):
    store = InMemoryAuditLog()
    store.append(AuditEntry(action="scan", actor="alice", resource="job/1", details={"tenant_id": "tenant-alpha"}))
    monkeypatch.setattr("agent_bom.api.audit_log.get_audit_log", lambda: store)

    response = await enterprise.export_audit_entries(_request("tenant-alpha", "alice-admin"))
    payload = json.loads(response.body.decode())
    signature = response.headers["x-agent-bom-audit-export-signature"]

    verified = await enterprise.verify_audit_export(
        _request("tenant-alpha", "alice-admin"),
        enterprise.AuditExportVerifyRequest(payload=payload, signature=signature),
    )

    assert verified["valid"] is True
    assert verified["payload_bytes"] > 0


@pytest.mark.asyncio
async def test_verify_audit_export_rejects_tampered_payload(monkeypatch):
    store = InMemoryAuditLog()
    store.append(AuditEntry(action="scan", actor="alice", resource="job/1", details={"tenant_id": "tenant-alpha"}))
    monkeypatch.setattr("agent_bom.api.audit_log.get_audit_log", lambda: store)

    response = await enterprise.export_audit_entries(_request("tenant-alpha", "alice-admin"))
    payload = json.loads(response.body.decode())
    payload["tenant_id"] = "tenant-beta"

    verified = await enterprise.verify_audit_export(
        _request("tenant-alpha", "alice-admin"),
        enterprise.AuditExportVerifyRequest(payload=payload, signature=response.headers["x-agent-bom-audit-export-signature"]),
    )

    assert verified["valid"] is False


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
    alpha_current_job = ScanJob(
        job_id="job-alpha-current",
        tenant_id="tenant-alpha",
        status=JobStatus.DONE,
        created_at="2026-04-21T00:00:00Z",
        completed_at="2026-04-21T00:01:00Z",
        request=ScanRequest(),
        result={"blast_radius": []},
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
    isolated_job_store.put(alpha_current_job)
    isolated_job_store.put(beta_job)

    diff = await enterprise.compare_baseline(
        _request("tenant-alpha"),
        previous_job_id="job-alpha",
        current_job_id="job-alpha-current",
    )
    assert diff["persistent_count"] == 0
    assert diff["resolved_count"] == 1

    with pytest.raises(HTTPException) as error:
        await enterprise.compare_baseline(
            _request("tenant-alpha"),
            previous_job_id="job-beta",
            current_job_id="job-alpha-current",
        )

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
