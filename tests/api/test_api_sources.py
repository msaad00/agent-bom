"""Tests for hosted-product source registry routes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as _stores
from agent_bom.api.credential_store import InMemoryCredentialRefStore
from agent_bom.api.server import app, configure_api
from agent_bom.api.source_store import InMemorySourceStore
from agent_bom.api.store import InMemoryJobStore
from agent_bom.connectors.base import ConnectorHealthState, ConnectorStatus
from tests.auth_helpers import PROXY_SECRET

ADMIN_HEADERS = {
    "X-Agent-Bom-Role": "admin",
    "X-Agent-Bom-Tenant-ID": "tenant-alpha",
    "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
}
ANALYST_HEADERS = {
    "X-Agent-Bom-Role": "analyst",
    "X-Agent-Bom-Tenant-ID": "tenant-alpha",
    "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
}
VIEWER_HEADERS = {
    "X-Agent-Bom-Role": "viewer",
    "X-Agent-Bom-Tenant-ID": "tenant-alpha",
    "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
}
OTHER_TENANT_HEADERS = {
    "X-Agent-Bom-Role": "viewer",
    "X-Agent-Bom-Tenant-ID": "tenant-beta",
    "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
}


@pytest.fixture
def source_client(monkeypatch: pytest.MonkeyPatch):
    old_source_store = _stores._source_store
    old_credential_store = _stores._credential_ref_store
    old_job_store = _stores._store

    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
    configure_api(api_key=None)
    _stores.set_source_store(InMemorySourceStore())
    _stores.set_credential_ref_store(InMemoryCredentialRefStore())
    _stores.set_job_store(InMemoryJobStore())

    try:
        with TestClient(app) as client:
            yield client
    finally:
        monkeypatch.delenv("AGENT_BOM_TRUST_PROXY_AUTH", raising=False)
        configure_api(api_key=None)
        _stores._source_store = old_source_store
        _stores._credential_ref_store = old_credential_store
        _stores._store = old_job_store


def test_source_crud_and_role_enforcement(source_client: TestClient) -> None:
    create = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "AWS production account",
            "kind": "connector.cloud_read_only",
            "owner": "platform-security",
            "connector_name": "jira",
            "credential_mode": "reference",
            "description": "Read-only cloud discovery source",
        },
    )
    assert create.status_code == 201
    body = create.json()
    source_id = body["source_id"]
    assert body["tenant_id"] == "tenant-alpha"
    assert body["status"] == "configured"

    listed = source_client.get("/v1/sources", headers=VIEWER_HEADERS)
    assert listed.status_code == 200
    listed_body = listed.json()
    assert listed_body["count"] == 1
    assert listed_body["sources"][0]["source_id"] == source_id

    updated = source_client.put(
        f"/v1/sources/{source_id}",
        headers=ANALYST_HEADERS,
        json={"description": "Updated source description", "owner": "security-engineering"},
    )
    assert updated.status_code == 200
    assert updated.json()["owner"] == "security-engineering"

    other_tenant = source_client.get(f"/v1/sources/{source_id}", headers=OTHER_TENANT_HEADERS)
    assert other_tenant.status_code == 404

    delete_forbidden = source_client.delete(f"/v1/sources/{source_id}", headers=ANALYST_HEADERS)
    assert delete_forbidden.status_code == 403

    deleted = source_client.delete(f"/v1/sources/{source_id}", headers=ADMIN_HEADERS)
    assert deleted.status_code == 204
    assert source_client.get("/v1/sources", headers=VIEWER_HEADERS).json()["count"] == 0


def test_source_create_rejects_mismatched_tenant(source_client: TestClient) -> None:
    resp = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Wrong tenant source",
            "kind": "scan.repo",
            "tenant_id": "tenant-beta",
        },
    )
    assert resp.status_code == 403
    assert "tenant_id must match" in resp.json()["detail"]


def test_credential_reference_crud_and_tenant_isolation(source_client: TestClient) -> None:
    create = source_client.post(
        "/v1/credentials",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "AWS prod read-only role",
            "provider": "aws",
            "mode": "role_arn",
            "external_ref": "arn:aws:iam::123456789012:role/agent-bom-readonly",
            "owner": "platform-security",
            "scopes": ["iam:GetRole", "iam:ListAttachedRolePolicies"],
        },
    )
    assert create.status_code == 201
    body = create.json()
    credential_ref_id = body["credential_ref_id"]
    assert body["tenant_id"] == "tenant-alpha"
    assert "secret" not in body

    listed = source_client.get("/v1/credentials", headers=VIEWER_HEADERS)
    assert listed.status_code == 200
    assert listed.json()["credentials"][0]["credential_ref_id"] == credential_ref_id

    other_tenant = source_client.get(f"/v1/credentials/{credential_ref_id}", headers=OTHER_TENANT_HEADERS)
    assert other_tenant.status_code == 404

    delete_forbidden = source_client.delete(f"/v1/credentials/{credential_ref_id}", headers=ANALYST_HEADERS)
    assert delete_forbidden.status_code == 403

    deleted = source_client.delete(f"/v1/credentials/{credential_ref_id}", headers=ADMIN_HEADERS)
    assert deleted.status_code == 204
    assert source_client.get("/v1/credentials", headers=VIEWER_HEADERS).json()["count"] == 0


def test_credential_rotation_posture_flags_stale_and_expiring_refs(source_client: TestClient) -> None:
    stale = source_client.post(
        "/v1/credentials",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "AWS stale automation key",
            "provider": "aws",
            "mode": "secret_manager",
            "external_ref": "aws-secretsmanager://prod/agent-bom/stale",
            "owner": "platform-security",
            "credential_class": "api_key",
            "last_rotated_at": "2026-01-01T00:00:00+00:00",
            "rotation_interval_days": 30,
            "max_age_days": 60,
        },
    )
    assert stale.status_code == 201

    near_expiry_at = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
    expiring = source_client.post(
        "/v1/credentials",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "ServiceNow near-expiry token",
            "provider": "servicenow",
            "mode": "secret_manager",
            "external_ref": "vault://servicenow/token",
            "owner": "it-operations",
            "credential_class": "service_account",
            "last_rotated_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": near_expiry_at,
            "expiry_warning_days": 14,
        },
    )
    assert expiring.status_code == 201

    posture = source_client.get("/v1/credentials/posture", headers=VIEWER_HEADERS)
    assert posture.status_code == 200
    body = posture.json()
    assert body["schema_version"] == "credential.rotation_governance.v1"
    assert body["tenant_id"] == "tenant-alpha"
    assert body["summary"]["total"] == 2
    assert body["summary"]["max_age_exceeded"] == 1
    assert body["summary"]["near_expiry"] == 1
    assert body["summary"]["findings"] == 2

    statuses = {row["display_name"]: row["rotation_status"] for row in body["credentials"]}
    assert statuses == {
        "AWS stale automation key": "max_age_exceeded",
        "ServiceNow near-expiry token": "near_expiry",
    }
    assert all("external_ref" not in row for row in body["credentials"])
    assert "aws-secretsmanager://prod/agent-bom/stale" not in posture.text
    assert "vault://servicenow/token" not in posture.text
    assert all(finding["type"] == "credential_rotation" for finding in body["findings"])

    other_tenant = source_client.get("/v1/credentials/posture", headers=OTHER_TENANT_HEADERS)
    assert other_tenant.status_code == 200
    assert other_tenant.json()["summary"]["total"] == 0


def test_posture_credentials_includes_rotation_governance_without_scan(source_client: TestClient) -> None:
    created = source_client.post(
        "/v1/credentials",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Unknown rotation ref",
            "provider": "azure",
            "mode": "secret_manager",
            "external_ref": "keyvault://agent-bom/prod",
            "credential_class": "service_account",
        },
    )
    assert created.status_code == 201

    posture = source_client.get("/v1/posture/credentials", headers=VIEWER_HEADERS)
    assert posture.status_code == 200
    body = posture.json()
    assert body["credentials"] == []
    assert body["count"] == 0
    assert body["rotation_governance"]["summary"]["unknown_age"] == 1
    assert body["rotation_governance"]["findings"][0]["status"] == "unknown_age"
    assert "keyvault://agent-bom/prod" not in posture.text


def test_credential_reference_rejects_secret_material(source_client: TestClient) -> None:
    create = source_client.post(
        "/v1/credentials",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Unsafe credential",
            "provider": "aws",
            "external_ref": "secret-manager://agent-bom/prod",
            "secret_value": "AKIA...",
        },
    )
    assert create.status_code == 422


def test_source_with_credential_reference_requires_same_tenant_ref(source_client: TestClient) -> None:
    missing_ref = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "AWS source with missing credential",
            "kind": "scan.cloud",
            "credential_mode": "reference",
            "credential_ref": "missing-ref",
        },
    )
    assert missing_ref.status_code == 409

    credential = source_client.post(
        "/v1/credentials",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "AWS prod read-only role",
            "provider": "aws",
            "mode": "role_arn",
            "external_ref": "arn:aws:iam::123456789012:role/agent-bom-readonly",
        },
    )
    credential_ref_id = credential.json()["credential_ref_id"]

    create = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "AWS source",
            "kind": "scan.cloud",
            "credential_mode": "reference",
            "credential_ref": credential_ref_id,
            "config": {"scan_request": {"inventory": "agents.json", "format": "json"}},
        },
    )
    assert create.status_code == 201
    assert create.json()["credential_ref"] == credential_ref_id


def test_connector_source_test_updates_health(source_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "agent_bom.connectors.check_connector_health",
        lambda connector_name: ConnectorStatus(
            connector=connector_name,
            state=ConnectorHealthState.HEALTHY,
            message="Connector can authenticate",
            api_version="2026-04",
        ),
    )

    create = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Snowflake lake",
            "kind": "connector.warehouse",
            "connector_name": "slack",
            "credential_mode": "reference",
        },
    )
    source_id = create.json()["source_id"]

    tested = source_client.post(f"/v1/sources/{source_id}/test", headers=ANALYST_HEADERS)
    assert tested.status_code == 200
    tested_body = tested.json()
    assert tested_body["status"] == "healthy"
    assert tested_body["message"] == "Connector can authenticate"

    fetched = source_client.get(f"/v1/sources/{source_id}", headers=VIEWER_HEADERS)
    assert fetched.status_code == 200
    fetched_body = fetched.json()
    assert fetched_body["last_test_status"] == "healthy"
    assert fetched_body["status"] == "healthy"


def test_viewer_cannot_test_or_run_sources(source_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def _must_not_check_connector_health(connector_name: str):
        raise AssertionError("viewer must not reach connector health checks")

    def _must_not_enqueue_scan_job(**kwargs):
        raise AssertionError("viewer must not enqueue source scans")

    monkeypatch.setattr("agent_bom.connectors.check_connector_health", _must_not_check_connector_health)
    monkeypatch.setattr("agent_bom.api.routes.sources.enqueue_scan_job", _must_not_enqueue_scan_job)

    created = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Repo scan source",
            "kind": "scan.repo",
            "config": {"scan_request": {"inventory": "agents.json", "format": "json"}},
        },
    )
    source_id = created.json()["source_id"]

    test_resp = source_client.post(f"/v1/sources/{source_id}/test", headers=VIEWER_HEADERS)
    run_resp = source_client.post(f"/v1/sources/{source_id}/run", headers=VIEWER_HEADERS)

    assert test_resp.status_code == 403
    assert run_resp.status_code == 403


def test_running_source_queues_source_linked_job(source_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api.models import ScanJob
    from agent_bom.api.stores import _get_store, _jobs_put

    def _fake_enqueue(*, tenant_id: str, triggered_by: str, request_body, source_id: str | None = None) -> ScanJob:
        job = ScanJob(
            job_id="job-source-1",
            tenant_id=tenant_id,
            source_id=source_id,
            triggered_by=triggered_by,
            created_at="2026-04-20T00:00:00+00:00",
            request=request_body,
        )
        _get_store().put(job)
        _jobs_put(job.job_id, job)
        return job

    monkeypatch.setattr("agent_bom.api.routes.sources.enqueue_scan_job", _fake_enqueue)

    created = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Repo scan source",
            "kind": "scan.repo",
            "config": {"scan_request": {"inventory": "agents.json", "format": "json"}},
        },
    )
    source_id = created.json()["source_id"]

    run = source_client.post(f"/v1/sources/{source_id}/run", headers=ANALYST_HEADERS)
    assert run.status_code == 202
    run_body = run.json()
    assert run_body["source_id"] == source_id
    assert run_body["status"] == "pending"

    source = source_client.get(f"/v1/sources/{source_id}", headers=VIEWER_HEADERS).json()
    assert source["last_job_id"] == run_body["job_id"]
    assert source["last_run_status"] == "pending"

    jobs = source_client.get(f"/v1/sources/{source_id}/jobs", headers=VIEWER_HEADERS)
    assert jobs.status_code == 200
    jobs_body = jobs.json()
    assert jobs_body["count"] == 1
    assert jobs_body["jobs"][0]["job_id"] == run_body["job_id"]
    assert jobs_body["jobs"][0]["source_id"] == source_id


def test_source_run_rejects_unknown_scan_request_fields(source_client: TestClient) -> None:
    created = source_client.post(
        "/v1/sources",
        headers=ANALYST_HEADERS,
        json={
            "display_name": "Typoed repo source",
            "kind": "scan.repo",
            "config": {"scan_request": {"project_path": "."}},
        },
    )
    source_id = created.json()["source_id"]

    resp = source_client.post(f"/v1/sources/{source_id}/run", headers=ANALYST_HEADERS)

    assert resp.status_code == 422
    body = resp.json()
    assert "project_path" in str(body)
    assert "extra_forbidden" in str(body)


def test_push_and_runtime_sources_reject_run_now(source_client: TestClient) -> None:
    for kind in ("ingest.trace_push", "runtime.gateway"):
        created = source_client.post(
            "/v1/sources",
            headers=ANALYST_HEADERS,
            json={
                "display_name": f"Source for {kind}",
                "kind": kind,
            },
        )
        source_id = created.json()["source_id"]
        resp = source_client.post(f"/v1/sources/{source_id}/run", headers=ANALYST_HEADERS)
        assert resp.status_code == 409
