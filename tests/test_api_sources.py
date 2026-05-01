"""Tests for hosted-product source registry routes."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as _stores
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
    old_job_store = _stores._store

    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
    configure_api(api_key=None)
    _stores.set_source_store(InMemorySourceStore())
    _stores.set_job_store(InMemoryJobStore())

    try:
        with TestClient(app) as client:
            yield client
    finally:
        monkeypatch.delenv("AGENT_BOM_TRUST_PROXY_AUTH", raising=False)
        configure_api(api_key=None)
        _stores._source_store = old_source_store
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
