"""Push boundary derives totals, redacts arbitrary metadata, and audits admission."""

from __future__ import annotations

import json

import pytest
from starlette.testclient import TestClient

from agent_bom.api import audit_log, stores
from agent_bom.api.audit_log import SQLiteAuditLog
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.idempotency_store import SQLiteIdempotencyStore
from agent_bom.api.models import PushPayload
from agent_bom.api.routes.observability import _normalize_pushed_report
from agent_bom.api.server import app
from agent_bom.api.store import SQLiteJobStore


def payload():
    return {
        "source_id": "runner",
        "target_scope": "v1:" + "a" * 64,
        "idempotency_key": "one-report",
        "metadata": {"password": "private-value", "nested": {"api_token": "private-token"}},
        "summary": {"total_vulnerabilities": 0, "total_packages": 999},
        "finding_summary": {"total": 0, "by_severity": {"critical": 0}},
        "agents": [
            {
                "name": "agent",
                "type": "custom",
                "mcp_servers": [
                    {
                        "name": "server",
                        "command": "node",
                        "packages": [
                            {
                                "name": "pkg",
                                "version": "1.0",
                                "ecosystem": "npm",
                                "vulnerabilities": [{"id": "CVE-2026-12345", "severity": "critical"}],
                            }
                        ],
                    }
                ],
            }
        ],
    }


def test_push_redacts_metadata_before_storage_and_preserves_target():
    original = payload()
    report = _normalize_pushed_report(PushPayload(**original), fallback_scan_id="report")
    serialized = json.dumps(report)
    assert "private-value" not in serialized
    assert "private-token" not in serialized
    assert report["target_scope"] == original["target_scope"]
    assert original["metadata"]["password"] == "private-value"


def test_push_derives_counts_from_evidence_not_client_summary():
    report = _normalize_pushed_report(PushPayload(**payload()), fallback_scan_id="report")
    assert report["summary"]["total_packages"] == 1
    assert report["summary"]["total_vulnerabilities"] == 1
    assert report["finding_summary"]["total"] == 1
    assert report["finding_summary"]["by_severity"]["critical"] == 1


@pytest.fixture
def durable_push(tmp_path, monkeypatch):
    jobs = SQLiteJobStore(tmp_path / "jobs.db")
    graph = SQLiteGraphStore(tmp_path / "graph.db")
    audit = SQLiteAuditLog(str(tmp_path / "audit.db"))
    monkeypatch.setattr(stores, "_store", jobs)
    monkeypatch.setattr(stores, "_graph_store", graph)
    monkeypatch.setattr(stores, "_idempotency_store", SQLiteIdempotencyStore(tmp_path / "idempotency.db"))
    monkeypatch.setattr(audit_log, "get_audit_log", lambda: audit)
    return TestClient(app, raise_server_exceptions=False), jobs, graph, audit


def test_push_audits_admission_once_and_retains_receipt_after_restart(durable_push):
    client, jobs, graph, audit = durable_push
    first = client.post("/v1/results/push", json=payload())
    assert first.status_code == 201, first.text
    assert client.post("/v1/results/push", json=payload()).json()["job_id"] == first.json()["job_id"]
    entries = SQLiteAuditLog(audit._db_path).list_entries(tenant_id="default", action="results.push.accepted")
    assert len(entries) == 1
    assert entries[0].details["job_id"] == first.json()["job_id"]
    assert entries[0].details["outcome"] == "accepted"
    assert audit.list_entries(tenant_id="another", action="results.push.accepted") == []
    assert "private-value" not in json.dumps(SQLiteJobStore(jobs._db_path).get(first.json()["job_id"], tenant_id="default").result)


def test_audit_failure_rejects_push_without_persisting_evidence(durable_push, monkeypatch):
    client, jobs, graph, audit = durable_push

    def fail(_entry):
        raise OSError("audit unavailable")

    monkeypatch.setattr(audit, "append", fail)
    response = client.post("/v1/results/push", json=payload())
    assert response.status_code == 503
    assert jobs.list_all(all_tenants=True) == []


def test_push_ignores_producer_grade_and_counts_versions_without_double_counting():
    body = payload()
    body["posture_scorecard"] = {"grade": "A", "score": 100}
    body["blast_radius"] = [
        {"vulnerability_id": "CVE-2026-12345", "package": "pkg", "package_version": "1.0", "ecosystem": "npm", "severity": "critical"}
    ]
    packages = body["agents"][0]["mcp_servers"][0]["packages"]
    packages.append({**packages[0], "version": "2.0"})
    report = _normalize_pushed_report(PushPayload(**body), fallback_scan_id="report")
    assert report["summary"]["unique_packages"] == 2
    assert report["finding_summary"]["total"] == 2
    assert "posture_scorecard" not in report


def test_push_failure_keeps_attempt_but_no_false_commit_receipt(durable_push, monkeypatch):
    client, jobs, graph, audit = durable_push

    def fail(*args, **kwargs):
        raise OSError("graph unavailable")

    monkeypatch.setattr("agent_bom.api.routes.observability._persist_graph_snapshot", fail)
    response = client.post("/v1/results/push", json=payload())
    assert response.status_code == 503
    assert jobs.list_all(all_tenants=True) == []
    entries = audit.list_entries(tenant_id="default", action="results.push.accepted")
    assert len(entries) == 1
    assert entries[0].details["outcome"] == "accepted"
    assert "private-value" not in json.dumps(entries[0].details)


def test_summary_only_push_cannot_replace_prior_evidence():
    report = _normalize_pushed_report(
        PushPayload(source_id="runner", target_scope="v1:" + "a" * 64, summary={"total_vulnerabilities": 0}),
        fallback_scan_id="summary-only",
    )
    assert report["scan_run"]["outcome"] == "partial"


def test_genuine_empty_evidence_retains_complete_coverage():
    report = _normalize_pushed_report(
        PushPayload(source_id="runner", target_scope="v1:" + "a" * 64, agents=[], findings=[]), fallback_scan_id="empty"
    )
    assert report["scan_run"]["outcome"] == "complete"
    assert report["finding_summary"]["total"] == 0


def test_postgres_push_redaction_audit_and_failed_write(monkeypatch):
    import os
    from uuid import uuid4

    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        pytest.skip("requires isolated live Postgres")
    from agent_bom.api import postgres_common
    from agent_bom.api.idempotency_store import PostgresIdempotencyStore
    from agent_bom.api.postgres_audit import PostgresAuditLog
    from agent_bom.api.postgres_graph import PostgresGraphStore
    from agent_bom.api.postgres_job_store import PostgresJobStore
    from agent_bom.api.server import configure_api
    from tests.auth_helpers import PROXY_SECRET

    tenant = "push-hardening-" + uuid4().hex
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
    configure_api(api_key=None)
    headers = {"X-Agent-Bom-Role": "analyst", "X-Agent-Bom-Tenant-ID": tenant, "X-Agent-Bom-Proxy-Secret": PROXY_SECRET}
    token = postgres_common.set_current_tenant(tenant)
    postgres_common.reset_pool()
    try:
        jobs, graph, audit = PostgresJobStore(), PostgresGraphStore(), PostgresAuditLog()
        monkeypatch.setattr(stores, "_store", jobs)
        monkeypatch.setattr(stores, "_graph_store", graph)
        monkeypatch.setattr(stores, "_idempotency_store", PostgresIdempotencyStore())
        monkeypatch.setattr(audit_log, "get_audit_log", lambda: audit)
        with jobs._pool.connection() as conn:
            assert conn.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user").fetchone() == (False, False)
        client = TestClient(app, raise_server_exceptions=False)
        first = client.post("/v1/results/push", headers=headers, json=payload())
        assert first.status_code == 201, first.text
        assert client.post("/v1/results/push", headers=headers, json=payload()).json()["job_id"] == first.json()["job_id"]
        restored = PostgresJobStore().get(first.json()["job_id"], tenant_id=tenant)
        assert restored.result["summary"]["total_vulnerabilities"] == 1
        assert "private-value" not in json.dumps(restored.result)
        assert len(PostgresAuditLog().list_entries(tenant_id=tenant, action="results.push.accepted")) == 1
        assert PostgresJobStore().get(first.json()["job_id"], tenant_id="other") is None
        with PostgresJobStore()._pool.connection() as conn:
            conn.execute("SELECT set_config('app.tenant_id', 'other', true)")
            assert conn.execute("SELECT count(*) FROM scan_jobs WHERE team_id = %s", (tenant,)).fetchone()[0] == 0

        def fail(_entry):
            raise OSError("audit unavailable")

        monkeypatch.setattr(audit, "append", fail)
        retry = {**payload(), "idempotency_key": "audit-down"}
        assert client.post("/v1/results/push", headers=headers, json=retry).status_code == 503
        assert len(PostgresJobStore().list_all(tenant_id=tenant)) == 1
        postgres_common.reset_pool()
        assert PostgresJobStore().get(first.json()["job_id"], tenant_id=tenant).result == restored.result
    finally:
        postgres_common.reset_pool()
        postgres_common.reset_current_tenant(token)
        configure_api(api_key=None)


@pytest.mark.parametrize("credential", ["Bearer synthetic-short-token", ".".join(("eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxIn0", "signature"))])
def test_pushed_credentials_cannot_return_through_inventory_or_durable_storage(durable_push, credential):
    client, jobs, graph, audit = durable_push
    body = payload()
    body["agents"][0]["name"] = credential
    body["agents"][0]["mcp_servers"][0]["name"] = credential
    pushed = client.post("/v1/results/push", json=body)
    assert pushed.status_code == 201, pushed.text
    inventory = client.get("/v1/inventory")
    assert inventory.status_code == 200, inventory.text
    assert credential not in inventory.text
    persisted = SQLiteJobStore(jobs._db_path).get(pushed.json()["job_id"], tenant_id="default")
    assert credential not in json.dumps(persisted.result)
