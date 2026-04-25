from __future__ import annotations

from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from agent_bom.api.audit_log import InMemoryAuditLog, set_audit_log
from agent_bom.api.exception_store import InMemoryExceptionStore, VulnException
from agent_bom.api.fleet_store import FleetAgent, InMemoryFleetStore
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest, SourceKind, SourceRecord
from agent_bom.api.policy_store import GatewayPolicy, InMemoryPolicyStore
from agent_bom.api.routes.privacy import delete_tenant_data, export_tenant_data
from agent_bom.api.schedule_store import InMemoryScheduleStore, ScanSchedule
from agent_bom.api.server import app
from agent_bom.api.source_store import InMemorySourceStore
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import (
    set_exception_store,
    set_fleet_store,
    set_graph_store,
    set_job_store,
    set_policy_store,
    set_schedule_store,
    set_source_store,
    set_tenant_quota_store,
)
from agent_bom.api.tenant_quota_store import InMemoryTenantQuotaStore
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


class _GraphStore:
    def __init__(self) -> None:
        self.snapshots = {
            "tenant-a": [{"scan_id": "scan-a", "tenant_id": "tenant-a"}],
            "tenant-b": [{"scan_id": "scan-b", "tenant_id": "tenant-b"}],
        }

    def list_snapshots(self, *, tenant_id: str = "", limit: int = 50):
        return self.snapshots.get(tenant_id, [])[:limit]

    def delete_tenant(self, *, tenant_id: str = "") -> int:
        rows = len(self.snapshots.pop(tenant_id, []))
        return rows


@pytest.fixture()
def tenant_stores():
    jobs = InMemoryJobStore()
    fleet = InMemoryFleetStore()
    policies = InMemoryPolicyStore()
    schedules = InMemoryScheduleStore()
    sources = InMemorySourceStore()
    exceptions = InMemoryExceptionStore()
    quota = InMemoryTenantQuotaStore()
    graph = _GraphStore()
    audit = InMemoryAuditLog()

    set_job_store(jobs)
    set_fleet_store(fleet)
    set_policy_store(policies)
    set_schedule_store(schedules)
    set_source_store(sources)
    set_exception_store(exceptions)
    set_tenant_quota_store(quota)
    set_graph_store(graph)
    set_audit_log(audit)

    for tenant_id in ("tenant-a", "tenant-b"):
        jobs.put(
            ScanJob(
                job_id=f"job-{tenant_id}",
                tenant_id=tenant_id,
                triggered_by="tester",
                status=JobStatus.DONE,
                created_at="2026-04-24T00:00:00Z",
                completed_at="2026-04-24T00:01:00Z",
                request=ScanRequest(),
            )
        )
        fleet.put(FleetAgent(agent_id=f"agent-{tenant_id}", name=f"Agent {tenant_id}", agent_type="mcp", tenant_id=tenant_id))
        policies.put_policy(GatewayPolicy(policy_id=f"policy-{tenant_id}", name=f"Policy {tenant_id}", tenant_id=tenant_id))
        schedules.put(
            ScanSchedule(
                schedule_id=f"schedule-{tenant_id}",
                name=f"Schedule {tenant_id}",
                cron_expression="0 * * * *",
                scan_config={},
                tenant_id=tenant_id,
            )
        )
        sources.put(
            SourceRecord(
                source_id=f"source-{tenant_id}",
                tenant_id=tenant_id,
                display_name=f"Source {tenant_id}",
                kind=SourceKind.SCAN_REPO,
                credential_ref="secret/ref",
                config={"token": "do-not-export"},
            )
        )
        exceptions.put(VulnException(exception_id=f"exception-{tenant_id}", vuln_id="CVE-2026-0001", tenant_id=tenant_id))
        quota.put(tenant_id, {"scan_jobs": 10})

    yield {
        "jobs": jobs,
        "fleet": fleet,
        "policies": policies,
        "schedules": schedules,
        "sources": sources,
        "exceptions": exceptions,
        "quota": quota,
        "graph": graph,
    }


def _request(tenant_id: str = "tenant-a"):
    return SimpleNamespace(state=SimpleNamespace(tenant_id=tenant_id, api_key_name="admin-key", auth_method="api_key"))


def test_tenant_data_export_is_tenant_scoped_and_redacts_source_secrets(tenant_stores) -> None:
    response = export_tenant_data("tenant-a", _request("tenant-a"), include_records=True, record_limit=10)

    assert response["counts"]["jobs"] == 1
    assert response["records"]["jobs"][0]["job_id"] == "job-tenant-a"
    assert response["records"]["fleet_agents"][0]["agent_id"] == "agent-tenant-a"
    assert response["records"]["sources"][0]["credential_ref"] == "[redacted]"
    assert response["records"]["sources"][0]["config"] == {"redacted": True}
    assert "retained_immutable_hmac_chain" == response["retention"]["audit_log"]


def test_tenant_data_http_endpoint_requires_authenticated_admin(tenant_stores) -> None:
    client = TestClient(app)

    unauthenticated = client.get("/v1/tenant/tenant-a/data")
    assert unauthenticated.status_code == 401

    viewer = client.get(
        "/v1/tenant/tenant-a/data",
        headers=proxy_headers(role="viewer", tenant="tenant-a"),
    )
    assert viewer.status_code == 403

    admin = client.get(
        "/v1/tenant/tenant-a/data",
        headers=proxy_headers(role="admin", tenant="tenant-a"),
    )
    assert admin.status_code == 200
    assert admin.json()["counts"]["jobs"] == 1


def test_tenant_data_export_rejects_cross_tenant_access(tenant_stores) -> None:
    with pytest.raises(Exception) as exc:
        export_tenant_data("tenant-b", _request("tenant-a"), include_records=False, record_limit=10)

    assert getattr(exc.value, "status_code", None) == 403


def test_tenant_data_delete_defaults_to_dry_run(tenant_stores) -> None:
    response = delete_tenant_data("tenant-a", _request("tenant-a"))

    assert response["dry_run"] is True
    assert response["would_delete"]["jobs"] == 1
    assert tenant_stores["jobs"].get("job-tenant-a", tenant_id="tenant-a") is not None


def test_tenant_data_delete_requires_exact_confirmation(tenant_stores) -> None:
    with pytest.raises(Exception) as exc:
        delete_tenant_data("tenant-a", _request("tenant-a"), dry_run=False, confirm_tenant_id="")

    assert getattr(exc.value, "status_code", None) == 400
    assert tenant_stores["jobs"].get("job-tenant-a", tenant_id="tenant-a") is not None


def test_tenant_data_delete_removes_only_authenticated_tenant(tenant_stores) -> None:
    response = delete_tenant_data("tenant-a", _request("tenant-a"), dry_run=False, confirm_tenant_id="tenant-a")

    assert response["dry_run"] is False
    assert response["deleted"]["jobs"] == 1
    assert response["deleted"]["fleet_agents"] == 1
    assert response["deleted"]["gateway_policies"] == 1
    assert response["deleted"]["scan_schedules"] == 1
    assert response["deleted"]["sources"] == 1
    assert response["deleted"]["exceptions"] == 1
    assert response["deleted"]["tenant_quota_overrides"] == 1
    assert response["deleted"]["graph_rows"] == 1

    assert tenant_stores["jobs"].get("job-tenant-a", tenant_id="tenant-a") is None
    assert tenant_stores["jobs"].get("job-tenant-b", tenant_id="tenant-b") is not None
    assert tenant_stores["sources"].get("source-tenant-b") is not None


def test_sqlite_graph_store_delete_tenant_removes_graph_rows(tmp_path) -> None:
    store = SQLiteGraphStore(tmp_path / "graph.db")
    conn = store._open_rw_conn()
    try:
        conn.execute(
            """
            INSERT INTO graph_nodes (
                id, entity_type, label, first_seen, last_seen, scan_id, tenant_id
            ) VALUES ('node-a', 'agent', 'Node A', 'now', 'now', 'scan-a', 'tenant-a')
            """
        )
        conn.execute(
            """
            INSERT INTO graph_edges (
                source_id, target_id, relationship, first_seen, last_seen, scan_id, tenant_id
            ) VALUES ('node-a', 'node-b', 'invoked', 'now', 'now', 'scan-a', 'tenant-a')
            """
        )
        conn.execute("INSERT INTO graph_snapshots (scan_id, tenant_id, created_at) VALUES ('scan-a', 'tenant-a', 'now')")
        conn.execute("INSERT INTO graph_snapshots (scan_id, tenant_id, created_at) VALUES ('scan-b', 'tenant-b', 'now')")
        conn.execute(
            """
            INSERT INTO attack_paths (source_node, target_node, scan_id, tenant_id, computed_at)
            VALUES ('node-a', 'node-b', 'scan-a', 'tenant-a', 'now')
            """
        )
        conn.execute(
            """
            INSERT INTO interaction_risks (pattern, agents, scan_id, tenant_id)
            VALUES ('pattern', '[]', 'scan-a', 'tenant-a')
            """
        )
        conn.execute(
            """
            INSERT INTO graph_filter_presets (name, tenant_id, filters, created_at)
            VALUES ('preset-a', 'tenant-a', '{}', 'now')
            """
        )
        conn.execute(
            """
            INSERT INTO graph_node_search (
                tenant_id, scan_id, node_id, entity_type, severity, compliance_tags, data_sources, search_text
            ) VALUES ('tenant-a', 'scan-a', 'node-a', 'agent', '', '', '', 'node a')
            """
        )
        conn.commit()
    finally:
        conn.close()

    assert store.delete_tenant(tenant_id="tenant-a") == 7

    conn = store._open_ro_conn()
    assert conn is not None
    try:
        assert conn.execute("SELECT COUNT(*) FROM graph_snapshots WHERE tenant_id = 'tenant-a'").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM graph_snapshots WHERE tenant_id = 'tenant-b'").fetchone()[0] == 1
    finally:
        conn.close()
