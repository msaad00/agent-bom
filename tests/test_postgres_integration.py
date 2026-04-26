"""Real PostgreSQL integration contract.

These tests are intentionally opt-in for local runs. CI provides a Postgres
service and sets AGENT_BOM_POSTGRES_URL so the storage contract is exercised
against a real server instead of the MockConnection unit-test harness.
"""

from __future__ import annotations

import os
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("AGENT_BOM_POSTGRES_URL"),
    reason="AGENT_BOM_POSTGRES_URL is required for real Postgres integration tests",
)


@pytest.fixture(autouse=True)
def reset_postgres_pool():
    from agent_bom.api import postgres_common

    postgres_common.reset_pool()
    yield
    pool = postgres_common._pool
    if pool is not None:
        pool.close()
    postgres_common.reset_pool()


def test_postgres_job_store_real_roundtrip_and_tenant_filter():
    from agent_bom.api.postgres_store import PostgresJobStore
    from agent_bom.api.server import JobStatus, ScanJob, ScanRequest

    store = PostgresJobStore()
    suffix = uuid4().hex
    job_id = f"pg-contract-{suffix}"
    job = ScanJob(
        job_id=job_id,
        tenant_id=f"tenant-{suffix}",
        triggered_by="ci-postgres-contract",
        status=JobStatus.PENDING,
        created_at="2026-04-25T00:00:00Z",
        request=ScanRequest(format="json"),
    )

    store.put(job)

    same_tenant = store.get(job_id, tenant_id=job.tenant_id)
    other_tenant = store.get(job_id, tenant_id=f"other-{suffix}")

    assert same_tenant is not None
    assert same_tenant.job_id == job_id
    assert same_tenant.triggered_by == "ci-postgres-contract"
    assert other_tenant is None
    assert any(item.job_id == job_id for item in store.list_all(tenant_id=job.tenant_id))


def test_postgres_audit_log_real_roundtrip_and_schema_marker():
    from agent_bom.api.audit_log import AuditEntry
    from agent_bom.api.postgres_store import PostgresAuditLog, _get_pool
    from agent_bom.api.storage_schema import CONTROL_PLANE_SCHEMA_VERSION

    suffix = uuid4().hex
    tenant_id = f"tenant-{suffix}"
    store = PostgresAuditLog()
    entry = AuditEntry(
        action="scan",
        actor="ci",
        resource=f"job/{suffix}",
        details={"tenant_id": tenant_id, "packages": 3},
    )

    store.append(entry)

    entries = store.list_entries(action="scan", tenant_id=tenant_id, limit=5)
    assert any(item.entry_id == entry.entry_id and item.verify() for item in entries)

    with _get_pool().connection() as conn:
        row = conn.execute(
            "SELECT version FROM control_plane_schema_versions WHERE component = %s",
            ("audit_log",),
        ).fetchone()

    assert row is not None
    assert row[0] == CONTROL_PLANE_SCHEMA_VERSION
