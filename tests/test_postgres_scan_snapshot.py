"""Live Postgres contract for materialized scan snapshots (forced tenant RLS)."""

from __future__ import annotations

import os
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires restricted-role Postgres")


def _meta(completed_at: str) -> dict:
    return {
        "scope_key": "request:{}",
        "authority_evidence_at": completed_at,
        "authority_completed_at": completed_at,
        "authoritative": True,
        "incomplete_reasons": [],
        "completed_at": completed_at,
        "created_at": completed_at,
        "row_schema_version": 1,
        "row_count": 1,
        "materialized_at": completed_at,
    }


def _row(identity: str) -> dict:
    return {"finding_identity": identity, "canonical_id": f"canon-{identity}", "severity": "high", "payload": {"id": identity}}


def test_postgres_scan_snapshots_replace_atomically_and_stay_tenant_isolated() -> None:
    from agent_bom.api.postgres_common import _new_application_pool, _tenant_connection
    from agent_bom.api.postgres_scan_snapshot import PostgresScanSnapshotStore
    from tests.test_postgres_job_evidence_revision import tenant_scope

    tenant, other = ("snapshot-" + uuid4().hex for _ in range(2))
    pool = _new_application_pool(min_size=1, max_size=2)
    try:
        with pool.connection() as conn:
            for table in ("scan_snapshot_jobs", "scan_snapshot_rows"):
                assert conn.execute(
                    "SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid=%s::regclass", (table,)
                ).fetchone() == (True, True)
        store = PostgresScanSnapshotStore(pool=pool)
        store.put_snapshot(tenant, "same-job", _meta("2026-01-01T00:00:00+00:00"), [_row("a"), _row("b")])
        store.put_snapshot(other, "same-job", _meta("2026-10-01T00:00:00+00:00"), [_row("c")])
        store.put_snapshot(tenant, "same-job", _meta("2026-01-01T00:00:00+00:00"), [_row("z")])

        assert [row["finding_identity"] for row in store.get_rows(tenant, "same-job")] == ["z"]
        assert store.get_meta(tenant, ["same-job"])["same-job"]["authoritative"] is True
        with tenant_scope(other), _tenant_connection(pool) as conn:
            conn.execute("SELECT set_config('app.bypass_rls','1',true)")
            assert conn.execute("SELECT count(*) FROM scan_snapshot_rows WHERE tenant_id=%s", (tenant,)).fetchone() == (0,)

        assert store.delete_older_than(tenant, "2026-06-01T00:00:00+00:00") == 1
        assert store.get_rows(tenant, "same-job") == []
        assert [row["finding_identity"] for row in store.get_rows(other, "same-job")] == ["c"]
        assert store.delete_job(other, "same-job") is True
        assert store.get_meta(other) == {}
    finally:
        pool.close()


@pytest.mark.parametrize("all_tenants", [False, True])
def test_postgres_job_deletion_cleans_snapshots_after_opt_out(monkeypatch, all_tenants):
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.postgres_job_store import PostgresJobStore
    from agent_bom.api.postgres_scan_snapshot import PostgresScanSnapshotStore
    from agent_bom.api.scan_snapshot_store import set_scan_snapshot_store
    from tests.test_postgres_job_evidence_revision import job, tenant_scope

    tenants = ["snapshot-delete-" + uuid4().hex for _ in range(2)]
    job_id = "delete-" + uuid4().hex
    pool = _new_application_pool(min_size=1, max_size=2)
    snapshots = PostgresScanSnapshotStore(pool=pool)
    jobs = PostgresJobStore(pool=pool)
    set_scan_snapshot_store(snapshots)
    try:
        for tenant in tenants:
            with tenant_scope(tenant):
                jobs.put(job(tenant).model_copy(update={"job_id": job_id}))
            snapshots.put_snapshot(tenant, job_id, _meta("2026-10-01T00:00:00+00:00"), [_row(tenant)])
        monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOTS", "0")
        with tenant_scope(tenants[0]):
            assert jobs.delete(job_id, tenant_id=None if all_tenants else tenants[0], all_tenants=all_tenants)
        assert snapshots.get_meta(tenants[0]) == {}
        assert snapshots.get_rows(tenants[0], job_id) == []
        assert bool(snapshots.get_meta(tenants[1])) is (not all_tenants)
    finally:
        set_scan_snapshot_store(None)
        pool.close()
