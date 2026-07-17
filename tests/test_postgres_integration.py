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
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
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

    # Production middleware sets _current_tenant before any store call so the
    # WITH CHECK clause on scan_jobs_tenant_isolation can match the inserted
    # team_id. The non-superuser CI role enforces this; the test must too.
    token = set_current_tenant(job.tenant_id)
    try:
        store.put(job)
        same_tenant = store.get(job_id, tenant_id=job.tenant_id)
        results = list(store.list_all(tenant_id=job.tenant_id))
    finally:
        reset_current_tenant(token)

    other_token = set_current_tenant(f"other-{suffix}")
    try:
        other_tenant = store.get(job_id, tenant_id=f"other-{suffix}")
    finally:
        reset_current_tenant(other_token)

    assert same_tenant is not None
    assert same_tenant.job_id == job_id
    assert same_tenant.triggered_by == "ci-postgres-contract"
    assert other_tenant is None
    assert any(item.job_id == job_id for item in results)


def test_budget_pk_migration_targets_visible_relation_across_search_path():
    """The inspected and altered table must be the same visible relation."""
    import psycopg

    from agent_bom.api.postgres_cost import BUDGET_PK_MIGRATION_SQL

    dsn = os.environ["AGENT_BOM_POSTGRES_URL"]
    suffix = uuid4().hex[:12]
    first_schema = f"empty_{suffix}"
    data_schema = f"budget_{suffix}"
    try:
        with psycopg.connect(dsn) as conn:
            try:
                conn.execute(f'CREATE SCHEMA "{first_schema}"')
                conn.execute(f'CREATE SCHEMA "{data_schema}"')
            except psycopg.errors.InsufficientPrivilege:
                pytest.skip("Postgres integration role cannot create schemas")
            conn.execute(
                f'CREATE TABLE "{data_schema}".llm_cost_budgets ('
                "tenant_id TEXT NOT NULL, agent TEXT NOT NULL DEFAULT '', "
                "cost_center TEXT NOT NULL DEFAULT '', owner TEXT NOT NULL DEFAULT '', "
                "workflow TEXT NOT NULL DEFAULT '', PRIMARY KEY (tenant_id, agent, cost_center))"
            )
            conn.execute(f'SET LOCAL search_path TO "{first_schema}", "{data_schema}"')
            conn.execute(BUDGET_PK_MIGRATION_SQL)
            columns = conn.execute(
                "SELECT a.attname FROM pg_constraint c "
                "JOIN unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) ON TRUE "
                "JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum "
                "WHERE c.conrelid = to_regclass('llm_cost_budgets') AND c.contype = 'p' ORDER BY k.ord"
            ).fetchall()
            assert [row[0] for row in columns] == ["tenant_id", "agent", "cost_center", "owner", "workflow"]
    finally:
        with psycopg.connect(dsn, autocommit=True) as cleanup:
            cleanup.execute(f'DROP SCHEMA IF EXISTS "{first_schema}" CASCADE')
            cleanup.execute(f'DROP SCHEMA IF EXISTS "{data_schema}" CASCADE')


def test_postgres_cis_checks_dedupe_latest_per_check_across_scans():
    """Re-scanning a cloud must surface one row per check, not one-per-scan.

    ``cis_benchmark_checks`` is insert-only and keyed by scan_id, so two scans
    of the same cloud persist two copies of every (cloud, check_id). The read
    path must collapse to the most recent measurement via DISTINCT ON.
    """
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_store import PostgresJobStore
    from agent_bom.api.server import JobStatus, ScanJob, ScanRequest

    store = PostgresJobStore()
    suffix = uuid4().hex
    tenant_id = f"tenant-{suffix}"

    def _cis_job(job_id: str, completed_at: str, status: str) -> ScanJob:
        job = ScanJob(
            job_id=job_id,
            tenant_id=tenant_id,
            status=JobStatus.DONE,
            created_at=completed_at,
            completed_at=completed_at,
            request=ScanRequest(format="json"),
        )
        job.result = {
            "scan_id": job_id,
            "cis_benchmark": {
                "checks": [
                    {
                        "check_id": "1.5",
                        "title": "Ensure MFA is enabled for the root user",
                        "status": status,
                        "severity": "high",
                        "cis_section": "1 - IAM",
                        "evidence": f"status={status}",
                        "resource_ids": ["root"],
                        "remediation": {"priority": 1},
                    }
                ]
            },
        }
        return job

    token = set_current_tenant(tenant_id)
    try:
        store.put(_cis_job(f"scan-old-{suffix}", "2026-01-01T00:00:00Z", "fail"))
        store.put(_cis_job(f"scan-new-{suffix}", "2026-02-01T00:00:00Z", "pass"))
        rows = store.query_cis_benchmark_checks(tenant_id, cloud="aws")
    finally:
        reset_current_tenant(token)

    aws_15 = [row for row in rows if row["check_id"] == "1.5"]
    assert len(aws_15) == 1  # not one-per-scan
    assert aws_15[0]["status"] == "pass"  # latest measurement wins


def test_postgres_audit_log_real_roundtrip_and_schema_marker():
    from agent_bom.api.audit_log import AuditEntry
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
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

    token = set_current_tenant(tenant_id)
    try:
        store.append(entry)
        entries = store.list_entries(action="scan", tenant_id=tenant_id, limit=5)
    finally:
        reset_current_tenant(token)

    assert any(item.entry_id == entry.entry_id and item.verify() for item in entries)

    with _get_pool().connection() as conn:
        row = conn.execute(
            "SELECT version FROM control_plane_schema_versions WHERE component = %s",
            ("audit_log",),
        ).fetchone()

    assert row is not None
    assert row[0] == CONTROL_PLANE_SCHEMA_VERSION


def test_postgres_scan_jobs_rls_schema_is_locked_down():
    # Schema-level guard for #1815: assert the structural RLS guarantees on
    # scan_jobs so a future migration cannot quietly relax them. This catches
    # regressions whether or not the test connection is a superuser, because
    # it inspects pg_class and pg_policies directly.
    from agent_bom.api.postgres_common import _get_pool
    from agent_bom.api.postgres_store import PostgresJobStore

    PostgresJobStore()  # triggers _ensure_tenant_rls on scan_jobs

    pool = _get_pool()
    with pool.connection() as conn:
        rls_state = conn.execute(
            """
            SELECT relrowsecurity, relforcerowsecurity
            FROM pg_class
            WHERE relname = 'scan_jobs' AND relnamespace = 'public'::regnamespace
            """
        ).fetchone()

        policy_rows = conn.execute(
            """
            SELECT policyname, cmd, qual, with_check
            FROM pg_policies
            WHERE schemaname = 'public' AND tablename = 'scan_jobs'
            """
        ).fetchall()

    assert rls_state is not None, "scan_jobs table is missing — RLS check cannot run"
    assert rls_state == (True, True), (
        "scan_jobs must have ENABLE ROW LEVEL SECURITY and FORCE ROW LEVEL SECURITY both "
        f"set; got (rowsecurity, forcerowsecurity) = {rls_state}"
    )

    isolation = [row for row in policy_rows if row[0] == "scan_jobs_tenant_isolation"]
    assert isolation, (
        f"scan_jobs is missing the scan_jobs_tenant_isolation RLS policy; present policies: {sorted(name for name, *_ in policy_rows)}"
    )
    _, cmd, qual, with_check = isolation[0]
    assert cmd in {"ALL", "*"}, f"scan_jobs_tenant_isolation must gate ALL commands; got cmd={cmd!r}"
    assert "abom_current_tenant" in (qual or ""), (
        f"scan_jobs_tenant_isolation USING clause must reference public.abom_current_tenant(); got qual={qual!r}"
    )
    assert "abom_current_tenant" in (with_check or ""), (
        f"scan_jobs_tenant_isolation WITH CHECK clause must reference public.abom_current_tenant(); got with_check={with_check!r}"
    )


def test_postgres_scan_jobs_rls_blocks_cross_tenant_raw_select():
    # Runtime red-team for #1815: insert under tenant A, then run a
    # tenant-blind raw SELECT under a session bound to tenant B. RLS must
    # return zero rows. This only exercises RLS when the test connection is
    # a non-superuser (Postgres superusers BYPASSRLS implicitly even when
    # FORCE ROW LEVEL SECURITY is set on the table); CI provisions a
    # dedicated NOSUPERUSER NOBYPASSRLS application role for that reason.
    # The test skips itself if the role check shows superuser/bypass — in
    # that case the schema-level test above is the only relevant signal.
    from agent_bom.api import postgres_common
    from agent_bom.api.postgres_common import (
        _apply_tenant_session,
        reset_current_tenant,
        set_current_tenant,
    )
    from agent_bom.api.postgres_store import PostgresJobStore
    from agent_bom.api.server import JobStatus, ScanJob, ScanRequest

    pool = postgres_common._get_pool()
    with pool.connection() as conn:
        role_state = conn.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user").fetchone()
    if role_state is None or role_state[0] or role_state[1]:
        pytest.skip(
            f"Runtime RLS check requires a non-superuser, non-bypassrls role. current_user has (rolsuper, rolbypassrls)={role_state}."
        )

    store = PostgresJobStore()
    suffix = uuid4().hex
    job_id = f"rls-redteam-{suffix}"
    tenant_a = f"tenant-a-{suffix}"
    tenant_b = f"tenant-b-{suffix}"

    job = ScanJob(
        job_id=job_id,
        tenant_id=tenant_a,
        triggered_by="ci-rls-redteam",
        status=JobStatus.PENDING,
        created_at="2026-04-26T00:00:00Z",
        request=ScanRequest(format="json"),
    )

    token_a = set_current_tenant(tenant_a)
    try:
        store.put(job)
    finally:
        reset_current_tenant(token_a)

    token_b = set_current_tenant(tenant_b)
    try:
        with pool.connection() as conn:
            _apply_tenant_session(conn)
            cross_tenant_rows = conn.execute(
                "SELECT job_id FROM scan_jobs WHERE job_id = %s",
                (job_id,),
            ).fetchall()
    finally:
        reset_current_tenant(token_b)

    assert cross_tenant_rows == [], (
        "scan_jobs RLS leaked tenant A data into a session bound to tenant B; "
        "verify that ALTER TABLE scan_jobs FORCE ROW LEVEL SECURITY is in place "
        "and that the scan_jobs_tenant_isolation policy gates ALL commands."
    )
