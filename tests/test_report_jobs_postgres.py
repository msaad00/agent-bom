"""Live Postgres report recovery and tenant-RLS acceptance tests."""

import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest

from agent_bom.api.models import JobStatus, ReportJob
from agent_bom.api.tenant_worker import run_tenant_bound

pytestmark = pytest.mark.skipif(
    not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="Requires real Postgres application and maintenance roles"
)


@pytest.fixture
def report_stores():
    from agent_bom.api.postgres_common import _tenant_connection
    from agent_bom.api.postgres_report_jobs import PostgresReportJobStore

    first, second = PostgresReportJobStore(), PostgresReportJobStore()
    tenant = "report-pg-" + uuid4().hex
    yield first, second, tenant

    def cleanup():
        with _tenant_connection(first._pool) as conn:
            conn.execute("DELETE FROM report_jobs WHERE tenant_id = %s", (tenant,))
            conn.commit()

    run_tenant_bound(tenant, cleanup)


def new_job(tenant, name=None):
    return ReportJob(job_id=name or str(uuid4()), tenant_id=tenant, created_at="2026-09-11T00:00:00Z")


def test_postgres_report_admission_is_atomic(report_stores):
    first, second, tenant = report_stores
    with ThreadPoolExecutor(max_workers=8) as executor:
        admitted = list(
            executor.map(lambda i: run_tenant_bound(tenant, (first if i % 2 else second).enqueue, new_job(tenant), 2), range(16))
        )
    assert sum(admitted) == 2


def test_postgres_report_rls_survives_independent_store(report_stores):
    from agent_bom.api.postgres_common import _tenant_connection

    first, second, tenant = report_stores
    job = new_job(tenant)
    assert run_tenant_bound(tenant, first.enqueue, job, 2)
    assert run_tenant_bound(tenant, second.get, job.job_id, tenant) == job
    # Even a forged explicit tenant filter cannot override the authenticated context.
    assert run_tenant_bound("foreign", second.get, job.job_id, tenant) is None

    def raw_read():
        with _tenant_connection(first._pool) as conn:
            conn.execute("SELECT set_config('app.bypass_rls', '1', true)")
            return conn.execute("SELECT job_id FROM report_jobs WHERE job_id = %s", (job.job_id,)).fetchall()

    assert run_tenant_bound("foreign", raw_read) == []


def test_postgres_report_claim_recovery_and_fencing(report_stores):
    from agent_bom.api.postgres_common import _tenant_connection

    first, second, tenant = report_stores
    job = new_job(tenant)
    run_tenant_bound(tenant, first.enqueue, job, 2)
    old = first.claim_next(60, 3)
    assert old.tenant_id == tenant
    assert second.claim_next(60, 3) is None

    def expire():
        with _tenant_connection(first._pool) as conn:
            conn.execute("UPDATE report_jobs SET lease_expires_at = 0 WHERE job_id = %s", (job.job_id,))
            conn.commit()

    run_tenant_bound(tenant, expire)
    new = second.claim_next(60, 3)
    assert new.token != old.token
    done = job.model_copy(update={"status": JobStatus.DONE, "row_count": 9})
    assert not run_tenant_bound(tenant, first.renew, old, 60)
    assert not run_tenant_bound(tenant, first.finish, done, old)
    assert run_tenant_bound(tenant, second.finish, done, new)
    assert run_tenant_bound(tenant, first.get, job.job_id, tenant).row_count == 9
