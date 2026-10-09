"""Committed job revisions must be durable, tenant scoped, and shared by replicas."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from uuid import uuid4

import pytest

from agent_bom.api.models import ScanJob, ScanRequest
from agent_bom.api.postgres_common import _new_application_pool, _tenant_connection, reset_current_tenant, set_current_tenant
from agent_bom.api.postgres_job_store import PostgresJobStore

pytestmark = pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires restricted-role Postgres")


@contextmanager
def tenant_scope(tenant):
    token = set_current_tenant(tenant)
    try:
        yield
    finally:
        reset_current_tenant(token)


def job(tenant, *, value=1):
    return ScanJob(job_id="same-id", tenant_id=tenant, created_at="2026-10-06T00:00:00Z", request=ScanRequest(), result={"value": value})


@pytest.fixture
def replicas():
    pools = [_new_application_pool(min_size=1, max_size=2) for _ in range(2)]
    try:
        yield tuple(PostgresJobStore(pool=pool) for pool in pools)
    finally:
        for pool in pools:
            pool.close()


def test_job_revision_survives_replica_reopen_and_same_shape_refresh(replicas, monkeypatch):
    a, b = replicas
    tenant = "revision-" + uuid4().hex
    with tenant_scope(tenant):
        initial = a.overview_evidence_revision(tenant)
        a.put(job(tenant))
        first = b.overview_evidence_revision(tenant)
        b.put(job(tenant, value=2))
        second = a.overview_evidence_revision(tenant)
        assert initial != first != second
        monkeypatch.setattr(a, "list_all", lambda **kwargs: pytest.fail("revision read deserialized all job payloads"))
        assert a.overview_evidence_revision(tenant) == second
        assert PostgresJobStore(pool=b._pool).overview_evidence_revision(tenant) == second
        assert b.delete("same-id", tenant_id=tenant)
        assert a.overview_evidence_revision(tenant) not in {initial, first, second}


def test_job_revision_isolated_between_tenants_and_pooled_connections(replicas):
    a, b = replicas
    first, second = ("revision-" + uuid4().hex for _ in range(2))
    with tenant_scope(first):
        a.put(job(first))
        before = a.overview_evidence_revision(first)
    with tenant_scope(second):
        b.put(job(second))
        b.put(job(second, value=2))
        other = b.overview_evidence_revision(second)
        assert b.overview_evidence_revision(first) != before
    with tenant_scope(first):
        assert b.overview_evidence_revision(first) == before
        assert a.overview_evidence_revision(second) != other


def test_revision_changes_only_when_transaction_commits(replicas):
    a, b = replicas
    tenant = "revision-" + uuid4().hex
    with tenant_scope(tenant):
        a.put(job(tenant))
        before = b.overview_evidence_revision(tenant)
        with _tenant_connection(a._pool) as conn:
            conn.execute("UPDATE scan_jobs SET data=jsonb_set(data,'{result,value}','9') WHERE team_id=%s", (tenant,))
            assert b.overview_evidence_revision(tenant) == before
            conn.rollback()
        assert b.overview_evidence_revision(tenant) == before
        with _tenant_connection(a._pool) as conn:
            conn.execute("UPDATE scan_jobs SET data=jsonb_set(data,'{result,value}','9') WHERE team_id=%s", (tenant,))
            conn.commit()
        assert b.overview_evidence_revision(tenant) != before


def test_concurrent_replicas_do_not_lose_revision_updates(replicas):
    a, b = replicas
    tenant = "revision-" + uuid4().hex
    with tenant_scope(tenant):
        a.put(job(tenant))
        before = a.overview_evidence_revision(tenant)

    def write(index):
        with tenant_scope(tenant):
            (a if index % 2 else b).put(job(tenant, value=index))

    with ThreadPoolExecutor(max_workers=2) as workers:
        list(workers.map(write, range(12)))
    with tenant_scope(tenant):
        after = b.overview_evidence_revision(tenant)
    assert before.rsplit(":", 1)[0] == after.rsplit(":", 1)[0]
    assert int(after.rsplit(":", 1)[1]) - int(before.rsplit(":", 1)[1]) == 12


def test_app_cannot_write_or_bypass_another_tenants_revision(replicas):
    from psycopg.errors import InsufficientPrivilege

    a, b = replicas
    first, second = ("revision-" + uuid4().hex for _ in range(2))
    with tenant_scope(second):
        b.put(job(second))
        before = b.overview_evidence_revision(second)
    with tenant_scope(first):
        with pytest.raises(InsufficientPrivilege), _tenant_connection(a._pool) as conn:
            conn.execute("INSERT INTO job_overview_revisions (tenant_id) VALUES (%s)", (second,))
        with _tenant_connection(a._pool) as conn:
            conn.execute("SELECT set_config('app.bypass_rls','1',true)")
            assert conn.execute("SELECT revision FROM job_overview_revisions WHERE tenant_id=%s", (second,)).fetchone() is None
            assert conn.execute("UPDATE job_overview_revisions SET revision=0 WHERE tenant_id=%s", (second,)).rowcount == 0
    with tenant_scope(second):
        assert b.overview_evidence_revision(second) == before


def test_runtime_bootstrap_includes_the_same_atomic_revision_schema():
    from pathlib import Path

    from agent_bom.api.storage.job_revisions import POSTGRES_JOB_REVISIONS_V1

    bootstrap = Path("deploy/supabase/postgres/runtime-schema.sql").read_text()
    assert POSTGRES_JOB_REVISIONS_V1 in bootstrap


def test_demo_existence_projection_is_tenant_scoped_and_skips_payload_parsing(replicas, monkeypatch):
    from agent_bom.api.models import JobStatus

    a, b = replicas
    first, second = ("demo-projection-" + uuid4().hex for _ in range(2))
    monkeypatch.setattr(a, "list_all", lambda **kwargs: pytest.fail("existence read materialized reports"))
    with tenant_scope(first):
        scan = job(first)
        scan.status = JobStatus.DONE
        scan.triggered_by = "demo-estate-bootstrap"
        scan.result = {"findings": [{"id": "example"}]}
        a.put(scan)
        assert b.has_usable_demo_job(first)
        scan.result = {"findings": []}
        a.put(scan)
        assert not b.has_usable_demo_job(first)
        scan.triggered_by = None
        scan.result = {"scan_sources": ["enterprise-demo"], "vulnerabilities": [{"id": "example"}]}
        a.put(scan)
        assert b.has_usable_demo_job(first)
    with tenant_scope(second):
        assert not a.has_usable_demo_job(first)
        assert not a.has_usable_demo_job(second)


def test_posture_projection_refreshes_after_another_replica_writes(replicas, monkeypatch):
    from agent_bom.api.models import JobStatus
    from agent_bom.api.posture_scan_snapshot import scan_posture_inputs

    a, b = replicas
    tenant = "posture-projection-" + uuid4().hex
    with tenant_scope(tenant):
        scan = job(tenant)
        scan.status = JobStatus.DONE
        scan.result = {"summary": {"total_packages": 1}, "posture_scorecard": {"score": 75}}
        a.put(scan)
        reads = []

        def load():
            reads.append(1)
            return a.list_all(tenant_id=tenant)

        assert scan_posture_inputs(a, tenant, load)["posture_scorecard"]["score"] == 75
        assert scan_posture_inputs(a, tenant, load)["posture_scorecard"]["score"] == 75
        assert len(reads) == 1
        scan.result["posture_scorecard"]["score"] = 50
        b.put(scan)
        assert scan_posture_inputs(a, tenant, load)["posture_scorecard"]["score"] == 50
        assert len(reads) == 2
