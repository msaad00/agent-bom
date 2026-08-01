"""Real PostgreSQL integration contract.

These tests are intentionally opt-in for local runs. CI provides a Postgres
service and sets AGENT_BOM_POSTGRES_URL so the storage contract is exercised
against a real server instead of the MockConnection unit-test harness.
"""

from __future__ import annotations

import os
from dataclasses import replace
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("AGENT_BOM_POSTGRES_URL"),
    reason="AGENT_BOM_POSTGRES_URL is required for real Postgres integration tests",
)


@pytest.fixture(autouse=True)
def reset_postgres_pool():
    from agent_bom.api import postgres_common
    from agent_bom.cloud.runtime_workload_evidence_store import reset_runtime_workload_evidence_store

    postgres_common.reset_pool()
    reset_runtime_workload_evidence_store()
    yield
    reset_runtime_workload_evidence_store()
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


def test_postgres_app_cannot_self_authorize_maintenance_and_dispatch_claim_is_tenant_safe():
    """The app GUC alone cannot cross tenants; the dedicated worker can."""
    import psycopg

    from agent_bom.api.postgres_common import (
        _get_maintenance_pool,
        _get_pool,
        _maintenance_connection,
        bypass_tenant_rls,
        reset_current_tenant,
        set_current_tenant,
    )
    from agent_bom.api.postgres_store import PostgresJobStore
    from agent_bom.api.server import JobStatus, ScanJob, ScanRequest

    suffix = uuid4().hex
    tenant_id = f"dispatch-{suffix}"
    other_tenant = f"dispatch-other-{suffix}"
    queued = ScanJob(
        job_id=f"dispatch-queued-{suffix}",
        tenant_id=tenant_id,
        status=JobStatus.PENDING,
        created_at="1900-01-01T00:00:00Z",
        request=ScanRequest(format="json"),
    )
    cross_write = queued.model_copy(update={"job_id": f"dispatch-cross-{suffix}"})
    store = PostgresJobStore()

    tenant_token = set_current_tenant(tenant_id)
    try:
        store.put(queued)
        store.put(cross_write)
        store.enqueue_for_dispatch(queued)
    finally:
        reset_current_tenant(tenant_token)

    try:
        with _get_pool().connection() as conn:
            conn.execute("SELECT set_config('app.tenant_id', %s, false)", (other_tenant,))
            conn.execute("SELECT set_config('app.bypass_rls', '1', false)")
            assert conn.execute("SELECT public.abom_rls_bypass()").fetchone() == (False,)
            assert conn.execute(
                "SELECT job_id FROM scan_dispatch_queue WHERE job_id = %s", (queued.job_id,)
            ).fetchone() is None
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(
                    "INSERT INTO scan_dispatch_queue (job_id, tenant_id, created_at, status) "
                    "VALUES (%s, %s, %s, 'pending')",
                    (cross_write.job_id, tenant_id, cross_write.created_at),
                )
            conn.rollback()

        with _get_maintenance_pool().connection() as conn:
            conn.execute("SELECT set_config('app.tenant_id', %s, false)", (other_tenant,))
            conn.execute("SELECT set_config('app.bypass_rls', '0', false)")
            assert conn.execute("SELECT public.abom_rls_bypass()").fetchone() == (False,)
            assert conn.execute(
                "SELECT job_id FROM scan_dispatch_queue WHERE job_id = %s", (queued.job_id,)
            ).fetchone() is None

        with bypass_tenant_rls(audit=False):
            with _maintenance_connection() as conn:
                assert conn.execute("SELECT public.abom_rls_bypass()").fetchone() == (True,)
                assert conn.execute(
                    "SELECT job_id FROM scan_dispatch_queue WHERE job_id = %s", (queued.job_id,)
                ).fetchone() == (queued.job_id,)

        other_token = set_current_tenant(other_tenant)
        try:
            global_job_ids = {job.job_id for job in store.list_all(all_tenants=True)}
        finally:
            reset_current_tenant(other_token)
        assert {queued.job_id, cross_write.job_id}.issubset(global_job_ids)

        claimed = store.claim_next(f"worker-{suffix}", lease_seconds=30)
        assert claimed is not None
        assert claimed.job_id == queued.job_id
        assert claimed.tenant_id == tenant_id
        store.complete_dispatch(queued.job_id)
    finally:
        cleanup_token = set_current_tenant(tenant_id)
        try:
            store.delete(queued.job_id, tenant_id=tenant_id)
            store.delete(cross_write.job_id, tenant_id=tenant_id)
        finally:
            reset_current_tenant(cleanup_token)


def test_postgres_ticketing_store_real_dml_role_roundtrip_and_tenant_filter():
    from agent_bom.api.postgres_common import _get_pool, reset_current_tenant, set_current_tenant
    from agent_bom.ticketing.connection_store import TicketLink
    from agent_bom.ticketing.models import TicketingConnectionRecord
    from agent_bom.ticketing.postgres_store import PostgresTicketingStore

    pool = _get_pool()
    with pool.connection() as conn:
        role = conn.execute(
            "SELECT current_user, has_schema_privilege(current_user, current_schema(), 'CREATE')"
        ).fetchone()
    if role is None or role[1]:
        pytest.skip("Ticketing DML contract requires the migration-provisioned application role")

    suffix = uuid4().hex
    tenant_id = f"ticketing-{suffix}"
    other_tenant_id = f"ticketing-other-{suffix}"
    connection_id = f"ticketing-connection-{suffix}"
    ticket_id = f"ticket-link-{suffix}"
    store = PostgresTicketingStore(pool=pool)
    record = TicketingConnectionRecord(
        id=connection_id,
        tenant_id=tenant_id,
        provider="jira",
        transport="rest",
        auth_method="token",
        display_name="Postgres contract",
        endpoint="https://tickets.example.invalid",
        secret_encrypted="ciphertext",
        auth_params={"user": "contract@example.invalid"},
        status="active",
        created_at="2026-07-26T00:00:00Z",
        updated_at="2026-07-26T00:00:00Z",
    )
    link = TicketLink(
        id=ticket_id,
        tenant_id=tenant_id,
        connection_id=connection_id,
        dedupe_key=f"finding-{suffix}",
        provider="jira",
        created_at="2026-07-26T00:00:00Z",
        updated_at="2026-07-26T00:00:00Z",
    )

    tenant_token = set_current_tenant(tenant_id)
    try:
        store.put_connection(record)
        won, claimed = store.claim_ticket_link(link)
        replay_won, replayed = store.claim_ticket_link(
            TicketLink(**{**link.to_public_dict(), "id": f"ticket-link-replay-{suffix}"})
        )
        same_tenant = store.get_connection(tenant_id, connection_id)
    finally:
        reset_current_tenant(tenant_token)

    other_token = set_current_tenant(other_tenant_id)
    try:
        other_tenant = store.get_connection(tenant_id, connection_id)
        other_tenant_link = store.get_ticket_link(tenant_id, ticket_id)
    finally:
        reset_current_tenant(other_token)

    try:
        assert won is True
        assert claimed.id == ticket_id
        assert replay_won is False
        assert replayed.id == ticket_id
        assert same_tenant is not None
        assert same_tenant.auth_params == {"user": "contract@example.invalid"}
        assert other_tenant is None
        assert other_tenant_link is None
        with pool.connection() as conn:
            marker = conn.execute(
                "SELECT version FROM control_plane_schema_versions WHERE component = %s",
                ("ticketing_connections",),
            ).fetchone()
            rls = conn.execute(
                "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE oid IN ('public.ticketing_connections'::regclass, 'public.ticket_links'::regclass) "
                "ORDER BY relname"
            ).fetchall()
        assert marker == (1,)
        assert rls == [("ticket_links", True, True), ("ticketing_connections", True, True)]
    finally:
        cleanup_token = set_current_tenant(tenant_id)
        try:
            store.delete_ticket_link(tenant_id, ticket_id)
            store.delete_connection(tenant_id, connection_id)
        finally:
            reset_current_tenant(cleanup_token)


def test_postgres_invitation_provisions_team_and_key_atomically_under_new_tenant_rls():
    """An operator admin may provision a distinct tenant without an RLS or FK failure."""
    import psycopg

    from agent_bom.api.auth import Role, create_api_key
    from agent_bom.api.postgres_access import PostgresKeyStore
    from agent_bom.api.postgres_common import (
        _get_pool,
        _tenant_connection,
        reset_current_tenant,
        set_current_tenant,
    )

    def _read_team(tenant_id: str, team_id: str) -> tuple | None:
        """Read ``teams`` the way production does: on a tenant-bound session.

        ``teams`` now FORCEs RLS, so a raw ``_get_pool().connection()`` never
        runs ``_apply_tenant_session`` and reads as the ``'default'`` tenant —
        it would report ``None`` for every tenant's root row and make these
        assertions vacuous. Binding the session is what the policy is for.
        """
        token = set_current_tenant(tenant_id)
        try:
            with _tenant_connection(_get_pool()) as conn:
                return conn.execute("SELECT team_id, name, slug FROM teams WHERE team_id = %s", (team_id,)).fetchone()
        finally:
            reset_current_tenant(token)

    suffix = uuid4().hex
    tenant_id = f"invite-{suffix}"
    raw_key, api_key = create_api_key("invited-owner", Role.ADMIN, tenant_id=tenant_id)
    store = PostgresKeyStore()

    operator_token = set_current_tenant(f"operator-{suffix}")
    try:
        store.provision_tenant_key(api_key, team_name="Example Organization")
    finally:
        reset_current_tenant(operator_token)

    invited_token = set_current_tenant(tenant_id)
    try:
        assert store.verify(raw_key) is not None
        stored = store.get(api_key.key_id)
        assert stored is not None
        assert stored.tenant_id == tenant_id
    finally:
        reset_current_tenant(invited_token)

    assert _read_team(tenant_id, tenant_id) == (tenant_id, "Example Organization", tenant_id)

    # The FK root is the cascade root for every tenant table, so no other
    # tenant's app-role session may see (and therefore delete) it.
    assert _read_team(f"operator-{suffix}", tenant_id) is None

    # Reusing an existing key id must fail closed and roll back the team row;
    # otherwise a partial invitation leaves an orphan tenant behind.
    rejected_tenant_id = f"invite-rejected-{suffix}"
    colliding_key = replace(api_key, tenant_id=rejected_tenant_id)
    operator_token = set_current_tenant(f"operator-{suffix}")
    try:
        with pytest.raises(psycopg.errors.UniqueViolation):
            store.provision_tenant_key(colliding_key, team_name="Rejected Organization")
    finally:
        reset_current_tenant(operator_token)

    assert _read_team(rejected_tenant_id, rejected_tenant_id) is None


def test_postgres_teams_fk_root_is_tenant_isolated_but_still_purgeable_by_maintenance():
    """``teams`` RLS must block a cross-tenant purge without breaking the real one.

    ``teams`` is the FK root every tenant table references ``ON DELETE
    CASCADE``, and ``agent_bom_app`` holds ``DELETE`` on it, so one tenant
    reaching another tenant's root row destroys that tenant's whole dataset.
    The isolation is only safe to ship if the legitimate purge in
    ``tenant_lifecycle`` — ``bypass_tenant_rls()`` + ``_maintenance_connection()``
    — still deletes the row; otherwise cleanup silently reports
    ``tenant_root: 0`` and leaks orphan tenants forever.
    """
    from agent_bom.api.auth import Role, create_api_key
    from agent_bom.api.postgres_access import PostgresKeyStore
    from agent_bom.api.postgres_common import (
        _get_pool,
        _maintenance_connection,
        _tenant_connection,
        bypass_tenant_rls,
        reset_current_tenant,
        set_current_tenant,
    )

    suffix = uuid4().hex
    victim = f"teams-victim-{suffix}"
    attacker = f"teams-attacker-{suffix}"
    _, victim_key = create_api_key("victim-owner", Role.ADMIN, tenant_id=victim)
    store = PostgresKeyStore()
    store.provision_tenant_key(victim_key, team_name="Victim Organization")

    # An ordinary app-role session bound to another tenant can neither see nor
    # delete the victim's root row, so the cascade cannot be triggered.
    attacker_token = set_current_tenant(attacker)
    try:
        with _tenant_connection(_get_pool()) as conn:
            assert conn.execute("SELECT team_id FROM teams WHERE team_id = %s", (victim,)).fetchone() is None
            cursor = conn.execute("DELETE FROM teams WHERE team_id = %s", (victim,))
            assert cursor.rowcount == 0
            conn.commit()
    finally:
        reset_current_tenant(attacker_token)

    victim_token = set_current_tenant(victim)
    try:
        with _tenant_connection(_get_pool()) as conn:
            assert conn.execute("SELECT team_id FROM teams WHERE team_id = %s", (victim,)).fetchone() == (victim,)
    finally:
        reset_current_tenant(victim_token)

    # The maintenance purge path still reaches the row.
    purge_token = set_current_tenant(victim)
    try:
        with bypass_tenant_rls():
            with _maintenance_connection() as conn:
                assert conn.execute("SELECT public.abom_rls_bypass()").fetchone() == (True,)
                conn.execute("DELETE FROM api_keys WHERE team_id = %s", (victim,))
                cursor = conn.execute("DELETE FROM teams WHERE team_id = %s", (victim,))
                assert cursor.rowcount == 1
                conn.commit()
    finally:
        reset_current_tenant(purge_token)

    verify_token = set_current_tenant(victim)
    try:
        with _tenant_connection(_get_pool()) as conn:
            assert conn.execute("SELECT team_id FROM teams WHERE team_id = %s", (victim,)).fetchone() is None
    finally:
        reset_current_tenant(verify_token)


def test_postgres_managed_trial_invitation_is_digest_only_email_bound_and_single_use():
    from datetime import datetime, timezone

    from agent_bom.api.managed_trial_invitation import (
        ManagedTrialInvitationError,
        issue_managed_trial_invitation,
    )
    from agent_bom.api.postgres_common import _get_pool, _tenant_connection, reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_managed_trial_invitation import PostgresManagedTrialInvitationStore

    suffix = uuid4().hex
    tenant_id = f"trial-{suffix}"
    store = PostgresManagedTrialInvitationStore()
    issued = issue_managed_trial_invitation(
        store,
        email="Analyst@Example.COM",
        tenant_id=tenant_id,
        team_name="Synthetic Trial",
        now=datetime(2026, 7, 24, 12, 0, tzinfo=timezone.utc),
    )

    tenant_token = set_current_tenant(tenant_id)
    try:
        with _tenant_connection(_get_pool()) as conn:
            row = conn.execute(
                """SELECT invitation_id, token_digest, email, tenant_id, state,
                          created_at, expires_at, accepted_at, verified_subject
                   FROM managed_trial_invitations WHERE invitation_id = %s""",
                (issued.invitation.invitation_id,),
            ).fetchone()
            lifecycle = conn.execute(
                """SELECT state, trial_ends_at, cleanup_after
                   FROM managed_trial_tenants WHERE tenant_id = %s""",
                (tenant_id,),
            ).fetchone()
            key_count = conn.execute("SELECT count(*) FROM api_keys WHERE team_id = %s", (tenant_id,)).fetchone()[0]
            column_names = {
                value[0]
                for value in conn.execute(
                    """SELECT column_name FROM information_schema.columns
                       WHERE table_schema = current_schema() AND table_name = 'managed_trial_invitations'"""
                ).fetchall()
            }
    finally:
        reset_current_tenant(tenant_token)

    assert row is not None
    assert row[1] == issued.invitation.token_digest
    assert row[2] == "analyst@example.com"
    assert issued.raw_token not in repr(row)
    assert lifecycle is not None
    assert lifecycle[0] == "active"
    assert lifecycle[2] > lifecycle[1]
    assert key_count == 0
    assert not {"raw_token", "api_key", "oidc_subject"} & column_names

    accepted = store.accept_digest(
        issued.invitation.token_digest,
        verified_email="analyst@example.com",
        verified_subject="oidc|synthetic-subject",
        now=datetime(2026, 7, 24, 13, 0, tzinfo=timezone.utc),
    )
    assert accepted.state == "accepted"
    assert accepted.verified_subject == "oidc|synthetic-subject"

    other_tenant_token = set_current_tenant(f"other-{suffix}")
    try:
        with _tenant_connection(_get_pool()) as conn:
            cross_tenant_invitation = conn.execute(
                "SELECT invitation_id FROM managed_trial_invitations WHERE invitation_id = %s",
                (issued.invitation.invitation_id,),
            ).fetchone()
            cross_tenant_lifecycle = conn.execute(
                "SELECT tenant_id FROM managed_trial_tenants WHERE tenant_id = %s",
                (tenant_id,),
            ).fetchone()
    finally:
        reset_current_tenant(other_tenant_token)
    assert cross_tenant_invitation is None
    assert cross_tenant_lifecycle is None

    with pytest.raises(ManagedTrialInvitationError):
        store.accept_digest(
            issued.invitation.token_digest,
            verified_email="analyst@example.com",
            verified_subject="oidc|synthetic-subject",
            now=datetime(2026, 7, 24, 13, 1, tzinfo=timezone.utc),
        )


def test_demo_estate_bootstrap_uses_secret_aware_migrated_postgres(monkeypatch):
    """Compose's password-free app DSN must still persist demo findings."""
    from agent_bom.api.postgres_store import PostgresJobStore
    from agent_bom.api.stores import set_job_store
    from agent_bom.cloud.runtime_workload_evidence_store import reset_runtime_workload_evidence_store
    from agent_bom.demo_estate.bootstrap import maybe_bootstrap_demo_estate

    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE_FORCE", "1")
    store = PostgresJobStore()
    set_job_store(store)
    reset_runtime_workload_evidence_store()

    summary = maybe_bootstrap_demo_estate()

    assert summary.get("scan_error") is not True
    assert summary.get("seeded") is True
    assert int(summary.get("findings") or 0) > 0
    jobs = store.list_all(tenant_id="default")
    assert any(job.job_id == summary["job_id"] and job.result and job.result.get("findings") for job in jobs)


def test_runtime_workload_evidence_shared_pool_roundtrip_and_rls():
    from agent_bom.api.postgres_common import _get_pool
    from agent_bom.cloud.runtime_workload_evidence import RuntimeWorkloadSignal
    from agent_bom.cloud.runtime_workload_evidence_store import PostgresRuntimeWorkloadEvidenceStore

    suffix = uuid4().hex
    tenant_a = f"runtime-a-{suffix}"
    tenant_b = f"runtime-b-{suffix}"

    def signal(tenant_id: str) -> RuntimeWorkloadSignal:
        return RuntimeWorkloadSignal(
            tenant_id=tenant_id,
            provider="aws",
            account_id="123456789012",
            workload_ref="i-shared",
            signal_type="ioc_detection",
            severity="high",
            observed_at="2026-07-24T00:00:00Z",
            source_id="ci-edr",
            source_kind="edr",
            dedup_key="shared-event",
            title="CI runtime evidence",
            evidence={"kind": "integration"},
        )

    store = PostgresRuntimeWorkloadEvidenceStore()
    assert store.put_batch([signal(tenant_a)]) == 1
    assert store.put_batch([signal(tenant_b)]) == 1
    assert [row.tenant_id for row in store.list_for_tenant(tenant_a)] == [tenant_a]
    assert [row.tenant_id for row in store.list_for_tenant(tenant_b)] == [tenant_b]

    with _get_pool().connection() as connection:
        marker = connection.execute(
            "SELECT version FROM control_plane_schema_versions WHERE component = %s",
            ("runtime_workload_evidence",),
        ).fetchone()
        rls = connection.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = 'public.runtime_workload_evidence'::regclass"
        ).fetchone()
    assert marker == (2,)
    assert rls == (True, True)


def _postgres_connect(**kwargs):
    """Connect with the shared password-file/IAM-aware secret resolution."""
    import psycopg

    from agent_bom.api.postgres_common import resolve_postgres_secret, resolve_postgres_url

    connect_kwargs = dict(kwargs)
    password = resolve_postgres_secret()
    if password is not None:
        connect_kwargs["password"] = password
    return psycopg.connect(resolve_postgres_url(), **connect_kwargs)


def test_budget_pk_migration_targets_visible_relation_across_search_path():
    """The inspected and altered table must be the same visible relation.

    Migration DDL needs CREATE SCHEMA; the Compose/CI app role is DML-only, so
    prefer an explicit migrator/admin DSN when provided and otherwise use the
    password-file-aware app connection (skipping if schema DDL is denied).
    """
    import psycopg

    from agent_bom.api.postgres_cost import BUDGET_PK_MIGRATION_SQL

    admin_dsn = os.environ.get("AGENT_BOM_POSTGRES_ADMIN_URL", "").strip()
    suffix = uuid4().hex[:12]
    first_schema = f"empty_{suffix}"
    data_schema = f"budget_{suffix}"

    def _connect(**kwargs):
        if admin_dsn:
            return psycopg.connect(admin_dsn, **kwargs)
        return _postgres_connect(**kwargs)

    try:
        with _connect() as conn:
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
        with _connect(autocommit=True) as cleanup:
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


def test_policy_audit_dedup_is_tenant_safe_and_old_replica_compatible():
    """The database trigger preserves the legacy conflict target during rollout."""
    from agent_bom.api.policy_store import PolicyAuditEntry
    from agent_bom.api.postgres_common import _tenant_connection, reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_policy import PostgresPolicyStore

    store = PostgresPolicyStore()
    suffix = uuid4().hex
    logical_id = f"shared-{suffix}"
    tenant_a = f"policy-a-{suffix}"
    tenant_b = f"policy-b-{suffix}"

    def _entry(tenant_id: str) -> PolicyAuditEntry:
        return PolicyAuditEntry(
            entry_id=logical_id,
            policy_id="rollout-policy",
            policy_name="rollout compatibility",
            rule_id="r1",
            agent_name="agent-a",
            tool_name="shell",
            action_taken="blocked",
            reason="test",
            timestamp="2026-07-29T00:00:00+00:00",
            tenant_id=tenant_id,
        )

    physical_keys: list[str] = []
    for tenant_id in (tenant_a, tenant_b):
        entry = _entry(tenant_id)
        token = set_current_tenant(tenant_id)
        try:
            store.put_audit_entry(entry)
            store.put_audit_entry(entry)  # same-tenant retry still dedupes
            rows = store.list_audit_entries(tenant_id=tenant_id)
            with _tenant_connection(store._pool) as conn:
                stored = conn.execute(
                    """
                    SELECT entry_id, logical_entry_id, data ->> 'entry_id'
                      FROM policy_audit_log
                     WHERE logical_entry_id = %s
                    """,
                    (logical_id,),
                ).fetchall()
        finally:
            reset_current_tenant(token)

        assert [row.entry_id for row in rows if row.entry_id == logical_id] == [logical_id]
        assert len(stored) == 1
        assert stored[0][1:] == (logical_id, logical_id)
        physical_keys.append(stored[0][0])

    assert physical_keys[0] != physical_keys[1]


# Bare unique indexes on tenant tables need an explicit identity contract. Most
# are server-issued opaque/global IDs, database surrogates, security-token
# digests, or the globally unique team slug. policy_audit_log is the one
# compatibility exception: its trigger turns the bare entry_id column into a
# tenant-derived physical key so old ON CONFLICT(entry_id) writers remain valid.
_AUDITED_GLOBAL_TENANT_INDEXES = {
    # Server-issued or globally canonical opaque identifiers.
    ("agent_conditional_access_policies", "agent_conditional_access_policies_pkey"),
    ("agent_identities", "agent_identities_pkey"),
    ("agent_identity_jit_grants", "agent_identity_jit_grants_pkey"),
    ("agents", "agents_pkey"),
    ("api_keys", "api_keys_pkey"),
    ("audit_log", "audit_log_pkey"),
    ("cloud_connections", "cloud_connections_pkey"),
    ("control_plane_sources", "control_plane_sources_pkey"),
    ("credential_refs", "credential_refs_pkey"),
    ("exceptions", "exceptions_pkey"),
    ("findings", "findings_pkey"),
    # fleet_agents deliberately absent: its agent_id is derived from agent
    # CONTENT with no tenant component (canonical_ids.canonical_agent_id), so a
    # bare key let the first tenant to register a stock agent deny every other
    # tenant its own. Re-keyed to (tenant_id, agent_id) by 20260801_01; adding
    # it back here would re-admit the cross-tenant denial.
    ("gateway_policies", "gateway_policies_pkey"),
    ("job_queue", "job_queue_pkey"),
    ("managed_trial_invitations", "managed_trial_invitations_pkey"),
    ("mcp_client_configs", "mcp_client_configs_pkey"),
    ("model_provider_keys", "model_provider_keys_pkey"),
    ("model_virtual_keys", "model_virtual_keys_pkey"),
    ("policy_results", "policy_results_pkey"),
    ("proxy_replay_log", "proxy_replay_log_pkey"),
    ("scan_dispatch_queue", "scan_dispatch_queue_pkey"),
    ("scan_jobs", "scan_jobs_pkey"),
    ("scan_schedules", "scan_schedules_pkey"),
    ("ticket_links", "ticket_links_pkey"),
    ("ticketing_connections", "ticketing_connections_pkey"),
    # Database-generated surrogate sequence keys; tenant uniqueness is carried
    # by a separate logical index where the table has a logical dedupe key.
    ("cis_benchmark_checks", "cis_benchmark_checks_pkey"),
    ("governance_audit_log", "governance_audit_log_pkey"),
    ("policy_audit_log", "policy_audit_log_pkey"),
    ("trend_history", "trend_history_pkey"),
    # Credential/token digests are intentionally globally unique so the same
    # bearer secret can never authenticate as two principals or invitations.
    ("agent_identities", "agent_identities_token_hash_key"),
    ("managed_trial_invitations", "managed_trial_invitations_token_digest_key"),
    ("model_virtual_keys", "model_virtual_keys_token_hash_key"),
    # Team slugs are the global routing namespace.
    ("teams", "teams_slug_key"),
    # Rolling-deployment-compatible tenant-derived physical key, asserted below.
    ("policy_audit_log", "uq_policy_audit_log_entry"),
}


def test_every_tenant_table_global_unique_index_has_an_audited_contract():
    """Fail CI when a tenant table gains a bare unique key without review."""
    from agent_bom.api.postgres_common import _get_pool

    with _get_pool().connection() as conn:
        rows = conn.execute(
            """
            WITH tenant_tables AS (
                SELECT c.oid,
                       c.relname,
                       array_agg(a.attname ORDER BY a.attname)
                           FILTER (WHERE a.attname IN ('tenant_id', 'team_id')) AS tenant_cols
                  FROM pg_class c
                  JOIN pg_namespace n ON n.oid = c.relnamespace
                  JOIN pg_attribute a
                    ON a.attrelid = c.oid
                   AND a.attnum > 0
                   AND NOT a.attisdropped
                 WHERE n.nspname = 'public'
                   AND c.relkind IN ('r', 'p')
                 GROUP BY c.oid, c.relname
                HAVING bool_or(a.attname IN ('tenant_id', 'team_id'))
            ), unique_indexes AS (
                SELECT tables.relname AS table_name,
                       tables.tenant_cols,
                       index_class.relname AS index_name,
                       array_agg(attribute.attname ORDER BY key.ordinality)
                           FILTER (WHERE attribute.attname IS NOT NULL) AS index_cols
                  FROM tenant_tables tables
                  JOIN pg_index index_meta
                    ON index_meta.indrelid = tables.oid
                   AND index_meta.indisunique
                  JOIN pg_class index_class ON index_class.oid = index_meta.indexrelid
                  LEFT JOIN LATERAL unnest(index_meta.indkey)
                       WITH ORDINALITY AS key(attnum, ordinality) ON TRUE
                  LEFT JOIN pg_attribute attribute
                    ON attribute.attrelid = tables.oid
                   AND attribute.attnum = key.attnum
                 GROUP BY tables.relname, tables.tenant_cols, index_class.relname
            )
            SELECT table_name, index_name
              FROM unique_indexes
             WHERE NOT (index_cols && tenant_cols)
             ORDER BY table_name, index_name
            """
        ).fetchall()
        policy_key = conn.execute(
            """
            SELECT indexdef,
                   obj_description(to_regclass('public.uq_policy_audit_log_entry'), 'pg_class'),
                   EXISTS (
                       SELECT 1 FROM pg_trigger
                        WHERE tgrelid = 'public.policy_audit_log'::regclass
                          AND tgname = 'policy_audit_set_key'
                          AND NOT tgisinternal
                   )
              FROM pg_indexes
             WHERE schemaname = 'public'
               AND indexname = 'uq_policy_audit_log_entry'
            """
        ).fetchone()

    actual = {(str(table), str(index)) for table, index in rows}
    assert actual == _AUDITED_GLOBAL_TENANT_INDEXES
    assert policy_key is not None
    assert "(entry_id)" in policy_key[0] and "team_id, entry_id" not in policy_key[0]
    assert policy_key[1] == "agent-bom policy audit tenant key v2"
    assert policy_key[2] is True


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


def test_postgres_second_large_graph_snapshot_reconciles_within_statement_timeout(monkeypatch):
    """A 7k-edge second persist completes under the production timeout contract."""
    from agent_bom.api import postgres_common
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore
    from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedNode

    edge_count = 7_000
    suffix = uuid4().hex
    tenant_id = f"graph-reconcile-{suffix}"
    prior_scan = f"prior-{suffix}"
    current_scan = f"current-{suffix}"

    def nodes():
        for index in range(edge_count + 1):
            yield UnifiedNode(id=f"node:{index}", entity_type=EntityType.AGENT, label=f"Node {index}")

    def edges():
        for index in range(edge_count):
            yield UnifiedEdge(
                source=f"node:{index}",
                target=f"node:{index + 1}",
                relationship=RelationshipType.DEPENDS_ON,
            )

    # Keep the live regression tighter than the production 15s default while
    # leaving ample room for CI variance. The timeout is applied when the pool
    # checks out each connection.
    monkeypatch.setattr(postgres_common, "POSTGRES_STATEMENT_TIMEOUT_MS", 5_000)
    postgres_common.reset_pool()
    store = PostgresGraphStore()
    token = set_current_tenant(tenant_id)
    try:
        store.save_graph_streaming(
            scan_id=prior_scan,
            tenant_id=tenant_id,
            nodes=nodes(),
            edges=edges(),
            created_at="2026-07-30T00:00:00Z",
        )
        persisted = store.save_graph_streaming(
            scan_id=current_scan,
            tenant_id=tenant_id,
            nodes=nodes(),
            edges=edges(),
            created_at="2026-07-30T00:01:00Z",
        )
        stats = store.snapshot_stats(tenant_id=tenant_id, scan_id=current_scan)
        assert persisted["edges"] == edge_count
        assert stats["total_edges"] == edge_count
    finally:
        store.delete_tenant(tenant_id=tenant_id)
        reset_current_tenant(token)


def test_postgres_graph_build_workspace_rls_schema_is_locked_down():
    """Structural RLS guard for graph_build_workspace_* staging tables."""
    from agent_bom.api.postgres_common import _get_pool
    from agent_bom.api.postgres_graph import PostgresGraphStore

    PostgresGraphStore()  # registers _ensure_tenant_rls on workspace tables

    pool = _get_pool()
    with pool.connection() as conn:
        for table in ("graph_build_workspace_nodes", "graph_build_workspace_edges"):
            rls_state = conn.execute(
                """
                SELECT relrowsecurity, relforcerowsecurity
                FROM pg_class
                WHERE relname = %s AND relnamespace = 'public'::regnamespace
                """,
                (table,),
            ).fetchone()
            policy_rows = conn.execute(
                """
                SELECT policyname, cmd, qual, with_check
                FROM pg_policies
                WHERE schemaname = 'public' AND tablename = %s
                """,
                (table,),
            ).fetchall()
            assert rls_state == (True, True), f"{table} must ENABLE+FORCE RLS; got {rls_state}"
            isolation = [row for row in policy_rows if row[0] == f"{table}_tenant_isolation"]
            assert isolation, f"{table} missing tenant_isolation policy"
            _, cmd, qual, with_check = isolation[0]
            assert cmd in {"ALL", "*"}
            assert "abom_current_tenant" in (qual or "")
            assert "abom_current_tenant" in (with_check or "")


def test_postgres_graph_build_workspace_rls_blocks_cross_tenant_raw_select():
    """Insert workspace rows under tenant A; tenant B raw SELECT must see zero."""
    from agent_bom.api import postgres_common
    from agent_bom.api.postgres_common import (
        _apply_tenant_session,
        reset_current_tenant,
        set_current_tenant,
    )
    from agent_bom.api.postgres_graph import PostgresGraphStore

    PostgresGraphStore()
    pool = postgres_common._get_pool()
    with pool.connection() as conn:
        role_state = conn.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user").fetchone()
    if role_state is None or role_state[0] or role_state[1]:
        pytest.skip(
            f"Runtime RLS check requires a non-superuser, non-bypassrls role. current_user has (rolsuper, rolbypassrls)={role_state}."
        )

    suffix = uuid4().hex
    workspace_id = f"gbw-rls-{suffix}"
    tenant_a = f"tenant-a-{suffix}"
    tenant_b = f"tenant-b-{suffix}"
    node_id = f"node-{suffix}"

    token_a = set_current_tenant(tenant_a)
    try:
        with pool.connection() as conn:
            _apply_tenant_session(conn)
            conn.execute(
                """
                INSERT INTO graph_build_workspace_nodes
                    (workspace_id, tenant_id, node_id, payload, entity_type)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (workspace_id, tenant_a, node_id, '{"id":"x"}', "agent"),
            )
            conn.commit()
    finally:
        reset_current_tenant(token_a)

    token_b = set_current_tenant(tenant_b)
    try:
        with pool.connection() as conn:
            _apply_tenant_session(conn)
            cross_tenant_rows = conn.execute(
                "SELECT node_id FROM graph_build_workspace_nodes WHERE workspace_id = %s AND node_id = %s",
                (workspace_id, node_id),
            ).fetchall()
    finally:
        reset_current_tenant(token_b)

    assert cross_tenant_rows == [], "graph_build_workspace_nodes RLS leaked tenant A data into a session bound to tenant B"

    # Cleanup under tenant A (and edges table is unused here).
    token_a = set_current_tenant(tenant_a)
    try:
        with pool.connection() as conn:
            _apply_tenant_session(conn)
            conn.execute(
                "DELETE FROM graph_build_workspace_nodes WHERE workspace_id = %s",
                (workspace_id,),
            )
            conn.commit()
    finally:
        reset_current_tenant(token_a)


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


def test_cloud_connections_rls_requires_the_scheduler_to_bind_the_record_tenant():
    """Regression cover for #4452 against a real server.

    The connections scheduler writes on behalf of whichever tenant owns the
    record, so it must bind that tenant before touching the store. Without the
    binding the session still reports the ``default`` fallback and the
    ``cloud_connections_tenant_isolation`` WITH CHECK clause rejects the row —
    on a multi-tenant Postgres control plane every scheduled write for a
    non-``default`` tenant failed.

    Only a live server can prove the three things below: that the owner's write
    round-trips, that the unbound write raises the real
    ``psycopg.errors.InsufficientPrivilege`` (which pins the WITH CHECK half of
    the policy, so a migration that drops it fails here), and that one tenant's
    rejection does not poison the next tenant's write.
    """
    import psycopg

    from agent_bom.api import postgres_common
    from agent_bom.api.connection_store import CloudConnectionRecord
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_connection import PostgresConnectionStore

    pool = postgres_common._get_pool()
    with pool.connection() as conn:
        role_state = conn.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user").fetchone()
    if role_state is None or role_state[0] or role_state[1]:
        pytest.skip(
            f"Runtime RLS check requires a non-superuser, non-bypassrls role. current_user has (rolsuper, rolbypassrls)={role_state}."
        )

    store = PostgresConnectionStore()
    suffix = uuid4().hex
    tenant_a = f"conn-a-{suffix}"
    tenant_b = f"conn-b-{suffix}"

    def _record(connection_id: str, tenant_id: str) -> CloudConnectionRecord:
        return CloudConnectionRecord(
            id=connection_id,
            tenant_id=tenant_id,
            provider="aws",
            display_name="Scheduled production",
            role_ref="arn:aws:iam::123456789012:role/agent-bom-read-only",
            external_id_encrypted="",
            created_at="2026-07-24T00:00:00Z",
            updated_at="2026-07-24T00:00:01Z",
            scan_interval_minutes=60,
        )

    record_a = _record(f"sched-a-{suffix}", tenant_a)
    record_b = _record(f"sched-b-{suffix}", tenant_b)

    try:
        # 1. The scheduler's fixed behaviour: bind the record's tenant, write,
        #    and read the row back as its owner.
        token = set_current_tenant(tenant_a)
        try:
            store.put(record_a)
            owned = store.get(tenant_a, record_a.id)
        finally:
            reset_current_tenant(token)
        assert owned is not None, "a tenant-bound scheduled write did not persist"
        assert owned.tenant_id == tenant_a
        assert owned.scan_interval_minutes == 60

        # 2. The pre-fix behaviour: no binding, so the session is still on the
        #    'default' fallback and the WITH CHECK clause must refuse the row.
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            store.put(_record(f"sched-unbound-{suffix}", tenant_a))

        # 3. A rejected write for one tenant must not stop the next tenant's.
        token = set_current_tenant(tenant_a)
        try:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                store.put(record_b)
        finally:
            reset_current_tenant(token)

        token = set_current_tenant(tenant_b)
        try:
            store.put(record_b)
            second = store.get(tenant_b, record_b.id)
            leaked = store.get(tenant_a, record_a.id)
        finally:
            reset_current_tenant(token)
        assert second is not None, "tenant B's write was lost after tenant A's rejection"
        assert second.tenant_id == tenant_b
        assert leaked is None, "cloud_connections RLS leaked tenant A's row into a session bound to tenant B"
    finally:
        for tenant_id, connection_id in ((tenant_a, record_a.id), (tenant_b, record_b.id)):
            token = set_current_tenant(tenant_id)
            try:
                store.delete(tenant_id, connection_id)
            finally:
                reset_current_tenant(token)


def test_audit_append_persists_entry_tenant_under_mismatched_ambient_context():
    """Regression for #4276: proxy-header auth emits its audit event BEFORE the
    request tenant context is installed, so ``append`` runs while the ambient
    contextvar still points at another tenant. The INSERT must bind the entry's
    own tenant (as the head read already does) so RLS ``WITH CHECK`` accepts the
    row instead of silently dropping the authentication event.
    """
    from agent_bom.api.audit_log import AuditEntry
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_store import PostgresAuditLog

    store = PostgresAuditLog()
    suffix = uuid4().hex
    tenant = f"tenant-proxy-{suffix}"

    # Ambient context deliberately left at its 'default' fallback, mirroring the
    # middleware ordering at the proxy-auth call site.
    first = AuditEntry(
        action="auth.proxy_header_authenticated",
        actor="proxy-user",
        resource="/v1/findings",
        details={"tenant_id": tenant},
    )
    store.append(first)
    second = AuditEntry(
        action="auth.proxy_header_authenticated",
        actor="proxy-user",
        resource="/v1/graph",
        details={"tenant_id": tenant},
    )
    store.append(second)

    token = set_current_tenant(tenant)
    try:
        rows = store.list_entries(action="auth.proxy_header_authenticated", tenant_id=tenant, limit=10)
        verified, tampered = store.verify_integrity(tenant_id=tenant)
    finally:
        reset_current_tenant(token)

    assert {e.entry_id for e in rows} == {first.entry_id, second.entry_id}, "proxy-auth audit events were dropped under Postgres RLS"
    by_id = {e.entry_id: e for e in rows}
    assert by_id[second.entry_id].prev_signature == by_id[first.entry_id].hmac_signature
    assert (verified, tampered) == (2, 0)
