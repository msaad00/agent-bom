"""Durable schedule selection, application RLS, maintenance discovery and CAS."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest

from agent_bom.api import export_schedule_store as stores
from agent_bom.api.storage import export_schedules as postgres


def test_postgres_factory_selects_schedules_and_never_falls_back(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://fixture.invalid/control_plane")
    monkeypatch.delenv("AGENT_BOM_STORE_BACKEND", raising=False)
    monkeypatch.setattr(stores, "_EXPORT_SCHEDULE_STORE", None)
    marker = object()
    monkeypatch.setattr(postgres, "PostgresExportScheduleStore", lambda: marker)
    assert stores.get_export_schedule_store() is marker
    monkeypatch.setattr(stores, "_EXPORT_SCHEDULE_STORE", None)

    def fail():
        raise RuntimeError("Storage unavailable")

    monkeypatch.setattr(postgres, "PostgresExportScheduleStore", fail)
    with pytest.raises(RuntimeError, match="Storage unavailable"):
        stores.get_export_schedule_store()
    assert stores._EXPORT_SCHEDULE_STORE is None


@pytest.fixture
def pg_stores(monkeypatch):
    dsn = os.environ.get("AGENT_BOM_TEST_EXPORT_PG_DSN") or os.environ.get("AGENT_BOM_POSTGRES_ADMIN_URL")
    if not dsn:
        pytest.skip("isolated Postgres admin DSN required")
    from psycopg import sql
    from psycopg_pool import ConnectionPool

    from agent_bom.api import postgres_common
    from agent_bom.api.export_destination_store import PostgresExportDestinationStore

    app_role, maintenance_role = "export_app_" + uuid4().hex[:12], "export_maint_" + uuid4().hex[:12]
    with ConnectionPool(dsn) as owner:
        with owner.connection() as conn:
            for role in (app_role, maintenance_role):
                conn.execute(sql.SQL("CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS").format(sql.Identifier(role)))
                conn.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(role)))
                conn.execute(sql.SQL("GRANT SELECT ON control_plane_schema_versions TO {}").format(sql.Identifier(role)))
                conn.execute(
                    sql.SQL("GRANT SELECT, INSERT, UPDATE, DELETE ON export_schedules, export_destinations TO {}").format(
                        sql.Identifier(role)
                    )
                )
            conn.execute(sql.SQL("GRANT agent_bom_rls_maintenance TO {}").format(sql.Identifier(maintenance_role)))

        def configure(role):
            def apply(conn):
                conn.execute(sql.SQL("SET SESSION AUTHORIZATION {}").format(sql.Identifier(role)))
                conn.commit()

            return apply

        monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", dsn)
        with (
            ConnectionPool(dsn, configure=configure(app_role)) as app,
            ConnectionPool(dsn, configure=configure(maintenance_role)) as maintenance,
        ):
            monkeypatch.setattr(postgres_common, "_maintenance_roles_checked", False)
            postgres_common._guard_maintenance_role_separation(app, maintenance)
            yield postgres.PostgresExportScheduleStore(app, maintenance_pool=maintenance), PostgresExportDestinationStore(app), app, owner
        with owner.connection() as conn:
            for role in (app_role, maintenance_role):
                conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
                conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


def test_postgres_schedule_durability_rls_claim_and_completion(pg_stores):
    from psycopg.errors import InsufficientPrivilege

    from agent_bom.api.postgres_common import _tenant_connection
    from agent_bom.api.tenant_worker import run_tenant_bound

    store, destinations, pool, owner = pg_stores
    tenant = "export-" + uuid4().hex
    schedule = stores.ExportSchedule(
        schedule_id=uuid4().hex,
        tenant_id=tenant,
        name="daily",
        cron_expression="0 3 * * *",
        destination_id="d",
        next_run="2026-09-28",
        created_at="v1",
        updated_at="v1",
    )

    def bound(fn, *args, **kwargs):
        return run_tenant_bound(tenant, fn, *args, **kwargs)

    try:
        bound(store.put, schedule, tenant_id=tenant)
        reconnected = postgres.PostgresExportScheduleStore(pool, maintenance_pool=store._maintenance_pool)
        assert bound(reconnected.get, schedule.schedule_id, tenant) == schedule
        assert any(row.schedule_id == schedule.schedule_id for row in store.list_due("2026-09-29", limit=100))
        assert run_tenant_bound("other", store.get, schedule.schedule_id, tenant) is None
        assert not run_tenant_bound("other", store.claim_due, schedule, "2026-09-30", tenant_id=tenant)
        with pytest.raises(InsufficientPrivilege):
            run_tenant_bound("other", store.put, schedule, tenant_id=tenant)

        def forge_bypass():
            with _tenant_connection(pool) as conn:
                conn.execute("SELECT set_config('app.bypass_rls','1',true)")
                assert conn.execute("SELECT schedule_id FROM export_schedules WHERE tenant_id=%s", (tenant,)).fetchall() == []

        run_tenant_bound("other", forge_bypass)
        with ThreadPoolExecutor(max_workers=4) as workers:
            claims = list(workers.map(lambda _: bound(store.claim_due, schedule, "2026-09-30", tenant_id=tenant), range(4)))
        assert sum(claims) == 1
        claimed = bound(store.get, schedule.schedule_id, tenant)
        assert claimed.next_run == "2026-09-30"
        assert bound(store.record_run, claimed, tenant_id=tenant, at="2026-09-29", status="success", row_count=4)
        assert not bound(store.record_run, schedule, tenant_id=tenant, at="2026-09-29", status="error", row_count=0)
        assert bound(store.get, schedule.schedule_id, tenant).last_row_count == 4
        assert bound(store.delete, schedule.schedule_id, tenant)
        assert not bound(store.record_run, claimed, tenant_id=tenant, at="2026-09-29", status="success", row_count=4)
        assert bound(store.get, schedule.schedule_id, tenant) is None
        with owner.connection() as conn:
            assert conn.execute("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE relname='export_schedules'").fetchone() == (
                True,
                True,
            )
    finally:
        bound(store.delete, schedule.schedule_id, tenant)


def test_postgres_destination_completion_preserves_edits_and_deletes(pg_stores):
    from dataclasses import replace

    from agent_bom.api.export_destination_store import ExportDestinationRecord
    from agent_bom.api.tenant_worker import run_tenant_bound

    _, store, _, _ = pg_stores
    tenant = "export-" + uuid4().hex
    record = ExportDestinationRecord(id=uuid4().hex, tenant_id=tenant, kind="s3", display_name="original", created_at="v1", updated_at="v1")

    def exercise():
        store.put(record, tenant_id=tenant)
        kwargs = dict(tenant_id=tenant, status="active", detail="", run_status="success", completed_at="2026-09-29")
        assert store.record_run(record, **kwargs)
        edited = replace(record, updated_at="v2", secret_encrypted="rotated")
        store.put(edited, tenant_id=tenant)
        assert not store.record_run(record, **kwargs)
        assert store.get(tenant, record.id) == edited
        assert store.delete(tenant, record.id)
        assert not store.record_run(record, **kwargs)
        assert store.get(tenant, record.id) is None

    run_tenant_bound(tenant, exercise)


def test_postgres_scheduler_binds_tenants_for_claim_and_delivery(pg_stores, monkeypatch):
    import asyncio
    from datetime import datetime, timezone

    from agent_bom.api.export_destination_store import ExportDestinationRecord
    from agent_bom.api.export_scheduler import run_due_exports_once
    from agent_bom.api.postgres_common import _bypass_tenant_rls, _current_tenant
    from agent_bom.api.tenant_worker import run_tenant_bound
    from agent_bom.export.destinations import ExportResult

    schedules, destinations, _, _ = pg_stores
    tenants = ["export-" + uuid4().hex for _ in range(2)]
    captured = []

    def publish(**kwargs):
        captured.append((_current_tenant.get(), _bypass_tenant_rls.get()))
        return ExportResult(kind="s3", destination_uri="s3://fixture/export", row_count=2)

    monkeypatch.setattr("agent_bom.api.export_scheduler.run_findings_export", publish)
    try:
        for tenant in tenants:
            schedule = stores.ExportSchedule(
                schedule_id="shared", tenant_id=tenant, name="daily", cron_expression="0 3 * * *", destination_id="d", next_run="2026-09-28"
            )
            destination = ExportDestinationRecord(id="d", tenant_id=tenant, kind="s3", display_name="fixture")
            run_tenant_bound(tenant, schedules.put, schedule, tenant_id=tenant)
            run_tenant_bound(tenant, destinations.put, destination, tenant_id=tenant)
        now = datetime(2026, 9, 29, 12, tzinfo=timezone.utc)
        assert asyncio.run(run_due_exports_once(schedules, destinations, now, max_concurrency=1)) == 2
        assert sorted(captured) == sorted((tenant, False) for tenant in tenants)
        for tenant in tenants:
            stored = run_tenant_bound(tenant, schedules.get, "shared", tenant)
            assert stored.last_row_count == 2
            assert stored.next_run > now.isoformat()
    finally:
        for tenant in tenants:
            run_tenant_bound(tenant, schedules.delete, "shared", tenant)
            run_tenant_bound(tenant, destinations.delete, tenant, "d")
