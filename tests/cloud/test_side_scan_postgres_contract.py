"""Migrated side-scan state works with a DML-only tenant application role."""

from __future__ import annotations

import os
from uuid import uuid4

import pytest

from agent_bom.cloud.side_scan_lifecycle import (
    ExecutionStatus,
    PostgresSideScanStateStore,
    SideScanStateConflictError,
    new_side_scan_execution,
)

_requires_postgres = pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires migrated private Postgres")


@_requires_postgres
def test_migrated_side_scan_store_keeps_tenant_cas_and_restart_contracts():
    from agent_bom.api.postgres_common import _new_application_pool, _tenant_connection
    from agent_bom.api.tenant_worker import tenant_bound_context

    tenant = "side-scan-" + uuid4().hex
    other = "side-scan-" + uuid4().hex
    record = new_side_scan_execution(
        tenant_id=tenant,
        provider="aws",
        account_id="account-a",
        target_id="volume-a",
        collector_id="collector-a",
        idempotency_key="same-request",
        now="2026-09-29T00:00:00Z",
    )
    with _new_application_pool(min_size=1, max_size=2) as pool:
        with pool.connection() as conn:
            assert conn.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user").fetchone() == (False, False)
            assert conn.execute("SELECT has_schema_privilege(current_user, 'public', 'CREATE')").fetchone() == (False,)
        store = PostgresSideScanStateStore(pool=pool)
        original = store.create_or_get(record)
        assert store.create_or_get(record) == original
        assert store.get(tenant_id=other, execution_id=record.execution_id) is None
        assert store.list_recent(tenant_id=other) == []
        running = original.transition(status=ExecutionStatus.RUNNING, phase="snapshot")
        store.save(running, expected_version=original.state_version)
        with pytest.raises(SideScanStateConflictError):
            store.save(running, expected_version=original.state_version)
        with tenant_bound_context(other), _tenant_connection(pool) as conn:
            assert (
                conn.execute("SELECT execution_id FROM side_scan_execution_state WHERE execution_id=%s", (record.execution_id,)).fetchall()
                == []
            )
    with _new_application_pool(min_size=1, max_size=2) as restarted_pool:
        restarted = PostgresSideScanStateStore(pool=restarted_pool)
        assert restarted.get(tenant_id=tenant, execution_id=record.execution_id) == running
        assert restarted.count(tenant_id=tenant) == 1


def test_configured_side_scan_startup_only_reads_schema_version(monkeypatch):
    from contextlib import contextmanager

    from agent_bom.api import storage_schema

    statements = []

    class Connection:
        def execute(self, statement, params=None):
            statements.append((statement, params))
            return self

        def fetchone(self):
            return (1,)

    class Pool:
        @contextmanager
        def connection(self):
            yield Connection()

    monkeypatch.setattr(storage_schema, "postgres_deployment_configured", lambda: True)
    PostgresSideScanStateStore(pool=Pool())
    assert statements == [("SELECT version FROM control_plane_schema_versions WHERE component = %s", ("side_scan_lifecycle",))]
