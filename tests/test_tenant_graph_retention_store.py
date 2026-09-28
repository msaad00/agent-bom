"""One contract for every tenant graph retention override store backend.

Each test runs against the in-memory fake, SQLite and (when
``AGENT_BOM_POSTGRES_URL`` is set, as in the Postgres Integration Contract CI
lane) a real Postgres with FORCE row-level security and a separate maintenance
role for the all-tenant listing.
"""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from agent_bom.api.postgres_common import MaintenanceRoleConfigurationError, reset_current_tenant, set_current_tenant
from agent_bom.api.tenant_graph_retention_store import (
    InMemoryTenantGraphRetentionStore,
    SQLiteTenantGraphRetentionStore,
    TenantGraphRetentionStore,
)

_POSTGRES_URL = os.environ.get("AGENT_BOM_POSTGRES_URL")
BACKENDS = [
    "memory",
    "sqlite",
    pytest.param(
        "postgres",
        marks=pytest.mark.skipif(not _POSTGRES_URL, reason="AGENT_BOM_POSTGRES_URL is required for the Postgres leg"),
    ),
]


@contextmanager
def as_tenant(tenant_id: str) -> Iterator[None]:
    """Bind the request tenant the way the API middleware does."""
    token = set_current_tenant(tenant_id)
    try:
        yield
    finally:
        reset_current_tenant(token)


@pytest.fixture
def tenants() -> tuple[str, str]:
    suffix = uuid4().hex[:12]
    return f"tenant-a-{suffix}", f"tenant-b-{suffix}"


@pytest.fixture
def make_store(
    request: pytest.FixtureRequest, tmp_path: Path, tenants: tuple[str, str]
) -> Iterator[Callable[[], TenantGraphRetentionStore]]:
    backend = request.param
    memory = InMemoryTenantGraphRetentionStore()
    db_path = str(tmp_path / "retention.db")
    pools: list[object] = []

    def factory() -> TenantGraphRetentionStore:
        if backend == "memory":
            return memory
        if backend == "sqlite":
            return SQLiteTenantGraphRetentionStore(db_path)
        from agent_bom.api.postgres_common import _new_application_pool
        from agent_bom.api.tenant_graph_retention_store import PostgresTenantGraphRetentionStore

        pool = _new_application_pool(min_size=1, max_size=2)
        pools.append(pool)
        return PostgresTenantGraphRetentionStore(pool)

    yield factory
    if backend == "postgres":
        cleanup = factory()
        for tenant in tenants:
            with as_tenant(tenant):
                cleanup.delete(tenant)
        for pool in pools:
            pool.close()  # type: ignore[attr-defined]


pytestmark = pytest.mark.parametrize("make_store", BACKENDS, indirect=True)


def test_missing_override_returns_none(make_store, tenants):
    tenant_a, _ = tenants
    with as_tenant(tenant_a):
        assert make_store().get(tenant_a) is None


def test_put_then_get_round_trips_and_clamps_to_one_day(make_store, tenants):
    tenant_a, _ = tenants
    store = make_store()
    with as_tenant(tenant_a):
        store.put(tenant_a, 45)
        assert store.get(tenant_a) == 45
        store.put(tenant_a, 0)
        assert store.get(tenant_a) == 1
        store.put(tenant_a, -9)
        assert store.get(tenant_a) == 1


def test_put_replaces_the_previous_override(make_store, tenants):
    tenant_a, _ = tenants
    store = make_store()
    with as_tenant(tenant_a):
        store.put(tenant_a, 30)
        store.put(tenant_a, 90)
        assert store.get(tenant_a) == 90


def test_delete_reports_whether_a_row_existed(make_store, tenants):
    tenant_a, _ = tenants
    store = make_store()
    with as_tenant(tenant_a):
        store.put(tenant_a, 30)
        assert store.delete(tenant_a) is True
        assert store.get(tenant_a) is None
        assert store.delete(tenant_a) is False


def test_overrides_survive_a_new_store_instance(make_store, tenants):
    tenant_a, _ = tenants
    with as_tenant(tenant_a):
        make_store().put(tenant_a, 14)
        assert make_store().get(tenant_a) == 14


def test_tenant_a_never_sees_or_deletes_tenant_b(make_store, tenants):
    tenant_a, tenant_b = tenants
    store = make_store()
    with as_tenant(tenant_a):
        store.put(tenant_a, 10)
    with as_tenant(tenant_b):
        store.put(tenant_b, 20)
        assert store.get(tenant_b) == 20
        assert store.list_overrides(tenant_b) == {tenant_b: 20}
    with as_tenant(tenant_a):
        assert store.get(tenant_a) == 10
        assert store.list_overrides(tenant_a) == {tenant_a: 10}
        assert store.delete(tenant_a) is True
    with as_tenant(tenant_b):
        assert store.get(tenant_b) == 20


def test_maintenance_listing_spans_every_tenant_only_when_flagged(make_store, tenants):
    tenant_a, tenant_b = tenants
    store = make_store()
    with as_tenant(tenant_a):
        store.put(tenant_a, 10)
    with as_tenant(tenant_b):
        store.put(tenant_b, 20)
    # The request context still names tenant A: only the explicit flag widens scope.
    with as_tenant(tenant_a):
        every = store.list_overrides(all_tenants=True)
        assert {tenant: every[tenant] for tenant in tenants if tenant in every} == {tenant_a: 10, tenant_b: 20}
        assert store.list_overrides(tenant_a) == {tenant_a: 10}


@pytest.mark.parametrize("missing", ["", "   ", None])
def test_missing_tenant_fails_closed(make_store, tenants, missing):
    tenant_a, _ = tenants
    store = make_store()
    with as_tenant(tenant_a):
        store.put(tenant_a, 30)
        with pytest.raises(ValueError, match="tenant_id"):
            store.get(missing)
        with pytest.raises(ValueError, match="tenant_id"):
            store.put(missing, 9)
        with pytest.raises(ValueError, match="tenant_id"):
            store.delete(missing)
        with pytest.raises(ValueError, match="all_tenants=True"):
            store.list_overrides(missing)
        assert store.get(tenant_a) == 30


def test_listing_rejects_a_tenant_combined_with_all_tenants(make_store, tenants):
    tenant_a, _ = tenants
    with as_tenant(tenant_a), pytest.raises(ValueError, match="not both"):
        make_store().list_overrides(tenant_a, all_tenants=True)


def test_listing_requires_the_literal_true_flag(make_store, tenants):
    tenant_a, _ = tenants
    with as_tenant(tenant_a), pytest.raises(ValueError, match="all_tenants=True"):
        make_store().list_overrides(all_tenants="yes")  # type: ignore[arg-type]


def test_postgres_session_tenant_gates_rows_even_when_the_argument_names_another(make_store, tenants, request):
    if "postgres" not in request.node.callspec.id:
        pytest.skip("row-level security is Postgres-only; SQLite relies on the tenant_id filter")
    tenant_a, tenant_b = tenants
    store = make_store()
    with as_tenant(tenant_b):
        store.put(tenant_b, 20)
    with as_tenant(tenant_a):
        assert store.get(tenant_b) is None
        assert store.list_overrides(tenant_b) == {}
        assert store.delete(tenant_b) is False
        with pytest.raises(Exception, match="row-level security"):
            store.put(tenant_b, 99)
    with as_tenant(tenant_b):
        assert store.get(tenant_b) == 20


def test_postgres_maintenance_listing_fails_closed_without_the_maintenance_role(make_store, tenants, request, monkeypatch):
    if "postgres" not in request.node.callspec.id:
        pytest.skip("the maintenance role exists only on Postgres")
    import agent_bom.api.postgres_common as pc

    def _unconfigured() -> object:
        raise MaintenanceRoleConfigurationError("maintenance URL not configured")

    store = make_store()
    monkeypatch.setattr(pc, "_get_maintenance_pool", _unconfigured)
    with as_tenant(tenants[0]), pytest.raises(MaintenanceRoleConfigurationError):
        store.list_overrides(all_tenants=True)


def test_sqlite_reads_rows_written_by_the_previous_implementation(make_store, tenants, tmp_path, request):
    if "sqlite" not in request.node.callspec.id:
        pytest.skip("on-disk compatibility applies to SQLite files")
    tenant_a, tenant_b = tenants
    store = make_store()
    conn = sqlite3.connect(tmp_path / "retention.db")
    conn.executemany(
        "INSERT OR REPLACE INTO tenant_graph_retention_overrides (tenant_id, updated_at, retention_days) VALUES (?, datetime('now'), ?)",
        [(tenant_a, 0), (tenant_b, 60)],
    )
    conn.commit()
    conn.close()
    assert store.get(tenant_a) == 1
    assert store.list_overrides(all_tenants=True) == {tenant_a: 1, tenant_b: 60}


def test_cross_tenant_purge_resolves_windows_with_one_maintenance_listing(make_store, tenants, monkeypatch):
    """The SQLite graph purge sweeps every tenant: one flagged listing, no per-tenant reads."""
    from agent_bom.api.stores import set_tenant_graph_retention_store
    from agent_bom.db.graph_store import _init_db, purge_expired_graph_snapshots

    tenant_a, tenant_b = tenants
    store = make_store()
    with as_tenant(tenant_a):
        store.put(tenant_a, 90)
    calls: list[tuple[str, object]] = []

    class Spy:
        def get(self, tenant_id: str) -> int | None:
            calls.append(("get", tenant_id))
            return store.get(tenant_id)

        def put(self, tenant_id: str, retention_days: int) -> None:
            store.put(tenant_id, retention_days)

        def delete(self, tenant_id: str) -> bool:
            return store.delete(tenant_id)

        def list_overrides(self, tenant_id: str | None = None, *, all_tenants: bool = False) -> dict[str, int]:
            calls.append(("list_overrides", all_tenants))
            return store.list_overrides(tenant_id, all_tenants=all_tenants)

    monkeypatch.setenv("AGENT_BOM_GRAPH_RETENTION_DAYS", "30")
    monkeypatch.setenv("AGENT_BOM_GRAPH_RETENTION_OVERRIDES", json.dumps({tenant_b: 60}))
    set_tenant_graph_retention_store(Spy())  # type: ignore[arg-type]
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    _init_db(conn)
    now = datetime(2026, 9, 28, tzinfo=timezone.utc)
    aged = (now - timedelta(days=45)).isoformat()
    for scan_id, tenant in (("a", tenant_a), ("b", tenant_b), ("c", "tenant-c-default-window")):
        conn.execute(
            "INSERT INTO graph_snapshots (scan_id, tenant_id, created_at, node_count, edge_count, risk_summary) "
            "VALUES (?, ?, ?, 0, 0, '{}')",
            (scan_id, tenant, aged),
        )
    conn.commit()
    try:
        with as_tenant(tenant_b):
            result = purge_expired_graph_snapshots(conn, now=now)
    finally:
        set_tenant_graph_retention_store(InMemoryTenantGraphRetentionStore())
    assert calls == [("list_overrides", True)]
    assert result["purged_snapshots"] == [{"scan_id": "c", "tenant_id": "tenant-c-default-window"}]
    assert result["per_tenant_retention_days"] == {tenant_a: 90, tenant_b: 60, "tenant-c-default-window": 30}
