"""One contract for every tenant quota store backend.

Each test runs against the in-memory fake, SQLite and (when
``AGENT_BOM_POSTGRES_URL`` is set, as in the Postgres Integration Contract CI
lane) a real Postgres with FORCE row-level security.
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

import pytest

from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
from agent_bom.api.tenant_quota_store import (
    InMemoryTenantQuotaStore,
    SQLiteTenantQuotaStore,
    TenantQuotaStore,
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
def make_store(request: pytest.FixtureRequest, tmp_path: Path, tenants: tuple[str, str]) -> Iterator[Callable[[], TenantQuotaStore]]:
    backend = request.param
    memory = InMemoryTenantQuotaStore()
    db_path = str(tmp_path / "quota.db")
    pools: list[object] = []

    def factory() -> TenantQuotaStore:
        if backend == "memory":
            return memory
        if backend == "sqlite":
            return SQLiteTenantQuotaStore(db_path)
        from agent_bom.api.postgres_common import _new_application_pool
        from agent_bom.api.tenant_quota_store import PostgresTenantQuotaStore

        pool = _new_application_pool(min_size=1, max_size=2)
        pools.append(pool)
        return PostgresTenantQuotaStore(pool)

    yield factory
    if backend == "postgres":
        cleanup = factory()
        for tenant in tenants:
            with as_tenant(tenant):
                cleanup.delete(tenant)
        for pool in pools:
            pool.close()  # type: ignore[attr-defined]


pytestmark = pytest.mark.parametrize("make_store", BACKENDS, indirect=True)


def test_missing_tenant_returns_none(make_store, tenants):
    tenant_a, _ = tenants
    with as_tenant(tenant_a):
        assert make_store().get(tenant_a) is None


def test_put_then_get_round_trips_int_overrides(make_store, tenants):
    tenant_a, _ = tenants
    store = make_store()
    with as_tenant(tenant_a):
        store.put(tenant_a, {"active_scan_jobs": 3, "retained_jobs": 50})
        assert store.get(tenant_a) == {"active_scan_jobs": 3, "retained_jobs": 50}


def test_put_replaces_rather_than_merges(make_store, tenants):
    tenant_a, _ = tenants
    store = make_store()
    with as_tenant(tenant_a):
        store.put(tenant_a, {"active_scan_jobs": 3, "retained_jobs": 50})
        store.put(tenant_a, {"fleet_agents": 7})
        assert store.get(tenant_a) == {"fleet_agents": 7}


def test_get_returns_a_copy(make_store, tenants):
    tenant_a, _ = tenants
    store = make_store()
    with as_tenant(tenant_a):
        store.put(tenant_a, {"schedules": 2})
        first = store.get(tenant_a)
        assert first is not None
        first["schedules"] = 999
        assert store.get(tenant_a) == {"schedules": 2}


def test_put_does_not_alias_the_callers_mapping(make_store, tenants):
    tenant_a, _ = tenants
    store = make_store()
    overrides = {"schedules": 2}
    with as_tenant(tenant_a):
        store.put(tenant_a, overrides)
        overrides["schedules"] = 999
        assert store.get(tenant_a) == {"schedules": 2}


def test_delete_reports_whether_a_row_existed(make_store, tenants):
    tenant_a, _ = tenants
    store = make_store()
    with as_tenant(tenant_a):
        store.put(tenant_a, {"schedules": 2})
        assert store.delete(tenant_a) is True
        assert store.get(tenant_a) is None
        assert store.delete(tenant_a) is False


def test_overrides_survive_a_new_store_instance(make_store, tenants):
    tenant_a, _ = tenants
    with as_tenant(tenant_a):
        make_store().put(tenant_a, {"retained_jobs": 11})
        assert make_store().get(tenant_a) == {"retained_jobs": 11}


def test_tenant_a_never_sees_or_deletes_tenant_b(make_store, tenants):
    tenant_a, tenant_b = tenants
    store = make_store()
    with as_tenant(tenant_a):
        store.put(tenant_a, {"schedules": 1})
    with as_tenant(tenant_b):
        store.put(tenant_b, {"schedules": 2})
        assert store.get(tenant_b) == {"schedules": 2}
    with as_tenant(tenant_a):
        assert store.get(tenant_a) == {"schedules": 1}
        assert store.delete(tenant_a) is True
    with as_tenant(tenant_b):
        assert store.get(tenant_b) == {"schedules": 2}


@pytest.mark.parametrize("missing", ["", "   ", None])
def test_missing_tenant_fails_closed(make_store, tenants, missing):
    tenant_a, _ = tenants
    store = make_store()
    with as_tenant(tenant_a):
        store.put(tenant_a, {"schedules": 1})
        with pytest.raises(ValueError, match="tenant_id"):
            store.get(missing)
        with pytest.raises(ValueError, match="tenant_id"):
            store.put(missing, {"schedules": 9})
        with pytest.raises(ValueError, match="tenant_id"):
            store.delete(missing)
        assert store.get(tenant_a) == {"schedules": 1}


def test_postgres_session_tenant_gates_rows_even_when_the_argument_names_another(make_store, tenants, request):
    if "postgres" not in request.node.callspec.id:
        pytest.skip("row-level security is Postgres-only; SQLite relies on the tenant_id filter")
    tenant_a, tenant_b = tenants
    store = make_store()
    with as_tenant(tenant_b):
        store.put(tenant_b, {"schedules": 2})
    with as_tenant(tenant_a):
        assert store.get(tenant_b) is None
        assert store.delete(tenant_b) is False
        with pytest.raises(Exception, match="row-level security"):
            store.put(tenant_b, {"schedules": 9})
    with as_tenant(tenant_b):
        assert store.get(tenant_b) == {"schedules": 2}


def test_sqlite_reads_rows_written_by_the_previous_implementation(make_store, tenants, tmp_path, request):
    if "sqlite" not in request.node.callspec.id:
        pytest.skip("on-disk compatibility applies to SQLite files")
    tenant_a, _ = tenants
    store = make_store()
    conn = sqlite3.connect(tmp_path / "quota.db")
    conn.execute(
        "INSERT OR REPLACE INTO tenant_quota_overrides (tenant_id, updated_at, data) VALUES (?, datetime('now'), ?)",
        (tenant_a, '{"retained_jobs": "12"}'),
    )
    conn.commit()
    conn.close()
    assert store.get(tenant_a) == {"retained_jobs": 12}
