"""Row-level-security guard for the Postgres cloud-connections write path.

Cover for the defect class fixed in #4452: a caller that reaches
``PostgresConnectionStore.put`` without binding the record's tenant writes a row
whose ``tenant_id`` disagrees with ``app.tenant_id``, and Postgres rejects it
with ``InsufficientPrivilege`` under the shipped
``cloud_connections_tenant_isolation`` policy. On a multi-tenant control plane
that turned every scheduled write for a non-``default`` tenant into a hard
failure.

The fake pool below models that policy instead of ignoring it. It learns the
guarded column from the ``WITH CHECK`` clause the store's own DDL emits, tracks
the ``app.tenant_id`` / ``app.bypass_rls`` settings written by
``_apply_tenant_session``, and rejects a mismatched INSERT. The semantics-free
fake in ``tests/test_postgres_connection_parity.py`` cannot see any of this: it
absorbs the ``set_config`` calls and stores the row regardless, which is exactly
why the defect reached main with a green unit suite. Deleting that fake's
``_tenant_connection`` monkeypatch is not enough — the policy has to be modelled.

These tests need no Postgres container, so they run on every PR. The same
invariant is pinned against a live ``postgres:16-alpine`` and the real
``psycopg.errors.InsufficientPrivilege`` in ``tests/test_postgres_integration``.
"""

from __future__ import annotations

import re

import pytest

from agent_bom.api.connection_store import CloudConnectionRecord
from agent_bom.api.postgres_common import bypass_tenant_rls, reset_current_tenant, set_current_tenant
from agent_bom.api.postgres_connection import PostgresConnectionStore

_SET_CONFIG = re.compile(r"^select set_config\('(?P<name>[^']+)'")
_FORCE_RLS = re.compile(r"^alter table (?P<table>\w+) force row level security")
_CREATE_POLICY = re.compile(
    r"create policy \w+ on (?P<table>\w+) .*?"
    r"with check \(public\.abom_rls_bypass\(\) or (?P<column>\w+) = public\.abom_current_tenant\(\)\)"
)
_INSERT = re.compile(r"^insert into (?P<table>\w+) \((?P<columns>[^)]*)\) values")
_SELECT = re.compile(r"^select (?P<columns>.*?) from (?P<table>\w+)")


class InsufficientPrivilegeError(Exception):
    """Stand-in for ``psycopg.errors.InsufficientPrivilege``.

    psycopg is an optional extra and is absent from the always-on test job, so
    the fake raises its own type. The real exception class is asserted against a
    live server in ``tests/test_postgres_integration.py``.
    """


class _Cursor:
    def __init__(self, rows=()):
        self._rows = list(rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return self._rows


class _RlsConnection:
    """A connection that enforces the tenant-isolation policy it was taught."""

    def __init__(self, pool):
        self._pool = pool
        self._settings: dict[str, str] = {}

    def _current_tenant(self) -> str:
        return self._settings.get("app.tenant_id") or "default"

    def _bypassed(self) -> bool:
        return self._settings.get("app.bypass_rls") == "1"

    def _row_matches_policy(self, table: str, row: dict[str, object]) -> bool:
        column = self._pool.guarded_columns.get(table)
        if column is None:
            return True
        return self._bypassed() or row.get(column) == self._current_tenant()

    def execute(self, sql, params=None):
        normalized = " ".join(sql.lower().split())
        params = tuple(params or ())

        setting = _SET_CONFIG.match(normalized)
        if setting:
            self._settings[setting.group("name")] = str(params[0]) if params else ""
            return _Cursor()

        force = _FORCE_RLS.match(normalized)
        if force:
            self._pool.forced_tables.add(force.group("table"))
            return _Cursor()

        policy = _CREATE_POLICY.search(normalized)
        if policy and policy.group("table") in self._pool.forced_tables:
            self._pool.guarded_columns[policy.group("table")] = policy.group("column")
            return _Cursor()

        insert = _INSERT.match(normalized)
        if insert:
            table = insert.group("table")
            columns = [name.strip() for name in insert.group("columns").split(",")]
            # Columns backed by a SQL expression rather than a placeholder (the
            # schema-marker table's ``now()``) simply fall off the end. Every
            # column of a guarded table is bound to a placeholder.
            row = dict(zip(columns, params, strict=False))
            if not self._row_matches_policy(table, row):
                raise InsufficientPrivilegeError(f'new row violates row-level security policy for table "{table}"')
            self._pool.rows.setdefault(table, {})[row[columns[0]]] = row
            return _Cursor()

        select = _SELECT.match(normalized)
        if select:
            table = select.group("table")
            visible = [row for row in self._pool.rows.get(table, {}).values() if self._row_matches_policy(table, row)]
            if "where tenant_id = %s and id = %s" in normalized:
                visible = [row for row in visible if (row.get("tenant_id"), row.get("id")) == params[:2]]
            elif "where tenant_id = %s" in normalized:
                visible = [row for row in visible if row.get("tenant_id") == params[0]]
            projection = [name.strip() for name in select.group("columns").split(",")]
            return _Cursor([tuple(row.get(name) for name in projection) for row in visible])

        return _Cursor()

    def commit(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class _RlsPool:
    def __init__(self):
        self.rows: dict[str, dict[object, dict[str, object]]] = {}
        self.forced_tables: set[str] = set()
        self.guarded_columns: dict[str, str] = {}

    def connection(self):
        return _RlsConnection(self)


def _record(connection_id: str, tenant_id: str) -> CloudConnectionRecord:
    return CloudConnectionRecord(
        id=connection_id,
        tenant_id=tenant_id,
        provider="aws",
        display_name="Production",
        role_ref="arn:aws:iam::123:role/read-only",
        external_id_encrypted="",
        created_at="2026-07-24T00:00:00Z",
        updated_at="2026-07-24T00:00:01Z",
        scan_interval_minutes=60,
    )


@pytest.fixture
def store(monkeypatch) -> PostgresConnectionStore:
    """A store over the RLS-modelling pool, using the real tenant helpers.

    ``_tenant_connection`` is deliberately NOT monkeypatched: the point of this
    module is that ``_apply_tenant_session`` runs for real and the fake reacts
    to the settings it writes. Clearing the deployment env keeps the store on
    its bootstrap-DDL path so the fake is taught the policy from the same SQL a
    fresh deployment executes.
    """
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.delenv("AGENT_BOM_DB", raising=False)
    return PostgresConnectionStore(pool=_RlsPool())


def test_fake_pool_learns_the_guard_from_the_stores_own_policy_ddl(store):
    pool = store._pool
    assert "cloud_connections" in pool.forced_tables, "the store no longer FORCEs row level security on cloud_connections"
    assert pool.guarded_columns == {"cloud_connections": "tenant_id"}, (
        "the cloud_connections_tenant_isolation policy no longer carries a "
        "WITH CHECK clause keyed on tenant_id; the write path is unguarded"
    )


def test_put_under_the_records_bound_tenant_persists_and_reads_back(store):
    record = _record("conn-bound", "acme")

    token = set_current_tenant(record.tenant_id)
    try:
        store.put(record)
        restored = store.get(record.tenant_id, record.id)
    finally:
        reset_current_tenant(token)

    assert restored is not None
    assert restored.tenant_id == "acme"
    assert restored.scan_interval_minutes == 60


def test_put_without_a_bound_tenant_is_rejected_by_the_with_check_clause(store):
    """The pre-#4452 scheduler shape: a non-``default`` tenant, no binding."""
    record = _record("conn-unbound", "acme")

    with pytest.raises(InsufficientPrivilegeError, match="cloud_connections"):
        store.put(record)

    assert store._pool.rows.get("cloud_connections", {}) == {}


def test_put_bound_to_another_tenant_is_rejected(store):
    record = _record("conn-crossed", "acme")

    token = set_current_tenant("initech")
    try:
        with pytest.raises(InsufficientPrivilegeError, match="cloud_connections"):
            store.put(record)
    finally:
        reset_current_tenant(token)


def test_a_bound_tenant_cannot_read_another_tenants_connection(store):
    record = _record("conn-isolated", "acme")

    token = set_current_tenant("acme")
    try:
        store.put(record)
    finally:
        reset_current_tenant(token)

    other = set_current_tenant("initech")
    try:
        assert store.get("acme", record.id) is None
        assert store.list_for_tenant("initech") == []
    finally:
        reset_current_tenant(other)


def test_trusted_rls_bypass_accepts_a_write_for_any_tenant(store):
    """The scheduler's cross-tenant read/claim path must stay usable.

    ``audit=False`` keeps the bypass from emitting a signed audit entry through
    whichever store happens to be configured for the test session.
    """
    record = _record("conn-bypassed", "acme")

    with bypass_tenant_rls(audit=False):
        store.put(record)

    assert record.id in store._pool.rows["cloud_connections"]
