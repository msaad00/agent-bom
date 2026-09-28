"""Dialect contract for the shared SQL storage layer.

Every behaviour runs on SQLite and, when ``AGENT_BOM_POSTGRES_URL`` is set (the
Postgres Integration Contract CI lane), on a real Postgres whose schema comes
from Alembic, as the non-superuser ``NOBYPASSRLS`` application role, with the
separate maintenance role for all-tenant work. The fixture table is
``tenant_quota_overrides`` because it exists on both engines and carries a JSON
column (``JSONB`` on Postgres, ``TEXT`` on SQLite).
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

import pytest

from agent_bom.api.postgres_common import (
    MaintenanceRoleConfigurationError,
    bypass_tenant_rls,
    reset_current_tenant,
    set_current_tenant,
)
from agent_bom.api.storage.sql import (
    Keyset,
    SqlBackend,
    SQLiteBackend,
    json_text,
    like_clause,
    like_pattern,
    require_tenant_scope,
)
from agent_bom.api.tenant_quota_store import _DDL

_POSTGRES_URL = os.environ.get("AGENT_BOM_POSTGRES_URL")
BACKENDS = [
    "sqlite",
    pytest.param(
        "postgres",
        marks=pytest.mark.skipif(not _POSTGRES_URL, reason="AGENT_BOM_POSTGRES_URL is required for the Postgres leg"),
    ),
]
_UPSERT = (
    "INSERT INTO tenant_quota_overrides (tenant_id, updated_at, data) VALUES (?, ?, ?) "
    "ON CONFLICT (tenant_id) DO UPDATE SET updated_at = excluded.updated_at, data = excluded.data"
)


@contextmanager
def as_tenant(tenant_id: str) -> Iterator[None]:
    token = set_current_tenant(tenant_id)
    try:
        yield
    finally:
        reset_current_tenant(token)


@pytest.fixture
def prefix() -> str:
    return f"sqlt-{uuid4().hex[:10]}-"


@pytest.fixture(params=BACKENDS)
def backend(request: pytest.FixtureRequest, tmp_path: Path, prefix: str) -> Iterator[SqlBackend]:
    if request.param == "sqlite":
        sqlite_backend = SQLiteBackend(str(tmp_path / "layer.db"))
        sqlite_backend.bootstrap("tenant_quotas", _DDL, rls_table="tenant_quota_overrides")
        yield sqlite_backend
        return
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.storage.sql import PostgresBackend

    pool = _new_application_pool(min_size=1, max_size=2)
    pg_backend = PostgresBackend(pool)
    pg_backend.bootstrap("tenant_quotas", _DDL, rls_table="tenant_quota_overrides")
    try:
        yield pg_backend
    finally:
        with pg_backend.transaction(all_tenants=True) as tx:
            tx.execute(
                f"DELETE FROM tenant_quota_overrides WHERE {like_clause(pg_backend.dialect, 'tenant_id')}",
                (like_pattern(prefix, mode="prefix"),),
            )
        pool.close()


def _seed(backend: SqlBackend, rows: list[tuple[str, str, dict[str, object]]]) -> int:
    with backend.transaction(all_tenants=True) as tx:
        return tx.executemany(_UPSERT, [(tenant, stamp, json.dumps(data)) for tenant, stamp, data in rows])


# ── tenant scope ─────────────────────────────────────────────────────────────


def test_require_tenant_scope_is_explicit_and_fails_closed() -> None:
    assert require_tenant_scope("tenant-a", all_tenants=False) == "tenant-a"
    assert require_tenant_scope(None, all_tenants=True) is None
    for missing in (None, "", "   "):
        with pytest.raises(ValueError, match="all_tenants=True"):
            require_tenant_scope(missing, all_tenants=False)
    with pytest.raises(ValueError, match="either"):
        require_tenant_scope("tenant-a", all_tenants=True)
    with pytest.raises(ValueError, match="all_tenants=True"):
        require_tenant_scope(None, all_tenants=1)  # type: ignore[arg-type]


def test_tenant_transaction_sees_only_the_bound_tenant_on_postgres(backend: SqlBackend, prefix: str) -> None:
    tenant_a, tenant_b = f"{prefix}a", f"{prefix}b"
    _seed(backend, [(tenant_a, "t1", {"n": 1}), (tenant_b, "t1", {"n": 2})])
    with as_tenant(tenant_a), backend.transaction() as tx:
        visible = {row[0] for row in tx.execute("SELECT tenant_id FROM tenant_quota_overrides").fetchall()}
    if backend.dialect == "postgres":
        assert tenant_a in visible and tenant_b not in visible
    else:
        assert {tenant_a, tenant_b} <= visible


def test_maintenance_transaction_lists_every_tenant(backend: SqlBackend, prefix: str) -> None:
    tenants = [f"{prefix}{name}" for name in ("a", "b", "c")]
    _seed(backend, [(tenant, "t1", {}) for tenant in tenants])
    with as_tenant(tenants[0]), backend.transaction(all_tenants=True, read_only=True) as tx:
        rows = tx.execute(
            f"SELECT tenant_id FROM tenant_quota_overrides WHERE {like_clause(backend.dialect, 'tenant_id')}",
            (like_pattern(prefix, mode="prefix"),),
        ).fetchall()
    assert sorted(row[0] for row in rows) == tenants


def test_postgres_maintenance_requires_the_maintenance_role(backend: SqlBackend, monkeypatch: pytest.MonkeyPatch) -> None:
    if backend.dialect != "postgres":
        pytest.skip("the maintenance role exists only on Postgres")
    import agent_bom.api.postgres_common as pc

    def _unconfigured() -> object:
        raise MaintenanceRoleConfigurationError("maintenance URL not configured")

    monkeypatch.setattr(backend, "_maintenance_pool", None)
    monkeypatch.setattr(pc, "_get_maintenance_pool", _unconfigured)
    with pytest.raises(MaintenanceRoleConfigurationError):
        with backend.transaction(all_tenants=True):
            pass


def test_tenant_transaction_refuses_to_run_inside_an_rls_bypass(backend: SqlBackend) -> None:
    if backend.dialect != "postgres":
        pytest.skip("RLS bypass is Postgres-only")
    with bypass_tenant_rls(audit=False, warn=False):
        with pytest.raises(MaintenanceRoleConfigurationError):
            with backend.transaction():
                pass


# ── read-only transactions and batched writes ───────────────────────────────


def test_read_only_transaction_rejects_writes(backend: SqlBackend, prefix: str) -> None:
    tenant = f"{prefix}ro"
    with as_tenant(tenant):
        with pytest.raises(Exception, match="(?i)read-only|readonly"):
            with backend.transaction(read_only=True) as tx:
                tx.execute(_UPSERT, (tenant, "t1", "{}"))
        with backend.transaction() as tx:
            tx.execute(_UPSERT, (tenant, "t2", "{}"))
        with backend.transaction(read_only=True) as tx:
            assert tx.execute("SELECT updated_at FROM tenant_quota_overrides WHERE tenant_id = ?", (tenant,)).fetchone()[0] == "t2"


def test_read_only_transaction_does_not_leak_read_only_mode(backend: SqlBackend, prefix: str) -> None:
    tenant = f"{prefix}leak"
    with as_tenant(tenant):
        with backend.transaction(read_only=True) as tx:
            tx.execute("SELECT 1").fetchone()
        with backend.transaction() as tx:
            tx.execute(_UPSERT, (tenant, "t1", "{}"))
        with backend.transaction(read_only=True) as tx:
            assert tx.execute("SELECT count(*) FROM tenant_quota_overrides WHERE tenant_id = ?", (tenant,)).fetchone()[0] == 1


def test_executemany_writes_every_row_and_reports_the_total(backend: SqlBackend, prefix: str) -> None:
    rows = [(f"{prefix}{index:03d}", "t1", {"i": index}) for index in range(25)]
    assert _seed(backend, rows) == 25
    with backend.transaction(all_tenants=True) as tx:
        assert tx.executemany("DELETE FROM tenant_quota_overrides WHERE tenant_id = ?", [(tenant,) for tenant, _, _ in rows[:10]]) == 10
        assert tx.executemany("DELETE FROM tenant_quota_overrides WHERE tenant_id = ?", []) == 0


def test_failed_batch_rolls_back_the_whole_transaction(backend: SqlBackend, prefix: str) -> None:
    with pytest.raises(Exception):
        with backend.transaction(all_tenants=True) as tx:
            tx.executemany(_UPSERT, [(f"{prefix}ok", "t1", "{}"), (f"{prefix}bad", "t1", None)])
    with backend.transaction(all_tenants=True, read_only=True) as tx:
        assert tx.execute("SELECT count(*) FROM tenant_quota_overrides WHERE tenant_id = ?", (f"{prefix}ok",)).fetchone()[0] == 0


# ── keyset pagination ───────────────────────────────────────────────────────

# Mixed case, punctuation and non-ASCII: a locale collation (en_US) orders
# these differently from byte order, so identical pages prove the collation.
_KEY_SUFFIXES = ["a", "B", "Z", "_x", "é", "~", "a0", "A", "b", "0", "É", "zz"]


@pytest.mark.parametrize("descending", [False, True])
@pytest.mark.parametrize("page_size", [1, 5, 50])
def test_keyset_pages_are_complete_ordered_and_identical_across_engines(
    backend: SqlBackend, prefix: str, descending: bool, page_size: int
) -> None:
    rows = [
        (f"{prefix}{suffix}", "2026-09-28T00:00:00Z" if index % 2 else "2026-09-27T00:00:00Z", {})
        for index, suffix in enumerate(_KEY_SUFFIXES)
    ]
    _seed(backend, rows)
    keyset = Keyset(("updated_at", "tenant_id"), descending=descending)
    expected = sorted(((stamp, tenant) for tenant, stamp, _ in rows), reverse=descending)

    seen: list[tuple[str, str]] = []
    after: tuple[object, ...] | None = None
    pages = 0
    while True:
        predicate, params = keyset.after(backend.dialect, after)
        sql = (
            f"SELECT updated_at, tenant_id FROM tenant_quota_overrides WHERE {like_clause(backend.dialect, 'tenant_id')}"
            f"{' AND ' + predicate if predicate else ''} ORDER BY {keyset.order_by(backend.dialect)} LIMIT ?"
        )
        with backend.transaction(all_tenants=True, read_only=True) as tx:
            fetched = tx.execute(sql, (like_pattern(prefix, mode="prefix"), *params, page_size + 1)).fetchall()
        page, after = keyset.page(fetched, page_size)
        assert len(page) <= page_size
        seen.extend((str(row[0]), str(row[1])) for row in page)
        pages += 1
        if after is None:
            break
        assert pages <= len(rows)
    assert seen == expected
    assert pages == max(1, -(-len(rows) // page_size))


def test_keyset_rejects_unsafe_identifiers_and_mismatched_cursors() -> None:
    with pytest.raises(ValueError, match="identifier"):
        Keyset(("tenant_id; DROP TABLE x",))
    with pytest.raises(ValueError, match="at least one"):
        Keyset(())
    keyset = Keyset(("updated_at", "tenant_id"))
    with pytest.raises(ValueError, match="cursor"):
        keyset.after("sqlite", ("only-one",))
    assert keyset.after("sqlite", None) == ("", ())


def test_keyset_numeric_columns_skip_text_collation() -> None:
    keyset = Keyset(("retention_days", "tenant_id"), numeric=frozenset({"retention_days"}))
    assert keyset.order_by("postgres") == 'retention_days ASC, tenant_id COLLATE "C" ASC'
    assert keyset.order_by("sqlite") == "retention_days ASC, tenant_id COLLATE BINARY ASC"
    with pytest.raises(ValueError, match="numeric"):
        Keyset(("tenant_id",), numeric=frozenset({"other"}))


# ── JSON path and LIKE hooks ────────────────────────────────────────────────


def test_json_text_extracts_scalars_as_text_on_both_engines(backend: SqlBackend, prefix: str) -> None:
    tenant = f"{prefix}json"
    _seed(backend, [(tenant, "t1", {"name": "ci-bot", "count": 5, "ratio": 1.5, "nested": {"source_id": "src-1"}})])
    with backend.transaction(all_tenants=True, read_only=True) as tx:
        row = tx.execute(
            f"SELECT {json_text(backend.dialect, 'data', 'name')}, {json_text(backend.dialect, 'data', 'count')}, "
            f"{json_text(backend.dialect, 'data', 'ratio')}, {json_text(backend.dialect, 'data', 'nested', 'source_id')}, "
            f"{json_text(backend.dialect, 'data', 'missing')} FROM tenant_quota_overrides WHERE tenant_id = ?",
            (tenant,),
        ).fetchone()
        assert tuple(row) == ("ci-bot", "5", "1.5", "src-1", None)
        matched = tx.execute(
            f"SELECT tenant_id FROM tenant_quota_overrides WHERE {json_text(backend.dialect, 'data', 'count')} = ? AND tenant_id = ?",
            ("5", tenant),
        ).fetchall()
        assert [r[0] for r in matched] == [tenant]


def test_json_text_rejects_unsafe_paths() -> None:
    for bad in ("a'b", "a.b", "", "a}"):
        with pytest.raises(ValueError, match="JSON key"):
            json_text("postgres", "data", bad)
    with pytest.raises(ValueError, match="at least one"):
        json_text("sqlite", "data")
    with pytest.raises(ValueError, match="identifier"):
        json_text("sqlite", "data) --", "a")


@pytest.mark.parametrize(
    ("needle", "mode", "expected"),
    [
        ("100%", "contains", {"x-100%-y"}),
        ("a_b", "contains", {"a_b"}),
        ("!", "contains", {"bang!"}),
        ("ABC", "contains", {"xabcx", "ABC"}),
        ("X-", "prefix", {"x-100%-y", "x-100-y"}),
    ],
)
def test_like_matches_literals_case_insensitively(backend: SqlBackend, prefix: str, needle: str, mode: str, expected: set[str]) -> None:
    values = ["x-100%-y", "x-100-y", "a_b", "axb", "bang!", "bang", "xabcx", "ABC"]
    _seed(backend, [(f"{prefix}{index}", "t1", {"v": value}) for index, value in enumerate(values)])
    expression = json_text(backend.dialect, "data", "v")
    with backend.transaction(all_tenants=True, read_only=True) as tx:
        rows = tx.execute(
            f"SELECT {expression} FROM tenant_quota_overrides "
            f"WHERE {like_clause(backend.dialect, expression)} AND {like_clause(backend.dialect, 'tenant_id')}",
            (like_pattern(needle, mode=mode), like_pattern(prefix, mode="prefix")),  # type: ignore[arg-type]
        ).fetchall()
    assert {row[0] for row in rows} == expected


def test_like_pattern_escapes_wildcards_and_the_escape_character() -> None:
    assert like_pattern("50%_off!", mode="contains") == "%50!%!_off!!%"
    assert like_pattern("Tenant-", mode="prefix") == "tenant-%"
    with pytest.raises(ValueError, match="mode"):
        like_pattern("x", mode="suffix")  # type: ignore[arg-type]


@pytest.mark.parametrize("directions", [(True, False), (False, True)])
@pytest.mark.parametrize("page_size", [1, 5, 50])
def test_keyset_mixed_directions_preserve_ties(backend, prefix, directions, page_size):
    from functools import cmp_to_key

    rows = [(f"{prefix}{suffix}", f"t{index % 3}", {}) for index, suffix in enumerate(_KEY_SUFFIXES)]
    _seed(backend, rows)
    keyset = Keyset(("updated_at", "tenant_id"), directions=directions)

    def compare(left, right):
        for a, b, descending in zip(left, right, directions):
            if a != b:
                return ((a > b) - (a < b)) * (-1 if descending else 1)
        return 0

    expected = sorted(((stamp, tenant) for tenant, stamp, _ in rows), key=cmp_to_key(compare))
    seen = []
    after = None
    while True:
        predicate, params = keyset.after(backend.dialect, after)
        sql = (
            f"SELECT updated_at, tenant_id FROM tenant_quota_overrides WHERE {like_clause(backend.dialect, 'tenant_id')}"
            f"{' AND ' + predicate if predicate else ''} ORDER BY {keyset.order_by(backend.dialect)} LIMIT ?"
        )
        with backend.transaction(all_tenants=True, read_only=True) as tx:
            fetched = tx.execute(sql, (like_pattern(prefix, mode="prefix"), *params, page_size + 1)).fetchall()
        page, after = keyset.page(fetched, page_size)
        seen.extend(tuple(row) for row in page)
        if after is None:
            break
        assert len(seen) <= len(expected), "cursor did not advance"
    assert seen == expected


@pytest.mark.parametrize("directions", [(), (True,), (True, False, True), ("DESC", "ASC"), (1, 0)])
def test_keyset_rejects_invalid_direction_contract(directions):
    with pytest.raises(ValueError):
        Keyset(("updated_at", "tenant_id"), directions=directions)


def test_borrowed_sqlite_snapshot_does_not_rollback_an_active_caller_transaction(tmp_path):
    import sqlite3

    conn = sqlite3.connect(str(tmp_path / "borrowed.db"))
    conn.execute("CREATE TABLE writes (value TEXT)")
    conn.execute("INSERT INTO writes VALUES ('pending')")
    backend = SQLiteBackend("unused", connection_factory=lambda: conn)
    with pytest.raises(ValueError, match="idle connection"):
        with backend.transaction(read_only=True):
            pytest.fail("active caller transaction was adopted")
    assert conn.in_transaction
    assert conn.execute("SELECT value FROM writes").fetchall() == [("pending",)]
    assert conn.execute("PRAGMA query_only").fetchone()[0] == 0
    conn.rollback()
    conn.close()


def test_batched_returning_tracks_only_inserted_rows_and_rolls_back(backend: SqlBackend, prefix: str) -> None:
    tenant = prefix + "returning"
    statement = (
        "INSERT INTO tenant_quota_overrides (tenant_id, updated_at, data) VALUES (?, ?, ?) ON CONFLICT DO NOTHING RETURNING tenant_id"
    )
    with as_tenant(tenant):
        with pytest.raises(RuntimeError, match="rollback"):
            with backend.transaction() as tx:
                assert tx.executemany_returning(statement, [(tenant, "t1", "{}"), (tenant, "t2", "{}")]) == [(tenant,)]
                assert tx.executemany_returning(statement, []) == []
                raise RuntimeError("rollback")
        with backend.transaction(read_only=True) as tx:
            assert tx.execute("SELECT COUNT(*) FROM tenant_quota_overrides WHERE tenant_id = ?", (tenant,)).fetchone()[0] == 0
