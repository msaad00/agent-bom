"""One parameterised-SQL layer that runs a store on SQLite or Postgres.

Stores write portable SQL with ``?`` placeholders and ``ON CONFLICT ... DO
UPDATE`` upserts (SQLite >= 3.24 and Postgres share that syntax). The backend
owns everything that differs between engines:

* placeholders: ``?`` on SQLite, rewritten to ``%s`` for psycopg;
* tenant binding: Postgres opens every transaction through
  ``_tenant_connection`` so FORCE row-level security sees ``app.tenant_id``;
  SQLite has no RLS, so stores MUST filter on ``tenant_id`` in SQL and call
  :func:`require_tenant_id` (or :func:`require_tenant_scope`) first;
* all-tenant maintenance: ``transaction(all_tenants=True)`` is the only way to
  reach rows of every tenant. On Postgres it uses the separate maintenance
  role through ``_maintenance_connection`` and fails closed when that role is
  not configured; the application pool never bypasses RLS;
* read-only work: ``transaction(read_only=True)`` is a REPEATABLE READ, READ
  ONLY snapshot on Postgres and a ``query_only`` deferred transaction on
  SQLite, so a read-heavy port sees one consistent snapshot and cannot write;
* batched writes: :meth:`SqlSession.executemany` returns the total row count;
* schema bootstrap: per-dialect DDL, schema-version bookkeeping, and the RLS
  policy on Postgres (skipped when Alembic owns the deployment schema);
* JSON columns: Postgres JSONB decodes to ``dict``, SQLite TEXT to ``str``;
  :func:`load_json` accepts both, and :func:`json_text` extracts a scalar;
* ordering and search: :class:`Keyset` pages identically on both engines and
  :func:`like_clause` / :func:`like_pattern` match literals the same way.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

from agent_bom.api.postgres_common import (
    ConnectionPool,
    _ensure_tenant_rls,
    _get_pool,
    _maintenance_connection,
    _tenant_connection,
    bypass_tenant_rls,
)
from agent_bom.api.storage_schema import ensure_postgres_schema_version, ensure_sqlite_schema_version

Dialect = Literal["sqlite", "postgres"]
LikeMode = Literal["contains", "prefix"]

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$")
_JSON_KEY = re.compile(r"^[A-Za-z0-9_-]+$")
_LIKE_ESCAPE = "!"


def require_tenant_id(tenant_id: str | None) -> str:
    """Fail closed when a store call carries no tenant."""
    if tenant_id is None or not str(tenant_id).strip():
        raise ValueError("tenant-scoped store call requires a non-empty tenant_id")
    return tenant_id


def require_tenant_scope(tenant_id: str | None, *, all_tenants: bool) -> str | None:
    """Resolve a call's scope: exactly one tenant, or every tenant by explicit flag.

    Returns the tenant for a tenant-scoped call and ``None`` for an all-tenant
    call. ``all_tenants`` must be the literal ``True``; a missing tenant without
    it fails closed, and naming a tenant together with it is ambiguous and is
    rejected too.
    """
    if all_tenants is True:
        if tenant_id is not None:
            raise ValueError("pass either a tenant_id or all_tenants=True, not both")
        return None
    if tenant_id is None or not str(tenant_id).strip():
        raise ValueError("store call requires a tenant_id; pass all_tenants=True for background maintenance")
    return tenant_id


def utc_timestamp() -> str:
    """Timestamp format shared by both engines' TEXT ``updated_at`` columns."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(value: Any) -> Any:
    """Decode a JSON column that may arrive as JSONB (decoded) or TEXT."""
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8")
    return json.loads(value) if isinstance(value, str) else value


def _identifier(name: str) -> str:
    if not _IDENTIFIER.match(name):
        raise ValueError(f"not a plain SQL identifier: {name!r}")
    return name


def json_text(dialect: Dialect, column: str, *path: str) -> str:
    """SQL expression for the scalar at ``column -> path...`` as TEXT, or NULL.

    SQLite: ``CAST(json_extract(col, '$.a.b') AS TEXT)``. Postgres:
    ``(col)::jsonb #>> '{a,b}'``, which also accepts a TEXT column holding
    JSON. Strings and numbers render identically on both engines; booleans
    (``1`` vs ``true``) and nested objects (spacing) do not, so use it for
    scalar string/number fields. Keys are inlined, so only ``[A-Za-z0-9_-]``
    keys are accepted.
    """
    column = _identifier(column)
    if not path:
        raise ValueError("json_text needs at least one JSON key")
    for key in path:
        if not _JSON_KEY.match(key):
            raise ValueError(f"unsupported JSON key: {key!r}")
    if dialect == "postgres":
        return f"({column})::jsonb #>> '{{{','.join(path)}}}'"
    return f"CAST(json_extract({column}, '$.{'.'.join(path)}') AS TEXT)"


def like_pattern(value: str, *, mode: LikeMode) -> str:
    """Parameter for :func:`like_clause` that matches ``value`` literally.

    ``%``, ``_`` and the escape character are escaped, and the value is
    lower-cased to pair with the ``LOWER(...)`` in :func:`like_clause`.
    """
    escaped = value.lower().replace(_LIKE_ESCAPE, _LIKE_ESCAPE * 2).replace("%", f"{_LIKE_ESCAPE}%").replace("_", f"{_LIKE_ESCAPE}_")
    if mode == "contains":
        return f"%{escaped}%"
    if mode == "prefix":
        return f"{escaped}%"
    raise ValueError(f"unsupported like mode: {mode!r}")


def like_clause(dialect: Dialect, expression: str) -> str:
    """Case-insensitive ``LIKE`` predicate with one ``?`` for :func:`like_pattern`.

    Both engines get ``LOWER(expr) LIKE ? ESCAPE '!'``. SQLite has no default
    escape character and folds ASCII case in ``LIKE``; Postgres escapes with a
    backslash by default and is case-sensitive. An explicit non-backslash
    escape (independent of ``standard_conforming_strings``) plus lower-casing
    both sides makes them agree. Non-ASCII case folding still follows each
    engine's ``LOWER`` (SQLite folds ASCII only).
    """
    del dialect
    return f"LOWER({expression}) LIKE ? ESCAPE '{_LIKE_ESCAPE}'"


@dataclass(frozen=True)
class Keyset:
    """Keyset (seek) pagination with the same order on SQLite and Postgres.

    ``columns`` are the sort key, most significant first. They must be NOT
    NULL (the engines order NULLs differently) and together unique, and they
    must be the first columns of the SELECT so :meth:`page` can read the
    cursor. ``directions`` optionally supplies one descending flag per column
    for mixed orders; otherwise ``descending`` applies to every column.
    Text columns are compared by code point: ``COLLATE BINARY`` on
    SQLite and ``COLLATE "C"`` on a UTF-8 Postgres, which agree, whereas a
    locale collation such as ``en_US`` would not. On Postgres an index serves
    this order only if it is built with ``COLLATE "C"`` (or the database
    collation is ``C``). List integer columns in ``numeric``; Postgres rejects a
    collation on them.
    """

    columns: tuple[str, ...]
    descending: bool = False
    numeric: frozenset[str] = frozenset()
    directions: tuple[bool, ...] | None = None

    def __post_init__(self) -> None:
        if not self.columns:
            raise ValueError("keyset needs at least one column")
        for column in self.columns:
            _identifier(column)
        if not self.numeric <= set(self.columns):
            raise ValueError("numeric columns must be keyset columns")
        if self.directions is not None:
            if len(self.directions) != len(self.columns) or any(type(value) is not bool for value in self.directions):
                raise ValueError("keyset directions must provide one boolean per column")
            if self.descending:
                raise ValueError("use descending or per-column directions, not both")

    def _directions(self) -> tuple[bool, ...]:
        return self.directions if self.directions is not None else (self.descending,) * len(self.columns)

    def _term(self, dialect: Dialect, column: str) -> str:
        if column in self.numeric:
            return column
        return f'{column} COLLATE "C"' if dialect == "postgres" else f"{column} COLLATE BINARY"

    def order_by(self, dialect: Dialect) -> str:
        """``ORDER BY`` body (without the keywords)."""
        return ", ".join(
            f"{self._term(dialect, column)} {'DESC' if descending else 'ASC'}"
            for column, descending in zip(self.columns, self._directions())
        )

    def after(self, dialect: Dialect, cursor: Sequence[Any] | None) -> tuple[str, tuple[Any, ...]]:
        """Predicate selecting rows strictly after ``cursor``, or ``("", ())`` for the first page."""
        if cursor is None:
            return "", ()
        if len(cursor) != len(self.columns):
            raise ValueError("keyset cursor does not match the keyset columns")
        directions = self._directions()
        expressions = [self._term(dialect, column) for column in self.columns]
        if len(set(directions)) > 1:
            clauses = []
            params: list[Any] = []
            for index, (term, descending) in enumerate(zip(expressions, directions)):
                prefix = [f"{prior} = ?" for prior in expressions[:index]]
                clauses.append("(" + " AND ".join([*prefix, f"{term} {'<' if descending else '>'} ?"]) + ")")
                params.extend(cursor[: index + 1])
            return "(" + " OR ".join(clauses) + ")", tuple(params)
        terms = ", ".join(expressions)
        placeholders = ", ".join("?" for _ in self.columns)
        operator = "<" if directions[0] else ">"
        return f"({terms}) {operator} ({placeholders})", tuple(cursor)

    def page(self, rows: Sequence[Sequence[Any]], limit: int) -> tuple[list[Sequence[Any]], tuple[Any, ...] | None]:
        """Split rows fetched with ``LIMIT limit + 1`` into a page and the next cursor."""
        page = list(rows[:limit])
        if len(rows) <= limit or not page:
            return page, None
        return page, tuple(page[-1][: len(self.columns)])


class SqlSession(Protocol):
    """One transaction: tenant-bound, or all-tenant maintenance when asked for."""

    def execute(self, sql: str, params: Sequence[Any] = ()) -> Any: ...

    def executemany(self, sql: str, rows: Iterable[Sequence[Any]]) -> int: ...

    def executemany_returning(self, sql: str, rows: Iterable[Sequence[Any]]) -> list[tuple[Any, ...]]: ...


class SqlBackend(Protocol):
    """Connection source plus the dialect differences a store must not see."""

    dialect: Dialect

    def transaction(self, *, read_only: bool = False, all_tenants: bool = False) -> AbstractContextManager[SqlSession]: ...

    def bootstrap(self, component: str, ddl: Mapping[Dialect, Sequence[str]], *, rls_table: str | None = None) -> None: ...


class _Session:
    def __init__(self, conn: Any, *, rewrite_placeholders: bool) -> None:
        self._conn = conn
        self._rewrite = rewrite_placeholders

    def _sql(self, sql: str) -> str:
        if not self._rewrite:
            return sql
        if "%" in sql:
            raise ValueError("portable SQL must not contain '%'; pass literals as parameters")
        return sql.replace("?", "%s")

    def execute(self, sql: str, params: Sequence[Any] = ()) -> Any:
        return self._conn.execute(self._sql(sql), tuple(params))

    def executemany(self, sql: str, rows: Iterable[Sequence[Any]]) -> int:
        batch = [tuple(row) for row in rows]
        if not batch:
            return 0
        statement = self._sql(sql)
        if self._rewrite:
            with self._conn.cursor() as cursor:
                cursor.executemany(statement, batch)
                return int(cursor.rowcount)
        return int(self._conn.executemany(statement, batch).rowcount)

    def executemany_returning(self, sql: str, rows: Iterable[Sequence[Any]]) -> list[tuple[Any, ...]]:
        batch = [tuple(row) for row in rows]
        if not batch:
            return []
        statement = self._sql(sql)
        if not self._rewrite:
            return [tuple(result) for row in batch for result in self._conn.execute(statement, row).fetchall()]
        results: list[tuple[Any, ...]] = []
        with self._conn.cursor() as cursor:
            cursor.executemany(statement, batch, returning=True)
            while True:
                results.extend(tuple(row) for row in cursor.fetchall())
                if not cursor.nextset():
                    break
        return results


def connection_session(conn: Any, dialect: Dialect) -> SqlSession:
    """Bind portable SQL to an adapter-owned transaction without committing it."""
    return _Session(conn, rewrite_placeholders=dialect == "postgres")


class SQLiteBackend:
    """Thread-local SQLite connections; tenant isolation is the store's WHERE clause.

    ``all_tenants`` changes nothing on SQLite (there is no RLS); the explicit
    scope check lives in :func:`require_tenant_scope`. A connection factory can
    share an existing store's thread-local connection during a gradual port;
    a read-only snapshot rejects an active caller transaction without altering it.
    """

    dialect: Dialect = "sqlite"

    def __init__(self, db_path: str, *, connection_factory: Callable[[], sqlite3.Connection] | None = None) -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._connection_factory = connection_factory

    def _conn(self) -> sqlite3.Connection:
        if self._connection_factory is not None:
            return self._connection_factory()
        conn: sqlite3.Connection | None = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._db_path, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
        return conn

    @contextmanager
    def transaction(self, *, read_only: bool = False, all_tenants: bool = False) -> Iterator[SqlSession]:
        del all_tenants
        conn = self._conn()
        if read_only:
            if conn.in_transaction:
                raise ValueError("read-only snapshot requires an idle connection")
            conn.execute("PRAGMA query_only = ON")
            try:
                conn.execute("BEGIN")
                try:
                    yield _Session(conn, rewrite_placeholders=False)
                finally:
                    conn.rollback()
            finally:
                conn.execute("PRAGMA query_only = OFF")
            return
        try:
            yield _Session(conn, rewrite_placeholders=False)
        except BaseException:
            conn.rollback()
            raise
        conn.commit()

    def bootstrap(self, component: str, ddl: Mapping[Dialect, Sequence[str]], *, rls_table: str | None = None) -> None:
        del rls_table
        conn = self._conn()
        ensure_sqlite_schema_version(conn, component)
        for statement in ddl["sqlite"]:
            conn.execute(statement)
        conn.commit()


class PostgresBackend:
    """Pooled Postgres connections bound to the request tenant for RLS.

    ``maintenance_pool`` is the maintenance-role pool used by
    ``transaction(all_tenants=True)``; when omitted, the shared, lazily built
    maintenance pool is used, which fails closed unless the maintenance role is
    configured.
    """

    dialect: Dialect = "postgres"

    def __init__(self, pool: ConnectionPool | None = None, *, maintenance_pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()
        self._maintenance_pool = maintenance_pool

    @contextmanager
    def _connection(self, *, read_only: bool, all_tenants: bool) -> Iterator[Any]:
        if all_tenants is True:
            # Bounded background sweeps run on every tick; like the job store,
            # they skip the per-call signed bypass event and stack walk.
            with bypass_tenant_rls(audit=False, warn=False):
                with _maintenance_connection(self._maintenance_pool, repeatable_read=read_only) as conn:
                    yield conn
            return
        with _tenant_connection(self._pool, repeatable_read=read_only) as conn:
            yield conn

    @contextmanager
    def transaction(self, *, read_only: bool = False, all_tenants: bool = False) -> Iterator[SqlSession]:
        with self._connection(read_only=read_only, all_tenants=all_tenants) as conn:
            try:
                yield _Session(conn, rewrite_placeholders=True)
            except BaseException:
                conn.rollback()
                raise
            if read_only:
                conn.rollback()
            else:
                conn.commit()

    def bootstrap(self, component: str, ddl: Mapping[Dialect, Sequence[str]], *, rls_table: str | None = None) -> None:
        with self._pool.connection() as conn:
            if not ensure_postgres_schema_version(conn, component):
                return
            for statement in ddl["postgres"]:
                conn.execute(statement)
            if rls_table is not None:
                _ensure_tenant_rls(conn, rls_table, "tenant_id")
            conn.commit()
