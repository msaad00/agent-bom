"""One parameterised-SQL layer that runs a store on SQLite or Postgres.

Stores write portable SQL with ``?`` placeholders and ``ON CONFLICT ... DO
UPDATE`` upserts (SQLite >= 3.24 and Postgres share that syntax). The backend
owns everything that differs between engines:

* placeholders: ``?`` on SQLite, rewritten to ``%s`` for psycopg;
* tenant binding: Postgres opens every transaction through
  ``_tenant_connection`` so FORCE row-level security sees ``app.tenant_id``;
  SQLite has no RLS, so stores MUST filter on ``tenant_id`` in SQL and call
  :func:`require_tenant_id` first;
* schema bootstrap: per-dialect DDL, schema-version bookkeeping, and the RLS
  policy on Postgres (skipped when Alembic owns the deployment schema);
* JSON columns: Postgres JSONB decodes to ``dict``, SQLite TEXT to ``str``;
  :func:`load_json` accepts both.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

from agent_bom.api.postgres_common import ConnectionPool, _ensure_tenant_rls, _get_pool, _tenant_connection
from agent_bom.api.storage_schema import ensure_postgres_schema_version, ensure_sqlite_schema_version

Dialect = Literal["sqlite", "postgres"]


def require_tenant_id(tenant_id: str | None) -> str:
    """Fail closed when a store call carries no tenant."""
    if tenant_id is None or not str(tenant_id).strip():
        raise ValueError("tenant-scoped store call requires a non-empty tenant_id")
    return tenant_id


def utc_timestamp() -> str:
    """Timestamp format shared by both engines' TEXT ``updated_at`` columns."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(value: Any) -> Any:
    """Decode a JSON column that may arrive as JSONB (decoded) or TEXT."""
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8")
    return json.loads(value) if isinstance(value, str) else value


class SqlSession(Protocol):
    """One tenant-bound transaction."""

    def execute(self, sql: str, params: Sequence[Any] = ()) -> Any: ...


class SqlBackend(Protocol):
    """Connection source plus the dialect differences a store must not see."""

    dialect: Dialect

    def transaction(self) -> AbstractContextManager[SqlSession]: ...

    def bootstrap(self, component: str, ddl: Mapping[Dialect, Sequence[str]], *, rls_table: str | None = None) -> None: ...


class _Session:
    def __init__(self, conn: Any, *, rewrite_placeholders: bool) -> None:
        self._conn = conn
        self._rewrite = rewrite_placeholders

    def execute(self, sql: str, params: Sequence[Any] = ()) -> Any:
        if self._rewrite:
            if "%" in sql:
                raise ValueError("portable SQL must not contain '%'; pass literals as parameters")
            sql = sql.replace("?", "%s")
        return self._conn.execute(sql, tuple(params))


class SQLiteBackend:
    """Thread-local SQLite connections; tenant isolation is the store's WHERE clause."""

    dialect: Dialect = "sqlite"

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._local = threading.local()

    def _conn(self) -> sqlite3.Connection:
        conn: sqlite3.Connection | None = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._db_path, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
        return conn

    @contextmanager
    def transaction(self) -> Iterator[SqlSession]:
        conn = self._conn()
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
    """Pooled Postgres connections bound to the request tenant for RLS."""

    dialect: Dialect = "postgres"

    def __init__(self, pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()

    @contextmanager
    def transaction(self) -> Iterator[SqlSession]:
        with _tenant_connection(self._pool) as conn:
            try:
                yield _Session(conn, rewrite_placeholders=True)
            except BaseException:
                conn.rollback()
                raise
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
