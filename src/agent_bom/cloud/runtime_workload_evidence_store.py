"""Durable persistence for CWPP runtime/EDR workload evidence (stage 3, #4158).

Three interchangeable backends behind one contract:

* :class:`InMemoryRuntimeWorkloadEvidenceStore` — explicit ephemeral opt-out
  (``AGENT_BOM_EPHEMERAL_STORE=1``); process-local, non-durable.
* :class:`SQLiteRuntimeWorkloadEvidenceStore` — node-local default, restart-safe,
  and safe under cross-process writers (WAL + busy timeout).
* :class:`PostgresRuntimeWorkloadEvidenceStore` — shared across control-plane
  replicas.

:func:`get_runtime_workload_evidence_store` selects the tier via
:func:`agent_bom.storage.factory.resolve_backend` with ``mode="durable"``
(Postgres → ephemeral opt-out → SQLite), matching the runtime event store so
CLI ingest and API enrichment share evidence across processes and workers.

Tenant isolation is application-level and follows the stage-1 lifecycle store
(:mod:`agent_bom.cloud.side_scan_lifecycle`): ``tenant_id`` leads every WHERE
clause and is part of the dedup key, so two tenants can carry the SAME logical
signal without one dropping or leaking into the other. Dedup is on
``(tenant_id, provider, account_id, workload_ref, dedup_key)``. Only redacted
metadata (never data-plane bytes) is stored — the signal already redacts itself
at construction.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator, Protocol

from agent_bom.cloud.runtime_workload_evidence import RuntimeWorkloadSignal

if TYPE_CHECKING:
    from psycopg import Connection
    from psycopg_pool import ConnectionPool

_COLUMNS = (
    "tenant_id",
    "provider",
    "account_id",
    "workload_ref",
    "dedup_key",
    "workload_id",
    "signal_type",
    "severity",
    "observed_at",
    "source_id",
    "source_kind",
    "payload_json",
)


def _row_values(signal: RuntimeWorkloadSignal) -> tuple[Any, ...]:
    return (
        signal.tenant_id,
        signal.provider,
        signal.account_id,
        signal.workload_ref,
        signal.dedup_key,
        signal.workload_id,
        signal.signal_type.value,
        signal.severity,
        signal.observed_at,
        signal.source_id,
        signal.source_kind,
        json.dumps(signal.to_dict(), sort_keys=True, separators=(",", ":")),
    )


def _signal_from_json(raw: str) -> RuntimeWorkloadSignal:
    payload = json.loads(raw)
    return RuntimeWorkloadSignal.from_dict(payload)


class RuntimeWorkloadEvidenceStore(Protocol):
    """Contract shared by every runtime workload-evidence backend."""

    def init_schema(self) -> None: ...

    def put_batch(self, signals: list[RuntimeWorkloadSignal]) -> int:
        """Persist new signals, dedup on the scope key; return newly inserted count."""
        ...

    def list_for_tenant(self, tenant_id: str, *, limit: int = 5000) -> list[RuntimeWorkloadSignal]:
        """Return one tenant's signals, most recent first."""
        ...


class InMemoryRuntimeWorkloadEvidenceStore:
    """Process-local, non-durable store (default tier)."""

    def __init__(self) -> None:
        self._rows: dict[tuple[str, str, str, str, str], RuntimeWorkloadSignal] = {}
        self._lock = threading.Lock()

    def init_schema(self) -> None:  # pragma: no cover - nothing to create
        return None

    @staticmethod
    def _key(signal: RuntimeWorkloadSignal) -> tuple[str, str, str, str, str]:
        return (
            signal.tenant_id,
            signal.provider,
            signal.account_id.lower(),
            signal.workload_ref.lower(),
            signal.dedup_key,
        )

    def put_batch(self, signals: list[RuntimeWorkloadSignal]) -> int:
        inserted = 0
        with self._lock:
            for signal in signals:
                key = self._key(signal)
                if key not in self._rows:
                    self._rows[key] = signal
                    inserted += 1
        return inserted

    def list_for_tenant(self, tenant_id: str, *, limit: int = 5000) -> list[RuntimeWorkloadSignal]:
        with self._lock:
            rows = [s for s in self._rows.values() if s.tenant_id == tenant_id]
        rows.sort(key=lambda s: (s.observed_at, s.dedup_key), reverse=True)
        return rows[:limit]


class SQLiteRuntimeWorkloadEvidenceStore:
    """Node-local, restart-safe, cross-process-safe SQLite backend."""

    def __init__(self, path: str | Path) -> None:
        self._path = str(path)
        self.init_schema()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def init_schema(self) -> None:
        with self._connect() as connection:
            from agent_bom.api.storage_schema import ensure_sqlite_schema_version

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS runtime_workload_evidence (
                    tenant_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    workload_ref TEXT NOT NULL,
                    dedup_key TEXT NOT NULL,
                    workload_id TEXT NOT NULL,
                    signal_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    source_kind TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, provider, account_id, workload_ref, dedup_key)
                )
                """
            )
            # Match the ``list_for_tenant`` query: WHERE tenant_id = ?
            # ORDER BY observed_at DESC, dedup_key DESC. The leading tenant
            # predicate plus the two ORDER BY columns (same direction) lets the
            # planner satisfy the sort from the index instead of a temp b-tree.
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_rwe_tenant_observed_dedup "
                "ON runtime_workload_evidence (tenant_id, observed_at DESC, dedup_key DESC)"
            )
            # Drop the stale index that ordered by (tenant_id, workload_id,
            # observed_at) — unusable for the tenant read's ORDER BY.
            connection.execute("DROP INDEX IF EXISTS idx_rwe_tenant_workload_time")
            ensure_sqlite_schema_version(connection, "runtime_workload_evidence")

    def put_batch(self, signals: list[RuntimeWorkloadSignal]) -> int:
        if not signals:
            return 0
        placeholders = ",".join("?" for _ in _COLUMNS)
        sql = f"INSERT OR IGNORE INTO runtime_workload_evidence ({','.join(_COLUMNS)}) VALUES ({placeholders})"  # noqa: S608
        with self._connect() as connection:
            before = connection.total_changes
            connection.executemany(sql, [_row_values(signal) for signal in signals])
            return connection.total_changes - before

    def list_for_tenant(self, tenant_id: str, *, limit: int = 5000) -> list[RuntimeWorkloadSignal]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload_json FROM runtime_workload_evidence WHERE tenant_id = ? ORDER BY observed_at DESC, dedup_key DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [_signal_from_json(str(row["payload_json"])) for row in rows]


class PostgresRuntimeWorkloadEvidenceStore:
    """Shared Postgres backend with migration-owned schema and tenant RLS.

    Production construction uses the shared secret-aware Postgres pool and the
    same request-scoped tenant session as the rest of the control plane. An
    explicit ``dsn`` remains available only for isolated development/tests that
    own a throwaway table.
    """

    def __init__(
        self,
        dsn: str | None = None,
        *,
        table: str = "runtime_workload_evidence",
        pool: ConnectionPool | None = None,
    ) -> None:
        if not table.replace("_", "").isalnum():
            raise ValueError("table name must be alphanumeric/underscore")
        self._dsn = dsn
        self.table = table
        self._pool: Any = None
        if dsn is not None and pool is not None:
            raise ValueError("Pass either dsn or pool, not both")
        if dsn is None:
            from agent_bom.api.postgres_common import _get_pool

            self._pool = pool or _get_pool()
        else:
            self._pool = None
        self.init_schema()

    def _connect(self) -> Any:
        if self._dsn is None:
            raise RuntimeError("Direct Postgres connections require an explicit development/test DSN")
        import psycopg

        return psycopg.connect(self._dsn)

    @contextmanager
    def _tenant_connection(self, tenant_id: str) -> Iterator[Connection]:
        if self._pool is None:
            with self._connect() as conn:
                yield conn
            return

        from agent_bom.api.postgres_common import (
            _tenant_connection,
            reset_current_tenant,
            set_current_tenant,
        )

        token = set_current_tenant(tenant_id)
        try:
            with _tenant_connection(self._pool) as conn:
                yield conn
        finally:
            reset_current_tenant(token)

    def _create_schema(self, conn: Connection) -> None:
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {self.table} (
                tenant_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                account_id TEXT NOT NULL,
                workload_ref TEXT NOT NULL,
                dedup_key TEXT NOT NULL,
                workload_id TEXT NOT NULL,
                signal_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                source_id TEXT NOT NULL,
                source_kind TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (tenant_id, provider, account_id, workload_ref, dedup_key)
            )
            """  # noqa: S608
        )
        conn.execute(
            f"CREATE INDEX IF NOT EXISTS idx_{self.table}_tenant_observed_dedup "  # noqa: S608
            f"ON {self.table} (tenant_id, observed_at DESC, dedup_key DESC)"
        )
        conn.execute(f"DROP INDEX IF EXISTS idx_{self.table}_tenant_time")  # noqa: S608
        conn.commit()

    def init_schema(self) -> None:
        if self._pool is not None:
            from agent_bom.api.storage_schema import ensure_postgres_schema_version

            with self._pool.connection() as conn:
                if not ensure_postgres_schema_version(conn, "runtime_workload_evidence"):
                    return
                self._create_schema(conn)
            return

        with self._connect() as conn:
            self._create_schema(conn)

    def put_batch(self, signals: list[RuntimeWorkloadSignal]) -> int:
        if not signals:
            return 0
        tenant_ids = {signal.tenant_id for signal in signals}
        if len(tenant_ids) != 1:
            raise ValueError("A runtime workload evidence batch must contain exactly one tenant")
        tenant_id = next(iter(tenant_ids))
        placeholders = ",".join("%s" for _ in _COLUMNS)
        sql = (
            f"INSERT INTO {self.table} ({','.join(_COLUMNS)}) VALUES ({placeholders}) "  # noqa: S608  # nosec B608 — table validated in __init__, values parameterized
            "ON CONFLICT (tenant_id, provider, account_id, workload_ref, dedup_key) DO NOTHING"
        )
        inserted = 0
        with self._tenant_connection(tenant_id) as conn:
            with conn.cursor() as cur:
                for signal in signals:
                    cur.execute(sql, _row_values(signal))
                    inserted += cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
            conn.commit()
        return inserted

    def list_for_tenant(self, tenant_id: str, *, limit: int = 5000) -> list[RuntimeWorkloadSignal]:
        with self._tenant_connection(tenant_id) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"SELECT payload_json FROM {self.table} WHERE tenant_id = %s "  # noqa: S608  # nosec B608 — table validated in __init__, values parameterized
                    "ORDER BY observed_at DESC, dedup_key DESC LIMIT %s",
                    (tenant_id, limit),
                )
                rows = cur.fetchall()
        return [_signal_from_json(str(row[0])) for row in rows]

    def drop_table(self) -> None:
        """Drop the backing relation (test cleanup helper)."""
        if self._pool is not None:
            raise RuntimeError("Migration-owned Postgres tables cannot be dropped by the runtime store")
        with self._connect() as conn:
            conn.execute(f"DROP TABLE IF EXISTS {self.table}")  # noqa: S608
            conn.commit()


# ── process-global default store (for the live enrichment read path) ─────────

_default_store: RuntimeWorkloadEvidenceStore | None = None
_default_lock = threading.Lock()


def get_runtime_workload_evidence_store() -> RuntimeWorkloadEvidenceStore:
    """Return the process default runtime workload-evidence store, durable by default.

    Selection (highest precedence first), via :mod:`agent_bom.storage.factory`:
    - Postgres (``AGENT_BOM_POSTGRES_URL`` / ``AGENT_BOM_DB`` Postgres URL):
      multi-replica — CLI ingest and API enrichment share one evidence table.
    - in-memory (``AGENT_BOM_EPHEMERAL_STORE=1``): explicit opt-out; signals are
      lost on restart and across processes/workers.
    - SQLite (default, or ``AGENT_BOM_DB`` file path): single-node durable —
      evidence survives a restart and is visible to a co-located API process.

    Tests and callers can still inject a store with
    :func:`set_runtime_workload_evidence_store`.
    """
    global _default_store
    with _default_lock:
        if _default_store is not None:
            return _default_store
        from agent_bom.storage.base import BackendKind
        from agent_bom.storage.factory import resolve_backend

        # mode="durable" matches runtime_event_store: Postgres → ephemeral only
        # on explicit opt-out → SQLite default. The prior always-InMemory factory
        # silently dropped CLI→API and multi-worker evidence.
        selection = resolve_backend(mode="durable")
        if selection.backend is BackendKind.POSTGRES:
            import os

            dsn = selection.dsn or os.environ.get("AGENT_BOM_POSTGRES_URL") or os.environ.get("AGENT_BOM_DB", "")
            if not dsn.strip():
                raise RuntimeError("Postgres workload-evidence store selected but no Postgres URL is configured")
            # The production store resolves the configured URL, mounted secret
            # file/IAM token, pool bounds, and tenant RLS through postgres_common.
            # The raw password-free Compose DSN must never be connected directly.
            _default_store = PostgresRuntimeWorkloadEvidenceStore()
        elif selection.backend is BackendKind.MEMORY:
            _default_store = InMemoryRuntimeWorkloadEvidenceStore()
        else:
            _default_store = SQLiteRuntimeWorkloadEvidenceStore(selection.sqlite_path or "agent_bom.db")
        return _default_store


def set_runtime_workload_evidence_store(store: RuntimeWorkloadEvidenceStore | None) -> None:
    global _default_store
    with _default_lock:
        _default_store = store


def reset_runtime_workload_evidence_store() -> None:
    set_runtime_workload_evidence_store(None)


__all__ = [
    "InMemoryRuntimeWorkloadEvidenceStore",
    "PostgresRuntimeWorkloadEvidenceStore",
    "RuntimeWorkloadEvidenceStore",
    "SQLiteRuntimeWorkloadEvidenceStore",
    "get_runtime_workload_evidence_store",
    "reset_runtime_workload_evidence_store",
    "set_runtime_workload_evidence_store",
]
