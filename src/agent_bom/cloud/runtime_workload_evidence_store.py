"""Durable persistence for CWPP runtime/EDR workload evidence (stage 3, #4158).

Three interchangeable backends behind one contract:

* :class:`InMemoryRuntimeWorkloadEvidenceStore` — the default, non-durable tier.
* :class:`SQLiteRuntimeWorkloadEvidenceStore` — node-local, restart-safe, and
  safe under cross-process writers (WAL + busy timeout).
* :class:`PostgresRuntimeWorkloadEvidenceStore` — shared across control-plane
  replicas.

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
from pathlib import Path
from typing import Any, Protocol

from agent_bom.cloud.runtime_workload_evidence import RuntimeWorkloadSignal

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
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_rwe_tenant_workload_time "
                "ON runtime_workload_evidence (tenant_id, workload_id, observed_at DESC)"
            )

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
    """Shared Postgres backend with application-level tenant scoping.

    Uses a direct connection (not the RLS pool) so tenant isolation is enforced by
    the leading ``tenant_id`` predicate and the composite dedup key — the same
    model the stage-1 lifecycle store uses. ``table`` is parameterizable so tests
    can isolate into a throwaway relation.
    """

    def __init__(self, dsn: str, *, table: str = "runtime_workload_evidence") -> None:
        if not table.replace("_", "").isalnum():
            raise ValueError("table name must be alphanumeric/underscore")
        self._dsn = dsn
        self.table = table
        self.init_schema()

    def _connect(self) -> Any:
        import psycopg

        return psycopg.connect(self._dsn)

    def init_schema(self) -> None:
        with self._connect() as conn:
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
                f"CREATE INDEX IF NOT EXISTS idx_{self.table}_tenant_time ON {self.table} (tenant_id, workload_id, observed_at DESC)"  # noqa: S608
            )
            conn.commit()

    def put_batch(self, signals: list[RuntimeWorkloadSignal]) -> int:
        if not signals:
            return 0
        placeholders = ",".join("%s" for _ in _COLUMNS)
        sql = (
            f"INSERT INTO {self.table} ({','.join(_COLUMNS)}) VALUES ({placeholders}) "  # noqa: S608  # nosec B608 — table validated in __init__, values parameterized
            "ON CONFLICT (tenant_id, provider, account_id, workload_ref, dedup_key) DO NOTHING"
        )
        inserted = 0
        with self._connect() as conn:
            with conn.cursor() as cur:
                for signal in signals:
                    cur.execute(sql, _row_values(signal))
                    inserted += cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
            conn.commit()
        return inserted

    def list_for_tenant(self, tenant_id: str, *, limit: int = 5000) -> list[RuntimeWorkloadSignal]:
        with self._connect() as conn:
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
        with self._connect() as conn:
            conn.execute(f"DROP TABLE IF EXISTS {self.table}")  # noqa: S608
            conn.commit()


# ── process-global default store (for the live enrichment read path) ─────────

_default_store: RuntimeWorkloadEvidenceStore | None = None
_default_lock = threading.Lock()


def get_runtime_workload_evidence_store() -> RuntimeWorkloadEvidenceStore:
    """Return the process default runtime workload-evidence store.

    Defaults to the in-memory tier so the finding/graph read path is a no-op until
    an operator configures a durable backend or seeds signals. Durable SQLite /
    Postgres backends are wired by stage-4 lock-in (scheduler + config); tests and
    callers can inject one with :func:`set_runtime_workload_evidence_store`.
    """
    global _default_store
    with _default_lock:
        if _default_store is None:
            _default_store = InMemoryRuntimeWorkloadEvidenceStore()
        return _default_store


def set_runtime_workload_evidence_store(store: RuntimeWorkloadEvidenceStore | None) -> None:
    global _default_store
    with _default_lock:
        _default_store = store


__all__ = [
    "InMemoryRuntimeWorkloadEvidenceStore",
    "PostgresRuntimeWorkloadEvidenceStore",
    "RuntimeWorkloadEvidenceStore",
    "SQLiteRuntimeWorkloadEvidenceStore",
    "get_runtime_workload_evidence_store",
    "set_runtime_workload_evidence_store",
]
