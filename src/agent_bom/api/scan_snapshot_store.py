"""Tenant-scoped store for materialized scan finding snapshots (ADR-015).

A snapshot is derived data: the fold inputs of one completed scan job, written
once after the job is durably ``DONE``. ``scan_snapshot_jobs`` holds one
metadata row per job (scope, evidence authority, incompleteness, row-schema
version); ``scan_snapshot_rows`` holds the job's intrinsic finding rows in
collection order. Job deletion attempts snapshot cleanup; failed cleanup is
retried by the job TTL sweep. Explicit tenant erasure propagates purge failures.

Backends follow the existing selection: Postgres (tenant RLS, see
``postgres_scan_snapshot``) when a Postgres deployment is configured, SQLite
when ``AGENT_BOM_DB`` names a file, and in-memory otherwise.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version, postgres_deployment_configured
from agent_bom.core.settings import env_raw
from agent_bom.security import sanitize_text

_logger = logging.getLogger(__name__)

SCAN_SNAPSHOT_COMPONENT = "scan_snapshots"
SCAN_SNAPSHOT_ROW_SCHEMA_VERSION = 1
META_FIELDS = (
    "scope_key",
    "authority_evidence_at",
    "authority_completed_at",
    "authoritative",
    "incomplete_reasons",
    "completed_at",
    "created_at",
    "row_schema_version",
    "row_count",
    "materialized_at",
)

SQLITE_SCAN_SNAPSHOT_DDL = (
    """
    CREATE TABLE IF NOT EXISTS scan_snapshot_jobs (
        tenant_id TEXT NOT NULL,
        job_id TEXT NOT NULL,
        scope_key TEXT NOT NULL,
        authority_evidence_at TEXT NOT NULL,
        authority_completed_at TEXT NOT NULL,
        authoritative INTEGER NOT NULL,
        incomplete_reasons TEXT NOT NULL,
        completed_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        row_schema_version INTEGER NOT NULL,
        row_count INTEGER NOT NULL,
        materialized_at TEXT NOT NULL,
        PRIMARY KEY (tenant_id, job_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_scan_snapshot_jobs_completed ON scan_snapshot_jobs (completed_at)",
    """
    CREATE TABLE IF NOT EXISTS scan_snapshot_rows (
        tenant_id TEXT NOT NULL,
        job_id TEXT NOT NULL,
        ordinal INTEGER NOT NULL,
        finding_identity TEXT NOT NULL,
        canonical_id TEXT NOT NULL DEFAULT '',
        severity TEXT NOT NULL DEFAULT '',
        payload TEXT NOT NULL,
        PRIMARY KEY (tenant_id, job_id, ordinal)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_scan_snapshot_rows_job ON scan_snapshot_rows (tenant_id, job_id)",
    "CREATE INDEX IF NOT EXISTS idx_scan_snapshot_rows_canonical ON scan_snapshot_rows (tenant_id, canonical_id) WHERE canonical_id != ''",
)


class ScanSnapshotStore(Protocol):
    """Persistence contract for per-job scan finding snapshots."""

    def put_snapshot(self, tenant_id: str, job_id: str, meta: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]) -> None: ...
    def get_meta(self, tenant_id: str, job_ids: Iterable[str] | None = None) -> dict[str, dict[str, Any]]: ...
    def get_rows(self, tenant_id: str, job_id: str) -> list[dict[str, Any]]: ...
    def delete_job(self, tenant_id: str, job_id: str) -> bool: ...
    def delete_older_than(self, tenant_id: str | None, cutoff_iso: str) -> int: ...
    def delete_tenant(self, tenant_id: str) -> int: ...


def require_tenant(tenant_id: str) -> str:
    """Snapshots are always tenant-owned; an empty tenant is a caller bug."""
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ValueError("scan snapshot access requires an explicit tenant_id")
    return tenant_id


def meta_columns(meta: Mapping[str, Any]) -> tuple[Any, ...]:
    """Ordered column values for one metadata row (``authoritative`` as bool)."""
    reasons = [str(item) for item in meta.get("incomplete_reasons") or []]
    return (
        str(meta.get("scope_key") or ""),
        str(meta.get("authority_evidence_at") or ""),
        str(meta.get("authority_completed_at") or ""),
        bool(meta.get("authoritative")),
        json.dumps(reasons, separators=(",", ":")),
        str(meta.get("completed_at") or ""),
        str(meta.get("created_at") or ""),
        int(meta.get("row_schema_version") or 0),
        int(meta.get("row_count") or 0),
        str(meta.get("materialized_at") or ""),
    )


def meta_from_columns(job_id: str, values: Sequence[Any]) -> dict[str, Any]:
    """Rebuild a metadata dict from the ``META_FIELDS`` column order."""
    meta: dict[str, Any] = dict(zip(META_FIELDS, values, strict=True))
    meta["authoritative"] = bool(meta["authoritative"])
    loaded = json.loads(meta["incomplete_reasons"] or "[]")
    meta["incomplete_reasons"] = [str(item) for item in loaded] if isinstance(loaded, list) else []
    meta["row_schema_version"] = int(meta["row_schema_version"])
    meta["row_count"] = int(meta["row_count"])
    meta["job_id"] = job_id
    return meta


def row_columns(ordinal: int, row: Mapping[str, Any]) -> tuple[Any, ...]:
    """Ordered column values for one finding row; payload is canonical JSON."""
    return (
        ordinal,
        str(row.get("finding_identity") or ""),
        str(row.get("canonical_id") or ""),
        str(row.get("severity") or ""),
        json.dumps(row.get("payload") or {}, sort_keys=True, separators=(",", ":"), default=str),
    )


def row_from_columns(values: Sequence[Any]) -> dict[str, Any]:
    ordinal, identity, canonical_id, severity, payload = values
    loaded = json.loads(payload)
    return {
        "ordinal": int(ordinal),
        "finding_identity": str(identity),
        "canonical_id": str(canonical_id),
        "severity": str(severity),
        "payload": loaded if isinstance(loaded, dict) else {},
    }


class InMemoryScanSnapshotStore:
    """Process-local snapshot store for development and tests."""

    def __init__(self) -> None:
        self._jobs: dict[tuple[str, str], dict[str, Any]] = {}
        self._rows: dict[tuple[str, str], list[dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def put_snapshot(self, tenant_id: str, job_id: str, meta: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]) -> None:
        key = (require_tenant(tenant_id), job_id)
        stored_meta = meta_from_columns(job_id, meta_columns(meta))
        stored_rows = [row_from_columns(row_columns(index, row)) for index, row in enumerate(rows)]
        with self._lock:
            self._jobs[key] = stored_meta
            self._rows[key] = stored_rows

    def get_meta(self, tenant_id: str, job_ids: Iterable[str] | None = None) -> dict[str, dict[str, Any]]:
        require_tenant(tenant_id)
        wanted = None if job_ids is None else set(job_ids)
        with self._lock:
            return {
                job_id: dict(meta)
                for (tenant, job_id), meta in self._jobs.items()
                if tenant == tenant_id and (wanted is None or job_id in wanted)
            }

    def get_rows(self, tenant_id: str, job_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [json.loads(json.dumps(row)) for row in self._rows.get((require_tenant(tenant_id), job_id), [])]

    def delete_job(self, tenant_id: str, job_id: str) -> bool:
        key = (require_tenant(tenant_id), job_id)
        with self._lock:
            self._rows.pop(key, None)
            return self._jobs.pop(key, None) is not None

    def delete_older_than(self, tenant_id: str | None, cutoff_iso: str) -> int:
        if tenant_id is not None:
            require_tenant(tenant_id)
        with self._lock:
            expired = [
                key
                for key, meta in self._jobs.items()
                if (tenant_id is None or key[0] == tenant_id) and str(meta.get("completed_at") or "") < cutoff_iso
            ]
            for key in expired:
                self._jobs.pop(key, None)
                self._rows.pop(key, None)
            return len(expired)

    def delete_tenant(self, tenant_id: str) -> int:
        require_tenant(tenant_id)
        with self._lock:
            owned = [key for key in self._jobs if key[0] == tenant_id]
            for key in owned:
                self._jobs.pop(key, None)
                self._rows.pop(key, None)
            return len(owned)


META_COLUMNS_SQL = ", ".join(META_FIELDS)


class SQLiteScanSnapshotStore:
    """SQLite-backed snapshot store; each snapshot is replaced in one transaction."""

    def __init__(self, db_path: str = "agent_bom.db") -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        conn: sqlite3.Connection = self._local.conn
        return conn

    def _init_db(self) -> None:
        ensure_sqlite_schema_version(self._conn, SCAN_SNAPSHOT_COMPONENT)
        for statement in SQLITE_SCAN_SNAPSHOT_DDL:
            self._conn.execute(statement)
        self._conn.commit()

    def put_snapshot(self, tenant_id: str, job_id: str, meta: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]) -> None:
        require_tenant(tenant_id)
        values = meta_columns(meta)
        with self._conn as conn:
            conn.execute("DELETE FROM scan_snapshot_rows WHERE tenant_id = ? AND job_id = ?", (tenant_id, job_id))
            conn.execute("DELETE FROM scan_snapshot_jobs WHERE tenant_id = ? AND job_id = ?", (tenant_id, job_id))
            conn.execute(
                f"INSERT INTO scan_snapshot_jobs (tenant_id, job_id, {META_COLUMNS_SQL}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",  # nosec B608
                (tenant_id, job_id, *values[:3], int(values[3]), *values[4:]),
            )
            conn.executemany(
                "INSERT INTO scan_snapshot_rows (tenant_id, job_id, ordinal, finding_identity, canonical_id, severity, payload) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                [(tenant_id, job_id, *row_columns(index, row)) for index, row in enumerate(rows)],
            )

    def get_meta(self, tenant_id: str, job_ids: Iterable[str] | None = None) -> dict[str, dict[str, Any]]:
        require_tenant(tenant_id)
        sql = f"SELECT job_id, {META_COLUMNS_SQL} FROM scan_snapshot_jobs WHERE tenant_id = ?"  # nosec B608
        params: list[Any] = [tenant_id]
        if job_ids is not None:
            wanted = sorted(set(job_ids))
            if not wanted:
                return {}
            sql += f" AND job_id IN ({', '.join('?' for _ in wanted)})"
            params.extend(wanted)
        rows = self._conn.execute(sql, params).fetchall()
        return {str(row[0]): meta_from_columns(str(row[0]), row[1:]) for row in rows}

    def get_rows(self, tenant_id: str, job_id: str) -> list[dict[str, Any]]:
        require_tenant(tenant_id)
        rows = self._conn.execute(
            "SELECT ordinal, finding_identity, canonical_id, severity, payload FROM scan_snapshot_rows "
            "WHERE tenant_id = ? AND job_id = ? ORDER BY ordinal",
            (tenant_id, job_id),
        ).fetchall()
        return [row_from_columns(row) for row in rows]

    def delete_job(self, tenant_id: str, job_id: str) -> bool:
        require_tenant(tenant_id)
        with self._conn as conn:
            conn.execute("DELETE FROM scan_snapshot_rows WHERE tenant_id = ? AND job_id = ?", (tenant_id, job_id))
            cursor = conn.execute("DELETE FROM scan_snapshot_jobs WHERE tenant_id = ? AND job_id = ?", (tenant_id, job_id))
        return cursor.rowcount > 0

    def delete_older_than(self, tenant_id: str | None, cutoff_iso: str) -> int:
        scope, params = ("", [cutoff_iso]) if tenant_id is None else (" AND tenant_id = ?", [cutoff_iso, require_tenant(tenant_id)])
        expired = f"SELECT tenant_id, job_id FROM scan_snapshot_jobs WHERE completed_at < ?{scope}"  # nosec B608
        with self._conn as conn:
            conn.execute(f"DELETE FROM scan_snapshot_rows WHERE (tenant_id, job_id) IN ({expired})", params)  # nosec B608
            cursor = conn.execute(f"DELETE FROM scan_snapshot_jobs WHERE completed_at < ?{scope}", params)  # nosec B608
        return cursor.rowcount

    def delete_tenant(self, tenant_id: str) -> int:
        require_tenant(tenant_id)
        with self._conn as conn:
            conn.execute("DELETE FROM scan_snapshot_rows WHERE tenant_id = ?", (tenant_id,))
            cursor = conn.execute("DELETE FROM scan_snapshot_jobs WHERE tenant_id = ?", (tenant_id,))
        return cursor.rowcount


# ── process-global store selection ─────────────────────────────────────────

_default_store: ScanSnapshotStore | None = None
_default_lock = threading.Lock()


def get_scan_snapshot_store() -> ScanSnapshotStore:
    """Return the configured snapshot store: Postgres, then SQLite, then in-memory."""
    global _default_store
    with _default_lock:
        if _default_store is None:
            db_path = (env_raw("AGENT_BOM_DB") or "").strip()
            if postgres_deployment_configured():
                from agent_bom.api.postgres_scan_snapshot import PostgresScanSnapshotStore

                _default_store = PostgresScanSnapshotStore()
            elif db_path:
                _default_store = SQLiteScanSnapshotStore(db_path)
            else:
                _default_store = InMemoryScanSnapshotStore()
        return _default_store


def set_scan_snapshot_store(store: ScanSnapshotStore | None) -> None:
    """Switch the snapshot store backend (``None`` re-selects from configuration)."""
    global _default_store
    with _default_lock:
        _default_store = store


def discard_job_snapshot(tenant_id: str | None, job_id: str, *, deleted: bool) -> bool:
    """Remove a deleted job's snapshot; never changes the job deletion result.

    Called by the job stores after their own delete commits. Best-effort: a
    snapshot failure is logged and left for TTL expiry, because blocking the
    authoritative job deletion on derived data would be the wrong trade.
    Cleanup runs even when new snapshot writes have been disabled.
    """
    if not deleted or not tenant_id:
        return deleted
    try:
        get_scan_snapshot_store().delete_job(tenant_id, job_id)
    except Exception as exc:  # broad-except: derived-data cleanup must never fail the authoritative job delete
        _logger.warning("scan snapshot delete skipped job=%s: %s", sanitize_text(job_id), sanitize_text(exc))
    return deleted


def expire_jobs_and_snapshots(job_store: Any, ttl_seconds: int) -> int:
    """Run job TTL cleanup, then expire snapshots under the same TTL."""
    removed = int(job_store.cleanup_expired(ttl_seconds) or 0)
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=ttl_seconds)).isoformat()
    try:
        get_scan_snapshot_store().delete_older_than(None, cutoff)
    except Exception as exc:  # broad-except: one failed sweep must not stop the maintenance loop; the next tick retries
        _logger.warning("scan snapshot expiry skipped: %s", sanitize_text(exc))
    return removed


def purge_tenant_snapshots(tenant_id: str) -> int:
    """Delete every snapshot a tenant owns (tenant data erasure).

    Runs whether or not materialization is currently enabled, so snapshots
    written before an operator turned the setting off are erased too.
    """
    return get_scan_snapshot_store().delete_tenant(tenant_id)
