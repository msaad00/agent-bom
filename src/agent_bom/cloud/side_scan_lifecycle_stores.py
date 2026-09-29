"""Side-scan state-store protocol plus the in-memory and SQLite backends."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Protocol

from .side_scan_lifecycle_models import (
    SideScanExecutionRecord,
    SideScanStateConflictError,
    _record_from_json,
    _record_json,
)
from .side_scan_lifecycle_status import CleanupStatus


class SideScanStateStore(Protocol):
    """Tenant-scoped lifecycle contract shared by every persistence backend."""

    def create_or_get(self, record: SideScanExecutionRecord) -> SideScanExecutionRecord: ...

    def get(self, *, tenant_id: str, execution_id: str) -> SideScanExecutionRecord | None: ...

    def save(self, record: SideScanExecutionRecord, *, expected_version: int) -> None: ...

    def list_recent(self, *, tenant_id: str, limit: int = 50) -> list[SideScanExecutionRecord]: ...

    def list_page(
        self,
        *,
        tenant_id: str,
        limit: int,
        offset: int,
        provider: str | None = None,
        status: str | None = None,
        query: str = "",
    ) -> list[SideScanExecutionRecord]: ...

    def list_page_with_total(
        self,
        *,
        tenant_id: str,
        limit: int,
        offset: int,
        provider: str | None = None,
        status: str | None = None,
        query: str = "",
    ) -> tuple[list[SideScanExecutionRecord], int]: ...

    def count(
        self,
        *,
        tenant_id: str,
        provider: str | None = None,
        status: str | None = None,
        query: str = "",
    ) -> int: ...

    def list_cleanup_due(self, *, tenant_id: str, limit: int = 100) -> list[SideScanExecutionRecord]: ...


class InMemorySideScanStateStore:
    """Explicit ephemeral backend; never selected unless the operator opts out."""

    def __init__(self) -> None:
        self._records: dict[str, SideScanExecutionRecord] = {}
        self._dedup: dict[tuple[str, str, str, str, str], str] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(record: SideScanExecutionRecord) -> tuple[str, str, str, str, str]:
        return (record.tenant_id, record.provider, record.account_id, record.target_id, record.idempotency_key)

    def create_or_get(self, record: SideScanExecutionRecord) -> SideScanExecutionRecord:
        with self._lock:
            existing_id = self._dedup.get(self._key(record))
            if existing_id is not None:
                return self._records[existing_id]
            self._records[record.execution_id] = record
            self._dedup[self._key(record)] = record.execution_id
            return record

    def get(self, *, tenant_id: str, execution_id: str) -> SideScanExecutionRecord | None:
        with self._lock:
            record = self._records.get(execution_id)
            return record if record is not None and record.tenant_id == tenant_id else None

    def save(self, record: SideScanExecutionRecord, *, expected_version: int) -> None:
        if record.state_version != expected_version + 1:
            raise SideScanStateConflictError("side-scan state version must advance by exactly one")
        with self._lock:
            current = self._records.get(record.execution_id)
            if current is None or current.tenant_id != record.tenant_id or current.state_version != expected_version:
                raise SideScanStateConflictError("side-scan execution was updated by another worker")
            self._records[record.execution_id] = record

    def list_recent(self, *, tenant_id: str, limit: int = 50) -> list[SideScanExecutionRecord]:
        return self.list_page(tenant_id=tenant_id, limit=limit, offset=0)

    def _filtered(
        self,
        *,
        tenant_id: str,
        provider: str | None,
        status: str | None,
        query: str,
    ) -> list[SideScanExecutionRecord]:
        needle = query.strip().lower()
        with self._lock:
            rows = [
                record
                for record in self._records.values()
                if record.tenant_id == tenant_id
                and (provider is None or record.provider == provider)
                and (status is None or record.status.value == status)
                and (
                    not needle
                    or needle in record.target_id.lower()
                    or needle in record.account_id.lower()
                    or needle in record.execution_id.lower()
                )
            ]
        rows.sort(key=lambda record: (record.updated_at, record.execution_id), reverse=True)
        return rows

    def list_page(
        self,
        *,
        tenant_id: str,
        limit: int,
        offset: int,
        provider: str | None = None,
        status: str | None = None,
        query: str = "",
    ) -> list[SideScanExecutionRecord]:
        if limit < 1 or offset < 0:
            raise ValueError("limit must be at least 1 and offset cannot be negative")
        rows, _total = self.list_page_with_total(
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
            provider=provider,
            status=status,
            query=query,
        )
        return rows

    def list_page_with_total(
        self,
        *,
        tenant_id: str,
        limit: int,
        offset: int,
        provider: str | None = None,
        status: str | None = None,
        query: str = "",
    ) -> tuple[list[SideScanExecutionRecord], int]:
        if limit < 1 or offset < 0:
            raise ValueError("limit must be at least 1 and offset cannot be negative")
        rows = self._filtered(tenant_id=tenant_id, provider=provider, status=status, query=query)
        return rows[offset : offset + limit], len(rows)

    def count(
        self,
        *,
        tenant_id: str,
        provider: str | None = None,
        status: str | None = None,
        query: str = "",
    ) -> int:
        return len(self._filtered(tenant_id=tenant_id, provider=provider, status=status, query=query))

    def list_cleanup_due(self, *, tenant_id: str, limit: int = 100) -> list[SideScanExecutionRecord]:
        due = {CleanupStatus.PENDING, CleanupStatus.IN_PROGRESS, CleanupStatus.PARTIAL}
        candidates = self.list_recent(tenant_id=tenant_id, limit=max(limit, len(self._records) or 1))
        rows = [record for record in candidates if record.cleanup_status in due]
        rows.sort(key=lambda record: (record.updated_at, record.execution_id))
        return rows[:limit]


class SQLiteSideScanStateStore:
    """Tenant-scoped SQLite persistence for restart-safe execution state."""

    def __init__(self, path: str | Path) -> None:
        self._path = str(path)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS side_scan_execution_state (
                    execution_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    state_version INTEGER NOT NULL,
                    cleanup_status TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    UNIQUE (tenant_id, provider, account_id, target_id, idempotency_key)
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_side_scan_cleanup ON side_scan_execution_state (tenant_id, cleanup_status, updated_at)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_side_scan_recent "
                "ON side_scan_execution_state (tenant_id, updated_at DESC, execution_id DESC)"
            )

    def create_or_get(self, record: SideScanExecutionRecord) -> SideScanExecutionRecord:
        """Create once per tenant/target/idempotency key; duplicate requests reuse state."""
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT payload_json FROM side_scan_execution_state
                WHERE tenant_id = ? AND provider = ? AND account_id = ?
                  AND target_id = ? AND idempotency_key = ?
                """,
                (record.tenant_id, record.provider, record.account_id, record.target_id, record.idempotency_key),
            ).fetchone()
            if row is not None:
                return _record_from_json(str(row["payload_json"]))
            connection.execute(
                """
                INSERT INTO side_scan_execution_state
                    (execution_id, tenant_id, provider, account_id, target_id, idempotency_key,
                     state_version, cleanup_status, updated_at, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                self._row_values(record),
            )
        return record

    def get(self, *, tenant_id: str, execution_id: str) -> SideScanExecutionRecord | None:
        """Load one execution without crossing the tenant boundary."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload_json FROM side_scan_execution_state WHERE tenant_id = ? AND execution_id = ?",
                (tenant_id, execution_id),
            ).fetchone()
        return _record_from_json(str(row["payload_json"])) if row is not None else None

    def save(self, record: SideScanExecutionRecord, *, expected_version: int) -> None:
        """Persist one state advance and reject stale-worker overwrites."""
        if record.state_version != expected_version + 1:
            raise SideScanStateConflictError("side-scan state version must advance by exactly one")
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE side_scan_execution_state
                SET state_version = ?, cleanup_status = ?, updated_at = ?, payload_json = ?
                WHERE tenant_id = ? AND execution_id = ? AND state_version = ?
                """,
                (
                    record.state_version,
                    record.cleanup_status.value,
                    record.updated_at,
                    _record_json(record),
                    record.tenant_id,
                    record.execution_id,
                    expected_version,
                ),
            )
            if cursor.rowcount != 1:
                raise SideScanStateConflictError("side-scan execution was updated by another worker")

    def list_recent(self, *, tenant_id: str, limit: int = 50) -> list[SideScanExecutionRecord]:
        """Return the tenant's most recently updated executions (newest first).

        Bounded read for surfacing execution status/history on the API and UI
        without crossing the tenant boundary. Never returns another tenant's rows.
        """
        return self.list_page(tenant_id=tenant_id, limit=limit, offset=0)

    @staticmethod
    def _page_where(*, tenant_id: str, provider: str | None, status: str | None, query: str) -> tuple[str, list[object]]:
        clauses = ["tenant_id = ?"]
        params: list[object] = [tenant_id]
        if provider is not None:
            clauses.append("provider = ?")
            params.append(provider)
        if status is not None:
            clauses.append("json_extract(payload_json, '$.status') = ?")
            params.append(status)
        if query.strip():
            pattern = f"%{query.strip().lower()}%"
            clauses.append("(lower(target_id) LIKE ? OR lower(account_id) LIKE ? OR lower(execution_id) LIKE ?)")
            params.extend((pattern, pattern, pattern))
        return " AND ".join(clauses), params

    def list_page(
        self,
        *,
        tenant_id: str,
        limit: int,
        offset: int,
        provider: str | None = None,
        status: str | None = None,
        query: str = "",
    ) -> list[SideScanExecutionRecord]:
        rows, _total = self.list_page_with_total(
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
            provider=provider,
            status=status,
            query=query,
        )
        return rows

    def list_page_with_total(
        self,
        *,
        tenant_id: str,
        limit: int,
        offset: int,
        provider: str | None = None,
        status: str | None = None,
        query: str = "",
    ) -> tuple[list[SideScanExecutionRecord], int]:
        """Return one page and its count from the same SQLite statement snapshot."""
        if limit < 1 or offset < 0:
            raise ValueError("limit must be at least 1 and offset cannot be negative")
        where, params = self._page_where(tenant_id=tenant_id, provider=provider, status=status, query=query)
        with self._connect() as connection:
            rows = connection.execute(
                f"""WITH filtered AS (
                    SELECT payload_json, updated_at, execution_id
                    FROM side_scan_execution_state WHERE {where}
                ), page AS (
                    SELECT payload_json FROM filtered
                    ORDER BY updated_at DESC, execution_id DESC LIMIT ? OFFSET ?
                )
                SELECT page.payload_json, totals.total
                FROM (SELECT COUNT(*) AS total FROM filtered) AS totals
                LEFT JOIN page ON 1 = 1""",  # nosec B608  # noqa: S608
                (*params, limit, offset),
            ).fetchall()
        total = int(rows[0]["total"]) if rows else 0
        records = [_record_from_json(str(row["payload_json"])) for row in rows if row["payload_json"] is not None]
        return records, total

    def count(
        self,
        *,
        tenant_id: str,
        provider: str | None = None,
        status: str | None = None,
        query: str = "",
    ) -> int:
        where, params = self._page_where(tenant_id=tenant_id, provider=provider, status=status, query=query)
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT COUNT(*) AS total FROM side_scan_execution_state WHERE {where}",  # nosec B608  # noqa: S608
                params,
            ).fetchone()
        return int(row["total"]) if row is not None else 0

    def list_cleanup_due(self, *, tenant_id: str, limit: int = 100) -> list[SideScanExecutionRecord]:
        """Return bounded retry work for incomplete cleanup in one tenant."""
        if limit < 1:
            raise ValueError("limit must be at least 1")
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload_json FROM side_scan_execution_state
                WHERE tenant_id = ? AND cleanup_status IN (?, ?, ?)
                ORDER BY updated_at, execution_id
                LIMIT ?
                """,
                (
                    tenant_id,
                    CleanupStatus.PENDING.value,
                    CleanupStatus.IN_PROGRESS.value,
                    CleanupStatus.PARTIAL.value,
                    limit,
                ),
            ).fetchall()
        return [_record_from_json(str(row["payload_json"])) for row in rows]

    @staticmethod
    def _row_values(record: SideScanExecutionRecord) -> tuple[object, ...]:
        return (
            record.execution_id,
            record.tenant_id,
            record.provider,
            record.account_id,
            record.target_id,
            record.idempotency_key,
            record.state_version,
            record.cleanup_status.value,
            record.updated_at,
            _record_json(record),
        )
