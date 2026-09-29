"""Shared multi-replica Postgres backend for side-scan lifecycle state."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

from agent_bom.api import postgres_common, storage_schema

from .side_scan_lifecycle_models import (
    SideScanExecutionRecord,
    SideScanStateConflictError,
    _record_from_json,
    _record_json,
)
from .side_scan_lifecycle_status import CleanupStatus


class PostgresSideScanStateStore:
    """Shared multi-replica lifecycle store with tenant RLS and CAS updates."""

    table = "side_scan_execution_state"

    def __init__(self, *, pool: Any | None = None) -> None:
        if pool is None:
            pool = postgres_common._get_pool()
        self._pool = pool
        self._initialize()

    @contextmanager
    def _tenant_connection(self, tenant_id: str) -> Iterator[Any]:
        token = postgres_common.set_current_tenant(tenant_id)
        try:
            with postgres_common._tenant_connection(self._pool) as connection:
                yield connection
        finally:
            postgres_common.reset_current_tenant(token)

    def _initialize(self) -> None:
        with self._pool.connection() as connection:
            if storage_schema.postgres_deployment_configured():
                storage_schema.ensure_postgres_schema_version(connection, "side_scan_lifecycle")
                return
            connection.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", ("agent_bom.schema.side_scan_execution_state",))
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
                    updated_at TIMESTAMPTZ NOT NULL,
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
            postgres_common._ensure_tenant_rls(connection, self.table, "tenant_id")
            connection.commit()

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

    def create_or_get(self, record: SideScanExecutionRecord) -> SideScanExecutionRecord:
        with self._tenant_connection(record.tenant_id) as connection:
            connection.execute(
                """
                INSERT INTO side_scan_execution_state
                    (execution_id, tenant_id, provider, account_id, target_id, idempotency_key,
                     state_version, cleanup_status, updated_at, payload_json)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, provider, account_id, target_id, idempotency_key) DO NOTHING
                """,
                self._row_values(record),
            )
            row = connection.execute(
                """
                SELECT payload_json FROM side_scan_execution_state
                WHERE tenant_id = %s AND provider = %s AND account_id = %s
                  AND target_id = %s AND idempotency_key = %s
                """,
                (record.tenant_id, record.provider, record.account_id, record.target_id, record.idempotency_key),
            ).fetchone()
            connection.commit()
        if row is None:
            raise RuntimeError("side-scan lifecycle record could not be persisted")
        return _record_from_json(str(row[0]))

    def get(self, *, tenant_id: str, execution_id: str) -> SideScanExecutionRecord | None:
        with self._tenant_connection(tenant_id) as connection:
            row = connection.execute(
                "SELECT payload_json FROM side_scan_execution_state WHERE tenant_id = %s AND execution_id = %s",
                (tenant_id, execution_id),
            ).fetchone()
        return _record_from_json(str(row[0])) if row is not None else None

    def save(self, record: SideScanExecutionRecord, *, expected_version: int) -> None:
        if record.state_version != expected_version + 1:
            raise SideScanStateConflictError("side-scan state version must advance by exactly one")
        with self._tenant_connection(record.tenant_id) as connection:
            cursor = connection.execute(
                """
                UPDATE side_scan_execution_state
                SET state_version = %s, cleanup_status = %s, updated_at = %s, payload_json = %s
                WHERE tenant_id = %s AND execution_id = %s AND state_version = %s
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
                connection.rollback()
                raise SideScanStateConflictError("side-scan execution was updated by another worker")
            connection.commit()

    def list_recent(self, *, tenant_id: str, limit: int = 50) -> list[SideScanExecutionRecord]:
        return self.list_page(tenant_id=tenant_id, limit=limit, offset=0)

    @staticmethod
    def _page_where(*, tenant_id: str, provider: str | None, status: str | None, query: str) -> tuple[str, list[object]]:
        clauses = ["tenant_id = %s"]
        params: list[object] = [tenant_id]
        if provider is not None:
            clauses.append("provider = %s")
            params.append(provider)
        if status is not None:
            clauses.append("payload_json::jsonb ->> 'status' = %s")
            params.append(status)
        if query.strip():
            pattern = f"%{query.strip()}%"
            clauses.append("(target_id ILIKE %s OR account_id ILIKE %s OR execution_id ILIKE %s)")
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
        """Return one page and its count from the same Postgres statement snapshot."""
        if limit < 1 or offset < 0:
            raise ValueError("limit must be at least 1 and offset cannot be negative")
        where, params = self._page_where(tenant_id=tenant_id, provider=provider, status=status, query=query)
        with self._tenant_connection(tenant_id) as connection:
            rows = connection.execute(
                f"""WITH filtered AS (
                    SELECT payload_json, updated_at, execution_id
                    FROM side_scan_execution_state WHERE {where}
                ), page AS (
                    SELECT payload_json FROM filtered
                    ORDER BY updated_at DESC, execution_id DESC LIMIT %s OFFSET %s
                )
                SELECT page.payload_json, totals.total
                FROM (SELECT COUNT(*) AS total FROM filtered) AS totals
                LEFT JOIN page ON TRUE""",  # nosec B608  # noqa: S608
                (*params, limit, offset),
            ).fetchall()
        total = int(rows[0][1]) if rows else 0
        records = [_record_from_json(str(row[0])) for row in rows if row[0] is not None]
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
        with self._tenant_connection(tenant_id) as connection:
            row = connection.execute(
                f"SELECT COUNT(*) FROM side_scan_execution_state WHERE {where}",  # nosec B608  # noqa: S608
                params,
            ).fetchone()
        return int(row[0]) if row is not None else 0

    def list_cleanup_due(self, *, tenant_id: str, limit: int = 100) -> list[SideScanExecutionRecord]:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        with self._tenant_connection(tenant_id) as connection:
            rows = connection.execute(
                """
                SELECT payload_json FROM side_scan_execution_state
                WHERE tenant_id = %s AND cleanup_status IN (%s, %s, %s)
                ORDER BY updated_at, execution_id LIMIT %s
                """,
                (
                    tenant_id,
                    CleanupStatus.PENDING.value,
                    CleanupStatus.IN_PROGRESS.value,
                    CleanupStatus.PARTIAL.value,
                    limit,
                ),
            ).fetchall()
        return [_record_from_json(str(row[0])) for row in rows]
