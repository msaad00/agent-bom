"""Shared-Postgres tier for the typed gateway activity ledger."""

from __future__ import annotations

from dataclasses import replace

from agent_bom.api.gateway_activity_store import (
    DEFAULT_MAX_EVENTS_PER_TENANT,
    DEFAULT_MAX_TOMBSTONES_PER_TENANT,
    GATEWAY_ACTIVITY_STORAGE_VERSION,
    GATEWAY_ACTIVITY_STORE_SCHEMA,
    MAX_ACTIVITY_PAGE_SIZE,
    GatewayActivityAppendResult,
    GatewayActivityConflictError,
    GatewayActivityCursorError,
    GatewayActivityCursorExpiredError,
    GatewayActivityPage,
    GatewayActivityRecord,
    GatewayActivityWindowSummary,
    _decode_cursor,
    _encode_cursor,
    _page,
    _prepare_batch,
    _record_from_json,
    _validate_store_config,
    _window_summary,
)
from agent_bom.api.postgres_common import Connection, ConnectionPool, _ensure_tenant_rls, _get_pool, _tenant_connection
from agent_bom.api.storage_schema import ensure_postgres_schema_version
from agent_bom.storage.base import BackendKind


def bootstrap_postgres_gateway_activity_schema(conn: Connection) -> None:
    """Create ledger tables for an explicitly non-authoritative dev/test pool."""

    for table_schema in GATEWAY_ACTIVITY_STORE_SCHEMA.tables:
        ddl = table_schema.ddl_for(BackendKind.POSTGRES)
        if ddl:
            conn.execute(ddl)
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_gateway_activity_events_tenant_ordinal "
        "ON gateway_activity_events(tenant_id, ingest_ordinal)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_gateway_activity_events_tenant_event_time "
        "ON gateway_activity_events("
        "tenant_id, event_timestamp, "
        "((data::jsonb) ->> 'event_type'), ((data::jsonb) ->> 'reason_code')"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_gateway_activity_tombstones_tenant_ordinal "
        "ON gateway_activity_tombstones(tenant_id, pruned_ordinal)"
    )
    for table_name in (
        "gateway_activity_events",
        "gateway_activity_sequences",
        "gateway_activity_tombstones",
    ):
        _ensure_tenant_rls(conn, table_name, "tenant_id")


class PostgresGatewayActivityStore:
    """Append-only, conflict-aware gateway activity shared by all replicas."""

    def __init__(
        self,
        pool: ConnectionPool | None = None,
        *,
        max_events_per_tenant: int = DEFAULT_MAX_EVENTS_PER_TENANT,
        max_tombstones_per_tenant: int = DEFAULT_MAX_TOMBSTONES_PER_TENANT,
    ) -> None:
        _validate_store_config(max_events_per_tenant, max_tombstones_per_tenant)
        self._pool = pool or _get_pool()
        self.max_events_per_tenant = max_events_per_tenant
        self.max_tombstones_per_tenant = max_tombstones_per_tenant
        self.init_schema()

    def init_schema(self) -> None:
        """Bootstrap isolated development pools or validate Alembic authority."""

        with self._pool.connection() as conn:
            if not ensure_postgres_schema_version(conn, "runtime_events", version=GATEWAY_ACTIVITY_STORAGE_VERSION):
                return
            bootstrap_postgres_gateway_activity_schema(conn)
            conn.commit()

    @staticmethod
    def encode_cursor(tenant_id: str, ordinal: int) -> str:
        return _encode_cursor(tenant_id, ordinal)

    def append_batch(self, records: list[GatewayActivityRecord]) -> GatewayActivityAppendResult:
        tenant_id, prepared = _prepare_batch(records)
        if not prepared:
            return GatewayActivityAppendResult()
        with _tenant_connection(self._pool) as conn:
            try:
                conn.execute(
                    "INSERT INTO gateway_activity_sequences(tenant_id, next_ordinal) VALUES (%s, 1) "
                    "ON CONFLICT(tenant_id) DO NOTHING",
                    (tenant_id,),
                )
                # This per-tenant row is the serialization point. It is locked
                # before dedupe reads, so a concurrent commit is visible before
                # this transaction decides whether an event is new.
                sequence_row = conn.execute(
                    "SELECT next_ordinal FROM gateway_activity_sequences "
                    "WHERE tenant_id = %s FOR UPDATE",
                    (tenant_id,),
                ).fetchone()
                if sequence_row is None:
                    raise RuntimeError("Gateway activity sequence was not initialized")
                next_ordinal = int(sequence_row[0])

                event_ids = [record.event_id for record in prepared]
                placeholders = ",".join("%s" for _ in event_ids)
                active = dict(
                    conn.execute(
                        f"SELECT event_id, event_digest FROM gateway_activity_events "  # nosec B608
                        f"WHERE tenant_id = %s AND event_id IN ({placeholders})",
                        (tenant_id, *event_ids),
                    ).fetchall()
                )
                tombstones = dict(
                    conn.execute(
                        f"SELECT event_id, event_digest FROM gateway_activity_tombstones "  # nosec B608
                        f"WHERE tenant_id = %s AND event_id IN ({placeholders})",
                        (tenant_id, *event_ids),
                    ).fetchall()
                )

                duplicates: list[str] = []
                new_records: list[GatewayActivityRecord] = []
                for record in prepared:
                    digest = active.get(record.event_id) or tombstones.get(record.event_id)
                    if digest is None:
                        new_records.append(record)
                    elif digest == record.event_digest:
                        duplicates.append(record.event_id)
                    else:
                        raise GatewayActivityConflictError(f"gateway activity event_id conflict: {record.event_id}")

                stored_records = [replace(record, ingest_ordinal=next_ordinal + index) for index, record in enumerate(new_records)]
                for record in stored_records:
                    conn.execute(
                        """
                        INSERT INTO gateway_activity_events
                            (tenant_id,event_id,ingest_ordinal,event_timestamp,ingested_at,event_digest,data)
                        VALUES (%s,%s,%s,%s,%s,%s,%s)
                        """,
                        (
                            record.tenant_id,
                            record.event_id,
                            record.ingest_ordinal,
                            record.event_timestamp,
                            record.ingested_at,
                            record.event_digest,
                            record.to_json(),
                        ),
                    )
                conn.execute(
                    "UPDATE gateway_activity_sequences SET next_ordinal = %s WHERE tenant_id = %s",
                    (next_ordinal + len(stored_records), tenant_id),
                )

                if self.max_events_per_tenant > 0:
                    stale = conn.execute(
                        """
                        SELECT event_id,event_digest,ingest_ordinal FROM gateway_activity_events
                        WHERE tenant_id = %s
                        ORDER BY ingest_ordinal DESC
                        OFFSET %s
                        """,
                        (tenant_id, self.max_events_per_tenant),
                    ).fetchall()
                    if stale:
                        for event_id, event_digest, ingest_ordinal in stale:
                            conn.execute(
                                """
                                INSERT INTO gateway_activity_tombstones
                                    (tenant_id,event_id,event_digest,pruned_ordinal)
                                VALUES (%s,%s,%s,%s)
                                ON CONFLICT(tenant_id,event_id) DO UPDATE SET
                                    event_digest=EXCLUDED.event_digest,
                                    pruned_ordinal=EXCLUDED.pruned_ordinal
                                """,
                                (tenant_id, event_id, event_digest, ingest_ordinal),
                            )
                            conn.execute(
                                "DELETE FROM gateway_activity_events WHERE tenant_id = %s AND event_id = %s",
                                (tenant_id, event_id),
                            )
                        stale_tombstones = conn.execute(
                            """
                            SELECT event_id FROM gateway_activity_tombstones
                            WHERE tenant_id = %s
                            ORDER BY pruned_ordinal DESC
                            OFFSET %s
                            """,
                            (tenant_id, self.max_tombstones_per_tenant),
                        ).fetchall()
                        for (event_id,) in stale_tombstones:
                            conn.execute(
                                "DELETE FROM gateway_activity_tombstones WHERE tenant_id = %s AND event_id = %s",
                                (tenant_id, event_id),
                            )
                conn.commit()
            except Exception:
                conn.rollback()
                raise

        return GatewayActivityAppendResult(
            tuple(record.event_id for record in stored_records),
            tuple(duplicates),
        )

    def list_activity(self, tenant_id: str, *, cursor: str | None = None, limit: int = 100) -> GatewayActivityPage:
        bounded_limit = max(1, min(limit, MAX_ACTIVITY_PAGE_SIZE))
        requested_after = _decode_cursor(cursor, tenant_id) if cursor else None
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                """
                WITH bounds AS (
                    SELECT
                        COALESCE((SELECT next_ordinal - 1 FROM gateway_activity_sequences WHERE tenant_id = %s), 0) AS latest,
                        COALESCE(
                            (SELECT MIN(ingest_ordinal) FROM gateway_activity_events WHERE tenant_id = %s),
                            (SELECT next_ordinal FROM gateway_activity_sequences WHERE tenant_id = %s),
                            1
                        ) AS floor
                ), page AS (
                    SELECT data, ingest_ordinal
                    FROM gateway_activity_events, bounds
                    WHERE tenant_id = %s
                      AND ingest_ordinal > COALESCE(%s, bounds.floor - 1)
                    ORDER BY ingest_ordinal ASC
                    LIMIT %s
                )
                SELECT bounds.latest, bounds.floor, page.data
                FROM bounds LEFT JOIN page ON TRUE
                ORDER BY page.ingest_ordinal ASC NULLS LAST
                """,
                (tenant_id, tenant_id, tenant_id, tenant_id, requested_after, bounded_limit + 1),
            ).fetchall()
        latest = int(rows[0][0])
        floor = int(rows[0][1])
        after = requested_after if requested_after is not None else floor - 1
        if cursor:
            if after > latest:
                raise GatewayActivityCursorError("Invalid gateway activity cursor")
            if after < floor - 1:
                raise GatewayActivityCursorExpiredError(floor)
        records = [_record_from_json(row[2]) for row in rows if row[2] is not None]
        return _page(
            tenant_id,
            records,
            cursor=cursor,
            limit=bounded_limit,
            floor=floor,
            latest=latest,
            max_events=self.max_events_per_tenant,
            max_tombstones=self.max_tombstones_per_tenant,
        )

    def summarize_window(self, tenant_id: str, *, start: str, end: str) -> GatewayActivityWindowSummary:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                """
                WITH bounds AS (
                    SELECT
                        COALESCE(
                            (SELECT next_ordinal - 1 FROM gateway_activity_sequences WHERE tenant_id = %s),
                            0
                        ) AS latest,
                        COALESCE(
                            (SELECT MIN(ingest_ordinal) FROM gateway_activity_events WHERE tenant_id = %s),
                            (SELECT next_ordinal FROM gateway_activity_sequences WHERE tenant_id = %s),
                            1
                        ) AS floor
                ), grouped AS (
                    SELECT
                        ((data::jsonb) ->> 'event_type') AS event_type,
                        ((data::jsonb) ->> 'reason_code') AS reason_code,
                        COUNT(*) AS event_count
                    FROM gateway_activity_events
                    WHERE tenant_id = %s AND event_timestamp >= %s AND event_timestamp <= %s
                    GROUP BY 1, 2
                )
                SELECT bounds.latest, bounds.floor, grouped.event_type, grouped.reason_code, grouped.event_count
                FROM bounds LEFT JOIN grouped ON TRUE
                """,
                (tenant_id, tenant_id, tenant_id, tenant_id, start, end),
            ).fetchall()
        latest, floor = int(rows[0][0]), int(rows[0][1])
        return _window_summary(
            tenant_id,
            start=start,
            end=end,
            event_rows=[
                (str(event_type), str(reason), int(count))
                for _, _, event_type, reason, count in rows
                if event_type is not None and count is not None
            ],
            floor=floor,
            latest=latest,
        )


__all__ = ["PostgresGatewayActivityStore", "bootstrap_postgres_gateway_activity_schema"]
