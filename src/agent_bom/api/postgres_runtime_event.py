"""Postgres-backed runtime session/observation store for horizontal scaling.

Mirrors :class:`agent_bom.api.runtime_event_store.SQLiteRuntimeEventStore` but
stores runtime observations and their rolled-up session records in shared
Postgres with tenant RLS, so the runtime session/event timeline stays
consistent across every control-plane replica instead of diverging on
node-local SQLite (or vanishing on an in-memory restart). This is the
multi-replica tier of the durable-by-default runtime store.

Redaction is preserved: only metadata-safe observation records (raw prompt /
argument / tool-output fields already stripped upstream) are persisted, exactly
as in the SQLite tier.
"""

from __future__ import annotations

import json

from agent_bom.analytics_retention import prune_runtime_observations_for_tenant
from agent_bom.api.postgres_common import ConnectionPool, _ensure_tenant_rls, _get_pool, _tenant_connection
from agent_bom.api.runtime_event_store import (
    _BATCH_LOOKUP_CHUNK,
    RuntimeObservationRecord,
    RuntimeSessionRecord,
    _dedupe_observation_records,
    _merge_sessions_for_batch,
    _observation_from_json,
    _session_from_json,
)
from agent_bom.api.storage_schema import ensure_postgres_schema_version


class PostgresRuntimeEventStore:
    """Shared runtime session + observation store backed by Postgres with tenant RLS."""

    def __init__(self, pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def init_schema(self) -> None:
        """Idempotently (re)create this store's tables. Satisfies the shared
        :class:`agent_bom.storage.base.TenantScopedStore` contract."""
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            ensure_postgres_schema_version(conn, "runtime_events")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS runtime_observations (
                    tenant_id      TEXT NOT NULL,
                    observation_id TEXT NOT NULL,
                    session_id     TEXT NOT NULL,
                    observed_at    TEXT NOT NULL,
                    data           TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, observation_id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS runtime_sessions (
                    tenant_id  TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    last_seen  TEXT NOT NULL,
                    data       TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, session_id)
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_runtime_observations_tenant_session_time "
                "ON runtime_observations(tenant_id, session_id, observed_at DESC)"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_runtime_sessions_tenant_last_seen ON runtime_sessions(tenant_id, last_seen DESC)")
            _ensure_tenant_rls(conn, "runtime_observations", "tenant_id")
            _ensure_tenant_rls(conn, "runtime_sessions", "tenant_id")
            conn.commit()

    def put_observation(self, record: RuntimeObservationRecord) -> None:
        self.put_observations_batch([record])

    def put_observations_batch(self, records: list[RuntimeObservationRecord]) -> int:
        unique_records = _dedupe_observation_records(records)
        if not unique_records:
            return 0
        tenant_id = unique_records[0].tenant_id
        with _tenant_connection(self._pool) as conn:
            existing_ids: set[str] = set()
            observation_ids = [record.observation_id for record in unique_records]
            for offset in range(0, len(observation_ids), _BATCH_LOOKUP_CHUNK):
                chunk = observation_ids[offset : offset + _BATCH_LOOKUP_CHUNK]
                placeholders = ",".join("%s" for _ in chunk)
                rows = conn.execute(
                    f"SELECT observation_id FROM runtime_observations WHERE tenant_id = %s AND observation_id IN ({placeholders})",  # nosec B608
                    (tenant_id, *chunk),
                ).fetchall()
                existing_ids.update(row[0] for row in rows)
            new_records = [record for record in unique_records if record.observation_id not in existing_ids]
            if not new_records:
                return 0
            session_ids = sorted({record.session_id for record in new_records})
            existing_sessions: dict[str, RuntimeSessionRecord] = {}
            for offset in range(0, len(session_ids), _BATCH_LOOKUP_CHUNK):
                chunk = session_ids[offset : offset + _BATCH_LOOKUP_CHUNK]
                placeholders = ",".join("%s" for _ in chunk)
                rows = conn.execute(
                    f"SELECT session_id, data FROM runtime_sessions WHERE tenant_id = %s AND session_id IN ({placeholders})",  # nosec B608
                    (tenant_id, *chunk),
                ).fetchall()
                for session_id, data in rows:
                    existing_sessions[session_id] = _session_from_json(data)
            merged_sessions = _merge_sessions_for_batch(existing_sessions, new_records)
            observation_sql = """
                INSERT INTO runtime_observations (tenant_id, observation_id, session_id, observed_at, data)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, observation_id) DO NOTHING
            """
            for record in new_records:
                conn.execute(
                    observation_sql,
                    (
                        record.tenant_id,
                        record.observation_id,
                        record.session_id,
                        record.observed_at,
                        json.dumps(record.to_dict(), sort_keys=True),
                    ),
                )
            session_sql = """
                INSERT INTO runtime_sessions (tenant_id, session_id, last_seen, data)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (tenant_id, session_id) DO UPDATE SET
                    last_seen = EXCLUDED.last_seen,
                    data = EXCLUDED.data
            """
            for session in merged_sessions.values():
                conn.execute(
                    session_sql,
                    (
                        session.tenant_id,
                        session.session_id,
                        session.last_seen,
                        json.dumps(session.to_dict(), sort_keys=True),
                    ),
                )
            prune_runtime_observations_for_tenant(conn, tenant_id, placeholder="%s")
            conn.commit()
            return len(new_records)

    def list_sessions(self, tenant_id: str, *, limit: int = 100, offset: int = 0) -> list[RuntimeSessionRecord]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT data FROM runtime_sessions WHERE tenant_id = %s ORDER BY last_seen DESC LIMIT %s OFFSET %s",
                (tenant_id, limit, offset),
            ).fetchall()
        return [_session_from_json(row[0]) for row in rows]

    def get_session(self, tenant_id: str, session_id: str) -> RuntimeSessionRecord | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT data FROM runtime_sessions WHERE tenant_id = %s AND session_id = %s",
                (tenant_id, session_id),
            ).fetchone()
        return _session_from_json(row[0]) if row else None

    def list_observations(
        self,
        tenant_id: str,
        *,
        session_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[RuntimeObservationRecord]:
        with _tenant_connection(self._pool) as conn:
            if session_id:
                rows = conn.execute(
                    "SELECT data FROM runtime_observations WHERE tenant_id = %s AND session_id = %s "
                    "ORDER BY observed_at DESC LIMIT %s OFFSET %s",
                    (tenant_id, session_id, limit, offset),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT data FROM runtime_observations WHERE tenant_id = %s ORDER BY observed_at DESC LIMIT %s OFFSET %s",
                    (tenant_id, limit, offset),
                ).fetchall()
        return [_observation_from_json(row[0]) for row in rows]
