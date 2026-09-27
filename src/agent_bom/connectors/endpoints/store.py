"""Transactional page receipts and encrypted connections on SQLite or Postgres."""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from typing import Any, Iterator

from agent_bom.api.durable_store import postgres_configured, sqlite_path
from agent_bom.device_posture import DeviceSignal

from .models import Connection, SyncState
from .transport import CollectionError

_DDL = (
    "CREATE TABLE IF NOT EXISTS endpoint_agent_bindings (tenant_id TEXT NOT NULL, device_id TEXT NOT NULL, "
    "agent_id TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(tenant_id,device_id,agent_id))",
    "CREATE TABLE IF NOT EXISTS endpoint_sync_events (tenant_id TEXT NOT NULL, connection_id TEXT NOT NULL, "
    "event_id TEXT NOT NULL, recorded_at TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(tenant_id,connection_id,event_id))",
    "CREATE INDEX IF NOT EXISTS idx_endpoint_sync_events ON endpoint_sync_events(tenant_id,connection_id,recorded_at)",
    "CREATE TABLE IF NOT EXISTS endpoint_connections (tenant_id TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, "
    "secret TEXT NOT NULL, owner TEXT NOT NULL DEFAULT '', lease_until DOUBLE PRECISION NOT NULL DEFAULT 0, PRIMARY KEY(tenant_id,id))",
    "CREATE TABLE IF NOT EXISTS endpoint_syncs (tenant_id TEXT NOT NULL, connection_id TEXT NOT NULL, run_id TEXT NOT NULL, "
    "started_at TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(tenant_id,connection_id,run_id))",
    "CREATE INDEX IF NOT EXISTS idx_endpoint_sync_latest ON endpoint_syncs(tenant_id,connection_id,started_at)",
    "CREATE TABLE IF NOT EXISTS endpoint_devices (tenant_id TEXT NOT NULL, connection_id TEXT NOT NULL, run_id TEXT NOT NULL, "
    "device_id TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(tenant_id,connection_id,run_id,device_id))",
    "CREATE INDEX IF NOT EXISTS idx_endpoint_device_lookup ON endpoint_devices(tenant_id,device_id,connection_id,run_id)",
)


class EndpointStore:
    """One atomic page checkpoint; lease fencing prevents stale worker publication."""

    def __init__(self, path: str | None = None, *, pool: Any = None) -> None:
        self.pool = pool
        self.path = path
        if path is None and pool is None:
            if postgres_configured():
                from agent_bom.api.postgres_common import _get_pool

                self.pool = _get_pool()
            else:
                self.path = sqlite_path()
        with self.transaction(None) as conn:
            from agent_bom.api.storage_schema import ensure_postgres_schema_version, ensure_sqlite_schema_version

            if self.pool:
                if not ensure_postgres_schema_version(conn, "endpoint_connectors"):
                    return
            else:
                ensure_sqlite_schema_version(conn, "endpoint_connectors")
            for statement in _DDL:
                conn.execute(statement)
            if self.pool:
                from agent_bom.api.postgres_common import _ensure_tenant_rls

                for table in (
                    "endpoint_connections",
                    "endpoint_syncs",
                    "endpoint_devices",
                    "endpoint_sync_events",
                    "endpoint_agent_bindings",
                ):
                    _ensure_tenant_rls(conn, table, "tenant_id")

    @contextmanager
    def transaction(self, tenant: str | None, *, read_only: bool = False) -> Iterator[Any]:
        if self.pool:
            from agent_bom.api.postgres_common import _tenant_connection, reset_current_tenant, set_current_tenant

            token = set_current_tenant(tenant) if tenant else None
            try:
                with _tenant_connection(self.pool) if tenant else self.pool.connection() as db:
                    yield db
                    db.commit()
            finally:
                if token is not None:
                    reset_current_tenant(token)
        else:
            db = sqlite3.connect(self.path or ":memory:", timeout=10)
            try:
                db.execute("PRAGMA journal_mode=WAL")
                db.execute("BEGIN" if read_only else "BEGIN IMMEDIATE")
                yield db
                db.commit()
            except BaseException:
                db.rollback()
                raise
            finally:
                db.close()

    def execute(self, db: Any, sql: str, args: tuple[Any, ...]) -> Any:
        return db.execute(sql.replace("?", "%s") if self.pool else sql, args)

    def create(self, connection: Connection, encrypted_secret: str) -> None:
        with self.transaction(connection.tenant_id) as db:
            if self.pool:
                self.execute(db, "SELECT pg_advisory_xact_lock(hashtextextended(?,0))", (connection.tenant_id,))
            count = self.execute(db, "SELECT COUNT(*) FROM endpoint_connections WHERE tenant_id=?", (connection.tenant_id,)).fetchone()[0]
            if count >= 100:
                raise CollectionError("endpoint_connection_limit_reached")
            result = self.execute(
                db,
                "INSERT INTO endpoint_connections (tenant_id,id,data,secret) VALUES (?,?,?,?) ON CONFLICT(tenant_id,id) DO NOTHING",
                (connection.tenant_id, connection.id, connection.model_dump_json(), encrypted_secret),
            )
            if result.rowcount != 1:
                raise CollectionError("connection_already_exists_rotate_or_enable_existing")

    def get(self, tenant: str, connection_id: str) -> tuple[Connection, str] | None:
        with self.transaction(tenant, read_only=True) as db:
            row = self.execute(
                db, "SELECT data,secret FROM endpoint_connections WHERE tenant_id=? AND id=?", (tenant, connection_id)
            ).fetchone()
        return (Connection.model_validate_json(row[0]), row[1]) if row else None

    def connections(self, tenant: str) -> list[Connection]:
        with self.transaction(tenant, read_only=True) as db:
            rows = self.execute(db, "SELECT data FROM endpoint_connections WHERE tenant_id=? ORDER BY id LIMIT 100", (tenant,)).fetchall()
        return [Connection.model_validate_json(row[0]) for row in rows]

    def claim(self, tenant: str, connection_id: str, owner: str) -> None:
        with self.transaction(tenant) as db:
            result = self.execute(
                db,
                "UPDATE endpoint_connections SET owner=?,lease_until=? WHERE tenant_id=? AND id=? AND lease_until<?",
                (owner, time.time() + 180, tenant, connection_id, time.time()),
            )
            if result.rowcount != 1:
                raise CollectionError("sync_already_running")

    def release(self, tenant: str, connection_id: str, owner: str) -> None:
        with self.transaction(tenant) as db:
            self.execute(
                db,
                "UPDATE endpoint_connections SET owner='',lease_until=0 WHERE tenant_id=? AND id=? AND owner=?",
                (tenant, connection_id, owner),
            )

    def latest(self, tenant: str, connection_id: str) -> SyncState | None:
        with self.transaction(tenant, read_only=True) as db:
            row = self.execute(
                db,
                "SELECT data FROM endpoint_syncs WHERE tenant_id=? AND connection_id=? ORDER BY started_at DESC LIMIT 1",
                (tenant, connection_id),
            ).fetchone()
        return SyncState.model_validate_json(row[0]) if row else None

    def checkpoint(self, state: SyncState, devices: list[DeviceSignal], owner: str) -> None:
        with self.transaction(state.tenant_id) as db:
            result = self.execute(
                db,
                "UPDATE endpoint_connections SET lease_until=? WHERE tenant_id=? AND id=? AND owner=? AND lease_until>?",
                (time.time() + 180, state.tenant_id, state.connection_id, owner, time.time()),
            )
            if result.rowcount != 1:
                raise CollectionError("sync_lease_lost")
            if any(device.tenant_id != state.tenant_id for device in devices):
                raise CollectionError("device_tenant_mismatch")
            rows = [
                (state.tenant_id, state.connection_id, state.run_id, device.device_id, json.dumps(device.to_public_dict()))
                for device in devices
            ]
            statement = "INSERT INTO endpoint_devices (tenant_id,connection_id,run_id,device_id,data) VALUES (?,?,?,?,?)"
            try:
                with_cursor = db.cursor()
                try:
                    with_cursor.executemany(statement.replace("?", "%s") if self.pool else statement, rows)
                finally:
                    with_cursor.close()
            except Exception as exc:
                if isinstance(exc, sqlite3.IntegrityError) or getattr(exc, "sqlstate", None) == "23505":
                    raise CollectionError("duplicate_device_across_pages") from None
                raise
            self.execute(
                db,
                "INSERT INTO endpoint_syncs (tenant_id,connection_id,run_id,started_at,data) VALUES (?,?,?,?,?) "
                "ON CONFLICT(tenant_id,connection_id,run_id) DO UPDATE SET data=excluded.data",
                (state.tenant_id, state.connection_id, state.run_id, state.started_at, state.model_dump_json()),
            )

            self.execute(
                db,
                "INSERT INTO endpoint_sync_events (tenant_id,connection_id,event_id,recorded_at,data) VALUES (?,?,?,?,?)",
                (state.tenant_id, state.connection_id, str(uuid.uuid4()), state.updated_at, state.model_dump_json()),
            )

    def history(self, tenant: str, connection_id: str) -> list[SyncState]:
        with self.transaction(tenant, read_only=True) as db:
            rows = self.execute(
                db,
                "SELECT data FROM endpoint_sync_events WHERE tenant_id=? AND connection_id=? "
                "ORDER BY recorded_at DESC,event_id DESC LIMIT 20",
                (tenant, connection_id),
            ).fetchall()
        return [SyncState.model_validate_json(row[0]) for row in rows]

    def devices(self, tenant: str, connection_id: str, run_id: str, *, limit: int = 100, offset: int = 0) -> list[DeviceSignal]:
        with self.transaction(tenant, read_only=True) as db:
            rows = self.execute(
                db,
                "SELECT data FROM endpoint_devices WHERE tenant_id=? AND connection_id=? AND run_id=? ORDER BY device_id LIMIT ? OFFSET ?",
                (tenant, connection_id, run_id, min(limit, 500), max(offset, 0)),
            ).fetchall()
        return [DeviceSignal(**json.loads(row[0])) for row in rows]

    def current_device(self, tenant: str, device_id: str) -> DeviceSignal | None:
        with self.transaction(tenant, read_only=True) as db:
            row = self.execute(
                db,
                "SELECT d.data,c.data FROM endpoint_devices d JOIN endpoint_connections c "
                "ON c.tenant_id=d.tenant_id AND c.id=d.connection_id JOIN endpoint_syncs s "
                "ON s.tenant_id=d.tenant_id AND s.connection_id=d.connection_id AND s.run_id=d.run_id "
                "WHERE d.tenant_id=? AND d.device_id=? AND s.started_at=(SELECT MAX(s2.started_at) FROM endpoint_syncs s2 "
                "WHERE s2.tenant_id=d.tenant_id AND s2.connection_id=d.connection_id) ORDER BY s.started_at DESC LIMIT 1",
                (tenant, device_id),
            ).fetchone()
        if not row or not Connection.model_validate_json(row[1]).enabled:
            return None
        return DeviceSignal(**json.loads(row[0]))

    def update(self, connection: Connection, encrypted_secret: str) -> None:
        with self.transaction(connection.tenant_id) as db:
            result = self.execute(
                db,
                "UPDATE endpoint_connections SET data=?,secret=? WHERE tenant_id=? AND id=? AND lease_until<?",
                (connection.model_dump_json(), encrypted_secret, connection.tenant_id, connection.id, time.time()),
            )
            if result.rowcount != 1:
                raise CollectionError("sync_already_running")

    def bind_agent(self, tenant: str, device_id: str, agent_id: str, record: dict) -> None:
        with self.transaction(tenant) as db:
            if self.pool:
                self.execute(db, "SELECT pg_advisory_xact_lock(hashtextextended(?,0))", (tenant + ":" + device_id,))
            existing = self.execute(
                db, "SELECT agent_id FROM endpoint_agent_bindings WHERE tenant_id=? AND device_id=?", (tenant, device_id)
            ).fetchall()
            if len(existing) >= 100 and agent_id not in {row[0] for row in existing}:
                raise CollectionError("device_agent_binding_limit_reached")
            self.execute(
                db,
                "INSERT INTO endpoint_agent_bindings (tenant_id,device_id,agent_id,data) VALUES (?,?,?,?) "
                "ON CONFLICT(tenant_id,device_id,agent_id) DO UPDATE SET data=excluded.data",
                (tenant, device_id, agent_id, json.dumps(record)),
            )

    def bindings_for_devices(self, tenant: str, device_ids: list[str]) -> dict[str, list[dict]]:
        """One bounded query for a page, avoiding one transaction per device."""
        if not device_ids:
            return {}
        if len(device_ids) > 500:
            raise ValueError("Device page exceeds 500 records")
        placeholders = ",".join("?" for _ in device_ids)
        with self.transaction(tenant, read_only=True) as db:
            rows = self.execute(
                db,
                "SELECT device_id,data FROM endpoint_agent_bindings WHERE tenant_id=? "  # nosec B608
                f"AND device_id IN ({placeholders}) ORDER BY device_id,agent_id",  # IDs remain bound parameters.
                (tenant, *device_ids),
            ).fetchall()
        grouped: dict[str, list[dict]] = {}
        for device_id, data in rows:
            grouped.setdefault(device_id, []).append(json.loads(data))
        return grouped

    def agent_bindings(self, tenant: str, device_id: str) -> list[dict]:
        return self.bindings_for_devices(tenant, [device_id]).get(device_id, [])
