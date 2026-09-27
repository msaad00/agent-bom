"""Atomic tenant-scoped lifecycle registry and immutable BOM history.

No update/delete API exists for BOMs or run references. Retirement is a terminal
metadata transition; it preserves all prior references. This protects against
API mutation, not a database administrator. Independent audit protection is a
separate boundary. PostgreSQL and SQLite use the same transaction semantics.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from agent_bom.evidence.agent_bom import AgentBomDocument, validate_agent_bom_json
from agent_bom.evidence.lifecycle import (
    LifecyclePage,
    LifecycleRecord,
    RecordKind,
    RegisterDeployment,
    RegisterInstance,
    RegisterRun,
    composition_digest,
)


class LifecycleConflictError(ValueError):
    """A reference is missing, inactive, mismatched, or already bound."""


_DDL = (
    """CREATE TABLE IF NOT EXISTS agent_lifecycle_records (
        tenant_id TEXT NOT NULL, kind TEXT NOT NULL, record_id TEXT NOT NULL,
        agent_id TEXT NOT NULL, recorded_at TEXT NOT NULL, data TEXT NOT NULL,
        PRIMARY KEY (tenant_id, kind, record_id))""",
    """CREATE INDEX IF NOT EXISTS idx_agent_lifecycle_history
        ON agent_lifecycle_records (tenant_id, kind, agent_id, recorded_at, record_id)""",
    """CREATE TABLE IF NOT EXISTS agent_bom_snapshots (
        tenant_id TEXT NOT NULL, snapshot_id TEXT NOT NULL, document TEXT NOT NULL,
        PRIMARY KEY (tenant_id, snapshot_id))""",
)


class _SQL:
    def __init__(self, connection: Any, postgres: bool = False) -> None:
        self.connection = connection
        self.postgres = postgres

    def execute(self, sql: str, args: tuple[Any, ...] = ()) -> Any:
        # SQL comes only from this module's static statements, never input.
        return self.connection.execute(sql.replace("?", "%s") if self.postgres else sql, args)


class LifecycleStore:
    @contextmanager
    def transaction(self, tenant_id: str, *, write: bool = False) -> Iterator[_SQL]:
        raise NotImplementedError
        yield  # pragma: no cover

    @staticmethod
    def _get(db: _SQL, tenant: str, kind: RecordKind, record_id: str) -> LifecycleRecord | None:
        row = db.execute(
            "SELECT data FROM agent_lifecycle_records WHERE tenant_id=? AND kind=? AND record_id=?", (tenant, kind, record_id)
        ).fetchone()
        return LifecycleRecord.model_validate_json(row[0]) if row else None

    def _require(self, db: _SQL, tenant: str, kind: RecordKind, record_id: str, *, active: bool = False) -> LifecycleRecord:
        record = self._get(db, tenant, kind, record_id)
        if record is None or (active and not record.active(datetime.now(timezone.utc))):
            raise LifecycleConflictError("Required lifecycle reference is unavailable")
        return record

    def _insert(self, db: _SQL, record: LifecycleRecord) -> LifecycleRecord:
        previous = self._get(db, record.tenant_id, record.kind, record.record_id)
        if previous:
            ignore = {"recorded_at", "recorded_by", "retired_at", "retired_by"}
            if previous.model_dump(exclude=ignore) != record.model_dump(exclude=ignore):
                raise LifecycleConflictError("Lifecycle identifier is already bound")
            return previous
        db.execute(
            "INSERT INTO agent_lifecycle_records (tenant_id,kind,record_id,agent_id,recorded_at,data) VALUES (?,?,?,?,?,?)",
            (record.tenant_id, record.kind, record.record_id, record.agent_id, record.recorded_at.isoformat(), record.model_dump_json()),
        )
        return record

    def capture(self, tenant: str, document: AgentBomDocument, actor: str) -> LifecycleRecord:
        # Validate even model_copy/model_construct callers and enforce the byte bound.
        document = validate_agent_bom_json(document.model_dump_json())
        if document.content.tenant_id != tenant:
            raise LifecycleConflictError("Snapshot tenant does not match")
        now = datetime.now(timezone.utc)
        agent = document.content.subject.agent_id
        snapshot = LifecycleRecord(
            kind="snapshot",
            record_id=document.snapshot_id,
            tenant_id=tenant,
            agent_id=agent,
            recorded_at=now,
            recorded_by=actor,
            snapshot_id=document.snapshot_id,
            composition_digest=composition_digest(document),
            observed_at=document.generated_at,
        )
        with self.transaction(tenant, write=True) as db:
            self._insert(
                db, LifecycleRecord(kind="agent", record_id=agent, tenant_id=tenant, agent_id=agent, recorded_at=now, recorded_by=actor)
            )
            existing = db.execute(
                "SELECT document FROM agent_bom_snapshots WHERE tenant_id=? AND snapshot_id=?", (tenant, document.snapshot_id)
            ).fetchone()
            if existing:
                if validate_agent_bom_json(existing[0]) != document:
                    raise LifecycleConflictError("Snapshot is immutable")
            else:
                db.execute(
                    "INSERT INTO agent_bom_snapshots (tenant_id,snapshot_id,document) VALUES (?,?,?)",
                    (tenant, document.snapshot_id, document.model_dump_json()),
                )
            return self._insert(db, snapshot)

    def deployment(self, tenant: str, body: RegisterDeployment, actor: str) -> LifecycleRecord:
        with self.transaction(tenant, write=True) as db:
            self._require(db, tenant, "agent", body.agent_id, active=True)
            snapshot = self._require(db, tenant, "snapshot", body.snapshot_id)
            if snapshot.agent_id != body.agent_id:
                raise LifecycleConflictError("Snapshot belongs to another agent")
            return self._insert(
                db,
                LifecycleRecord(
                    kind="deployment",
                    record_id=body.deployment_id,
                    tenant_id=tenant,
                    agent_id=body.agent_id,
                    parent_id=body.agent_id,
                    snapshot_id=body.snapshot_id,
                    version=body.version,
                    recorded_at=datetime.now(timezone.utc),
                    recorded_by=actor,
                ),
            )

    def instance(self, tenant: str, body: RegisterInstance, actor: str, *, identity_agent_id: str) -> LifecycleRecord:
        with self.transaction(tenant, write=True) as db:
            deployment = self._require(db, tenant, "deployment", body.deployment_id, active=True)
            self._require(db, tenant, "agent", deployment.agent_id, active=True)
            if identity_agent_id != deployment.agent_id:
                raise LifecycleConflictError("Identity does not match the registered agent")
            if body.expires_at is not None and body.expires_at <= datetime.now(timezone.utc):
                raise LifecycleConflictError("Instance expiry must be in the future")
            return self._insert(
                db,
                LifecycleRecord(
                    kind="instance",
                    record_id=body.instance_id,
                    tenant_id=tenant,
                    agent_id=deployment.agent_id,
                    parent_id=body.deployment_id,
                    snapshot_id=deployment.snapshot_id,
                    identity_id=body.identity_id,
                    expires_at=body.expires_at,
                    recorded_at=datetime.now(timezone.utc),
                    recorded_by=actor,
                ),
            )

    def run(self, tenant: str, body: RegisterRun, actor: str) -> LifecycleRecord:
        with self.transaction(tenant, write=True) as db:
            instance = self._require(db, tenant, "instance", body.instance_id, active=True)
            self._require(db, tenant, "agent", instance.agent_id, active=True)
            self._require(db, tenant, "deployment", instance.parent_id or "", active=True)
            return self._insert(
                db,
                LifecycleRecord(
                    kind="run",
                    record_id=body.run_id,
                    tenant_id=tenant,
                    agent_id=instance.agent_id,
                    parent_id=body.instance_id,
                    snapshot_id=instance.snapshot_id,
                    identity_id=instance.identity_id,
                    conversation_id=body.conversation_id,
                    recorded_at=datetime.now(timezone.utc),
                    recorded_by=actor,
                ),
            )

    def retire(self, tenant: str, kind: RecordKind, record_id: str, actor: str) -> LifecycleRecord:
        if kind not in ("agent", "deployment", "instance"):
            raise LifecycleConflictError("Only registered agents, deployments and instances can retire")
        with self.transaction(tenant, write=True) as db:
            record = self._require(db, tenant, kind, record_id)
            if record.retired_at is None:
                record = record.model_copy(update={"retired_at": datetime.now(timezone.utc), "retired_by": actor})
                db.execute(
                    "UPDATE agent_lifecycle_records SET data=? WHERE tenant_id=? AND kind=? AND record_id=?",
                    (record.model_dump_json(), tenant, kind, record_id),
                )
            return record

    def get(self, tenant: str, kind: RecordKind, record_id: str) -> LifecycleRecord | None:
        with self.transaction(tenant) as db:
            return self._get(db, tenant, kind, record_id)

    def snapshot(self, tenant: str, snapshot_id: str) -> AgentBomDocument | None:
        with self.transaction(tenant) as db:
            row = db.execute(
                "SELECT document FROM agent_bom_snapshots WHERE tenant_id=? AND snapshot_id=?", (tenant, snapshot_id)
            ).fetchone()
            return validate_agent_bom_json(row[0]) if row else None

    def history(self, tenant: str, kind: RecordKind, agent_id: str, *, limit: int = 50, offset: int = 0) -> LifecyclePage:
        limit, offset = max(1, min(limit, 200)), max(0, min(offset, 10000))
        with self.transaction(tenant) as db:
            rows = db.execute(
                """SELECT data FROM agent_lifecycle_records WHERE tenant_id=? AND kind=? AND agent_id=?
                   ORDER BY recorded_at,record_id LIMIT ? OFFSET ?""",
                (tenant, kind, agent_id, limit + 1, offset),
            ).fetchall()
        return LifecyclePage(
            items=[LifecycleRecord.model_validate_json(row[0]) for row in rows[:limit]],
            next_offset=offset + limit if len(rows) > limit and offset + limit <= 10000 else None,
            history_limit_reached=len(rows) > limit and offset + limit > 10000,
        )


class SQLiteLifecycleStore(LifecycleStore):
    def __init__(self, path: str) -> None:
        import sqlite3

        from agent_bom.api.storage_schema import ensure_sqlite_schema_version

        self._connection = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=30)
        self._lock = threading.RLock()
        self._connection.execute("PRAGMA journal_mode=WAL")
        ensure_sqlite_schema_version(self._connection, "agent_lifecycle")
        for sql in _DDL:
            self._connection.execute(sql)

    @contextmanager
    def transaction(self, tenant_id: str, *, write: bool = False) -> Iterator[_SQL]:
        if not tenant_id.strip():
            raise LifecycleConflictError("Tenant is required")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            try:
                yield _SQL(self._connection)
                self._connection.commit()
            except BaseException:
                self._connection.rollback()
                raise

    def close(self) -> None:
        self._connection.close()


class PostgresLifecycleStore(LifecycleStore):
    def __init__(self, pool: Any = None) -> None:
        from agent_bom.api.postgres_common import _ensure_tenant_rls, _get_pool
        from agent_bom.api.storage_schema import ensure_postgres_schema_version

        self._pool = pool or _get_pool()
        with self._pool.connection() as conn:
            if ensure_postgres_schema_version(conn, "agent_lifecycle"):
                for sql in _DDL:
                    conn.execute(sql)
                _ensure_tenant_rls(conn, "agent_lifecycle_records", "tenant_id")
                _ensure_tenant_rls(conn, "agent_bom_snapshots", "tenant_id")
                conn.commit()

    @contextmanager
    def transaction(self, tenant_id: str, *, write: bool = False) -> Iterator[_SQL]:
        from agent_bom.api.postgres_common import _tenant_connection

        if not tenant_id.strip():
            raise LifecycleConflictError("Tenant is required")
        with _tenant_connection(self._pool) as conn:
            if write:
                # Serializes reference checks, retirement and creation per tenant,
                # including initially absent rows. No maintenance/RLS bypass.
                conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", ("agent-lifecycle:" + tenant_id,))
            yield _SQL(conn, postgres=True)
            conn.commit()


_store: LifecycleStore | None = None
_store_lock = threading.Lock()


def get_lifecycle_store() -> LifecycleStore:
    global _store
    with _store_lock:
        if _store is None:
            from agent_bom.api.durable_store import select_backend, sqlite_path

            backend = select_backend()
            _store = (
                PostgresLifecycleStore()
                if backend == "postgres"
                else SQLiteLifecycleStore(":memory:" if backend == "memory" else sqlite_path())
            )
        return _store
