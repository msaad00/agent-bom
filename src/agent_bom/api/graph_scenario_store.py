"""Tenant-scoped persistence for proposed graph scenarios.

Scenario rows are deliberately separate from ``graph_nodes`` and ``graph_edges``.
They describe proposed changes to one immutable observed snapshot; comparison
code may read that snapshot, but no scenario operation is ever persisted into
the observed graph tables.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Mapping
from typing import Any, Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version


class GraphScenarioConflictError(RuntimeError):
    """Raised when optimistic scenario revision control rejects a write."""


class GraphScenarioStore(Protocol):
    """Persistence contract for tenant-owned graph scenarios."""

    def create(self, tenant_id: str, scenario: Mapping[str, Any]) -> dict[str, Any]: ...
    def get(self, tenant_id: str, scenario_id: str) -> dict[str, Any] | None: ...
    def list(self, tenant_id: str, *, limit: int = 100) -> list[dict[str, Any]]: ...
    def count(self, tenant_id: str) -> int: ...
    def update(
        self,
        tenant_id: str,
        scenario_id: str,
        *,
        expected_revision: int,
        scenario: Mapping[str, Any],
    ) -> dict[str, Any]: ...
    def delete(self, tenant_id: str, scenario_id: str, *, expected_revision: int) -> bool: ...
    def delete_tenant(self, tenant_id: str) -> int: ...


def _copy_record(record: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(dict(record)))


def _assert_record_identity(record: Mapping[str, Any], *, tenant_id: str, scenario_id: str) -> None:
    if str(record.get("id", "")) != scenario_id or str(record.get("tenant_id", "")) != tenant_id:
        raise GraphScenarioConflictError("Graph scenario record identity does not match the write target")


def _assert_next_revision(record: Mapping[str, Any], *, expected_revision: int) -> None:
    if int(record.get("revision", 0)) != expected_revision + 1:
        raise GraphScenarioConflictError("Graph scenario revision must advance exactly once")


class InMemoryGraphScenarioStore:
    """Bounded process-local scenario store for development and tests."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, str], dict[str, Any]] = {}
        self._lock = threading.RLock()

    def create(self, tenant_id: str, scenario: Mapping[str, Any]) -> dict[str, Any]:
        record = _copy_record(scenario)
        _assert_record_identity(record, tenant_id=tenant_id, scenario_id=str(record.get("id", "")))
        key = (tenant_id, str(record["id"]))
        with self._lock:
            if key in self._records:
                raise GraphScenarioConflictError("Graph scenario already exists")
            self._records[key] = record
        return _copy_record(record)

    def get(self, tenant_id: str, scenario_id: str) -> dict[str, Any] | None:
        with self._lock:
            record = self._records.get((tenant_id, scenario_id))
            return _copy_record(record) if record is not None else None

    def list(self, tenant_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            records = [record for (record_tenant, _), record in self._records.items() if record_tenant == tenant_id]
            records.sort(key=lambda record: (str(record.get("updated_at", "")), str(record.get("id", ""))), reverse=True)
            return [_copy_record(record) for record in records[: max(1, min(limit, 100))]]

    def count(self, tenant_id: str) -> int:
        with self._lock:
            return sum(1 for record_tenant, _ in self._records if record_tenant == tenant_id)

    def update(
        self,
        tenant_id: str,
        scenario_id: str,
        *,
        expected_revision: int,
        scenario: Mapping[str, Any],
    ) -> dict[str, Any]:
        key = (tenant_id, scenario_id)
        record = _copy_record(scenario)
        _assert_record_identity(record, tenant_id=tenant_id, scenario_id=scenario_id)
        _assert_next_revision(record, expected_revision=expected_revision)
        with self._lock:
            current = self._records.get(key)
            if current is None:
                raise KeyError(scenario_id)
            if int(current["revision"]) != expected_revision:
                raise GraphScenarioConflictError("Graph scenario revision conflict")
            self._records[key] = record
        return _copy_record(record)

    def delete(self, tenant_id: str, scenario_id: str, *, expected_revision: int) -> bool:
        key = (tenant_id, scenario_id)
        with self._lock:
            current = self._records.get(key)
            if current is None:
                return False
            if int(current["revision"]) != expected_revision:
                raise GraphScenarioConflictError("Graph scenario revision conflict")
            del self._records[key]
            return True

    def delete_tenant(self, tenant_id: str) -> int:
        with self._lock:
            keys = [key for key in self._records if key[0] == tenant_id]
            for key in keys:
                del self._records[key]
            return len(keys)


class SQLiteGraphScenarioStore:
    """SQLite scenario persistence with tenant keys and atomic revisions."""

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
        ensure_sqlite_schema_version(self._conn, "graph_scenarios")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS graph_scenarios (
                id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                base_scan_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                operations TEXT NOT NULL,
                assumptions TEXT NOT NULL DEFAULT '[]',
                created_by TEXT NOT NULL DEFAULT '',
                provenance TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (id, tenant_id)
            );
            CREATE INDEX IF NOT EXISTS idx_graph_scenarios_tenant_updated
                ON graph_scenarios(tenant_id, updated_at DESC, id DESC);
            """
        )
        self._conn.commit()

    @staticmethod
    def _row_to_record(row: sqlite3.Row | tuple[Any, ...]) -> dict[str, Any]:
        return {
            "id": row[0],
            "tenant_id": row[1],
            "base_scan_id": row[2],
            "revision": int(row[3]),
            "name": row[4],
            "description": row[5],
            "operations": json.loads(row[6]),
            "assumptions": json.loads(row[7]),
            "created_by": row[8],
            "provenance": json.loads(row[9]),
            "created_at": row[10],
            "updated_at": row[11],
        }

    def create(self, tenant_id: str, scenario: Mapping[str, Any]) -> dict[str, Any]:
        record = _copy_record(scenario)
        _assert_record_identity(record, tenant_id=tenant_id, scenario_id=str(record.get("id", "")))
        try:
            self._conn.execute(
                """INSERT INTO graph_scenarios
                   (id, tenant_id, base_scan_id, revision, name, description,
                    operations, assumptions, created_by, provenance, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    record["id"],
                    tenant_id,
                    record["base_scan_id"],
                    record["revision"],
                    record["name"],
                    record["description"],
                    json.dumps(record["operations"], sort_keys=True),
                    json.dumps(record.get("assumptions") or [], sort_keys=True),
                    record.get("created_by", ""),
                    json.dumps(record["provenance"], sort_keys=True),
                    record["created_at"],
                    record["updated_at"],
                ),
            )
            self._conn.commit()
        except sqlite3.IntegrityError as exc:
            raise GraphScenarioConflictError("Graph scenario already exists") from exc
        return record

    def get(self, tenant_id: str, scenario_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            """SELECT id, tenant_id, base_scan_id, revision, name, description,
                      operations, assumptions, created_by, provenance, created_at, updated_at
               FROM graph_scenarios WHERE tenant_id = ? AND id = ?""",
            (tenant_id, scenario_id),
        ).fetchone()
        return self._row_to_record(row) if row is not None else None

    def list(self, tenant_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            """SELECT id, tenant_id, base_scan_id, revision, name, description,
                      operations, assumptions, created_by, provenance, created_at, updated_at
               FROM graph_scenarios WHERE tenant_id = ?
               ORDER BY updated_at DESC, id DESC LIMIT ?""",
            (tenant_id, max(1, min(limit, 100))),
        ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def count(self, tenant_id: str) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM graph_scenarios WHERE tenant_id = ?", (tenant_id,)).fetchone()
        return int(row[0]) if row is not None else 0

    def update(
        self,
        tenant_id: str,
        scenario_id: str,
        *,
        expected_revision: int,
        scenario: Mapping[str, Any],
    ) -> dict[str, Any]:
        record = _copy_record(scenario)
        _assert_record_identity(record, tenant_id=tenant_id, scenario_id=scenario_id)
        _assert_next_revision(record, expected_revision=expected_revision)
        cursor = self._conn.execute(
            """UPDATE graph_scenarios
               SET revision = ?, name = ?, description = ?, operations = ?, assumptions = ?,
                   provenance = ?, updated_at = ?
               WHERE tenant_id = ? AND id = ? AND revision = ?""",
            (
                record["revision"],
                record["name"],
                record["description"],
                json.dumps(record["operations"], sort_keys=True),
                json.dumps(record.get("assumptions") or [], sort_keys=True),
                json.dumps(record["provenance"], sort_keys=True),
                record["updated_at"],
                tenant_id,
                scenario_id,
                expected_revision,
            ),
        )
        self._conn.commit()
        if cursor.rowcount == 0:
            if self.get(tenant_id, scenario_id) is None:
                raise KeyError(scenario_id)
            raise GraphScenarioConflictError("Graph scenario revision conflict")
        return record

    def delete(self, tenant_id: str, scenario_id: str, *, expected_revision: int) -> bool:
        cursor = self._conn.execute(
            "DELETE FROM graph_scenarios WHERE tenant_id = ? AND id = ? AND revision = ?",
            (tenant_id, scenario_id, expected_revision),
        )
        self._conn.commit()
        if cursor.rowcount > 0:
            return True
        if self.get(tenant_id, scenario_id) is None:
            return False
        raise GraphScenarioConflictError("Graph scenario revision conflict")

    def delete_tenant(self, tenant_id: str) -> int:
        cursor = self._conn.execute("DELETE FROM graph_scenarios WHERE tenant_id = ?", (tenant_id,))
        self._conn.commit()
        return max(0, int(cursor.rowcount))


__all__ = [
    "GraphScenarioConflictError",
    "GraphScenarioStore",
    "InMemoryGraphScenarioStore",
    "SQLiteGraphScenarioStore",
]
