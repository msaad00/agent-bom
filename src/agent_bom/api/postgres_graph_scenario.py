"""Postgres persistence for tenant-scoped proposed graph scenarios."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from agent_bom.api.graph_scenario_store import (
    GraphScenarioConflictError,
    _assert_next_revision,
    _assert_record_identity,
)
from agent_bom.api.postgres_common import ConnectionPool, _ensure_tenant_rls, _get_pool, _tenant_connection
from agent_bom.api.storage_schema import ensure_postgres_schema_version


class PostgresGraphScenarioStore:
    """Multi-replica scenario persistence protected by tenant RLS."""

    def __init__(self, pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            if not ensure_postgres_schema_version(conn, "graph_scenarios"):
                return
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS graph_scenarios (
                    id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    base_scan_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    operations JSONB NOT NULL,
                    assumptions JSONB NOT NULL DEFAULT '[]'::jsonb,
                    created_by TEXT NOT NULL DEFAULT '',
                    provenance JSONB NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (id, tenant_id)
                )
                """
            )
            conn.execute(
                """CREATE INDEX IF NOT EXISTS idx_graph_scenarios_tenant_updated
                   ON graph_scenarios(tenant_id, updated_at DESC, id DESC)"""
            )
            _ensure_tenant_rls(conn, "graph_scenarios", "tenant_id")
            conn.commit()

    @staticmethod
    def _decode(value: Any) -> Any:
        return json.loads(value) if isinstance(value, str) else value

    @classmethod
    def _row_to_record(cls, row: Any) -> dict[str, Any]:
        return {
            "id": row[0],
            "tenant_id": row[1],
            "base_scan_id": row[2],
            "revision": int(row[3]),
            "name": row[4],
            "description": row[5],
            "operations": cls._decode(row[6]),
            "assumptions": cls._decode(row[7]),
            "created_by": row[8],
            "provenance": cls._decode(row[9]),
            "created_at": row[10],
            "updated_at": row[11],
        }

    def create(self, tenant_id: str, scenario: Mapping[str, Any]) -> dict[str, Any]:
        record = json.loads(json.dumps(dict(scenario)))
        _assert_record_identity(record, tenant_id=tenant_id, scenario_id=str(record.get("id", "")))
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                """INSERT INTO graph_scenarios
                   (id, tenant_id, base_scan_id, revision, name, description,
                    operations, assumptions, created_by, provenance, created_at, updated_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s, %s::jsonb, %s, %s)
                   ON CONFLICT (id, tenant_id) DO NOTHING
                   RETURNING id""",
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
            ).fetchone()
            conn.commit()
        if row is None:
            raise GraphScenarioConflictError("Graph scenario already exists")
        return record

    def get(self, tenant_id: str, scenario_id: str) -> dict[str, Any] | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                """SELECT id, tenant_id, base_scan_id, revision, name, description,
                          operations, assumptions, created_by, provenance, created_at, updated_at
                   FROM graph_scenarios WHERE tenant_id = %s AND id = %s""",
                (tenant_id, scenario_id),
            ).fetchone()
        return self._row_to_record(row) if row is not None else None

    def list(self, tenant_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                """SELECT id, tenant_id, base_scan_id, revision, name, description,
                          operations, assumptions, created_by, provenance, created_at, updated_at
                   FROM graph_scenarios WHERE tenant_id = %s
                   ORDER BY updated_at DESC, id DESC LIMIT %s""",
                (tenant_id, max(1, min(limit, 100))),
            ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def count(self, tenant_id: str) -> int:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute("SELECT COUNT(*) FROM graph_scenarios WHERE tenant_id = %s", (tenant_id,)).fetchone()
        return int(row[0]) if row is not None else 0

    def update(
        self,
        tenant_id: str,
        scenario_id: str,
        *,
        expected_revision: int,
        scenario: Mapping[str, Any],
    ) -> dict[str, Any]:
        record = json.loads(json.dumps(dict(scenario)))
        _assert_record_identity(record, tenant_id=tenant_id, scenario_id=scenario_id)
        _assert_next_revision(record, expected_revision=expected_revision)
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                """UPDATE graph_scenarios SET
                       revision = %s, name = %s, description = %s,
                       operations = %s::jsonb, assumptions = %s::jsonb,
                       provenance = %s::jsonb, updated_at = %s
                   WHERE tenant_id = %s AND id = %s AND revision = %s
                   RETURNING id""",
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
            ).fetchone()
            conn.commit()
        if row is None:
            if self.get(tenant_id, scenario_id) is None:
                raise KeyError(scenario_id)
            raise GraphScenarioConflictError("Graph scenario revision conflict")
        return record

    def delete(self, tenant_id: str, scenario_id: str, *, expected_revision: int) -> bool:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                """DELETE FROM graph_scenarios
                   WHERE tenant_id = %s AND id = %s AND revision = %s
                   RETURNING id""",
                (tenant_id, scenario_id, expected_revision),
            ).fetchone()
            conn.commit()
        if row is not None:
            return True
        if self.get(tenant_id, scenario_id) is None:
            return False
        raise GraphScenarioConflictError("Graph scenario revision conflict")

    def delete_tenant(self, tenant_id: str) -> int:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute("DELETE FROM graph_scenarios WHERE tenant_id = %s", (tenant_id,))
            conn.commit()
            return max(0, int(cursor.rowcount))


__all__ = ["PostgresGraphScenarioStore"]
