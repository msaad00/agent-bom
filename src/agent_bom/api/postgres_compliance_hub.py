"""Postgres-backed Compliance Hub store for clustered deployments.

Mirrors ``SQLiteComplianceHubStore`` but uses the same connection pool +
tenant-RLS pattern as ``PostgresSCIMStore``. Selected when
``AGENT_BOM_POSTGRES_URL`` is set so a clustered API deployment can
share ingested findings across replicas.
"""

from __future__ import annotations

import json
from typing import Any

from agent_bom.api.compliance_hub_store import _frameworks_csv, _now_utc_iso
from agent_bom.api.postgres_common import _ensure_tenant_rls, _get_pool, _tenant_connection
from agent_bom.api.storage_schema import ensure_postgres_schema_version


class PostgresComplianceHubStore:
    """Shared hub store backing multi-replica self-hosted deployments."""

    def __init__(self, pool=None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            ensure_postgres_schema_version(conn, "compliance_hub")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS compliance_hub_findings (
                    tenant_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    ingested_at TEXT NOT NULL,
                    source TEXT NOT NULL,
                    applicable_frameworks_csv TEXT NOT NULL DEFAULT '',
                    payload JSONB NOT NULL,
                    ordinal BIGSERIAL NOT NULL,
                    PRIMARY KEY (tenant_id, finding_id, ordinal)
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_order ON compliance_hub_findings(tenant_id, ordinal)")
            _ensure_tenant_rls(conn, "compliance_hub_findings", "tenant_id")
            conn.commit()

    def add(self, tenant_id: str, findings: list[dict[str, Any]]) -> int:
        if not findings:
            return self.count(tenant_id)
        now = _now_utc_iso()
        with _tenant_connection(self._pool) as conn:
            for payload in findings:
                conn.execute(
                    """
                    INSERT INTO compliance_hub_findings
                        (tenant_id, finding_id, ingested_at, source, applicable_frameworks_csv, payload)
                    VALUES (%s, %s, %s, %s, %s, %s::jsonb)
                    """,
                    (
                        tenant_id,
                        str(payload.get("id") or f"hub-{now}-{id(payload)}"),
                        now,
                        str(payload.get("source") or ""),
                        _frameworks_csv(payload),
                        json.dumps(payload, sort_keys=True),
                    ),
                )
            conn.commit()
        return self.count(tenant_id)

    def list(self, tenant_id: str) -> list[dict[str, Any]]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT payload FROM compliance_hub_findings WHERE tenant_id = %s ORDER BY ordinal ASC",
                (tenant_id,),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            raw = row[0]
            out.append(raw if isinstance(raw, dict) else json.loads(raw))
        return out

    def count(self, tenant_id: str) -> int:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM compliance_hub_findings WHERE tenant_id = %s",
                (tenant_id,),
            ).fetchone()
        return int(row[0]) if row else 0

    def clear(self, tenant_id: str) -> int:
        with _tenant_connection(self._pool) as conn:
            cur = conn.execute(
                "DELETE FROM compliance_hub_findings WHERE tenant_id = %s",
                (tenant_id,),
            )
            conn.commit()
        return cur.rowcount or 0
