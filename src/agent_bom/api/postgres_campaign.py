"""Shared Postgres persistence for tenant-scoped risk campaign workflow."""

from __future__ import annotations

from agent_bom.api.campaign_store import CampaignWorkflow, _now
from agent_bom.api.postgres_common import ConnectionPool, _ensure_tenant_rls, _get_pool, _tenant_connection
from agent_bom.api.storage_schema import ensure_postgres_schema_version


class PostgresCampaignStore:
    def __init__(self, pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()
        self._init_table()

    def _init_table(self) -> None:
        with self._pool.connection() as conn:
            ensure_postgres_schema_version(conn, "risk_campaign_workflows")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS risk_campaign_workflows (
                    tenant_id TEXT NOT NULL,
                    campaign_id TEXT NOT NULL,
                    owner TEXT,
                    sla_due_at TEXT,
                    state TEXT NOT NULL,
                    verification_status TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, campaign_id)
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_risk_campaign_workflows_tenant_state "
                "ON risk_campaign_workflows(tenant_id, state, updated_at)"
            )
            _ensure_tenant_rls(conn, "risk_campaign_workflows", "tenant_id")
            conn.commit()

    @staticmethod
    def _row(value: tuple[str, ...] | None) -> CampaignWorkflow | None:
        return CampaignWorkflow(*value) if value else None

    def get(self, tenant_id: str, campaign_id: str) -> CampaignWorkflow | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT tenant_id, campaign_id, owner, sla_due_at, state, verification_status, updated_at "
                "FROM risk_campaign_workflows WHERE tenant_id = %s AND campaign_id = %s",
                (tenant_id, campaign_id),
            ).fetchone()
        return self._row(row)

    def list(self, tenant_id: str) -> list[CampaignWorkflow]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT tenant_id, campaign_id, owner, sla_due_at, state, verification_status, updated_at "
                "FROM risk_campaign_workflows WHERE tenant_id = %s ORDER BY updated_at DESC, campaign_id",
                (tenant_id,),
            ).fetchall()
        return [CampaignWorkflow(*row) for row in rows]

    def upsert(
        self,
        tenant_id: str,
        campaign_id: str,
        *,
        owner: str | None = None,
        sla_due_at: str | None = None,
        state: str = "open",
        verification_status: str = "unverified",
    ) -> CampaignWorkflow:
        updated_at = _now()
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """
                INSERT INTO risk_campaign_workflows
                    (tenant_id, campaign_id, owner, sla_due_at, state, verification_status, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, campaign_id) DO UPDATE SET
                    owner = EXCLUDED.owner,
                    sla_due_at = EXCLUDED.sla_due_at,
                    state = EXCLUDED.state,
                    verification_status = EXCLUDED.verification_status,
                    updated_at = EXCLUDED.updated_at
                """,
                (tenant_id, campaign_id, owner, sla_due_at, state, verification_status, updated_at),
            )
            conn.commit()
        row = self.get(tenant_id, campaign_id)
        assert row is not None
        return row
