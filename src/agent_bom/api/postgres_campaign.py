"""Shared Postgres persistence for tenant-scoped risk campaign workflow."""

from __future__ import annotations

import json
from typing import Any, List

from agent_bom.api.campaign_store import CampaignWorkflow, MembershipEvidence, _membership, _now
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
                    title TEXT NOT NULL DEFAULT '',
                    member_ids TEXT NOT NULL DEFAULT '[]',
                    membership_fingerprint TEXT NOT NULL DEFAULT '',
                    generation INTEGER NOT NULL DEFAULT 1,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    version INTEGER NOT NULL DEFAULT 1,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, campaign_id)
                )
                """
            )
            conn.execute("ALTER TABLE risk_campaign_workflows ADD COLUMN IF NOT EXISTS member_ids TEXT NOT NULL DEFAULT '[]'")
            conn.execute("ALTER TABLE risk_campaign_workflows ADD COLUMN IF NOT EXISTS title TEXT NOT NULL DEFAULT ''")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_risk_campaign_workflows_tenant_state "
                "ON risk_campaign_workflows(tenant_id, state, updated_at)"
            )
            _ensure_tenant_rls(conn, "risk_campaign_workflows", "tenant_id")
            conn.commit()

    @staticmethod
    def _row(value: tuple[Any, ...] | None) -> CampaignWorkflow | None:
        if not value:
            return None
        values = list(value)
        values[7] = tuple(json.loads(values[7] or "[]"))
        return CampaignWorkflow(*values)

    def get(self, tenant_id: str, campaign_id: str) -> CampaignWorkflow | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT tenant_id, campaign_id, owner, sla_due_at, state, verification_status, "
                "title, member_ids, membership_fingerprint, generation, active, version, updated_at "
                "FROM risk_campaign_workflows WHERE tenant_id = %s AND campaign_id = %s",
                (tenant_id, campaign_id),
            ).fetchone()
        return self._row(row)

    def list(self, tenant_id: str) -> List[CampaignWorkflow]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT tenant_id, campaign_id, owner, sla_due_at, state, verification_status, "
                "title, member_ids, membership_fingerprint, generation, active, version, updated_at "
                "FROM risk_campaign_workflows WHERE tenant_id = %s ORDER BY updated_at DESC, campaign_id",
                (tenant_id,),
            ).fetchall()
        return [row for value in rows if (row := self._row(value)) is not None]

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

    def reconcile_memberships(
        self, tenant_id: str, memberships: dict[str, MembershipEvidence], *, complete: bool = True
    ) -> List[CampaignWorkflow]:
        if not complete:
            return [row for cid in memberships if (row := self.get(tenant_id, cid)) is not None]
        now = _now()
        with _tenant_connection(self._pool) as conn:
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (f"risk_campaign:{tenant_id}",))
            rows = conn.execute(
                "SELECT tenant_id, campaign_id, owner, sla_due_at, state, verification_status, "
                "title, member_ids, membership_fingerprint, generation, active, version, updated_at "
                "FROM risk_campaign_workflows WHERE tenant_id=%s FOR UPDATE",
                (tenant_id,),
            ).fetchall()
            existing = {row.campaign_id: row for value in rows if (row := self._row(value)) is not None}
            for campaign_id, evidence in memberships.items():
                fingerprint, member_ids, title = _membership(evidence)
                encoded_ids = json.dumps(member_ids, separators=(",", ":"))
                row = existing.get(campaign_id)
                if row is None:
                    conn.execute(
                        "INSERT INTO risk_campaign_workflows "
                        "(tenant_id,campaign_id,state,verification_status,title,member_ids,membership_fingerprint,"
                        "generation,active,version,updated_at) "
                        "VALUES (%s,%s,'open','unverified',%s,%s,%s,1,TRUE,1,%s)",
                        (tenant_id, campaign_id, title, encoded_ids, fingerprint, now),
                    )
                elif not row.active or row.membership_fingerprint != fingerprint or row.member_ids != member_ids:
                    conn.execute(
                        "UPDATE risk_campaign_workflows SET title=%s,member_ids=%s,membership_fingerprint=%s,"
                        "generation=generation+1,active=TRUE,"
                        "state='open',verification_status='unverified',version=version+1,updated_at=%s "
                        "WHERE tenant_id=%s AND campaign_id=%s",
                        (title, encoded_ids, fingerprint, now, tenant_id, campaign_id),
                    )
                elif row.title != title:
                    conn.execute(
                        "UPDATE risk_campaign_workflows SET title=%s WHERE tenant_id=%s AND campaign_id=%s",
                        (title, tenant_id, campaign_id),
                    )
            absent = (set(existing) - set(memberships)) if complete else set()
            for campaign_id in absent:
                conn.execute(
                    "UPDATE risk_campaign_workflows SET active=FALSE,version=version+1,updated_at=%s "
                    "WHERE tenant_id=%s AND campaign_id=%s AND active=TRUE",
                    (now, tenant_id, campaign_id),
                )
            conn.commit()
        return [row for cid in memberships if (row := self.get(tenant_id, cid)) is not None]

    def verify(self, tenant_id: str, campaign_id: str, *, expected_version: int, remaining_ids: tuple[str, ...]) -> CampaignWorkflow | None:
        status = "failed" if remaining_ids else "verified"
        state = "open" if remaining_ids else "done"
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                "UPDATE risk_campaign_workflows SET verification_status=%s,state=%s,version=version+1,updated_at=%s "
                "WHERE tenant_id=%s AND campaign_id=%s AND version=%s",
                (status, state, _now(), tenant_id, campaign_id, expected_version),
            )
            conn.commit()
            if cursor.rowcount != 1:
                return None
        return self.get(tenant_id, campaign_id)

    def patch(self, tenant_id: str, campaign_id: str, *, expected_version: int, fields: dict[str, str | None]) -> CampaignWorkflow | None:
        allowed = {"owner", "sla_due_at", "state"}
        assignments = [f"{key}=%s" for key in fields if key in allowed]
        values = [fields[key] for key in fields if key in allowed]
        if not assignments:
            return self.get(tenant_id, campaign_id)
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                f"UPDATE risk_campaign_workflows SET {','.join(assignments)}, version=version+1, updated_at=%s "  # nosec B608
                "WHERE tenant_id=%s AND campaign_id=%s AND version=%s AND active=TRUE",
                (*values, _now(), tenant_id, campaign_id, expected_version),
            )
            conn.commit()
            if cursor.rowcount != 1:
                return None
        return self.get(tenant_id, campaign_id)
