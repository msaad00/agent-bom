"""PostgreSQL-backed storage backends for agent-bom.

This module keeps the public import surface stable while the concrete store
implementations are split by responsibility:

- transactional control-plane stores live here
- shared pool / tenant / RLS helpers live in ``postgres_common.py``
- audit + trend stores live in ``postgres_audit.py``
- graph + cache stores live in ``postgres_graph.py``

Requires ``pip install 'agent-bom[postgres]'``.
"""

from __future__ import annotations

import json

from agent_bom.api.postgres_access import PostgresExceptionStore, PostgresKeyStore
from agent_bom.api.postgres_audit import PostgresAuditLog, PostgresTrendStore
from agent_bom.api.postgres_common import (
    _apply_tenant_session,
    _current_tenant,
    _ensure_tenant_rls,
    _get_pool,
    _tenant_connection,
    bypass_tenant_rls,
    reset_current_tenant,
    reset_pool,
    set_current_tenant,
)
from agent_bom.api.postgres_graph import PostgresGraphStore, PostgresScanCache
from agent_bom.api.postgres_policy import PostgresPolicyStore, PostgresScheduleStore, PostgresSourceStore  # noqa: F401
from agent_bom.api.postgres_tenant_quota import PostgresTenantQuotaStore  # noqa: F401

_JOB_TTL_SECONDS = 3600


# ── PostgresJobStore ───────────────────────────────────────────────────────


class PostgresJobStore:
    """PostgreSQL-backed scan job persistence."""

    def __init__(self, pool=None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_jobs (
                    job_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    team_id TEXT NOT NULL DEFAULT 'default',
                    triggered_by TEXT,
                    data JSONB NOT NULL
                )
            """)
            conn.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'scan_jobs' AND column_name = 'team_id'
                    ) THEN
                        ALTER TABLE scan_jobs ADD COLUMN team_id TEXT NOT NULL DEFAULT 'default';
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'scan_jobs' AND column_name = 'triggered_by'
                    ) THEN
                        ALTER TABLE scan_jobs ADD COLUMN triggered_by TEXT;
                    END IF;
                END
                $$;
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pg_jobs_team_created ON scan_jobs(team_id, created_at DESC)")
            _ensure_tenant_rls(conn, "scan_jobs", "team_id")
            conn.commit()

    def put(self, job) -> None:
        data = job.model_dump_json()
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """INSERT INTO scan_jobs (job_id, status, created_at, completed_at, team_id, triggered_by, data)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (job_id) DO UPDATE SET
                     status = EXCLUDED.status,
                     completed_at = EXCLUDED.completed_at,
                     team_id = EXCLUDED.team_id,
                     triggered_by = EXCLUDED.triggered_by,
                     data = EXCLUDED.data""",
                (job.job_id, job.status.value, job.created_at, job.completed_at, job.tenant_id, getattr(job, "triggered_by", None), data),
            )
            conn.commit()

    def get(self, job_id: str, tenant_id: str | None = None):
        from .server import ScanJob

        with _tenant_connection(self._pool) as conn:
            if tenant_id is None:
                row = conn.execute("SELECT data FROM scan_jobs WHERE job_id = %s", (job_id,)).fetchone()
            else:
                row = conn.execute(
                    "SELECT data FROM scan_jobs WHERE job_id = %s AND team_id = %s",
                    (job_id, tenant_id),
                ).fetchone()
            if row is None:
                return None
            raw = row[0] if isinstance(row[0], str) else json.dumps(row[0])
            return ScanJob.model_validate_json(raw)

    def delete(self, job_id: str, tenant_id: str | None = None) -> bool:
        with _tenant_connection(self._pool) as conn:
            if tenant_id is None:
                cursor = conn.execute("DELETE FROM scan_jobs WHERE job_id = %s", (job_id,))
            else:
                cursor = conn.execute(
                    "DELETE FROM scan_jobs WHERE job_id = %s AND team_id = %s",
                    (job_id, tenant_id),
                )
            conn.commit()
            return cursor.rowcount > 0

    def list_all(self, tenant_id: str | None = None) -> list:
        from .server import ScanJob

        if tenant_id is None:
            raise ValueError("tenant_id is required for PostgresJobStore.list_all()")

        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT data FROM scan_jobs WHERE team_id = %s ORDER BY created_at DESC",
                (tenant_id,),
            ).fetchall()
            return [ScanJob.model_validate_json(r[0] if isinstance(r[0], str) else json.dumps(r[0])) for r in rows]

    def list_summary(self, tenant_id: str | None = None) -> list[dict]:
        with _tenant_connection(self._pool) as conn:
            if tenant_id is None:
                rows = conn.execute(
                    "SELECT job_id, team_id, status, created_at, completed_at, triggered_by FROM scan_jobs ORDER BY created_at DESC"
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT job_id, team_id, status, created_at, completed_at, triggered_by
                       FROM scan_jobs
                       WHERE team_id = %s
                       ORDER BY created_at DESC""",
                    (tenant_id,),
                ).fetchall()
            return [
                {
                    "job_id": row[0],
                    "tenant_id": row[1],
                    "status": row[2],
                    "created_at": row[3],
                    "completed_at": row[4],
                    "triggered_by": row[5] if len(row) > 5 else None,
                }
                for row in rows
            ]

    def cleanup_expired(self, ttl_seconds: int = _JOB_TTL_SECONDS) -> int:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                """DELETE FROM scan_jobs
                   WHERE status IN ('done', 'failed', 'cancelled')
                     AND completed_at IS NOT NULL
                     AND completed_at::timestamptz < (now() AT TIME ZONE 'UTC') - (%s * INTERVAL '1 second')""",
                (ttl_seconds,),
            )
            conn.commit()
            return cursor.rowcount


# ── PostgresFleetStore ─────────────────────────────────────────────────────


class PostgresFleetStore:
    """PostgreSQL-backed fleet agent persistence."""

    def __init__(self, pool=None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS fleet_agents (
                    agent_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    lifecycle_state TEXT NOT NULL,
                    trust_score REAL DEFAULT 0.0,
                    tenant_id TEXT DEFAULT 'default',
                    updated_at TEXT NOT NULL,
                    data JSONB NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fleet_name ON fleet_agents(name)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fleet_state ON fleet_agents(lifecycle_state)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fleet_tenant ON fleet_agents(tenant_id)")
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_fleet_tenant_state_trust_name
                ON fleet_agents(tenant_id, lifecycle_state, trust_score DESC, name)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_fleet_tenant_name_lower
                ON fleet_agents(tenant_id, lower(name))
                """
            )
            _ensure_tenant_rls(conn, "fleet_agents", "tenant_id")
            conn.commit()

    def put(self, agent) -> None:
        data = agent.model_dump_json()
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """INSERT INTO fleet_agents (agent_id, name, lifecycle_state, trust_score, tenant_id, updated_at, data)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (agent_id) DO UPDATE SET
                     name = EXCLUDED.name,
                     lifecycle_state = EXCLUDED.lifecycle_state,
                     trust_score = EXCLUDED.trust_score,
                     tenant_id = EXCLUDED.tenant_id,
                     updated_at = EXCLUDED.updated_at,
                     data = EXCLUDED.data""",
                (agent.agent_id, agent.name, agent.lifecycle_state.value, agent.trust_score, agent.tenant_id, agent.updated_at, data),
            )
            conn.commit()

    def get(self, agent_id: str, tenant_id: str | None = None):
        from .fleet_store import FleetAgent

        with _tenant_connection(self._pool) as conn:
            if tenant_id is None:
                row = conn.execute("SELECT data FROM fleet_agents WHERE agent_id = %s", (agent_id,)).fetchone()
            else:
                row = conn.execute(
                    "SELECT data FROM fleet_agents WHERE agent_id = %s AND tenant_id = %s",
                    (agent_id, tenant_id),
                ).fetchone()
            if row is None:
                return None
            raw = row[0] if isinstance(row[0], str) else json.dumps(row[0])
            return FleetAgent.model_validate_json(raw)

    def get_by_name(self, name: str):
        from .fleet_store import FleetAgent

        with _tenant_connection(self._pool) as conn:
            row = conn.execute("SELECT data FROM fleet_agents WHERE name = %s", (name,)).fetchone()
            if row is None:
                return None
            raw = row[0] if isinstance(row[0], str) else json.dumps(row[0])
            return FleetAgent.model_validate_json(raw)

    def delete(self, agent_id: str, tenant_id: str | None = None) -> bool:
        with _tenant_connection(self._pool) as conn:
            if tenant_id is None:
                cursor = conn.execute("DELETE FROM fleet_agents WHERE agent_id = %s", (agent_id,))
            else:
                cursor = conn.execute(
                    "DELETE FROM fleet_agents WHERE agent_id = %s AND tenant_id = %s",
                    (agent_id, tenant_id),
                )
            conn.commit()
            return cursor.rowcount > 0

    def list_all(self) -> list:
        from .fleet_store import FleetAgent

        with _tenant_connection(self._pool) as conn:
            rows = conn.execute("SELECT data FROM fleet_agents ORDER BY name").fetchall()
            return [FleetAgent.model_validate_json(r[0] if isinstance(r[0], str) else json.dumps(r[0])) for r in rows]

    def list_summary(self) -> list[dict]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute("SELECT agent_id, name, lifecycle_state, trust_score FROM fleet_agents ORDER BY name").fetchall()
            return [{"agent_id": r[0], "name": r[1], "lifecycle_state": r[2], "trust_score": r[3]} for r in rows]

    def list_by_tenant(self, tenant_id: str) -> list:
        from .fleet_store import FleetAgent

        with _tenant_connection(self._pool) as conn:
            rows = conn.execute("SELECT data FROM fleet_agents WHERE tenant_id = %s ORDER BY name", (tenant_id,)).fetchall()
            return [FleetAgent.model_validate_json(r[0] if isinstance(r[0], str) else json.dumps(r[0])) for r in rows]

    def query_by_tenant(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        environment: str | None = None,
        min_trust: float | None = None,
        search: str | None = None,
        include_quarantined: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list, int]:
        from .fleet_store import FleetAgent

        clauses = ["tenant_id = %s"]
        params: list[object] = [tenant_id]
        if not include_quarantined and state is None:
            clauses.append("lifecycle_state NOT IN ('quarantined', 'decommissioned')")
        if state:
            clauses.append("lifecycle_state = %s")
            params.append(state)
        if min_trust is not None:
            clauses.append("trust_score >= %s")
            params.append(float(min_trust))
        if environment:
            clauses.append("data->>'environment' = %s")
            params.append(environment)
        if search:
            needle = f"%{search.lower()}%"
            clauses.append(
                """
                (
                    lower(name) LIKE %s
                    OR lower(COALESCE(data->>'owner', '')) LIKE %s
                    OR lower(COALESCE(data->>'environment', '')) LIKE %s
                    OR lower(COALESCE(data->>'tags', '')) LIKE %s
                )
                """
            )
            params.extend([needle, needle, needle, needle])
        where = " AND ".join(clauses)
        with _tenant_connection(self._pool) as conn:
            total_row = conn.execute(f"SELECT COUNT(*) FROM fleet_agents WHERE {where}", tuple(params)).fetchone()  # nosec B608 - clauses are static
            rows = conn.execute(
                f"""
                SELECT data
                FROM fleet_agents
                WHERE {where}
                ORDER BY name, agent_id
                LIMIT %s OFFSET %s
                """,  # nosec B608 - clauses are static
                (*params, int(limit), int(offset)),
            ).fetchall()
            agents = [FleetAgent.model_validate_json(r[0] if isinstance(r[0], str) else json.dumps(r[0])) for r in rows]
            return agents, int(total_row[0] if total_row else 0)

    def list_tenants(self) -> list[dict]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute("SELECT tenant_id, COUNT(*) as cnt FROM fleet_agents GROUP BY tenant_id ORDER BY tenant_id").fetchall()
            return [{"tenant_id": r[0], "agent_count": r[1]} for r in rows]

    def update_state(self, agent_id: str, state) -> bool:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                "UPDATE fleet_agents SET lifecycle_state = %s WHERE agent_id = %s",
                (state.value, agent_id),
            )
            if cursor.rowcount > 0:
                # Also update the JSON data
                row = conn.execute("SELECT data FROM fleet_agents WHERE agent_id = %s", (agent_id,)).fetchone()
                if row:
                    raw = row[0] if isinstance(row[0], str) else json.dumps(row[0])
                    data = json.loads(raw)
                    data["lifecycle_state"] = state.value
                    conn.execute(
                        "UPDATE fleet_agents SET data = %s WHERE agent_id = %s",
                        (json.dumps(data), agent_id),
                    )
            conn.commit()
            return cursor.rowcount > 0

    def batch_put(self, agents: list) -> int:
        count = 0
        for agent in agents:
            self.put(agent)
            count += 1
        return count


__all__ = [
    "_apply_tenant_session",
    "_current_tenant",
    "_ensure_tenant_rls",
    "_get_pool",
    "_tenant_connection",
    "PostgresAuditLog",
    "PostgresExceptionStore",
    "PostgresFleetStore",
    "PostgresGraphStore",
    "PostgresJobStore",
    "PostgresKeyStore",
    "PostgresPolicyStore",
    "PostgresScanCache",
    "PostgresScheduleStore",
    "PostgresTrendStore",
    "bypass_tenant_rls",
    "reset_current_tenant",
    "reset_pool",
    "set_current_tenant",
]
