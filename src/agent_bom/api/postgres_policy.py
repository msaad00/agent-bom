"""PostgreSQL-backed gateway policy, source, and schedule stores."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from agent_bom.api.storage_schema import ensure_postgres_schema_version

from .postgres_common import _ensure_tenant_rls, _get_pool, _tenant_connection


class PostgresPolicyStore:
    """PostgreSQL-backed gateway policy persistence."""

    def __init__(self, pool=None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            ensure_postgres_schema_version(conn, "gateway_policies")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS gateway_policies (
                    policy_id TEXT PRIMARY KEY,
                    team_id TEXT NOT NULL DEFAULT 'default',
                    data JSONB NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS policy_audit_log (
                    id SERIAL PRIMARY KEY,
                    ts TEXT NOT NULL,
                    team_id TEXT NOT NULL DEFAULT 'default',
                    data JSONB NOT NULL
                )
            """)
            conn.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'gateway_policies' AND column_name = 'team_id'
                    ) THEN
                        ALTER TABLE gateway_policies ADD COLUMN team_id TEXT NOT NULL DEFAULT 'default';
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'policy_audit_log' AND column_name = 'team_id'
                    ) THEN
                        ALTER TABLE policy_audit_log ADD COLUMN team_id TEXT NOT NULL DEFAULT 'default';
                    END IF;
                END
                $$;
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_gateway_policies_team ON gateway_policies(team_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_policy_audit_log_team_ts ON policy_audit_log(team_id, ts DESC)")
            _ensure_tenant_rls(conn, "gateway_policies", "team_id")
            _ensure_tenant_rls(conn, "policy_audit_log", "team_id")
            conn.commit()

    def put_policy(self, policy) -> None:
        data = policy.model_dump_json()
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """INSERT INTO gateway_policies (policy_id, team_id, data) VALUES (%s, %s, %s)
                   ON CONFLICT (policy_id) DO UPDATE SET team_id = EXCLUDED.team_id, data = EXCLUDED.data""",
                (policy.policy_id, policy.tenant_id, data),
            )
            conn.commit()

    def get_policy(self, policy_id: str, tenant_id: str | None = None):
        from .policy_store import GatewayPolicy

        sql = "SELECT data FROM gateway_policies WHERE policy_id = %s"
        params: list[object] = [policy_id]
        if tenant_id is not None:
            sql += " AND team_id = %s"
            params.append(tenant_id)
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(sql, params).fetchone()
            if row is None:
                return None
            raw = row[0] if isinstance(row[0], str) else json.dumps(row[0])
            return GatewayPolicy.model_validate_json(raw)

    def delete_policy(self, policy_id: str, tenant_id: str | None = None) -> bool:
        sql = "DELETE FROM gateway_policies WHERE policy_id = %s"
        params: list[object] = [policy_id]
        if tenant_id is not None:
            sql += " AND team_id = %s"
            params.append(tenant_id)
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(sql, params)
            conn.commit()
            return cursor.rowcount > 0

    def list_policies(self, tenant_id: str | None = None, enabled: bool | None = None, mode: str | None = None) -> list:
        from .policy_store import GatewayPolicy

        sql = "SELECT data FROM gateway_policies"
        params: list[object] = []
        if tenant_id is not None:
            sql += " WHERE team_id = %s"
            params.append(tenant_id)
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(sql, params).fetchall()
            policies = [GatewayPolicy.model_validate_json(r[0] if isinstance(r[0], str) else json.dumps(r[0])) for r in rows]
            if enabled is not None:
                policies = [p for p in policies if p.enabled == enabled]
            if mode is not None:
                policies = [p for p in policies if getattr(p.mode, "value", p.mode) == mode]
            return policies

    def get_policies_for_agent(
        self,
        agent_name: str | None = None,
        agent_type: str | None = None,
        environment: str | None = None,
        tenant_id: str | None = None,
    ) -> list:
        policies = self.list_policies(tenant_id=tenant_id, enabled=True)
        results = []
        for p in policies:
            if p.bound_agents and agent_name and agent_name not in p.bound_agents:
                continue
            if p.bound_agent_types and agent_type and agent_type not in p.bound_agent_types:
                continue
            if p.bound_environments and environment and environment not in p.bound_environments:
                continue
            results.append(p)
        return results

    def put_audit_entry(self, entry) -> None:
        data = entry.model_dump_json() if hasattr(entry, "model_dump_json") else json.dumps(entry)
        team_id = getattr(entry, "tenant_id", "default")
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                "INSERT INTO policy_audit_log (ts, team_id, data) VALUES (%s, %s, %s)",
                (datetime.now(timezone.utc).isoformat(), team_id, data),
            )
            conn.commit()

    def list_audit_entries(
        self,
        policy_id: str | None = None,
        agent_name: str | None = None,
        limit: int = 100,
        tenant_id: str | None = None,
    ) -> list:
        from .policy_store import PolicyAuditEntry

        sql = "SELECT data FROM policy_audit_log"
        clauses: list[str] = []
        params: list[object] = []
        if tenant_id is not None:
            clauses.append("team_id = %s")
            params.append(tenant_id)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY ts DESC LIMIT %s"
        params.append(limit)
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(sql, params).fetchall()
            results = []
            for r in rows:
                raw = r[0] if isinstance(r[0], str) else json.dumps(r[0])
                try:
                    entry = PolicyAuditEntry.model_validate_json(raw)
                except Exception:
                    entry = json.loads(raw)
                if isinstance(entry, dict):
                    entry_policy_id = entry.get("policy_id")
                    entry_agent_name = entry.get("agent_name")
                else:
                    entry_policy_id = entry.policy_id
                    entry_agent_name = entry.agent_name
                if policy_id and entry_policy_id != policy_id:
                    continue
                if agent_name and entry_agent_name != agent_name:
                    continue
                results.append(entry)
            return results


class PostgresScheduleStore:
    """PostgreSQL-backed recurring scan schedule persistence."""

    def __init__(self, pool=None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            ensure_postgres_schema_version(conn, "schedules")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_schedules (
                    schedule_id TEXT PRIMARY KEY,
                    enabled INTEGER DEFAULT 1,
                    next_run TEXT,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    data JSONB NOT NULL
                )
            """)
            conn.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'scan_schedules' AND column_name = 'tenant_id'
                    ) THEN
                        ALTER TABLE scan_schedules ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
                    END IF;
                END
                $$;
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sched_tenant_due ON scan_schedules(tenant_id, enabled, next_run)")
            _ensure_tenant_rls(conn, "scan_schedules", "tenant_id")
            conn.commit()

    def put(self, schedule) -> None:
        data = schedule.model_dump_json()
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """INSERT INTO scan_schedules (schedule_id, enabled, next_run, tenant_id, data)
                   VALUES (%s, %s, %s, %s, %s)
                   ON CONFLICT (schedule_id) DO UPDATE SET
                     enabled = EXCLUDED.enabled,
                     next_run = EXCLUDED.next_run,
                     tenant_id = EXCLUDED.tenant_id,
                     data = EXCLUDED.data""",
                (schedule.schedule_id, int(schedule.enabled), schedule.next_run, schedule.tenant_id, data),
            )
            conn.commit()

    def get(self, schedule_id: str, tenant_id: str | None = None):
        from .schedule_store import ScanSchedule

        with _tenant_connection(self._pool) as conn:
            if tenant_id is None:
                row = conn.execute("SELECT data FROM scan_schedules WHERE schedule_id = %s", (schedule_id,)).fetchone()
            else:
                row = conn.execute(
                    "SELECT data FROM scan_schedules WHERE schedule_id = %s AND tenant_id = %s",
                    (schedule_id, tenant_id),
                ).fetchone()
            if row is None:
                return None
            raw = row[0] if isinstance(row[0], str) else json.dumps(row[0])
            return ScanSchedule.model_validate_json(raw)

    def delete(self, schedule_id: str, tenant_id: str | None = None) -> bool:
        with _tenant_connection(self._pool) as conn:
            if tenant_id is None:
                cursor = conn.execute("DELETE FROM scan_schedules WHERE schedule_id = %s", (schedule_id,))
            else:
                cursor = conn.execute(
                    "DELETE FROM scan_schedules WHERE schedule_id = %s AND tenant_id = %s",
                    (schedule_id, tenant_id),
                )
            conn.commit()
            return cursor.rowcount > 0

    def list_all(self, tenant_id: str | None = None) -> list:
        from .schedule_store import ScanSchedule

        with _tenant_connection(self._pool) as conn:
            if tenant_id is None:
                rows = conn.execute("SELECT data FROM scan_schedules ORDER BY schedule_id").fetchall()
            else:
                rows = conn.execute(
                    "SELECT data FROM scan_schedules WHERE tenant_id = %s ORDER BY schedule_id",
                    (tenant_id,),
                ).fetchall()
            return [ScanSchedule.model_validate_json(r[0] if isinstance(r[0], str) else json.dumps(r[0])) for r in rows]

    def list_due(self, now_iso: str) -> list:
        from .schedule_store import ScanSchedule

        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT data FROM scan_schedules WHERE enabled = 1 AND next_run IS NOT NULL AND next_run <= %s",
                (now_iso,),
            ).fetchall()
            return [ScanSchedule.model_validate_json(r[0] if isinstance(r[0], str) else json.dumps(r[0])) for r in rows]


class PostgresSourceStore:
    """PostgreSQL-backed hosted product source registry."""

    def __init__(self, pool=None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            ensure_postgres_schema_version(conn, "sources")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS control_plane_sources (
                    source_id TEXT PRIMARY KEY,
                    enabled INTEGER DEFAULT 1,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    updated_at TEXT NOT NULL,
                    data JSONB NOT NULL
                )
            """)
            conn.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'control_plane_sources' AND column_name = 'tenant_id'
                    ) THEN
                        ALTER TABLE control_plane_sources ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'control_plane_sources' AND column_name = 'updated_at'
                    ) THEN
                        ALTER TABLE control_plane_sources ADD COLUMN updated_at TEXT NOT NULL DEFAULT '';
                    END IF;
                END
                $$;
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_control_plane_sources_tenant_updated ON control_plane_sources(tenant_id, updated_at DESC)"
            )
            _ensure_tenant_rls(conn, "control_plane_sources", "tenant_id")
            conn.commit()

    def put(self, source) -> None:
        data = source.model_dump_json()
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """INSERT INTO control_plane_sources (source_id, enabled, tenant_id, updated_at, data)
                   VALUES (%s, %s, %s, %s, %s)
                   ON CONFLICT (source_id) DO UPDATE SET
                     enabled = EXCLUDED.enabled,
                     tenant_id = EXCLUDED.tenant_id,
                     updated_at = EXCLUDED.updated_at,
                     data = EXCLUDED.data""",
                (source.source_id, int(source.enabled), source.tenant_id, source.updated_at, data),
            )
            conn.commit()

    def get(self, source_id: str):
        from .models import SourceRecord

        with _tenant_connection(self._pool) as conn:
            row = conn.execute("SELECT data FROM control_plane_sources WHERE source_id = %s", (source_id,)).fetchone()
            if row is None:
                return None
            raw = row[0] if isinstance(row[0], str) else json.dumps(row[0])
            return SourceRecord.model_validate_json(raw)

    def delete(self, source_id: str) -> bool:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute("DELETE FROM control_plane_sources WHERE source_id = %s", (source_id,))
            conn.commit()
            return cursor.rowcount > 0

    def list_all(self, tenant_id: str | None = None) -> list:
        from .models import SourceRecord

        with _tenant_connection(self._pool) as conn:
            if tenant_id is None:
                rows = conn.execute("SELECT data FROM control_plane_sources ORDER BY updated_at DESC, source_id").fetchall()
            else:
                rows = conn.execute(
                    """SELECT data FROM control_plane_sources
                       WHERE tenant_id = %s
                       ORDER BY updated_at DESC, source_id""",
                    (tenant_id,),
                ).fetchall()
            return [SourceRecord.model_validate_json(row[0] if isinstance(row[0], str) else json.dumps(row[0])) for row in rows]
