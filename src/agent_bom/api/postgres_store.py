"""PostgreSQL-backed storage backends for agent-bom.

Provides pluggable PostgreSQL persistence for all store protocols:
- ``PostgresJobStore``       — scan job persistence
- ``PostgresFleetStore``     — fleet agent lifecycle
- ``PostgresPolicyStore``    — gateway policies + audit log
- ``PostgresScheduleStore``  — recurring scan schedules
- ``PostgresScanCache``      — OSV vulnerability scan cache

Requires ``pip install 'agent-bom[postgres]'``.

Connection: set ``AGENT_BOM_POSTGRES_URL`` env var.
  e.g. ``postgresql://user:pass@host:5432/agent_bom``
"""

from __future__ import annotations

import json
import logging
import os
import time
from contextlib import contextmanager
from contextvars import ContextVar, Token
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_JOB_TTL_SECONDS = 3600

# Module-level pool singleton
_pool = None
_current_tenant: ContextVar[str] = ContextVar("agent_bom_postgres_tenant", default="default")
_bypass_tenant_rls: ContextVar[bool] = ContextVar("agent_bom_postgres_bypass_rls", default=False)


def set_current_tenant(tenant_id: str) -> Token[str]:
    """Bind the current Postgres tenant context for the active request/task."""
    return _current_tenant.set((tenant_id or "default").strip() or "default")


def reset_current_tenant(token: Token[str]) -> None:
    """Restore the previous Postgres tenant context."""
    _current_tenant.reset(token)


@contextmanager
def bypass_tenant_rls():
    """Temporarily disable Postgres tenant RLS for trusted internal tasks."""
    token = _bypass_tenant_rls.set(True)
    try:
        yield
    finally:
        _bypass_tenant_rls.reset(token)


def _get_pool():
    """Lazy-create a connection pool (singleton)."""
    global _pool
    if _pool is None:
        try:
            import psycopg_pool
        except ImportError as exc:
            raise ImportError("PostgreSQL support requires psycopg. Install with: pip install 'agent-bom[postgres]'") from exc

        url = os.environ.get("AGENT_BOM_POSTGRES_URL", "")
        if not url:
            raise ValueError("AGENT_BOM_POSTGRES_URL env var is required for PostgreSQL storage.")
        _pool = psycopg_pool.ConnectionPool(url, min_size=2, max_size=10)
    return _pool


def reset_pool():
    """Reset the connection pool (for testing)."""
    global _pool
    _pool = None


def _apply_tenant_session(conn) -> None:
    """Attach tenant session settings used by Postgres RLS policies."""
    conn.execute("SELECT set_config('app.tenant_id', %s, true)", (_current_tenant.get(),))
    conn.execute("SELECT set_config('app.bypass_rls', %s, true)", ("1" if _bypass_tenant_rls.get() else "0",))


def _ensure_rls_helpers(conn) -> None:
    """Create shared SQL helpers used by tenant RLS policies."""
    conn.execute("""
        CREATE OR REPLACE FUNCTION public.abom_current_tenant()
        RETURNS TEXT
        LANGUAGE SQL
        STABLE
        AS $$
            SELECT COALESCE(NULLIF(current_setting('app.tenant_id', true), ''), 'default')
        $$;
    """)
    conn.execute("""
        CREATE OR REPLACE FUNCTION public.abom_rls_bypass()
        RETURNS BOOLEAN
        LANGUAGE SQL
        STABLE
        AS $$
            SELECT COALESCE(NULLIF(current_setting('app.bypass_rls', true), ''), '0') = '1'
        $$;
    """)


def _ensure_tenant_rls(conn, table: str, column: str) -> None:
    """Enable tenant RLS for a table using the shared tenant session helpers."""
    _ensure_rls_helpers(conn)
    conn.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")  # nosec B608
    conn.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")  # nosec B608
    conn.execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_policies
                WHERE schemaname = 'public'
                  AND tablename = '{table}'
                  AND policyname = '{table}_tenant_isolation'
            ) THEN
                EXECUTE 'CREATE POLICY {table}_tenant_isolation ON {table}
                    USING (public.abom_rls_bypass() OR {column} = public.abom_current_tenant())
                    WITH CHECK (public.abom_rls_bypass() OR {column} = public.abom_current_tenant())';
            END IF;
        END
        $$;
        """  # nosec B608
    )


@contextmanager
def _tenant_connection(pool):
    """Open a connection with the current tenant/bypass settings attached."""
    with pool.connection() as conn:
        _apply_tenant_session(conn)
        yield conn


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
                    data JSONB NOT NULL
                )
            """)
            conn.commit()

    def put(self, job) -> None:
        data = job.model_dump_json()
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """INSERT INTO scan_jobs (job_id, status, created_at, completed_at, data)
                   VALUES (%s, %s, %s, %s, %s)
                   ON CONFLICT (job_id) DO UPDATE SET
                     status = EXCLUDED.status,
                     completed_at = EXCLUDED.completed_at,
                     data = EXCLUDED.data""",
                (job.job_id, job.status.value, job.created_at, job.completed_at, data),
            )
            conn.commit()

    def get(self, job_id: str):
        from .server import ScanJob

        with _tenant_connection(self._pool) as conn:
            row = conn.execute("SELECT data FROM scan_jobs WHERE job_id = %s", (job_id,)).fetchone()
            if row is None:
                return None
            raw = row[0] if isinstance(row[0], str) else json.dumps(row[0])
            return ScanJob.model_validate_json(raw)

    def delete(self, job_id: str) -> bool:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute("DELETE FROM scan_jobs WHERE job_id = %s", (job_id,))
            conn.commit()
            return cursor.rowcount > 0

    def list_all(self) -> list:
        from .server import ScanJob

        with _tenant_connection(self._pool) as conn:
            rows = conn.execute("SELECT data FROM scan_jobs ORDER BY created_at DESC").fetchall()
            return [ScanJob.model_validate_json(r[0] if isinstance(r[0], str) else json.dumps(r[0])) for r in rows]

    def list_summary(self) -> list[dict]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute("SELECT job_id, status, created_at, completed_at FROM scan_jobs ORDER BY created_at DESC").fetchall()
            return [{"job_id": r[0], "status": r[1], "created_at": r[2], "completed_at": r[3]} for r in rows]

    def cleanup_expired(self, ttl_seconds: int = _JOB_TTL_SECONDS) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                """DELETE FROM scan_jobs
                   WHERE status IN ('done', 'failed', 'cancelled')
                     AND completed_at IS NOT NULL
                     AND completed_at < %s""",
                (now,),
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

    def get(self, agent_id: str):
        from .fleet_store import FleetAgent

        with _tenant_connection(self._pool) as conn:
            row = conn.execute("SELECT data FROM fleet_agents WHERE agent_id = %s", (agent_id,)).fetchone()
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

    def delete(self, agent_id: str) -> bool:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute("DELETE FROM fleet_agents WHERE agent_id = %s", (agent_id,))
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


# ── PostgresPolicyStore ────────────────────────────────────────────────────


class PostgresPolicyStore:
    """PostgreSQL-backed gateway policy persistence."""

    def __init__(self, pool=None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS gateway_policies (
                    policy_id TEXT PRIMARY KEY,
                    data JSONB NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS policy_audit_log (
                    id SERIAL PRIMARY KEY,
                    ts TEXT NOT NULL,
                    data JSONB NOT NULL
                )
            """)
            conn.commit()

    def put_policy(self, policy) -> None:
        data = policy.model_dump_json()
        with self._pool.connection() as conn:
            conn.execute(
                """INSERT INTO gateway_policies (policy_id, data) VALUES (%s, %s)
                   ON CONFLICT (policy_id) DO UPDATE SET data = EXCLUDED.data""",
                (policy.policy_id, data),
            )
            conn.commit()

    def get_policy(self, policy_id: str):
        from .policy_store import GatewayPolicy

        with self._pool.connection() as conn:
            row = conn.execute("SELECT data FROM gateway_policies WHERE policy_id = %s", (policy_id,)).fetchone()
            if row is None:
                return None
            raw = row[0] if isinstance(row[0], str) else json.dumps(row[0])
            return GatewayPolicy.model_validate_json(raw)

    def delete_policy(self, policy_id: str) -> bool:
        with self._pool.connection() as conn:
            cursor = conn.execute("DELETE FROM gateway_policies WHERE policy_id = %s", (policy_id,))
            conn.commit()
            return cursor.rowcount > 0

    def list_policies(self, enabled: bool | None = None, mode: str | None = None) -> list:
        from .policy_store import GatewayPolicy

        with self._pool.connection() as conn:
            rows = conn.execute("SELECT data FROM gateway_policies").fetchall()
            policies = [GatewayPolicy.model_validate_json(r[0] if isinstance(r[0], str) else json.dumps(r[0])) for r in rows]
            if enabled is not None:
                policies = [p for p in policies if p.enabled == enabled]
            if mode is not None:
                policies = [p for p in policies if p.mode == mode]
            return policies

    def get_policies_for_agent(self, agent_type: str) -> list:
        return [p for p in self.list_policies(enabled=True) if not p.agent_types or agent_type in p.agent_types]

    def put_audit_entry(self, entry) -> None:
        data = entry.model_dump_json() if hasattr(entry, "model_dump_json") else json.dumps(entry)
        with self._pool.connection() as conn:
            conn.execute(
                "INSERT INTO policy_audit_log (ts, data) VALUES (%s, %s)",
                (datetime.now(timezone.utc).isoformat(), data),
            )
            conn.commit()

    def list_audit_entries(self, limit: int = 100) -> list:
        from .policy_store import PolicyAuditEntry

        with self._pool.connection() as conn:
            rows = conn.execute("SELECT data FROM policy_audit_log ORDER BY ts DESC LIMIT %s", (limit,)).fetchall()
            results = []
            for r in rows:
                raw = r[0] if isinstance(r[0], str) else json.dumps(r[0])
                try:
                    results.append(PolicyAuditEntry.model_validate_json(raw))
                except Exception:
                    results.append(json.loads(raw))
            return results


# ── PostgresScheduleStore ─────────────────────────────────────────────────


class PostgresScheduleStore:
    """PostgreSQL-backed recurring scan schedule persistence."""

    def __init__(self, pool=None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
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

    def get(self, schedule_id: str):
        from .schedule_store import ScanSchedule

        with _tenant_connection(self._pool) as conn:
            row = conn.execute("SELECT data FROM scan_schedules WHERE schedule_id = %s", (schedule_id,)).fetchone()
            if row is None:
                return None
            raw = row[0] if isinstance(row[0], str) else json.dumps(row[0])
            return ScanSchedule.model_validate_json(raw)

    def delete(self, schedule_id: str) -> bool:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute("DELETE FROM scan_schedules WHERE schedule_id = %s", (schedule_id,))
            conn.commit()
            return cursor.rowcount > 0

    def list_all(self) -> list:
        from .schedule_store import ScanSchedule

        with _tenant_connection(self._pool) as conn:
            rows = conn.execute("SELECT data FROM scan_schedules ORDER BY schedule_id").fetchall()
            return [ScanSchedule.model_validate_json(r[0] if isinstance(r[0], str) else json.dumps(r[0])) for r in rows]

    def list_due(self, now_iso: str) -> list:
        from .schedule_store import ScanSchedule

        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT data FROM scan_schedules WHERE enabled = 1 AND next_run IS NOT NULL AND next_run <= %s",
                (now_iso,),
            ).fetchall()
            return [ScanSchedule.model_validate_json(r[0] if isinstance(r[0], str) else json.dumps(r[0])) for r in rows]


# ── PostgresScanCache ─────────────────────────────────────────────────────


class PostgresScanCache:
    """PostgreSQL-backed OSV vulnerability scan cache.

    Drop-in replacement for the SQLite ``ScanCache`` — same public API,
    backed by PostgreSQL for multi-instance deployments.
    """

    def __init__(self, pool=None, ttl_seconds: int = 86_400) -> None:
        self._pool = pool or _get_pool()
        self._ttl = ttl_seconds
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS osv_cache (
                    cache_key  TEXT PRIMARY KEY,
                    vulns_json TEXT NOT NULL,
                    cached_at  REAL NOT NULL
                )
            """)
            conn.commit()

    def get(self, ecosystem: str, name: str, version: str) -> list[dict] | None:
        key = self._key(ecosystem, name, version)
        with self._pool.connection() as conn:
            row = conn.execute(
                "SELECT vulns_json, cached_at FROM osv_cache WHERE cache_key = %s",
                (key,),
            ).fetchone()
            if row is None:
                return None
            if time.time() - float(row[1]) > self._ttl:
                conn.execute("DELETE FROM osv_cache WHERE cache_key = %s", (key,))
                conn.commit()
                return None
            return json.loads(row[0])

    def put(self, ecosystem: str, name: str, version: str, vulns: list[dict]) -> None:
        key = self._key(ecosystem, name, version)
        with self._pool.connection() as conn:
            conn.execute(
                """INSERT INTO osv_cache (cache_key, vulns_json, cached_at)
                   VALUES (%s, %s, %s)
                   ON CONFLICT (cache_key) DO UPDATE SET
                     vulns_json = EXCLUDED.vulns_json,
                     cached_at = EXCLUDED.cached_at""",
                (key, json.dumps(vulns), time.time()),
            )
            conn.commit()

    def cleanup_expired(self) -> int:
        cutoff = time.time() - self._ttl
        with self._pool.connection() as conn:
            cursor = conn.execute("DELETE FROM osv_cache WHERE cached_at < %s", (cutoff,))
            conn.commit()
            return cursor.rowcount or 0

    def clear(self) -> None:
        with self._pool.connection() as conn:
            conn.execute("DELETE FROM osv_cache")
            conn.commit()

    @property
    def size(self) -> int:
        with self._pool.connection() as conn:
            row = conn.execute("SELECT COUNT(*) FROM osv_cache").fetchone()
            return row[0] if row else 0

    @staticmethod
    def _key(ecosystem: str, name: str, version: str) -> str:
        from agent_bom.models import normalize_package_name

        return f"{ecosystem}:{normalize_package_name(name, ecosystem)}@{version}"
