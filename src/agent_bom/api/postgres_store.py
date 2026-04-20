"""PostgreSQL-backed storage backends for agent-bom.

Provides pluggable PostgreSQL persistence for all store protocols:
- ``PostgresJobStore``       — scan job persistence
- ``PostgresFleetStore``     — fleet agent lifecycle
- ``PostgresGraphStore``     — unified graph persistence and queries
- ``PostgresKeyStore``       — persistent API key storage
- ``PostgresExceptionStore`` — exception and false-positive storage
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
from typing import Any

from agent_bom.api.audit_log import AuditEntry
from agent_bom.api.auth import ApiKey, Role, verify_api_key
from agent_bom.api.exception_store import ExceptionStatus, VulnException
from agent_bom.api.graph_store import _escape_like_query
from agent_bom.baseline import TrendPoint
from agent_bom.config import (
    POSTGRES_CONNECT_TIMEOUT_SECONDS,
    POSTGRES_POOL_MAX_SIZE,
    POSTGRES_POOL_MIN_SIZE,
    POSTGRES_STATEMENT_TIMEOUT_MS,
)

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
        min_size = max(1, POSTGRES_POOL_MIN_SIZE)
        max_size = max(min_size, POSTGRES_POOL_MAX_SIZE)
        kwargs: dict[str, object] = {}
        if POSTGRES_CONNECT_TIMEOUT_SECONDS > 0:
            kwargs["connect_timeout"] = POSTGRES_CONNECT_TIMEOUT_SECONDS
        _pool = psycopg_pool.ConnectionPool(
            url,
            min_size=min_size,
            max_size=max_size,
            kwargs=kwargs,
        )
    return _pool


def reset_pool():
    """Reset the connection pool (for testing)."""
    global _pool
    _pool = None


def _apply_tenant_session(conn) -> None:
    """Attach tenant session settings used by Postgres RLS policies."""
    conn.execute("SELECT set_config('app.tenant_id', %s, true)", (_current_tenant.get(),))
    conn.execute("SELECT set_config('app.bypass_rls', %s, true)", ("1" if _bypass_tenant_rls.get() else "0",))
    if POSTGRES_STATEMENT_TIMEOUT_MS > 0:
        conn.execute("SELECT set_config('statement_timeout', %s, false)", (str(POSTGRES_STATEMENT_TIMEOUT_MS),))


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
                    team_id TEXT NOT NULL DEFAULT 'default',
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
                """INSERT INTO scan_jobs (job_id, status, created_at, completed_at, team_id, data)
                   VALUES (%s, %s, %s, %s, %s, %s)
                   ON CONFLICT (job_id) DO UPDATE SET
                     status = EXCLUDED.status,
                     completed_at = EXCLUDED.completed_at,
                     team_id = EXCLUDED.team_id,
                     data = EXCLUDED.data""",
                (job.job_id, job.status.value, job.created_at, job.completed_at, job.tenant_id, data),
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

    def list_all(self, tenant_id: str | None = None) -> list:
        from .server import ScanJob

        with _tenant_connection(self._pool) as conn:
            if tenant_id is None:
                rows = conn.execute("SELECT data FROM scan_jobs ORDER BY created_at DESC").fetchall()
            else:
                rows = conn.execute(
                    "SELECT data FROM scan_jobs WHERE team_id = %s ORDER BY created_at DESC",
                    (tenant_id,),
                ).fetchall()
            return [ScanJob.model_validate_json(r[0] if isinstance(r[0], str) else json.dumps(r[0])) for r in rows]

    def list_summary(self, tenant_id: str | None = None) -> list[dict]:
        with _tenant_connection(self._pool) as conn:
            if tenant_id is None:
                rows = conn.execute(
                    "SELECT job_id, team_id, status, created_at, completed_at FROM scan_jobs ORDER BY created_at DESC"
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT job_id, team_id, status, created_at, completed_at
                       FROM scan_jobs
                       WHERE team_id = %s
                       ORDER BY created_at DESC""",
                    (tenant_id,),
                ).fetchall()
            return [{"job_id": r[0], "tenant_id": r[1], "status": r[2], "created_at": r[3], "completed_at": r[4]} for r in rows]

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


# ── PostgresKeyStore ───────────────────────────────────────────────────────


class PostgresKeyStore:
    """PostgreSQL-backed API key storage with tenant RLS."""

    def __init__(self, pool=None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    key_id TEXT PRIMARY KEY,
                    key_hash TEXT NOT NULL,
                    key_salt TEXT NOT NULL,
                    key_prefix TEXT NOT NULL,
                    name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    team_id TEXT NOT NULL DEFAULT 'default',
                    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
                    created_by TEXT,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    last_used TEXT,
                    revoked BOOLEAN NOT NULL DEFAULT FALSE
                )
            """)
            conn.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'api_keys' AND column_name = 'team_id'
                    ) THEN
                        ALTER TABLE api_keys ADD COLUMN team_id TEXT NOT NULL DEFAULT 'default';
                    END IF;
                END
                $$;
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_team ON api_keys(team_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(team_id, revoked)")
            _ensure_tenant_rls(conn, "api_keys", "team_id")
            conn.commit()

    @staticmethod
    def _row_to_key(row) -> ApiKey:
        scopes = row[7] if isinstance(row[7], list) else json.loads(row[7] or "[]")
        return ApiKey(
            key_id=row[0],
            key_hash=row[1],
            key_salt=row[2],
            key_prefix=row[3],
            name=row[4],
            role=Role(row[5]),
            tenant_id=row[6],
            scopes=scopes,
            created_at=row[8],
            expires_at=row[9],
        )

    def add(self, key: ApiKey) -> None:
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """INSERT INTO api_keys
                   (key_id, key_hash, key_salt, key_prefix, name, role, team_id, scopes, created_at, expires_at, revoked)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, FALSE)
                   ON CONFLICT (key_id) DO UPDATE SET
                     key_hash = EXCLUDED.key_hash,
                     key_salt = EXCLUDED.key_salt,
                     key_prefix = EXCLUDED.key_prefix,
                     name = EXCLUDED.name,
                     role = EXCLUDED.role,
                     team_id = EXCLUDED.team_id,
                     scopes = EXCLUDED.scopes,
                     created_at = EXCLUDED.created_at,
                     expires_at = EXCLUDED.expires_at,
                     revoked = FALSE""",
                (
                    key.key_id,
                    key.key_hash,
                    key.key_salt,
                    key.key_prefix,
                    key.name,
                    key.role.value,
                    key.tenant_id,
                    json.dumps(key.scopes),
                    key.created_at,
                    key.expires_at,
                ),
            )
            conn.commit()

    def remove(self, key_id: str) -> bool:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                "UPDATE api_keys SET revoked = TRUE WHERE key_id = %s AND revoked = FALSE",
                (key_id,),
            )
            conn.commit()
            return cursor.rowcount > 0

    def get(self, key_id: str) -> ApiKey | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                """SELECT key_id, key_hash, key_salt, key_prefix, name, role, team_id, scopes, created_at, expires_at
                   FROM api_keys
                   WHERE key_id = %s AND revoked = FALSE""",
                (key_id,),
            ).fetchone()
            return self._row_to_key(row) if row else None

    def list_keys(self, tenant_id: str | None = None) -> list[ApiKey]:
        query = """
            SELECT key_id, key_hash, key_salt, key_prefix, name, role, team_id, scopes, created_at, expires_at
            FROM api_keys
            WHERE revoked = FALSE
        """
        params: tuple[object, ...] = ()
        if tenant_id is not None:
            query += " AND team_id = %s"
            params = (tenant_id,)
        query += " ORDER BY created_at DESC"
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_key(row) for row in rows]

    def verify(self, raw_key: str) -> ApiKey | None:
        prefix = raw_key[:12]
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                """SELECT key_id, key_hash, key_salt, key_prefix, name, role, team_id, scopes, created_at, expires_at
                   FROM api_keys
                   WHERE key_prefix = %s AND revoked = FALSE""",
                (prefix,),
            ).fetchall()
        return verify_api_key(raw_key, [self._row_to_key(row) for row in rows])

    def has_keys(self) -> bool:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute("SELECT COUNT(*) FROM api_keys WHERE revoked = FALSE").fetchone()
            return bool(row and row[0] > 0)


# ── PostgresExceptionStore ─────────────────────────────────────────────────


class PostgresExceptionStore:
    """PostgreSQL-backed vulnerability exception storage with tenant RLS."""

    def __init__(self, pool=None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS exceptions (
                    exception_id TEXT PRIMARY KEY,
                    vuln_id TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    server_name TEXT NOT NULL DEFAULT '',
                    reason TEXT NOT NULL DEFAULT '',
                    requested_by TEXT NOT NULL DEFAULT '',
                    approved_by TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL DEFAULT '',
                    approved_at TEXT NOT NULL DEFAULT '',
                    revoked_at TEXT NOT NULL DEFAULT '',
                    team_id TEXT NOT NULL DEFAULT 'default'
                )
            """)
            conn.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'exceptions' AND column_name = 'team_id'
                    ) THEN
                        ALTER TABLE exceptions ADD COLUMN team_id TEXT NOT NULL DEFAULT 'default';
                    END IF;
                END
                $$;
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_exc_status ON exceptions(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_exc_team ON exceptions(team_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_exc_vuln ON exceptions(vuln_id)")
            _ensure_tenant_rls(conn, "exceptions", "team_id")
            conn.commit()

    @staticmethod
    def _row_to_exception(row) -> VulnException:
        return VulnException(
            exception_id=row[0],
            vuln_id=row[1],
            package_name=row[2],
            server_name=row[3],
            reason=row[4],
            requested_by=row[5],
            approved_by=row[6],
            status=ExceptionStatus(row[7]),
            created_at=row[8],
            expires_at=row[9],
            approved_at=row[10],
            revoked_at=row[11],
            tenant_id=row[12],
        )

    def put(self, exc: VulnException) -> None:
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """INSERT INTO exceptions
                   (exception_id, vuln_id, package_name, server_name, reason, requested_by, approved_by, status,
                    created_at, expires_at, approved_at, revoked_at, team_id)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (exception_id) DO UPDATE SET
                     vuln_id = EXCLUDED.vuln_id,
                     package_name = EXCLUDED.package_name,
                     server_name = EXCLUDED.server_name,
                     reason = EXCLUDED.reason,
                     requested_by = EXCLUDED.requested_by,
                     approved_by = EXCLUDED.approved_by,
                     status = EXCLUDED.status,
                     created_at = EXCLUDED.created_at,
                     expires_at = EXCLUDED.expires_at,
                     approved_at = EXCLUDED.approved_at,
                     revoked_at = EXCLUDED.revoked_at,
                     team_id = EXCLUDED.team_id""",
                (
                    exc.exception_id,
                    exc.vuln_id,
                    exc.package_name,
                    exc.server_name,
                    exc.reason,
                    exc.requested_by,
                    exc.approved_by,
                    exc.status.value,
                    exc.created_at,
                    exc.expires_at,
                    exc.approved_at,
                    exc.revoked_at,
                    exc.tenant_id,
                ),
            )
            conn.commit()

    def get(self, exception_id: str) -> VulnException | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                """SELECT exception_id, vuln_id, package_name, server_name, reason, requested_by, approved_by,
                          status, created_at, expires_at, approved_at, revoked_at, team_id
                   FROM exceptions
                   WHERE exception_id = %s""",
                (exception_id,),
            ).fetchone()
            return self._row_to_exception(row) if row else None

    def delete(self, exception_id: str) -> bool:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute("DELETE FROM exceptions WHERE exception_id = %s", (exception_id,))
            conn.commit()
            return cursor.rowcount > 0

    def list_all(self, status: str | None = None, tenant_id: str = "default") -> list[VulnException]:
        query = """
            SELECT exception_id, vuln_id, package_name, server_name, reason, requested_by, approved_by,
                   status, created_at, expires_at, approved_at, revoked_at, team_id
            FROM exceptions
            WHERE team_id = %s
        """
        params: list[object] = [tenant_id]
        if status:
            query += " AND status = %s"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
            return [self._row_to_exception(row) for row in rows]

    def find_matching(self, vuln_id: str, package_name: str, server_name: str = "", tenant_id: str = "default") -> VulnException | None:
        active = self.list_all(status="active", tenant_id=tenant_id)
        approved = self.list_all(status="approved", tenant_id=tenant_id)
        for exc in active + approved:
            if exc.matches(vuln_id, package_name, server_name):
                return exc
        return None


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


# ── PostgresAuditLog ──────────────────────────────────────────────────────


class PostgresAuditLog:
    """PostgreSQL-backed append-only audit log."""

    def __init__(self, pool=None) -> None:
        self._pool = pool or _get_pool()
        self._last_sig_by_tenant: dict[str, str] = {}
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    entry_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL DEFAULT '',
                    resource TEXT NOT NULL DEFAULT '',
                    team_id TEXT NOT NULL DEFAULT 'default',
                    details JSONB NOT NULL DEFAULT '{}'::jsonb,
                    prev_signature TEXT NOT NULL DEFAULT '',
                    hmac_signature TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(timestamp DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_resource ON audit_log(resource)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_team_ts ON audit_log(team_id, timestamp DESC)")
            _ensure_tenant_rls(conn, "audit_log", "team_id")
            conn.commit()

    def _latest_signature_for_tenant(self, tenant_id: str) -> str:
        with self._pool.connection() as conn:
            row = conn.execute(
                "SELECT hmac_signature FROM audit_log WHERE team_id = %s ORDER BY timestamp DESC LIMIT 1",
                (tenant_id,),
            ).fetchone()
        return row[0] if row else ""

    def append(self, entry: AuditEntry) -> None:
        tenant_id = str((entry.details or {}).get("tenant_id") or _current_tenant.get())
        prev_sig = self._last_sig_by_tenant.get(tenant_id)
        if not prev_sig:
            prev_sig = self._latest_signature_for_tenant(tenant_id)
        entry.prev_signature = prev_sig
        entry.sign()
        self._last_sig_by_tenant[tenant_id] = entry.hmac_signature
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """INSERT INTO audit_log
                   (entry_id, timestamp, action, actor, resource, team_id, details, prev_signature, hmac_signature)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    entry.entry_id,
                    entry.timestamp,
                    entry.action,
                    entry.actor,
                    entry.resource,
                    tenant_id,
                    json.dumps(entry.details),
                    entry.prev_signature,
                    entry.hmac_signature,
                ),
            )
            conn.commit()

    def list_entries(
        self,
        action: str | None = None,
        resource: str | None = None,
        since: str | None = None,
        limit: int = 100,
        offset: int = 0,
        tenant_id: str | None = None,
    ) -> list[AuditEntry]:
        clauses: list[str] = []
        params: list[object] = []
        if tenant_id is not None:
            clauses.append("team_id = %s")
            params.append(tenant_id)
        if action:
            clauses.append("action = %s")
            params.append(action)
        if resource:
            clauses.append("resource LIKE %s")
            params.append(f"{resource}%")
        if since:
            clauses.append("timestamp >= %s")
            params.append(since)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            "SELECT entry_id, timestamp, action, actor, resource, details, prev_signature, hmac_signature "
            f"FROM audit_log{where} ORDER BY timestamp DESC LIMIT %s OFFSET %s"  # nosec B608
        )
        params.extend([limit, offset])
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
        return [
            AuditEntry(
                entry_id=row[0],
                timestamp=row[1],
                action=row[2],
                actor=row[3],
                resource=row[4],
                details=row[5] if isinstance(row[5], dict) else json.loads(row[5]),
                prev_signature=row[6],
                hmac_signature=row[7],
            )
            for row in rows
        ]

    def count(self, action: str | None = None, tenant_id: str | None = None) -> int:
        sql = "SELECT COUNT(*) FROM audit_log"
        clauses: list[str] = []
        params: list[object] = []
        if tenant_id is not None:
            clauses.append("team_id = %s")
            params.append(tenant_id)
        if action:
            clauses.append("action = %s")
            params.append(action)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(sql, tuple(params)).fetchone()
        return row[0] if row else 0

    def verify_integrity(self, limit: int = 1000, tenant_id: str | None = None) -> tuple[int, int]:
        entries = list(reversed(self.list_entries(limit=limit, tenant_id=tenant_id)))
        verified = 0
        tampered = 0
        prev_sig = entries[0].prev_signature if entries else ""
        for entry in entries:
            if entry.prev_signature != prev_sig or not entry.verify():
                tampered += 1
            else:
                verified += 1
            prev_sig = entry.hmac_signature
        return verified, tampered


# ── PostgresTrendStore ─────────────────────────────────────────────────────


class PostgresTrendStore:
    """PostgreSQL-backed trend history persistence."""

    def __init__(self, pool=None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS trend_history (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    team_id TEXT NOT NULL DEFAULT 'default',
                    total_vulns INTEGER NOT NULL,
                    critical INTEGER NOT NULL DEFAULT 0,
                    high INTEGER NOT NULL DEFAULT 0,
                    medium INTEGER NOT NULL DEFAULT 0,
                    low INTEGER NOT NULL DEFAULT 0,
                    posture_score REAL NOT NULL DEFAULT 0,
                    posture_grade TEXT NOT NULL DEFAULT ''
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_trend_history_team_ts ON trend_history(team_id, timestamp DESC)")
            _ensure_tenant_rls(conn, "trend_history", "team_id")
            conn.commit()

    def record(self, point: TrendPoint) -> None:
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """INSERT INTO trend_history
                   (timestamp, team_id, total_vulns, critical, high, medium, low, posture_score, posture_grade)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    point.timestamp,
                    _current_tenant.get(),
                    point.total_vulns,
                    point.critical,
                    point.high,
                    point.medium,
                    point.low,
                    point.posture_score,
                    point.posture_grade,
                ),
            )
            conn.commit()

    def get_history(self, limit: int = 30) -> list[TrendPoint]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT timestamp, total_vulns, critical, high, medium, low, posture_score, posture_grade "
                "FROM trend_history ORDER BY timestamp DESC LIMIT %s",
                (limit,),
            ).fetchall()
        return [
            TrendPoint(
                timestamp=row[0],
                total_vulns=row[1],
                critical=row[2],
                high=row[3],
                medium=row[4],
                low=row[5],
                posture_score=row[6],
                posture_grade=row[7],
            )
            for row in rows
        ]


# ── PostgresScanCache ─────────────────────────────────────────────────────


class PostgresGraphStore:
    """PostgreSQL-backed unified graph persistence and query store."""

    def __init__(self, pool=None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS graph_nodes (
                    id TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    label TEXT NOT NULL,
                    category_uid INTEGER DEFAULT 0,
                    class_uid INTEGER DEFAULT 0,
                    type_uid INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'active',
                    risk_score DOUBLE PRECISION DEFAULT 0.0,
                    severity TEXT DEFAULT '',
                    severity_id INTEGER DEFAULT 0,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    attributes TEXT DEFAULT '{}',
                    compliance_tags TEXT DEFAULT '[]',
                    data_sources TEXT DEFAULT '[]',
                    dimensions TEXT DEFAULT '{}',
                    scan_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    PRIMARY KEY (id, scan_id, tenant_id)
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pg_graph_nodes_entity_type ON graph_nodes(entity_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pg_graph_nodes_scan ON graph_nodes(tenant_id, scan_id)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS graph_edges (
                    source_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    relationship TEXT NOT NULL,
                    direction TEXT DEFAULT 'directed',
                    weight DOUBLE PRECISION DEFAULT 1.0,
                    traversable INTEGER DEFAULT 1,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    evidence TEXT DEFAULT '{}',
                    activity_id INTEGER DEFAULT 1,
                    scan_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    PRIMARY KEY (source_id, target_id, relationship, scan_id, tenant_id)
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pg_graph_edges_scan ON graph_edges(tenant_id, scan_id)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS graph_snapshots (
                    scan_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    created_at TEXT NOT NULL,
                    node_count INTEGER DEFAULT 0,
                    edge_count INTEGER DEFAULT 0,
                    risk_summary TEXT DEFAULT '{}',
                    PRIMARY KEY (scan_id, tenant_id)
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pg_graph_snapshots_recent ON graph_snapshots(tenant_id, created_at DESC)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS attack_paths (
                    source_node TEXT NOT NULL,
                    target_node TEXT NOT NULL,
                    hop_count INTEGER DEFAULT 0,
                    composite_risk DOUBLE PRECISION DEFAULT 0.0,
                    path_nodes TEXT DEFAULT '[]',
                    path_edges TEXT DEFAULT '[]',
                    credential_exposure TEXT DEFAULT '[]',
                    vuln_ids TEXT DEFAULT '[]',
                    scan_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    computed_at TEXT NOT NULL,
                    PRIMARY KEY (source_node, target_node, scan_id, tenant_id)
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pg_attack_paths_scan ON attack_paths(tenant_id, scan_id)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS interaction_risks (
                    pattern TEXT NOT NULL,
                    agents TEXT NOT NULL,
                    risk_score DOUBLE PRECISION DEFAULT 0.0,
                    description TEXT DEFAULT '',
                    owasp_agentic_tag TEXT DEFAULT NULL,
                    scan_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    PRIMARY KEY (pattern, agents, scan_id, tenant_id)
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pg_interaction_risks_scan ON interaction_risks(tenant_id, scan_id)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS graph_filter_presets (
                    name TEXT NOT NULL,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    description TEXT DEFAULT '',
                    filters TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (name, tenant_id)
                )
                """
            )
            _ensure_tenant_rls(conn, "graph_nodes", "tenant_id")
            _ensure_tenant_rls(conn, "graph_edges", "tenant_id")
            _ensure_tenant_rls(conn, "graph_snapshots", "tenant_id")
            _ensure_tenant_rls(conn, "attack_paths", "tenant_id")
            _ensure_tenant_rls(conn, "interaction_risks", "tenant_id")
            _ensure_tenant_rls(conn, "graph_filter_presets", "tenant_id")
            conn.commit()

    def latest_snapshot_id(self, *, tenant_id: str = "") -> str:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                """
                SELECT scan_id
                FROM graph_snapshots
                WHERE tenant_id = %s
                ORDER BY created_at DESC, scan_id DESC
                LIMIT 1
                """,
                (tenant_id,),
            ).fetchone()
            return str(row[0]) if row else ""

    @staticmethod
    def _node_from_row(row):
        from agent_bom.graph import EntityType, NodeDimensions, NodeStatus, UnifiedNode

        return UnifiedNode(
            id=row[0],
            entity_type=EntityType(row[1]),
            label=row[2],
            category_uid=row[3],
            class_uid=row[4],
            type_uid=row[5],
            status=NodeStatus(row[6]),
            risk_score=row[7],
            severity=row[8] or "",
            severity_id=row[9],
            first_seen=row[10],
            last_seen=row[11],
            attributes=json.loads(row[12]),
            compliance_tags=json.loads(row[13]),
            data_sources=json.loads(row[14]),
            dimensions=NodeDimensions.from_dict(json.loads(row[15])),
        )

    def previous_snapshot_id(self, *, tenant_id: str = "", before_scan_id: str = "") -> str:
        if not before_scan_id:
            return ""
        with _tenant_connection(self._pool) as conn:
            current = conn.execute(
                "SELECT created_at FROM graph_snapshots WHERE tenant_id = %s AND scan_id = %s",
                (tenant_id, before_scan_id),
            ).fetchone()
            if not current:
                return ""
            row = conn.execute(
                """
                SELECT scan_id
                FROM graph_snapshots
                WHERE tenant_id = %s AND created_at < %s
                ORDER BY created_at DESC, scan_id DESC
                LIMIT 1
                """,
                (tenant_id, current[0]),
            ).fetchone()
            return str(row[0]) if row else ""

    def save_graph(self, graph) -> None:
        from agent_bom.graph import RelationshipType

        scan = graph.scan_id or ""
        tenant = graph.tenant_id or "default"
        now = graph.created_at or datetime.now(timezone.utc).isoformat()

        with _tenant_connection(self._pool) as conn:
            for node in graph.nodes.values():
                conn.execute(
                    """
                    INSERT INTO graph_nodes (
                        id, entity_type, label, category_uid, class_uid, type_uid,
                        status, risk_score, severity, severity_id,
                        first_seen, last_seen, attributes, compliance_tags,
                        data_sources, dimensions, scan_id, tenant_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id, scan_id, tenant_id) DO UPDATE SET
                        entity_type = EXCLUDED.entity_type,
                        label = EXCLUDED.label,
                        category_uid = EXCLUDED.category_uid,
                        class_uid = EXCLUDED.class_uid,
                        type_uid = EXCLUDED.type_uid,
                        status = EXCLUDED.status,
                        risk_score = EXCLUDED.risk_score,
                        severity = EXCLUDED.severity,
                        severity_id = EXCLUDED.severity_id,
                        first_seen = EXCLUDED.first_seen,
                        last_seen = EXCLUDED.last_seen,
                        attributes = EXCLUDED.attributes,
                        compliance_tags = EXCLUDED.compliance_tags,
                        data_sources = EXCLUDED.data_sources,
                        dimensions = EXCLUDED.dimensions
                    """,
                    (
                        node.id,
                        node.entity_type.value if hasattr(node.entity_type, "value") else node.entity_type,
                        node.label,
                        node.category_uid,
                        node.class_uid,
                        node.type_uid,
                        node.status.value if hasattr(node.status, "value") else node.status,
                        node.risk_score,
                        node.severity,
                        node.severity_id,
                        node.first_seen,
                        node.last_seen,
                        json.dumps(node.attributes, default=str),
                        json.dumps(node.compliance_tags),
                        json.dumps(node.data_sources),
                        json.dumps(node.dimensions.to_dict()),
                        scan,
                        tenant,
                    ),
                )

            for edge in graph.edges:
                rel = edge.relationship.value if isinstance(edge.relationship, RelationshipType) else edge.relationship
                conn.execute(
                    """
                    INSERT INTO graph_edges (
                        source_id, target_id, relationship, direction, weight,
                        traversable, first_seen, last_seen, evidence,
                        activity_id, scan_id, tenant_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (source_id, target_id, relationship, scan_id, tenant_id) DO UPDATE SET
                        direction = EXCLUDED.direction,
                        weight = EXCLUDED.weight,
                        traversable = EXCLUDED.traversable,
                        first_seen = EXCLUDED.first_seen,
                        last_seen = EXCLUDED.last_seen,
                        evidence = EXCLUDED.evidence,
                        activity_id = EXCLUDED.activity_id
                    """,
                    (
                        edge.source,
                        edge.target,
                        rel,
                        edge.direction,
                        edge.weight,
                        1 if edge.traversable else 0,
                        edge.first_seen,
                        edge.last_seen,
                        json.dumps(edge.evidence, default=str),
                        edge.activity_id,
                        scan,
                        tenant,
                    ),
                )

            for ap in graph.attack_paths:
                conn.execute(
                    """
                    INSERT INTO attack_paths (
                        source_node, target_node, hop_count, composite_risk,
                        path_nodes, path_edges, credential_exposure, vuln_ids,
                        scan_id, tenant_id, computed_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (source_node, target_node, scan_id, tenant_id) DO UPDATE SET
                        hop_count = EXCLUDED.hop_count,
                        composite_risk = EXCLUDED.composite_risk,
                        path_nodes = EXCLUDED.path_nodes,
                        path_edges = EXCLUDED.path_edges,
                        credential_exposure = EXCLUDED.credential_exposure,
                        vuln_ids = EXCLUDED.vuln_ids,
                        computed_at = EXCLUDED.computed_at
                    """,
                    (
                        ap.source,
                        ap.target,
                        len(ap.hops),
                        ap.composite_risk,
                        json.dumps(ap.hops),
                        json.dumps(ap.edges),
                        json.dumps(ap.credential_exposure),
                        json.dumps(ap.vuln_ids),
                        scan,
                        tenant,
                        now,
                    ),
                )

            for ir in graph.interaction_risks:
                conn.execute(
                    """
                    INSERT INTO interaction_risks (
                        pattern, agents, risk_score, description,
                        owasp_agentic_tag, scan_id, tenant_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (pattern, agents, scan_id, tenant_id) DO UPDATE SET
                        risk_score = EXCLUDED.risk_score,
                        description = EXCLUDED.description,
                        owasp_agentic_tag = EXCLUDED.owasp_agentic_tag
                    """,
                    (
                        ir.pattern,
                        json.dumps(sorted(ir.agents)),
                        ir.risk_score,
                        ir.description,
                        ir.owasp_agentic_tag,
                        scan,
                        tenant,
                    ),
                )

            stats = graph.stats()
            conn.execute(
                """
                INSERT INTO graph_snapshots (scan_id, tenant_id, created_at, node_count, edge_count, risk_summary)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (scan_id, tenant_id) DO UPDATE SET
                    created_at = EXCLUDED.created_at,
                    node_count = EXCLUDED.node_count,
                    edge_count = EXCLUDED.edge_count,
                    risk_summary = EXCLUDED.risk_summary
                """,
                (
                    scan,
                    tenant,
                    now,
                    stats["total_nodes"],
                    stats["total_edges"],
                    json.dumps(stats.get("severity_counts", {})),
                ),
            )
            conn.commit()

    def load_graph(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
    ):
        from agent_bom.graph import (
            SEVERITY_RANK,
            AttackPath,
            InteractionRisk,
            RelationshipType,
            UnifiedEdge,
            UnifiedGraph,
        )

        effective_scan_id = scan_id or self.latest_snapshot_id(tenant_id=tenant_id)
        if not effective_scan_id:
            return UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id)

        with _tenant_connection(self._pool) as conn:
            snapshot_row = conn.execute(
                "SELECT created_at FROM graph_snapshots WHERE scan_id = %s AND tenant_id = %s",
                (effective_scan_id, tenant_id),
            ).fetchone()
            graph = UnifiedGraph(scan_id=effective_scan_id, tenant_id=tenant_id, created_at=str(snapshot_row[0]) if snapshot_row else "")

            query = (
                "SELECT id, entity_type, label, category_uid, class_uid, type_uid, status, risk_score, severity, severity_id, "
                "first_seen, last_seen, attributes, compliance_tags, data_sources, dimensions "
                "FROM graph_nodes WHERE tenant_id = %s AND scan_id = %s"
            )
            params: list[Any] = [tenant_id, effective_scan_id]
            if entity_types:
                placeholders = ",".join(["%s"] * len(entity_types))
                query += f" AND entity_type IN ({placeholders})"
                params.extend(sorted(entity_types))

            node_ids: set[str] = set()
            for row in conn.execute(query, params).fetchall():
                severity = row[8] or ""
                if min_severity_rank and SEVERITY_RANK.get(severity, 0) < min_severity_rank:
                    continue
                graph.add_node(self._node_from_row(row))
                node_ids.add(row[0])

            for row in conn.execute(
                """
                SELECT source_id, target_id, relationship, direction, weight, traversable,
                       first_seen, last_seen, evidence, activity_id
                FROM graph_edges
                WHERE tenant_id = %s AND scan_id = %s
                """,
                (tenant_id, effective_scan_id),
            ).fetchall():
                if row[0] not in node_ids or row[1] not in node_ids:
                    continue
                graph.add_edge(
                    UnifiedEdge(
                        source=row[0],
                        target=row[1],
                        relationship=RelationshipType(row[2]),
                        direction=row[3],
                        weight=row[4],
                        traversable=bool(row[5]),
                        first_seen=row[6],
                        last_seen=row[7],
                        evidence=json.loads(row[8]),
                        activity_id=row[9],
                    )
                )

            for row in conn.execute(
                """
                SELECT source_node, target_node, path_nodes, path_edges, composite_risk, credential_exposure, vuln_ids
                FROM attack_paths
                WHERE tenant_id = %s AND scan_id = %s
                """,
                (tenant_id, effective_scan_id),
            ).fetchall():
                graph.attack_paths.append(
                    AttackPath(
                        source=row[0],
                        target=row[1],
                        hops=json.loads(row[2]),
                        edges=json.loads(row[3]),
                        composite_risk=row[4],
                        credential_exposure=json.loads(row[5]),
                        vuln_ids=json.loads(row[6]),
                    )
                )

            for row in conn.execute(
                """
                SELECT pattern, agents, risk_score, description, owasp_agentic_tag
                FROM interaction_risks
                WHERE tenant_id = %s AND scan_id = %s
                """,
                (tenant_id, effective_scan_id),
            ).fetchall():
                graph.interaction_risks.append(
                    InteractionRisk(
                        pattern=row[0],
                        agents=json.loads(row[1]),
                        risk_score=row[2],
                        description=row[3],
                        owasp_agentic_tag=row[4],
                    )
                )

            return graph

    def diff_snapshots(self, scan_id_old: str, scan_id_new: str, *, tenant_id: str = "") -> dict[str, Any]:
        with _tenant_connection(self._pool) as conn:
            old_nodes = {
                row[0]: {"severity": row[1], "risk_score": row[2]}
                for row in conn.execute(
                    "SELECT id, severity, risk_score FROM graph_nodes WHERE scan_id = %s AND tenant_id = %s",
                    (scan_id_old, tenant_id),
                ).fetchall()
            }
            new_nodes = {
                row[0]: {"severity": row[1], "risk_score": row[2]}
                for row in conn.execute(
                    "SELECT id, severity, risk_score FROM graph_nodes WHERE scan_id = %s AND tenant_id = %s",
                    (scan_id_new, tenant_id),
                ).fetchall()
            }
            old_ids, new_ids = set(old_nodes), set(new_nodes)
            old_edges = {
                (row[0], row[1], row[2])
                for row in conn.execute(
                    "SELECT source_id, target_id, relationship FROM graph_edges WHERE scan_id = %s AND tenant_id = %s",
                    (scan_id_old, tenant_id),
                ).fetchall()
            }
            new_edges = {
                (row[0], row[1], row[2])
                for row in conn.execute(
                    "SELECT source_id, target_id, relationship FROM graph_edges WHERE scan_id = %s AND tenant_id = %s",
                    (scan_id_new, tenant_id),
                ).fetchall()
            }
            return {
                "nodes_added": sorted(new_ids - old_ids),
                "nodes_removed": sorted(old_ids - new_ids),
                "nodes_changed": sorted(nid for nid in (old_ids & new_ids) if old_nodes[nid] != new_nodes[nid]),
                "edges_added": sorted(new_edges - old_edges),
                "edges_removed": sorted(old_edges - new_edges),
            }

    def list_snapshots(self, *, tenant_id: str = "", limit: int = 50) -> list[dict[str, Any]]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                """
                SELECT scan_id, created_at, node_count, edge_count, risk_summary
                FROM graph_snapshots
                WHERE tenant_id = %s
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (tenant_id, limit),
            ).fetchall()
            return [
                {
                    "scan_id": row[0],
                    "created_at": row[1],
                    "node_count": row[2],
                    "edge_count": row[3],
                    "risk_summary": json.loads(row[4]),
                }
                for row in rows
            ]

    def search_nodes(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        query: str,
        offset: int = 0,
        limit: int = 50,
    ):
        effective_scan_id = scan_id or self.latest_snapshot_id(tenant_id=tenant_id)
        if not effective_scan_id:
            return [], 0

        like = f"%{_escape_like_query(query.lower())}%"
        with _tenant_connection(self._pool) as conn:
            where = """
                FROM graph_nodes
                WHERE tenant_id = %s AND scan_id = %s
                  AND (
                    LOWER(id) LIKE %s ESCAPE '\\' OR
                    LOWER(label) LIKE %s ESCAPE '\\' OR
                    LOWER(entity_type) LIKE %s ESCAPE '\\' OR
                    LOWER(severity) LIKE %s ESCAPE '\\' OR
                    LOWER(compliance_tags) LIKE %s ESCAPE '\\' OR
                    LOWER(data_sources) LIKE %s ESCAPE '\\' OR
                    LOWER(attributes) LIKE %s ESCAPE '\\' OR
                    LOWER(dimensions) LIKE %s ESCAPE '\\'
                  )
            """
            params: list[Any] = [tenant_id, effective_scan_id, like, like, like, like, like, like, like, like]
            total_row = conn.execute("SELECT COUNT(*) " + where, params).fetchone()
            rows = conn.execute(
                """
                SELECT
                    id, entity_type, label, category_uid, class_uid, type_uid,
                    status, risk_score, severity, severity_id, first_seen, last_seen,
                    attributes, compliance_tags, data_sources, dimensions
                """
                + where
                + """
                ORDER BY severity_id DESC, risk_score DESC, label ASC
                LIMIT %s OFFSET %s
                """,
                [*params, limit, offset],
            ).fetchall()
            return [self._node_from_row(row) for row in rows], int(total_row[0] if total_row else 0)

    def save_preset(self, *, tenant_id: str, name: str, description: str, filters: dict[str, Any], created_at: str) -> None:
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """
                INSERT INTO graph_filter_presets (name, tenant_id, description, filters, created_at)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (name, tenant_id) DO UPDATE SET
                    description = EXCLUDED.description,
                    filters = EXCLUDED.filters,
                    created_at = EXCLUDED.created_at
                """,
                (name, tenant_id, description, json.dumps(filters), created_at),
            )
            conn.commit()

    def list_presets(self, *, tenant_id: str) -> list[dict[str, Any]]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT name, description, filters, created_at FROM graph_filter_presets WHERE tenant_id = %s ORDER BY name",
                (tenant_id,),
            ).fetchall()
            return [
                {
                    "name": row[0],
                    "description": row[1],
                    "filters": json.loads(row[2]),
                    "created_at": row[3],
                }
                for row in rows
            ]

    def delete_preset(self, *, tenant_id: str, name: str) -> bool:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                "DELETE FROM graph_filter_presets WHERE name = %s AND tenant_id = %s",
                (name, tenant_id),
            )
            conn.commit()
            return (cursor.rowcount or 0) > 0


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
        from agent_bom.package_utils import normalize_package_name

        return f"{ecosystem}:{normalize_package_name(name, ecosystem)}@{version}"
