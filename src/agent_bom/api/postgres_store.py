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
    is_tenant_rls_bypassed,
    reset_current_tenant,
    reset_pool,
    set_current_tenant,
)
from agent_bom.api.postgres_cost import PostgresCostStore  # noqa: F401
from agent_bom.api.postgres_graph import PostgresGraphStore, PostgresScanCache
from agent_bom.api.postgres_policy import (  # noqa: F401
    PostgresCredentialRefStore,
    PostgresPolicyStore,
    PostgresScheduleStore,
    PostgresSourceStore,
)
from agent_bom.api.postgres_tenant_quota import PostgresTenantQuotaStore  # noqa: F401
from agent_bom.api.storage_schema import ensure_postgres_schema_version

_JOB_TTL_SECONDS = 3600


# ── PostgresJobStore ───────────────────────────────────────────────────────


class PostgresJobStore:
    """PostgreSQL-backed scan job persistence."""

    retains_job_objects_in_memory = False

    def __init__(self, pool=None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            ensure_postgres_schema_version(conn, "scan_jobs")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_jobs (
                    job_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    team_id TEXT NOT NULL DEFAULT 'default',
                    batch_id TEXT,
                    parent_job_id TEXT,
                    child_job_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
                    target JSONB,
                    target_index INTEGER,
                    target_count INTEGER,
                    schedule_id TEXT,
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
                        WHERE table_name = 'scan_jobs' AND column_name = 'schedule_id'
                    ) THEN
                        ALTER TABLE scan_jobs ADD COLUMN schedule_id TEXT;
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'scan_jobs' AND column_name = 'triggered_by'
                    ) THEN
                        ALTER TABLE scan_jobs ADD COLUMN triggered_by TEXT;
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'scan_jobs' AND column_name = 'batch_id'
                    ) THEN
                        ALTER TABLE scan_jobs ADD COLUMN batch_id TEXT;
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'scan_jobs' AND column_name = 'parent_job_id'
                    ) THEN
                        ALTER TABLE scan_jobs ADD COLUMN parent_job_id TEXT;
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'scan_jobs' AND column_name = 'child_job_ids'
                    ) THEN
                        ALTER TABLE scan_jobs ADD COLUMN child_job_ids JSONB NOT NULL DEFAULT '[]'::jsonb;
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'scan_jobs' AND column_name = 'target'
                    ) THEN
                        ALTER TABLE scan_jobs ADD COLUMN target JSONB;
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'scan_jobs' AND column_name = 'target_index'
                    ) THEN
                        ALTER TABLE scan_jobs ADD COLUMN target_index INTEGER;
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'scan_jobs' AND column_name = 'target_count'
                    ) THEN
                        ALTER TABLE scan_jobs ADD COLUMN target_count INTEGER;
                    END IF;
                END
                $$;
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cis_benchmark_checks (
                    id BIGSERIAL PRIMARY KEY,
                    scan_id TEXT NOT NULL REFERENCES scan_jobs(job_id) ON DELETE CASCADE,
                    team_id TEXT NOT NULL DEFAULT 'default',
                    cloud TEXT NOT NULL,
                    check_id TEXT NOT NULL,
                    title TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'unknown',
                    severity TEXT NOT NULL DEFAULT 'unknown',
                    cis_section TEXT NOT NULL DEFAULT '',
                    evidence TEXT NOT NULL DEFAULT '',
                    resource_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
                    remediation JSONB NOT NULL DEFAULT '{}'::jsonb,
                    fix_cli TEXT NOT NULL DEFAULT '',
                    fix_console TEXT NOT NULL DEFAULT '',
                    effort TEXT NOT NULL DEFAULT '',
                    priority INTEGER NOT NULL DEFAULT 0,
                    guardrails TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
                    requires_human_review BOOLEAN NOT NULL DEFAULT FALSE,
                    measured_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pg_jobs_team_created ON scan_jobs(team_id, created_at DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pg_jobs_batch ON scan_jobs(team_id, batch_id, created_at DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pg_jobs_parent ON scan_jobs(team_id, parent_job_id, created_at DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pg_jobs_schedule ON scan_jobs(team_id, schedule_id, created_at DESC)")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cis_checks_team_cloud_status_priority "
                "ON cis_benchmark_checks(team_id, cloud, status, priority, measured_at DESC)"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cis_checks_scan ON cis_benchmark_checks(scan_id)")
            # Shared dispatch queue for multi-replica scan work-stealing. Holds
            # only routing metadata (job_id + tenant_id + timing), never scan
            # content or results — those stay in the RLS-protected scan_jobs.data.
            # It is intentionally NOT tenant-RLS'd: the background claim-loop is a
            # system dispatcher that must see pending jobs across all tenants, and
            # it is never exposed through the API. The full job is loaded from
            # scan_jobs under the job's own tenant context (RLS-scoped) before it
            # runs, so tenant isolation of actual data is preserved.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_dispatch_queue (
                    job_id           TEXT PRIMARY KEY REFERENCES scan_jobs(job_id) ON DELETE CASCADE,
                    tenant_id        TEXT NOT NULL,
                    created_at       TEXT NOT NULL,
                    status           TEXT NOT NULL DEFAULT 'pending',
                    claimed_by       TEXT,
                    lease_expires_at TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_dispatch_pending ON scan_dispatch_queue(status, created_at)")
            _ensure_tenant_rls(conn, "scan_jobs", "team_id")
            _ensure_tenant_rls(conn, "cis_benchmark_checks", "team_id")
            conn.commit()

    def put(self, job) -> None:
        data = job.model_dump_json()
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """INSERT INTO scan_jobs (
                       job_id, status, created_at, completed_at, team_id, batch_id, parent_job_id,
                       child_job_ids, target, target_index, target_count, schedule_id, triggered_by, data
                   )
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s, %s, %s, %s, %s)
                   ON CONFLICT (job_id) DO UPDATE SET
                     status = EXCLUDED.status,
                     completed_at = EXCLUDED.completed_at,
                     team_id = EXCLUDED.team_id,
                     batch_id = EXCLUDED.batch_id,
                     parent_job_id = EXCLUDED.parent_job_id,
                     child_job_ids = EXCLUDED.child_job_ids,
                     target = EXCLUDED.target,
                     target_index = EXCLUDED.target_index,
                     target_count = EXCLUDED.target_count,
                     schedule_id = EXCLUDED.schedule_id,
                     triggered_by = EXCLUDED.triggered_by,
                     data = EXCLUDED.data""",
                (
                    job.job_id,
                    job.status.value,
                    job.created_at,
                    job.completed_at,
                    job.tenant_id,
                    getattr(job, "batch_id", None),
                    getattr(job, "parent_job_id", None),
                    json.dumps(getattr(job, "child_job_ids", []) or []),
                    json.dumps(getattr(job, "target", None)) if getattr(job, "target", None) is not None else None,
                    getattr(job, "target_index", None),
                    getattr(job, "target_count", None),
                    getattr(job, "schedule_id", None),
                    getattr(job, "triggered_by", None),
                    data,
                ),
            )
            self._replace_cis_checks(conn, job)
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

    def list_summary(
        self,
        tenant_id: str | None = None,
        *,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[dict]:
        def _json_column(row: tuple, index: int, default: str, expected_type: type) -> object:
            if len(row) <= index:
                return json.loads(default)
            value = row[index]
            if isinstance(value, expected_type):
                return value
            return json.loads(value or default)

        base_sql = """SELECT job_id, team_id, status, created_at, completed_at, triggered_by, schedule_id,
                             batch_id, parent_job_id, child_job_ids, target, target_index, target_count
                      FROM scan_jobs"""
        params: list[object] = []
        if tenant_id is None:
            sql = f"{base_sql} ORDER BY created_at DESC"
        else:
            sql = f"{base_sql} WHERE team_id = %s ORDER BY created_at DESC"
            params.append(tenant_id)
        if limit is not None:
            sql = f"{sql} LIMIT %s OFFSET %s"
            params.extend([max(1, int(limit)), max(0, int(offset))])

        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
            return [
                {
                    "job_id": row[0],
                    "tenant_id": row[1],
                    "status": row[2],
                    "created_at": row[3],
                    "completed_at": row[4],
                    "triggered_by": row[5] if len(row) > 5 else None,
                    "schedule_id": row[6] if len(row) > 6 else None,
                    "batch_id": row[7] if len(row) > 7 else None,
                    "parent_job_id": row[8] if len(row) > 8 else None,
                    "child_job_ids": _json_column(row, 9, "[]", list),
                    "target": _json_column(row, 10, "null", dict),
                    "target_index": row[11] if len(row) > 11 else None,
                    "target_count": row[12] if len(row) > 12 else None,
                }
                for row in rows
            ]

    def count_summary(self, tenant_id: str | None = None) -> int:
        with _tenant_connection(self._pool) as conn:
            if tenant_id is None:
                row = conn.execute("SELECT COUNT(*) FROM scan_jobs").fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) FROM scan_jobs WHERE team_id = %s", (tenant_id,)).fetchone()
        return int(row[0]) if row else 0

    def query_cis_benchmark_checks(
        self,
        tenant_id: str,
        *,
        cloud: str | None = None,
        status: str | None = None,
        priority: int | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        clauses = ["team_id = %s"]
        params: list[object] = [tenant_id]
        if cloud:
            clauses.append("cloud = %s")
            params.append(cloud)
        if status:
            clauses.append("status = %s")
            params.append(status)
        if priority is not None:
            clauses.append("priority = %s")
            params.append(int(priority))
        params.extend([max(1, min(int(limit), 500)), max(0, int(offset))])
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                f"""SELECT scan_id, team_id, cloud, check_id, title, status, severity, cis_section, evidence,
                          resource_ids, remediation, fix_cli, fix_console, effort, priority, guardrails,
                          requires_human_review, measured_at
                   FROM cis_benchmark_checks
                   WHERE {" AND ".join(clauses)}
                   ORDER BY measured_at DESC, priority ASC, cloud, check_id
                   LIMIT %s OFFSET %s""",  # nosec B608 - clauses are fixed fragments, values are parameters.
                params,
            ).fetchall()
        return [
            {
                "scan_id": row[0],
                "tenant_id": row[1],
                "cloud": row[2],
                "check_id": row[3],
                "title": row[4],
                "status": row[5],
                "severity": row[6],
                "cis_section": row[7],
                "evidence": row[8],
                "resource_ids": row[9] if isinstance(row[9], list) else json.loads(row[9] or "[]"),
                "remediation": row[10] if isinstance(row[10], dict) else json.loads(row[10] or "{}"),
                "fix_cli": row[11],
                "fix_console": row[12],
                "effort": row[13],
                "priority": row[14],
                "guardrails": list(row[15] or []),
                "requires_human_review": bool(row[16]),
                "measured_at": row[17],
            }
            for row in rows
        ]

    def aggregate_cis_benchmark_checks(
        self,
        tenant_id: str,
        *,
        days: int = 30,
        cloud: str | None = None,
        section: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        bucket: str = "day",
    ) -> list[dict]:
        """Time-bucketed CIS finding counts for trend / drilldown surfaces (#1832).

        Groups by ``(bucket, cloud, cis_section, status, severity)`` and returns
        the count of checks in each cell over the last ``days`` days. Indexed
        by the ``cis_benchmark_checks`` table's ``(team_id, cloud, status,
        priority, measured_at)`` index — the bucket truncation runs over the
        already-narrow tenant-and-time slice.

        ``bucket`` is one of ``hour`` / ``day`` / ``week`` and is whitelisted
        below; everything else falls back to ``day`` so a typo never injects
        SQL.
        """
        bucket_unit = {"hour": "hour", "day": "day", "week": "week"}.get(str(bucket).lower(), "day")
        clauses = ["team_id = %s", "measured_at >= now() - (%s * INTERVAL '1 day')"]
        params: list[object] = [tenant_id, max(1, min(int(days), 366))]
        if cloud:
            clauses.append("cloud = %s")
            params.append(cloud)
        if section:
            clauses.append("cis_section = %s")
            params.append(section)
        if status:
            clauses.append("status = %s")
            params.append(status)
        if severity:
            clauses.append("severity = %s")
            params.append(severity)
        # The bucket value is not user-supplied at the SQL layer (already
        # whitelisted above) so it's safe to interpolate here. Filter
        # values still flow through bound parameters.
        sql = (
            "SELECT date_trunc(%s, measured_at) AS bucket, cloud, cis_section, status, severity, COUNT(*)"
            f" FROM cis_benchmark_checks WHERE {' AND '.join(clauses)}"  # nosec B608
            " GROUP BY bucket, cloud, cis_section, status, severity"
            " ORDER BY bucket DESC, cloud, cis_section, status, severity"
        )
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(sql, [bucket_unit, *params]).fetchall()
        return [
            {
                "bucket": row[0].isoformat() if hasattr(row[0], "isoformat") else str(row[0]),
                "cloud": row[1],
                "cis_section": row[2],
                "status": row[3],
                "severity": row[4],
                "count": int(row[5]),
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

    # ── Distributed dispatch queue ────────────────────────────────────────
    # All lease timing uses the database clock (now()) rather than per-node
    # wall clocks, so a multi-replica fleet with skewed clocks still leases
    # and reclaims consistently.

    _NOW_ISO = "to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')"
    _LEASE_ISO = "to_char(now() AT TIME ZONE 'UTC' + (%s * INTERVAL '1 second'), 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')"

    def enqueue_for_dispatch(self, job) -> None:
        """Register a persisted job in the shared queue for work-stealing."""
        with self._pool.connection() as conn:
            conn.execute(
                """INSERT INTO scan_dispatch_queue (job_id, tenant_id, created_at, status)
                   VALUES (%s, %s, %s, 'pending')
                   ON CONFLICT (job_id) DO NOTHING""",
                (job.job_id, job.tenant_id or "default", job.created_at),
            )
            conn.commit()

    def claim_next(self, worker_id: str, lease_seconds: int):
        """Atomically claim the oldest claimable job and return its full ScanJob.

        Claims a ``pending`` row, or a ``running`` row whose lease has expired
        (the owning node died), using ``FOR UPDATE SKIP LOCKED`` so concurrent
        claimers on other replicas never block or double-claim. Returns ``None``
        when nothing is claimable.
        """
        with self._pool.connection() as conn:
            row = conn.execute(
                f"""SELECT job_id, tenant_id FROM scan_dispatch_queue
                    WHERE status = 'pending'
                       OR (status = 'running'
                           AND lease_expires_at IS NOT NULL
                           AND lease_expires_at < {self._NOW_ISO})
                    ORDER BY created_at ASC
                    FOR UPDATE SKIP LOCKED
                    LIMIT 1""",  # nosec B608 - _NOW_ISO is a fixed SQL fragment, no user input
            ).fetchone()
            if row is None:
                conn.commit()
                return None
            job_id, tenant_id = row[0], row[1]
            conn.execute(
                f"""UPDATE scan_dispatch_queue
                    SET status = 'running', claimed_by = %s, lease_expires_at = {self._LEASE_ISO}
                    WHERE job_id = %s""",  # nosec B608 - _LEASE_ISO is a fixed SQL fragment
                (worker_id, int(lease_seconds), job_id),
            )
            conn.commit()
        # Load the full job under its own tenant context so the RLS-scoped read
        # succeeds and the running job carries the correct tenant.
        token = set_current_tenant(tenant_id)
        try:
            return self.get(job_id, tenant_id=tenant_id)
        finally:
            reset_current_tenant(token)

    def renew_leases(self, job_ids, lease_seconds: int) -> None:
        """Extend the lease on the given in-flight jobs (heartbeat)."""
        ids = [j for j in job_ids]
        if not ids:
            return
        with self._pool.connection() as conn:
            conn.execute(
                f"""UPDATE scan_dispatch_queue
                    SET lease_expires_at = {self._LEASE_ISO}
                    WHERE status = 'running' AND job_id = ANY(%s)""",  # nosec B608 - fixed fragment
                (int(lease_seconds), ids),
            )
            conn.commit()

    def complete_dispatch(self, job_id: str) -> None:
        """Remove a finished job from the dispatch queue."""
        with self._pool.connection() as conn:
            conn.execute("DELETE FROM scan_dispatch_queue WHERE job_id = %s", (job_id,))
            conn.commit()

    def requeue_expired_leases(self) -> int:
        """Reset jobs whose lease expired (dead node) back to pending. Returns count."""
        with self._pool.connection() as conn:
            cursor = conn.execute(
                f"""UPDATE scan_dispatch_queue
                    SET status = 'pending', claimed_by = NULL, lease_expires_at = NULL
                    WHERE status = 'running'
                      AND lease_expires_at IS NOT NULL
                      AND lease_expires_at < {self._NOW_ISO}""",  # nosec B608 - fixed fragment
            )
            conn.commit()
            return cursor.rowcount

    def pending_dispatch_count(self) -> int:
        """Number of jobs waiting to be claimed (operator/metrics visibility)."""
        with self._pool.connection() as conn:
            row = conn.execute("SELECT COUNT(*) FROM scan_dispatch_queue WHERE status = 'pending'").fetchone()
            return int(row[0]) if row else 0

    def _replace_cis_checks(self, conn, job) -> None:
        result = getattr(job, "result", None)
        if not isinstance(result, dict):
            return
        from agent_bom.analytics_contract import build_cis_benchmark_check_rows

        tenant_id = str(getattr(job, "tenant_id", None) or "default")
        measured_at = getattr(job, "completed_at", None) or getattr(job, "created_at", None)
        rows = build_cis_benchmark_check_rows(result, str(job.job_id), measured_at=measured_at)
        conn.execute("DELETE FROM cis_benchmark_checks WHERE scan_id = %s AND team_id = %s", (job.job_id, tenant_id))
        for row in rows:
            conn.execute(
                """INSERT INTO cis_benchmark_checks (
                       scan_id, team_id, cloud, check_id, title, status, severity, cis_section, evidence,
                       resource_ids, remediation, fix_cli, fix_console, effort, priority, guardrails,
                       requires_human_review, measured_at
                   ) VALUES (
                       %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s, %s, %s, %s, %s, %s, %s
                   )""",
                (
                    job.job_id,
                    tenant_id,
                    row["cloud"],
                    row["check_id"],
                    row["title"],
                    row["status"],
                    row["severity"],
                    row["cis_section"],
                    row["evidence"],
                    json.dumps(row["resource_ids"]),
                    json.dumps(row["remediation"], sort_keys=True),
                    row["fix_cli"],
                    row["fix_console"],
                    row["effort"],
                    int(row["priority"]),
                    row["guardrails"],
                    bool(row["requires_human_review"]),
                    row["measured_at"] or getattr(job, "completed_at", None) or getattr(job, "created_at", ""),
                ),
            )


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
                    canonical_id TEXT NOT NULL DEFAULT '',
                    name TEXT NOT NULL,
                    lifecycle_state TEXT NOT NULL,
                    trust_score REAL DEFAULT 0.0,
                    tenant_id TEXT DEFAULT 'default',
                    updated_at TEXT NOT NULL,
                    data JSONB NOT NULL
                )
            """)
            conn.execute("ALTER TABLE fleet_agents ADD COLUMN IF NOT EXISTS canonical_id TEXT NOT NULL DEFAULT ''")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fleet_name ON fleet_agents(name)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fleet_canonical_id ON fleet_agents(canonical_id)")
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
                """INSERT INTO fleet_agents (agent_id, canonical_id, name, lifecycle_state, trust_score, tenant_id, updated_at, data)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (agent_id) DO UPDATE SET
                     canonical_id = EXCLUDED.canonical_id,
                     name = EXCLUDED.name,
                     lifecycle_state = EXCLUDED.lifecycle_state,
                     trust_score = EXCLUDED.trust_score,
                     tenant_id = EXCLUDED.tenant_id,
                     updated_at = EXCLUDED.updated_at,
                     data = EXCLUDED.data""",
                (
                    agent.agent_id,
                    agent.canonical_id,
                    agent.name,
                    agent.lifecycle_state.value,
                    agent.trust_score,
                    agent.tenant_id,
                    agent.updated_at,
                    data,
                ),
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

    def get_by_canonical_id(self, canonical_id: str, tenant_id: str | None = None):
        from .fleet_store import FleetAgent

        with _tenant_connection(self._pool) as conn:
            if tenant_id is None:
                row = conn.execute("SELECT data FROM fleet_agents WHERE canonical_id = %s", (canonical_id,)).fetchone()
            else:
                row = conn.execute(
                    "SELECT data FROM fleet_agents WHERE canonical_id = %s AND tenant_id = %s",
                    (canonical_id, tenant_id),
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
            rows = conn.execute(
                "SELECT agent_id, canonical_id, name, lifecycle_state, trust_score FROM fleet_agents ORDER BY name"
            ).fetchall()
            return [{"agent_id": r[0], "canonical_id": r[1], "name": r[2], "lifecycle_state": r[3], "trust_score": r[4]} for r in rows]

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
    "is_tenant_rls_bypassed",
    "reset_current_tenant",
    "reset_pool",
    "set_current_tenant",
]
