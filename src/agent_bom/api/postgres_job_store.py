"""PostgreSQL-backed scan job persistence.

Split out of ``postgres_store.py`` (issue #1522) with no behavior change;
``postgres_store`` re-exports :class:`PostgresJobStore` for import stability.

Requires ``pip install 'agent-bom[postgres]'``.
"""

from __future__ import annotations

import json

from agent_bom.api.postgres_common import (
    _ensure_tenant_rls,
    _get_pool,
    _tenant_connection,
    reset_current_tenant,
    set_current_tenant,
)
from agent_bom.api.storage_schema import ensure_postgres_schema_version
from agent_bom.api.store import _require_tenant_scope

_JOB_TTL_SECONDS = 3600


class PostgresJobStore:
    """PostgreSQL-backed scan job persistence."""

    retains_job_objects_in_memory = False

    def __init__(self, pool=None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            if not ensure_postgres_schema_version(conn, "scan_jobs"):
                return
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

    def get(self, job_id: str, tenant_id: str | None = None, *, all_tenants: bool = False):
        from .server import ScanJob

        _require_tenant_scope(tenant_id, all_tenants, "PostgresJobStore.get()")
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

    def delete(self, job_id: str, tenant_id: str | None = None, *, all_tenants: bool = False) -> bool:
        _require_tenant_scope(tenant_id, all_tenants, "PostgresJobStore.delete()")
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

    def list_all(self, tenant_id: str | None = None, *, all_tenants: bool = False) -> list:
        from .server import ScanJob

        _require_tenant_scope(tenant_id, all_tenants, "PostgresJobStore.list_all()")

        with _tenant_connection(self._pool) as conn:
            if tenant_id is None:
                rows = conn.execute("SELECT data FROM scan_jobs ORDER BY created_at DESC").fetchall()
            else:
                rows = conn.execute(
                    "SELECT data FROM scan_jobs WHERE team_id = %s ORDER BY created_at DESC",
                    (tenant_id,),
                ).fetchall()
            return [ScanJob.model_validate_json(r[0] if isinstance(r[0], str) else json.dumps(r[0])) for r in rows]

    def list_summary(
        self,
        tenant_id: str | None = None,
        *,
        all_tenants: bool = False,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[dict]:
        _require_tenant_scope(tenant_id, all_tenants, "PostgresJobStore.list_summary()")

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
            # Each scan inserts a fresh set of rows keyed by its own scan_id
            # (the table is insert-only, deleted only per scan_id). Without a
            # latest-per-check filter, the compliance surface would stack every
            # historical scan's checks and show the same (cloud, check_id) N
            # times after N scans. DISTINCT ON collapses each logical check to
            # its most recent measurement; the outer query then restores the
            # caller's measured_at/priority ordering and applies pagination.
            rows = conn.execute(
                f"""SELECT scan_id, team_id, cloud, check_id, title, status, severity, cis_section, evidence,
                          resource_ids, remediation, fix_cli, fix_console, effort, priority, guardrails,
                          requires_human_review, measured_at
                   FROM (
                       SELECT DISTINCT ON (cloud, check_id)
                              scan_id, team_id, cloud, check_id, title, status, severity, cis_section, evidence,
                              resource_ids, remediation, fix_cli, fix_console, effort, priority, guardrails,
                              requires_human_review, measured_at
                       FROM cis_benchmark_checks
                       WHERE {" AND ".join(clauses)}
                       ORDER BY cloud, check_id, measured_at DESC
                   ) latest
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
