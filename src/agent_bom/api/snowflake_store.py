"""Snowflake-backed storage backends for agent-bom.

Provides pluggable Snowflake persistence for all four store protocols:
- ``SnowflakeJobStore``    — scan job persistence
- ``SnowflakeFleetStore``  — fleet agent lifecycle
- ``SnowflakeScheduleStore`` — recurring scan schedules
- ``SnowflakePolicyStore`` — gateway policies + audit log

Requires ``pip install 'agent-bom[snowflake]'``.

Auth auto-detection:
  - If ``SNOWFLAKE_PRIVATE_KEY_PATH`` is set → key-pair auth (recommended)
  - If ``SNOWFLAKE_AUTHENTICATOR`` is set → that authenticator (e.g. externalbrowser)
  - Otherwise falls back to SSO (externalbrowser) as safe default
  - ``SNOWFLAKE_PASSWORD`` is deprecated — emits a warning if used
"""

from __future__ import annotations

import json
import os
import warnings
from datetime import datetime, timezone

from .exception_store import ExceptionStatus, VulnException
from .fleet_store import FleetAgent, FleetLifecycleState
from .policy_store import GatewayPolicy, PolicyAuditEntry
from .server import ScanJob


def _sf_connect(**kwargs):  # type: ignore[no-untyped-def]
    """Lazy import of snowflake.connector.connect."""
    import snowflake.connector  # type: ignore[import-untyped]

    return snowflake.connector.connect(**kwargs)


_JOB_TTL_SECONDS = 3600


def build_connection_params() -> dict:
    """Build Snowflake connection params with auto-detected auth."""
    params: dict = {
        "account": os.environ["SNOWFLAKE_ACCOUNT"],
        "user": os.environ.get("SNOWFLAKE_USER", ""),
    }
    key_path = os.environ.get("SNOWFLAKE_PRIVATE_KEY_PATH")
    if key_path:
        params["private_key_file"] = key_path
        passphrase = os.environ.get("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE")
        if passphrase:
            params["private_key_file_pwd"] = passphrase
    elif os.environ.get("SNOWFLAKE_PASSWORD"):
        warnings.warn(
            "SNOWFLAKE_PASSWORD is deprecated. Migrate to key-pair (SNOWFLAKE_PRIVATE_KEY_PATH) or SSO.",
            DeprecationWarning,
            stacklevel=2,
        )
        params["password"] = os.environ["SNOWFLAKE_PASSWORD"]
    else:
        # Safe default — SSO via browser
        params["authenticator"] = "externalbrowser"
    params["database"] = os.environ.get("SNOWFLAKE_DATABASE", "AGENT_BOM")
    params["schema"] = os.environ.get("SNOWFLAKE_SCHEMA", "PUBLIC")
    return params


# ─── Job Store ────────────────────────────────────────────────────────────────


class SnowflakeJobStore:
    """Snowflake-backed scan job persistence."""

    retains_job_objects_in_memory = False

    def __init__(self, connection_params: dict) -> None:
        self._conn_params = connection_params
        self._init_tables()

    def _connect(self):  # type: ignore[no-untyped-def]
        return _sf_connect(**self._conn_params)

    def _init_tables(self) -> None:
        with self._connect() as conn:
            conn.cursor().execute("""
                CREATE TABLE IF NOT EXISTS scan_jobs (
                    job_id VARCHAR PRIMARY KEY,
                    status VARCHAR NOT NULL,
                    created_at TIMESTAMP_TZ NOT NULL,
                    completed_at TIMESTAMP_TZ,
                    tenant_id VARCHAR NOT NULL DEFAULT 'default',
                    data VARIANT NOT NULL
                )
            """)
            conn.cursor().execute("ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS tenant_id VARCHAR NOT NULL DEFAULT 'default'")

    def put(self, job: ScanJob) -> None:
        with self._connect() as conn:
            conn.cursor().execute(
                """MERGE INTO scan_jobs t USING (SELECT %s AS job_id) s
                   ON t.job_id = s.job_id
                   WHEN MATCHED THEN UPDATE SET
                     status = %s, created_at = %s, completed_at = %s, tenant_id = %s,
                     data = PARSE_JSON(%s)
                   WHEN NOT MATCHED THEN INSERT
                     (job_id, status, created_at, completed_at, tenant_id, data)
                     VALUES (%s, %s, %s, %s, %s, PARSE_JSON(%s))""",
                (
                    job.job_id,
                    job.status.value,
                    job.created_at,
                    job.completed_at,
                    job.tenant_id,
                    job.model_dump_json(),
                    job.job_id,
                    job.status.value,
                    job.created_at,
                    job.completed_at,
                    job.tenant_id,
                    job.model_dump_json(),
                ),
            )

    def get(self, job_id: str, tenant_id: str | None = None) -> ScanJob | None:
        with self._connect() as conn:
            cur = conn.cursor()
            if tenant_id is None:
                cur.execute("SELECT data FROM scan_jobs WHERE job_id = %s", (job_id,))
            else:
                cur.execute("SELECT data FROM scan_jobs WHERE job_id = %s AND tenant_id = %s", (job_id, tenant_id))
            row = cur.fetchone()
            if row is None:
                return None
            return ScanJob.model_validate_json(row[0] if isinstance(row[0], str) else json.dumps(row[0]))

    def delete(self, job_id: str, tenant_id: str | None = None) -> bool:
        with self._connect() as conn:
            cur = conn.cursor()
            if tenant_id is None:
                cur.execute("DELETE FROM scan_jobs WHERE job_id = %s", (job_id,))
            else:
                cur.execute("DELETE FROM scan_jobs WHERE job_id = %s AND tenant_id = %s", (job_id, tenant_id))
            return (cur.rowcount or 0) > 0

    def list_all(self, tenant_id: str | None = None) -> list[ScanJob]:
        with self._connect() as conn:
            cur = conn.cursor()
            if tenant_id is None:
                cur.execute("SELECT data FROM scan_jobs ORDER BY created_at DESC")
            else:
                cur.execute("SELECT data FROM scan_jobs WHERE tenant_id = %s ORDER BY created_at DESC", (tenant_id,))
            return [ScanJob.model_validate_json(r[0] if isinstance(r[0], str) else json.dumps(r[0])) for r in cur.fetchall()]

    def list_summary(self, tenant_id: str | None = None) -> list[dict]:
        with self._connect() as conn:
            cur = conn.cursor()
            if tenant_id is None:
                cur.execute("SELECT job_id, tenant_id, status, created_at, completed_at, data FROM scan_jobs ORDER BY created_at DESC")
            else:
                cur.execute(
                    """SELECT job_id, tenant_id, status, created_at, completed_at, data
                       FROM scan_jobs
                       WHERE tenant_id = %s
                       ORDER BY created_at DESC""",
                    (tenant_id,),
                )
            summaries: list[dict] = []
            for row in cur.fetchall():
                triggered_by = None
                if len(row) > 5:
                    job = ScanJob.model_validate_json(row[5] if isinstance(row[5], str) else json.dumps(row[5]))
                    triggered_by = job.triggered_by
                summaries.append(
                    {
                        "job_id": row[0],
                        "tenant_id": row[1],
                        "triggered_by": triggered_by,
                        "status": row[2],
                        "created_at": str(row[3]) if row[3] else None,
                        "completed_at": str(row[4]) if row[4] else None,
                    }
                )
            return summaries

    def cleanup_expired(self, ttl_seconds: int = _JOB_TTL_SECONDS) -> int:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """DELETE FROM scan_jobs
                   WHERE status IN ('done', 'failed', 'cancelled')
                     AND completed_at IS NOT NULL
                     AND TIMESTAMPDIFF(SECOND, completed_at, CURRENT_TIMESTAMP()) > %s""",
                (ttl_seconds,),
            )
            return cur.rowcount or 0


# ─── Fleet Store ──────────────────────────────────────────────────────────────


class SnowflakeFleetStore:
    """Snowflake-backed fleet agent persistence."""

    def __init__(self, connection_params: dict) -> None:
        self._conn_params = connection_params
        self._init_tables()

    def _connect(self):  # type: ignore[no-untyped-def]
        return _sf_connect(**self._conn_params)

    def _init_tables(self) -> None:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS fleet_agents (
                    agent_id VARCHAR PRIMARY KEY,
                    name VARCHAR NOT NULL,
                    lifecycle_state VARCHAR NOT NULL,
                    trust_score FLOAT DEFAULT 0.0,
                    updated_at TIMESTAMP_TZ NOT NULL,
                    tenant_id VARCHAR NOT NULL DEFAULT 'default',
                    data VARIANT NOT NULL
                )
            """)
            cur.execute("ALTER TABLE fleet_agents ADD COLUMN IF NOT EXISTS tenant_id VARCHAR NOT NULL DEFAULT 'default'")

    def put(self, agent: FleetAgent) -> None:
        with self._connect() as conn:
            conn.cursor().execute(
                """MERGE INTO fleet_agents t USING (SELECT %s AS agent_id) s
                   ON t.agent_id = s.agent_id
                   WHEN MATCHED THEN UPDATE SET
                     name = %s, lifecycle_state = %s, trust_score = %s,
                     updated_at = %s, tenant_id = %s, data = PARSE_JSON(%s)
                   WHEN NOT MATCHED THEN INSERT
                     (agent_id, name, lifecycle_state, trust_score, updated_at, tenant_id, data)
                     VALUES (%s, %s, %s, %s, %s, %s, PARSE_JSON(%s))""",
                (
                    agent.agent_id,
                    agent.name,
                    agent.lifecycle_state.value,
                    agent.trust_score,
                    agent.updated_at,
                    agent.tenant_id,
                    agent.model_dump_json(),
                    agent.agent_id,
                    agent.name,
                    agent.lifecycle_state.value,
                    agent.trust_score,
                    agent.updated_at,
                    agent.tenant_id,
                    agent.model_dump_json(),
                ),
            )

    def get(self, agent_id: str, tenant_id: str | None = None) -> FleetAgent | None:
        with self._connect() as conn:
            cur = conn.cursor()
            if tenant_id is None:
                cur.execute("SELECT data FROM fleet_agents WHERE agent_id = %s", (agent_id,))
            else:
                cur.execute("SELECT data FROM fleet_agents WHERE agent_id = %s AND tenant_id = %s", (agent_id, tenant_id))
            row = cur.fetchone()
            if row is None:
                return None
            return FleetAgent.model_validate_json(row[0] if isinstance(row[0], str) else json.dumps(row[0]))

    def get_by_name(self, name: str) -> FleetAgent | None:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT data FROM fleet_agents WHERE name = %s", (name,))
            row = cur.fetchone()
            if row is None:
                return None
            return FleetAgent.model_validate_json(row[0] if isinstance(row[0], str) else json.dumps(row[0]))

    def delete(self, agent_id: str, tenant_id: str | None = None) -> bool:
        with self._connect() as conn:
            cur = conn.cursor()
            if tenant_id is None:
                cur.execute("DELETE FROM fleet_agents WHERE agent_id = %s", (agent_id,))
            else:
                cur.execute("DELETE FROM fleet_agents WHERE agent_id = %s AND tenant_id = %s", (agent_id, tenant_id))
            return (cur.rowcount or 0) > 0

    def list_all(self) -> list[FleetAgent]:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT data FROM fleet_agents ORDER BY name")
            return [FleetAgent.model_validate_json(r[0] if isinstance(r[0], str) else json.dumps(r[0])) for r in cur.fetchall()]

    def list_summary(self) -> list[dict]:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT agent_id, name, lifecycle_state, trust_score, updated_at FROM fleet_agents ORDER BY name")
            return [
                {
                    "agent_id": r[0],
                    "name": r[1],
                    "lifecycle_state": r[2],
                    "trust_score": r[3],
                    "updated_at": str(r[4]) if r[4] else None,
                }
                for r in cur.fetchall()
            ]

    def list_by_tenant(self, tenant_id: str) -> list[FleetAgent]:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT data FROM fleet_agents WHERE tenant_id = %s ORDER BY name", (tenant_id,))
            return [FleetAgent.model_validate_json(r[0] if isinstance(r[0], str) else json.dumps(r[0])) for r in cur.fetchall()]

    def list_tenants(self) -> list[dict]:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """SELECT tenant_id, COUNT(*)
                   FROM fleet_agents
                   GROUP BY tenant_id
                   ORDER BY tenant_id"""
            )
            return [{"tenant_id": r[0], "agent_count": r[1]} for r in cur.fetchall()]

    def update_state(self, agent_id: str, state: FleetLifecycleState) -> bool:
        agent = self.get(agent_id)
        if agent is None:
            return False
        agent.lifecycle_state = state
        agent.updated_at = datetime.now(timezone.utc).isoformat()
        self.put(agent)
        return True

    def batch_put(self, agents: list[FleetAgent], batch_size: int = 100) -> int:
        """Upsert multiple agents in batched MERGE statements.

        Uses multi-row source via UNION ALL for fewer round-trips to Snowflake.
        """
        if not agents:
            return 0

        total = 0
        for i in range(0, len(agents), batch_size):
            batch = agents[i : i + batch_size]
            # Build parameterised multi-row source
            source_parts: list[str] = []
            params: list = []
            for agent in batch:
                source_parts.append(
                    "SELECT %s AS agent_id, %s AS name, %s AS lifecycle_state, "
                    "%s AS trust_score, %s AS updated_at, %s AS tenant_id, PARSE_JSON(%s) AS data"
                )
                params.extend(
                    [
                        agent.agent_id,
                        agent.name,
                        agent.lifecycle_state.value,
                        agent.trust_score,
                        agent.updated_at,
                        agent.tenant_id,
                        agent.model_dump_json(),
                    ]
                )

            source_sql = " UNION ALL ".join(source_parts)
            merge_sql = (
                f"MERGE INTO fleet_agents t USING ({source_sql}) s "  # nosec B608
                "ON t.agent_id = s.agent_id "
                "WHEN MATCHED THEN UPDATE SET "
                "  name = s.name, lifecycle_state = s.lifecycle_state, "
                "  trust_score = s.trust_score, updated_at = s.updated_at, tenant_id = s.tenant_id, data = s.data "
                "WHEN NOT MATCHED THEN INSERT "
                "  (agent_id, name, lifecycle_state, trust_score, updated_at, tenant_id, data) "
                "  VALUES (s.agent_id, s.name, s.lifecycle_state, s.trust_score, "
                "          s.updated_at, s.tenant_id, s.data)"
            )

            with self._connect() as conn:
                conn.cursor().execute(merge_sql, params)
            total += len(batch)

        return total


# ─── Schedule Store ───────────────────────────────────────────────────────────


class SnowflakeScheduleStore:
    """Snowflake-backed recurring scan schedule persistence."""

    def __init__(self, connection_params: dict) -> None:
        self._conn_params = connection_params
        self._init_tables()

    def _connect(self):  # type: ignore[no-untyped-def]
        return _sf_connect(**self._conn_params)

    def _init_tables(self) -> None:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scan_schedules (
                    schedule_id VARCHAR PRIMARY KEY,
                    enabled BOOLEAN NOT NULL DEFAULT TRUE,
                    next_run VARCHAR,
                    tenant_id VARCHAR NOT NULL DEFAULT 'default',
                    data VARIANT NOT NULL
                )
            """)
            cur.execute("ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS tenant_id VARCHAR NOT NULL DEFAULT 'default'")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_sched_tenant_due ON scan_schedules(tenant_id, enabled, next_run)")

    def put(self, schedule) -> None:
        with self._connect() as conn:
            conn.cursor().execute(
                """MERGE INTO scan_schedules t USING (SELECT %s AS schedule_id) s
                   ON t.schedule_id = s.schedule_id
                   WHEN MATCHED THEN UPDATE SET
                     enabled = %s, next_run = %s, tenant_id = %s, data = PARSE_JSON(%s)
                   WHEN NOT MATCHED THEN INSERT
                     (schedule_id, enabled, next_run, tenant_id, data)
                     VALUES (%s, %s, %s, %s, PARSE_JSON(%s))""",
                (
                    schedule.schedule_id,
                    schedule.enabled,
                    schedule.next_run,
                    schedule.tenant_id,
                    schedule.model_dump_json(),
                    schedule.schedule_id,
                    schedule.enabled,
                    schedule.next_run,
                    schedule.tenant_id,
                    schedule.model_dump_json(),
                ),
            )

    def get(self, schedule_id: str, tenant_id: str | None = None):
        from .schedule_store import ScanSchedule

        with self._connect() as conn:
            cur = conn.cursor()
            if tenant_id is None:
                cur.execute("SELECT data FROM scan_schedules WHERE schedule_id = %s", (schedule_id,))
            else:
                cur.execute("SELECT data FROM scan_schedules WHERE schedule_id = %s AND tenant_id = %s", (schedule_id, tenant_id))
            row = cur.fetchone()
            if row is None:
                return None
            return ScanSchedule.model_validate_json(row[0] if isinstance(row[0], str) else json.dumps(row[0]))

    def delete(self, schedule_id: str, tenant_id: str | None = None) -> bool:
        with self._connect() as conn:
            cur = conn.cursor()
            if tenant_id is None:
                cur.execute("DELETE FROM scan_schedules WHERE schedule_id = %s", (schedule_id,))
            else:
                cur.execute("DELETE FROM scan_schedules WHERE schedule_id = %s AND tenant_id = %s", (schedule_id, tenant_id))
            return (cur.rowcount or 0) > 0

    def list_all(self, tenant_id: str | None = None) -> list:
        from .schedule_store import ScanSchedule

        with self._connect() as conn:
            cur = conn.cursor()
            if tenant_id is None:
                cur.execute("SELECT data FROM scan_schedules ORDER BY schedule_id")
            else:
                cur.execute("SELECT data FROM scan_schedules WHERE tenant_id = %s ORDER BY schedule_id", (tenant_id,))
            return [ScanSchedule.model_validate_json(r[0] if isinstance(r[0], str) else json.dumps(r[0])) for r in cur.fetchall()]

    def list_due(self, now_iso: str) -> list:
        from .schedule_store import ScanSchedule

        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """SELECT data
                   FROM scan_schedules
                   WHERE enabled = TRUE AND next_run IS NOT NULL AND next_run <= %s""",
                (now_iso,),
            )
            return [ScanSchedule.model_validate_json(r[0] if isinstance(r[0], str) else json.dumps(r[0])) for r in cur.fetchall()]


# ─── Exception Store ─────────────────────────────────────────────────────────


class SnowflakeExceptionStore:
    """Snowflake-backed vulnerability exception persistence."""

    def __init__(self, connection_params: dict) -> None:
        self._conn_params = connection_params
        self._init_tables()

    def _connect(self):  # type: ignore[no-untyped-def]
        return _sf_connect(**self._conn_params)

    def _init_tables(self) -> None:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS exceptions (
                    exception_id VARCHAR PRIMARY KEY,
                    vuln_id VARCHAR NOT NULL,
                    package_name VARCHAR NOT NULL,
                    server_name VARCHAR NOT NULL DEFAULT '',
                    status VARCHAR NOT NULL DEFAULT 'pending',
                    created_at TIMESTAMP_TZ NOT NULL,
                    expires_at VARCHAR NOT NULL DEFAULT '',
                    tenant_id VARCHAR NOT NULL DEFAULT 'default',
                    data VARIANT NOT NULL
                )
            """)
            cur.execute("ALTER TABLE exceptions ADD COLUMN IF NOT EXISTS tenant_id VARCHAR NOT NULL DEFAULT 'default'")

    def put(self, exc: VulnException) -> None:
        with self._connect() as conn:
            conn.cursor().execute(
                """MERGE INTO exceptions t USING (SELECT %s AS exception_id) s
                   ON t.exception_id = s.exception_id
                   WHEN MATCHED THEN UPDATE SET
                     vuln_id = %s, package_name = %s, server_name = %s,
                     status = %s, created_at = %s, expires_at = %s, tenant_id = %s,
                     data = PARSE_JSON(%s)
                   WHEN NOT MATCHED THEN INSERT
                     (exception_id, vuln_id, package_name, server_name, status, created_at, expires_at, tenant_id, data)
                     VALUES (%s, %s, %s, %s, %s, %s, %s, %s, PARSE_JSON(%s))""",
                (
                    exc.exception_id,
                    exc.vuln_id,
                    exc.package_name,
                    exc.server_name,
                    exc.status.value,
                    exc.created_at,
                    exc.expires_at,
                    exc.tenant_id,
                    json.dumps(exc.to_dict(), sort_keys=True),
                    exc.exception_id,
                    exc.vuln_id,
                    exc.package_name,
                    exc.server_name,
                    exc.status.value,
                    exc.created_at,
                    exc.expires_at,
                    exc.tenant_id,
                    json.dumps(exc.to_dict(), sort_keys=True),
                ),
            )

    def get(self, exception_id: str, tenant_id: str | None = None) -> VulnException | None:
        with self._connect() as conn:
            cur = conn.cursor()
            if tenant_id is None:
                cur.execute("SELECT data FROM exceptions WHERE exception_id = %s", (exception_id,))
            else:
                cur.execute("SELECT data FROM exceptions WHERE exception_id = %s AND tenant_id = %s", (exception_id, tenant_id))
            row = cur.fetchone()
            if row is None:
                return None
            payload = row[0] if isinstance(row[0], str) else json.dumps(row[0])
            data = json.loads(payload)
            data["status"] = ExceptionStatus(data.get("status", ExceptionStatus.PENDING.value))
            return VulnException(**data)

    def delete(self, exception_id: str, tenant_id: str | None = None) -> bool:
        with self._connect() as conn:
            cur = conn.cursor()
            if tenant_id is None:
                cur.execute("DELETE FROM exceptions WHERE exception_id = %s", (exception_id,))
            else:
                cur.execute("DELETE FROM exceptions WHERE exception_id = %s AND tenant_id = %s", (exception_id, tenant_id))
            return (cur.rowcount or 0) > 0

    def list_all(self, status: str | None = None, tenant_id: str = "default") -> list[VulnException]:
        with self._connect() as conn:
            cur = conn.cursor()
            sql = "SELECT data FROM exceptions WHERE tenant_id = %s"
            params: list[object] = [tenant_id]
            if status:
                sql += " AND status = %s"
                params.append(status)
            sql += " ORDER BY created_at DESC"
            cur.execute(sql, tuple(params))
            results: list[VulnException] = []
            for row in cur.fetchall():
                payload = row[0] if isinstance(row[0], str) else json.dumps(row[0])
                data = json.loads(payload)
                data["status"] = ExceptionStatus(data.get("status", ExceptionStatus.PENDING.value))
                results.append(VulnException(**data))
            return results

    def find_matching(self, vuln_id: str, package_name: str, server_name: str = "", tenant_id: str = "default") -> VulnException | None:
        exceptions = self.list_all(status=ExceptionStatus.ACTIVE.value, tenant_id=tenant_id)
        exceptions += self.list_all(status=ExceptionStatus.APPROVED.value, tenant_id=tenant_id)
        for exc in exceptions:
            if exc.matches(vuln_id, package_name, server_name):
                return exc
        return None


# ─── Policy Store ─────────────────────────────────────────────────────────────


class SnowflakePolicyStore:
    """Snowflake-backed gateway policy persistence + audit log."""

    def __init__(self, connection_params: dict) -> None:
        self._conn_params = connection_params
        self._init_tables()

    def _connect(self):  # type: ignore[no-untyped-def]
        return _sf_connect(**self._conn_params)

    def _init_tables(self) -> None:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS gateway_policies (
                    policy_id VARCHAR PRIMARY KEY,
                    name VARCHAR NOT NULL,
                    mode VARCHAR NOT NULL,
                    enabled BOOLEAN NOT NULL DEFAULT TRUE,
                    updated_at TIMESTAMP_TZ,
                    tenant_id VARCHAR NOT NULL DEFAULT 'default',
                    data VARIANT NOT NULL
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS policy_audit_log (
                    entry_id VARCHAR PRIMARY KEY,
                    policy_id VARCHAR NOT NULL,
                    agent_name VARCHAR,
                    action_taken VARCHAR,
                    timestamp TIMESTAMP_TZ,
                    tenant_id VARCHAR NOT NULL DEFAULT 'default',
                    data VARIANT NOT NULL
                )
            """)
            cur.execute("ALTER TABLE gateway_policies ADD COLUMN IF NOT EXISTS tenant_id VARCHAR NOT NULL DEFAULT 'default'")
            cur.execute("ALTER TABLE policy_audit_log ADD COLUMN IF NOT EXISTS tenant_id VARCHAR NOT NULL DEFAULT 'default'")

    # ── policies ──

    def put_policy(self, policy: GatewayPolicy) -> None:
        with self._connect() as conn:
            conn.cursor().execute(
                """MERGE INTO gateway_policies t USING (SELECT %s AS policy_id) s
                   ON t.policy_id = s.policy_id
                   WHEN MATCHED THEN UPDATE SET
                     name = %s, mode = %s, enabled = %s,
                     updated_at = %s, tenant_id = %s, data = PARSE_JSON(%s)
                   WHEN NOT MATCHED THEN INSERT
                     (policy_id, name, mode, enabled, updated_at, tenant_id, data)
                     VALUES (%s, %s, %s, %s, %s, %s, PARSE_JSON(%s))""",
                (
                    policy.policy_id,
                    policy.name,
                    policy.mode.value,
                    policy.enabled,
                    policy.updated_at,
                    policy.tenant_id,
                    policy.model_dump_json(),
                    policy.policy_id,
                    policy.name,
                    policy.mode.value,
                    policy.enabled,
                    policy.updated_at,
                    policy.tenant_id,
                    policy.model_dump_json(),
                ),
            )

    def get_policy(self, policy_id: str, tenant_id: str | None = None) -> GatewayPolicy | None:
        with self._connect() as conn:
            cur = conn.cursor()
            if tenant_id is None:
                cur.execute("SELECT data FROM gateway_policies WHERE policy_id = %s", (policy_id,))
            else:
                cur.execute("SELECT data FROM gateway_policies WHERE policy_id = %s AND tenant_id = %s", (policy_id, tenant_id))
            row = cur.fetchone()
            if row is None:
                return None
            return GatewayPolicy.model_validate_json(row[0] if isinstance(row[0], str) else json.dumps(row[0]))

    def delete_policy(self, policy_id: str, tenant_id: str | None = None) -> bool:
        if tenant_id is not None and self.get_policy(policy_id, tenant_id=tenant_id) is None:
            return False
        with self._connect() as conn:
            cur = conn.cursor()
            if tenant_id is None:
                cur.execute(
                    "DELETE FROM gateway_policies WHERE policy_id = %s",
                    (policy_id,),
                )
            else:
                cur.execute(
                    "DELETE FROM gateway_policies WHERE policy_id = %s AND tenant_id = %s",
                    (policy_id, tenant_id),
                )
            return (cur.rowcount or 0) > 0

    def list_policies(self, tenant_id: str | None = None) -> list[GatewayPolicy]:
        with self._connect() as conn:
            cur = conn.cursor()
            if tenant_id is None:
                cur.execute("SELECT data FROM gateway_policies ORDER BY name")
            else:
                cur.execute("SELECT data FROM gateway_policies WHERE tenant_id = %s ORDER BY name", (tenant_id,))
            policies = [GatewayPolicy.model_validate_json(r[0] if isinstance(r[0], str) else json.dumps(r[0])) for r in cur.fetchall()]
            return policies

    def get_policies_for_agent(
        self,
        agent_name: str | None = None,
        agent_type: str | None = None,
        environment: str | None = None,
        tenant_id: str | None = None,
    ) -> list[GatewayPolicy]:
        policies = [p for p in self.list_policies(tenant_id=tenant_id) if p.enabled]
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

    # ── audit ──

    def put_audit_entry(self, entry: PolicyAuditEntry) -> None:
        with self._connect() as conn:
            conn.cursor().execute(
                """INSERT INTO policy_audit_log
                   (entry_id, policy_id, agent_name, action_taken, timestamp, tenant_id, data)
                   VALUES (%s, %s, %s, %s, %s, %s, PARSE_JSON(%s))""",
                (
                    entry.entry_id,
                    entry.policy_id,
                    entry.agent_name,
                    entry.action_taken,
                    entry.timestamp,
                    entry.tenant_id,
                    entry.model_dump_json(),
                ),
            )

    def list_audit_entries(
        self,
        policy_id: str | None = None,
        agent_name: str | None = None,
        limit: int = 100,
        tenant_id: str | None = None,
    ) -> list[PolicyAuditEntry]:
        with self._connect() as conn:
            sql = "SELECT data FROM policy_audit_log WHERE 1=1"
            params: list = []
            if tenant_id is not None:
                sql += " AND tenant_id = %s"
                params.append(tenant_id)
            if policy_id:
                sql += " AND policy_id = %s"
                params.append(policy_id)
            if agent_name:
                sql += " AND agent_name = %s"
                params.append(agent_name)
            sql += " ORDER BY timestamp DESC LIMIT %s"
            params.append(limit)
            cur = conn.cursor()
            cur.execute(sql, params)
            return [PolicyAuditEntry.model_validate_json(r[0] if isinstance(r[0], str) else json.dumps(r[0])) for r in cur.fetchall()]
