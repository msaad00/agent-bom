"""Snowflake-backed storage backends for agent-bom.

Provides pluggable Snowflake persistence for all three store protocols:
- ``SnowflakeJobStore``    — scan job persistence
- ``SnowflakeFleetStore``  — fleet agent lifecycle
- ``SnowflakePolicyStore`` — gateway policies + audit log

Requires ``pip install 'agent-bom[snowflake]'``.

Auth auto-detection:
  - If ``SNOWFLAKE_PRIVATE_KEY_PATH`` is set → key-pair auth
  - Otherwise falls back to ``SNOWFLAKE_PASSWORD``
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

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
    else:
        params["password"] = os.environ.get("SNOWFLAKE_PASSWORD", "")
    params["database"] = os.environ.get("SNOWFLAKE_DATABASE", "AGENT_BOM")
    params["schema"] = os.environ.get("SNOWFLAKE_SCHEMA", "PUBLIC")
    return params


# ─── Job Store ────────────────────────────────────────────────────────────────


class SnowflakeJobStore:
    """Snowflake-backed scan job persistence."""

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
                    data VARIANT NOT NULL
                )
            """)

    def put(self, job: ScanJob) -> None:
        with self._connect() as conn:
            conn.cursor().execute(
                """MERGE INTO scan_jobs t USING (SELECT %s AS job_id) s
                   ON t.job_id = s.job_id
                   WHEN MATCHED THEN UPDATE SET
                     status = %s, created_at = %s, completed_at = %s,
                     data = PARSE_JSON(%s)
                   WHEN NOT MATCHED THEN INSERT
                     (job_id, status, created_at, completed_at, data)
                     VALUES (%s, %s, %s, %s, PARSE_JSON(%s))""",
                (
                    job.job_id,
                    job.status.value,
                    job.created_at,
                    job.completed_at,
                    job.model_dump_json(),
                    job.job_id,
                    job.status.value,
                    job.created_at,
                    job.completed_at,
                    job.model_dump_json(),
                ),
            )

    def get(self, job_id: str) -> ScanJob | None:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT data FROM scan_jobs WHERE job_id = %s", (job_id,))
            row = cur.fetchone()
            if row is None:
                return None
            return ScanJob.model_validate_json(row[0] if isinstance(row[0], str) else json.dumps(row[0]))

    def delete(self, job_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM scan_jobs WHERE job_id = %s", (job_id,))
            return (cur.rowcount or 0) > 0

    def list_all(self) -> list[ScanJob]:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT data FROM scan_jobs ORDER BY created_at DESC")
            return [ScanJob.model_validate_json(r[0] if isinstance(r[0], str) else json.dumps(r[0])) for r in cur.fetchall()]

    def list_summary(self) -> list[dict]:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT job_id, status, created_at, completed_at FROM scan_jobs ORDER BY created_at DESC")
            return [
                {
                    "job_id": r[0],
                    "status": r[1],
                    "created_at": str(r[2]) if r[2] else None,
                    "completed_at": str(r[3]) if r[3] else None,
                }
                for r in cur.fetchall()
            ]

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
                    data VARIANT NOT NULL
                )
            """)

    def put(self, agent: FleetAgent) -> None:
        with self._connect() as conn:
            conn.cursor().execute(
                """MERGE INTO fleet_agents t USING (SELECT %s AS agent_id) s
                   ON t.agent_id = s.agent_id
                   WHEN MATCHED THEN UPDATE SET
                     name = %s, lifecycle_state = %s, trust_score = %s,
                     updated_at = %s, data = PARSE_JSON(%s)
                   WHEN NOT MATCHED THEN INSERT
                     (agent_id, name, lifecycle_state, trust_score, updated_at, data)
                     VALUES (%s, %s, %s, %s, %s, PARSE_JSON(%s))""",
                (
                    agent.agent_id,
                    agent.name,
                    agent.lifecycle_state.value,
                    agent.trust_score,
                    agent.updated_at,
                    agent.model_dump_json(),
                    agent.agent_id,
                    agent.name,
                    agent.lifecycle_state.value,
                    agent.trust_score,
                    agent.updated_at,
                    agent.model_dump_json(),
                ),
            )

    def get(self, agent_id: str) -> FleetAgent | None:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT data FROM fleet_agents WHERE agent_id = %s", (agent_id,))
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

    def delete(self, agent_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM fleet_agents WHERE agent_id = %s", (agent_id,))
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
                    "SELECT %s AS agent_id, %s AS name, %s AS lifecycle_state, %s AS trust_score, %s AS updated_at, PARSE_JSON(%s) AS data"
                )
                params.extend(
                    [
                        agent.agent_id,
                        agent.name,
                        agent.lifecycle_state.value,
                        agent.trust_score,
                        agent.updated_at,
                        agent.model_dump_json(),
                    ]
                )

            source_sql = " UNION ALL ".join(source_parts)
            merge_sql = (
                f"MERGE INTO fleet_agents t USING ({source_sql}) s "  # nosec B608
                "ON t.agent_id = s.agent_id "
                "WHEN MATCHED THEN UPDATE SET "
                "  name = s.name, lifecycle_state = s.lifecycle_state, "
                "  trust_score = s.trust_score, updated_at = s.updated_at, data = s.data "
                "WHEN NOT MATCHED THEN INSERT "
                "  (agent_id, name, lifecycle_state, trust_score, updated_at, data) "
                "  VALUES (s.agent_id, s.name, s.lifecycle_state, s.trust_score, "
                "          s.updated_at, s.data)"
            )

            with self._connect() as conn:
                conn.cursor().execute(merge_sql, params)
            total += len(batch)

        return total


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
                    data VARIANT NOT NULL
                )
            """)

    # ── policies ──

    def put_policy(self, policy: GatewayPolicy) -> None:
        with self._connect() as conn:
            conn.cursor().execute(
                """MERGE INTO gateway_policies t USING (SELECT %s AS policy_id) s
                   ON t.policy_id = s.policy_id
                   WHEN MATCHED THEN UPDATE SET
                     name = %s, mode = %s, enabled = %s,
                     updated_at = %s, data = PARSE_JSON(%s)
                   WHEN NOT MATCHED THEN INSERT
                     (policy_id, name, mode, enabled, updated_at, data)
                     VALUES (%s, %s, %s, %s, %s, PARSE_JSON(%s))""",
                (
                    policy.policy_id,
                    policy.name,
                    policy.mode.value,
                    policy.enabled,
                    policy.updated_at,
                    policy.model_dump_json(),
                    policy.policy_id,
                    policy.name,
                    policy.mode.value,
                    policy.enabled,
                    policy.updated_at,
                    policy.model_dump_json(),
                ),
            )

    def get_policy(self, policy_id: str) -> GatewayPolicy | None:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT data FROM gateway_policies WHERE policy_id = %s",
                (policy_id,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            return GatewayPolicy.model_validate_json(row[0] if isinstance(row[0], str) else json.dumps(row[0]))

    def delete_policy(self, policy_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "DELETE FROM gateway_policies WHERE policy_id = %s",
                (policy_id,),
            )
            return (cur.rowcount or 0) > 0

    def list_policies(self) -> list[GatewayPolicy]:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT data FROM gateway_policies ORDER BY name")
            return [GatewayPolicy.model_validate_json(r[0] if isinstance(r[0], str) else json.dumps(r[0])) for r in cur.fetchall()]

    def get_policies_for_agent(
        self,
        agent_name: str | None = None,
        agent_type: str | None = None,
        environment: str | None = None,
    ) -> list[GatewayPolicy]:
        policies = [p for p in self.list_policies() if p.enabled]
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
                   (entry_id, policy_id, agent_name, action_taken, timestamp, data)
                   VALUES (%s, %s, %s, %s, %s, PARSE_JSON(%s))""",
                (
                    entry.entry_id,
                    entry.policy_id,
                    entry.agent_name,
                    entry.action_taken,
                    entry.timestamp,
                    entry.model_dump_json(),
                ),
            )

    def list_audit_entries(
        self,
        policy_id: str | None = None,
        agent_name: str | None = None,
        limit: int = 100,
    ) -> list[PolicyAuditEntry]:
        with self._connect() as conn:
            sql = "SELECT data FROM policy_audit_log WHERE 1=1"
            params: list = []
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
