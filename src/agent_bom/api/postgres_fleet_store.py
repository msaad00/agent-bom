"""PostgreSQL-backed fleet agent persistence.

Split out of ``postgres_store.py`` (issue #1522) with no behavior change;
``postgres_store`` re-exports :class:`PostgresFleetStore` for import stability.

Requires ``pip install 'agent-bom[postgres]'``.
"""

from __future__ import annotations

import json

from agent_bom.api.postgres_common import (
    _ensure_tenant_rls,
    _get_pool,
    _tenant_connection,
)


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
