"""PostgreSQL-backed fleet agent persistence.

Split out of ``postgres_store.py`` (issue #1522) with no behavior change;
``postgres_store`` re-exports :class:`PostgresFleetStore` for import stability.

Requires ``pip install 'agent-bom[postgres]'``.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from agent_bom.api.postgres_common import (
    ConnectionPool,
    _ensure_tenant_rls,
    _get_pool,
    _tenant_connection,
)
from agent_bom.api.storage_schema import ensure_postgres_schema_version

if TYPE_CHECKING:
    # Imported lazily at runtime (inside methods) to avoid a circular import
    # with fleet_store; TYPE_CHECKING keeps the annotations resolvable.
    from .fleet_store import FleetAgent, FleetLifecycleState

# Every predicate that names a single agent: the caller's tenant and the RLS
# session tenant must both match, so neither an unscoped caller nor an
# RLS-bypassing maintenance connection can reach another tenant's row.
_TENANT_SCOPED_AGENT = "agent_id = %s AND tenant_id = %s AND tenant_id = abom_current_tenant()"


class PostgresFleetStore:
    """PostgreSQL-backed fleet agent persistence."""

    def __init__(self, pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            if not ensure_postgres_schema_version(conn, "fleet"):
                return
            # The key is (tenant_id, agent_id): agent IDs are derived from agent
            # content with no tenant component, so a global key lets the first
            # tenant to register a stock agent lock every other tenant out of
            # its own — the ON CONFLICT below resolves through the unique index,
            # which RLS does not filter.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS fleet_agents (
                    agent_id TEXT NOT NULL,
                    canonical_id TEXT NOT NULL DEFAULT '',
                    name TEXT NOT NULL,
                    lifecycle_state TEXT NOT NULL,
                    trust_score REAL DEFAULT 0.0,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    updated_at TEXT NOT NULL,
                    data JSONB NOT NULL,
                    PRIMARY KEY (tenant_id, agent_id)
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
            # The relay resolves a caller by any of its three identifiers; all
            # three need an index or quarantine enforcement pages the roster.
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fleet_tenant_agent_id_lower ON fleet_agents(tenant_id, lower(agent_id))")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fleet_tenant_canonical_id_lower ON fleet_agents(tenant_id, lower(canonical_id))")
            _ensure_tenant_rls(conn, "fleet_agents", "tenant_id")
            conn.commit()

    def put(self, agent: FleetAgent) -> None:
        data = agent.model_dump_json()
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """INSERT INTO fleet_agents (agent_id, canonical_id, name, lifecycle_state, trust_score, tenant_id, updated_at, data)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (tenant_id, agent_id) DO UPDATE SET
                     canonical_id = EXCLUDED.canonical_id,
                     name = EXCLUDED.name,
                     lifecycle_state = EXCLUDED.lifecycle_state,
                     trust_score = EXCLUDED.trust_score,
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

    def get(self, agent_id: str, *, tenant_id: str) -> FleetAgent | None:
        from .fleet_store import FleetAgent

        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT data FROM fleet_agents WHERE agent_id = %s AND tenant_id = %s",
                (agent_id, tenant_id),
            ).fetchone()
            if row is None:
                return None
            raw = row[0] if isinstance(row[0], str) else json.dumps(row[0])
            return FleetAgent.model_validate_json(raw)

    def get_by_canonical_id(self, canonical_id: str, tenant_id: str | None = None) -> FleetAgent | None:
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

    def get_by_name(self, name: str) -> FleetAgent | None:
        from .fleet_store import FleetAgent

        with _tenant_connection(self._pool) as conn:
            row = conn.execute("SELECT data FROM fleet_agents WHERE name = %s", (name,)).fetchone()
            if row is None:
                return None
            raw = row[0] if isinstance(row[0], str) else json.dumps(row[0])
            return FleetAgent.model_validate_json(raw)

    def delete(self, agent_id: str, *, tenant_id: str) -> bool:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                "DELETE FROM fleet_agents WHERE agent_id = %s AND tenant_id = %s",
                (agent_id, tenant_id),
            )
            conn.commit()
            return bool(cursor.rowcount > 0)

    def list_all(self) -> list[FleetAgent]:
        from .fleet_store import FleetAgent

        with _tenant_connection(self._pool) as conn:
            rows = conn.execute("SELECT data FROM fleet_agents ORDER BY name").fetchall()
            return [FleetAgent.model_validate_json(r[0] if isinstance(r[0], str) else json.dumps(r[0])) for r in rows]

    def list_summary(self) -> list[dict[str, Any]]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT agent_id, canonical_id, name, lifecycle_state, trust_score FROM fleet_agents ORDER BY name"
            ).fetchall()
            return [{"agent_id": r[0], "canonical_id": r[1], "name": r[2], "lifecycle_state": r[3], "trust_score": r[4]} for r in rows]

    def list_by_tenant(self, tenant_id: str) -> list[FleetAgent]:
        from .fleet_store import FleetAgent

        with _tenant_connection(self._pool) as conn:
            rows = conn.execute("SELECT data FROM fleet_agents WHERE tenant_id = %s ORDER BY name", (tenant_id,)).fetchall()
            return [FleetAgent.model_validate_json(r[0] if isinstance(r[0], str) else json.dumps(r[0])) for r in rows]

    def find_by_identifier(self, tenant_id: str, identifier: str) -> FleetAgent | None:
        from .fleet_store import FleetAgent

        key = (identifier or "").strip().lower()
        if not key:
            return None
        with _tenant_connection(self._pool) as conn:
            for column in ("name", "agent_id", "canonical_id"):
                row = conn.execute(
                    # nosec B608 - ``column`` comes from the fixed literal tuple
                    # in the loop above; the values are bound.
                    f"SELECT data FROM fleet_agents WHERE lower({column}) = %s AND tenant_id = %s LIMIT 1",  # nosec B608
                    (key, tenant_id),
                ).fetchone()
                if row is not None:
                    return FleetAgent.model_validate_json(row[0] if isinstance(row[0], str) else json.dumps(row[0]))
        return None

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
    ) -> tuple[list[FleetAgent], int]:
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

    def list_tenants(self) -> list[dict[str, Any]]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute("SELECT tenant_id, COUNT(*) as cnt FROM fleet_agents GROUP BY tenant_id ORDER BY tenant_id").fetchall()
            return [{"tenant_id": r[0], "agent_count": r[1]} for r in rows]

    def update_state(self, agent_id: str, state: FleetLifecycleState, *, tenant_id: str) -> bool:
        # agent_id is unique only WITHIN a tenant, so every predicate on it must
        # carry the tenant too. Leaning on RLS alone would let a maintenance
        # connection — which may bypass RLS — quarantine every tenant's copy of
        # a shared agent ID in one statement. The caller's tenant AND the
        # session tenant must agree, so a mismatch updates nothing.
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                # nosec B608 - _TENANT_SCOPED_AGENT is a module constant of %s
                # placeholders; agent_id and tenant_id are bound, never inlined.
                f"UPDATE fleet_agents SET lifecycle_state = %s WHERE {_TENANT_SCOPED_AGENT}",  # nosec B608
                (state.value, agent_id, tenant_id),
            )
            if cursor.rowcount > 0:
                # Also update the JSON data
                row = conn.execute(
                    f"SELECT data FROM fleet_agents WHERE {_TENANT_SCOPED_AGENT}",  # nosec B608 - static predicate
                    (agent_id, tenant_id),
                ).fetchone()
                if row:
                    raw = row[0] if isinstance(row[0], str) else json.dumps(row[0])
                    data = json.loads(raw)
                    data["lifecycle_state"] = state.value
                    conn.execute(
                        # nosec B608 - same module constant, same bound parameters.
                        f"UPDATE fleet_agents SET data = %s WHERE {_TENANT_SCOPED_AGENT}",  # nosec B608
                        (json.dumps(data), agent_id, tenant_id),
                    )
            conn.commit()
            return bool(cursor.rowcount > 0)

    def batch_put(self, agents: list[FleetAgent]) -> int:
        count = 0
        for agent in agents:
            self.put(agent)
            count += 1
        return count
