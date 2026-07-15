"""Postgres-backed LLM cost (FinOps) persistence for horizontal scaling.

Mirrors :class:`agent_bom.api.cost_store.SQLiteCostStore` but stores per-call
spend and budgets in shared Postgres with tenant RLS, so per-agent spend,
budget enforcement, and cost-anomaly baselines stay consistent across every
control-plane replica instead of diverging on node-local SQLite. This closes
the multi-replica budget-enforcement gap (rate limiting already shares state
via :class:`PostgresRateLimitStore`; cost governance must match).
"""

from __future__ import annotations

import json
from typing import Any

from agent_bom.api.cost_store import CostBudget, LLMCostRecord, _decode_tags
from agent_bom.api.postgres_common import ConnectionPool, _ensure_tenant_rls, _get_pool, _tenant_connection
from agent_bom.api.storage_schema import ensure_postgres_schema_version


class PostgresCostStore:
    """Shared LLM cost + budget store backed by Postgres with tenant RLS."""

    def __init__(self, pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()
        self._init_tables()

    def init_schema(self) -> None:
        """Idempotently (re)create this store's tables. Satisfies the shared
        :class:`agent_bom.storage.base.TenantScopedStore` contract."""
        self._init_tables()

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            ensure_postgres_schema_version(conn, "llm_costs")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS llm_costs (
                    tenant_id     TEXT NOT NULL,
                    call_id       TEXT NOT NULL,
                    agent         TEXT NOT NULL,
                    session_id    TEXT NOT NULL,
                    provider      TEXT NOT NULL,
                    model         TEXT NOT NULL,
                    input_tokens  INTEGER NOT NULL,
                    output_tokens INTEGER NOT NULL,
                    cost_usd      DOUBLE PRECISION NOT NULL,
                    priced        BOOLEAN NOT NULL,
                    observed_at   TEXT NOT NULL,
                    cost_center     TEXT NOT NULL DEFAULT '',
                    allocation_tags TEXT NOT NULL DEFAULT '{}',
                    PRIMARY KEY (tenant_id, call_id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS llm_cost_budgets (
                    tenant_id   TEXT NOT NULL,
                    agent       TEXT NOT NULL DEFAULT '',
                    limit_usd   DOUBLE PRECISION NOT NULL,
                    updated_at  TEXT NOT NULL,
                    mode        TEXT NOT NULL DEFAULT 'report',
                    cost_center TEXT NOT NULL DEFAULT '',
                    owner       TEXT NOT NULL DEFAULT '',
                    workflow    TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (tenant_id, agent, cost_center)
                )
            """)
            # Allocation columns (#2925) added additively for pre-migration
            # databases; existing rows default to '' / '{}' (unallocated).
            conn.execute("ALTER TABLE llm_costs ADD COLUMN IF NOT EXISTS cost_center TEXT NOT NULL DEFAULT ''")
            conn.execute("ALTER TABLE llm_costs ADD COLUMN IF NOT EXISTS allocation_tags TEXT NOT NULL DEFAULT '{}'")
            conn.execute("ALTER TABLE llm_cost_budgets ADD COLUMN IF NOT EXISTS cost_center TEXT NOT NULL DEFAULT ''")
            # Owner/workflow scoping (#3909) added additively; pre-migration rows
            # default to '' (not owner-scoped).
            conn.execute("ALTER TABLE llm_cost_budgets ADD COLUMN IF NOT EXISTS owner TEXT NOT NULL DEFAULT ''")
            conn.execute("ALTER TABLE llm_cost_budgets ADD COLUMN IF NOT EXISTS workflow TEXT NOT NULL DEFAULT ''")
            # Back the full-scope upsert conflict target with a unique index so it
            # works on pre-migration tables whose PK omits owner/workflow. The
            # widened scope (agent, cost_center, owner, workflow) keeps an owner
            # budget from colliding with the tenant-wide row.
            conn.execute("DROP INDEX IF EXISTS uq_llm_cost_budgets_scope")
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_llm_cost_budgets_scope "
                "ON llm_cost_budgets(tenant_id, agent, cost_center, owner, workflow)"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_llm_costs_tenant_agent ON llm_costs(tenant_id, agent)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_llm_costs_tenant_observed ON llm_costs(tenant_id, observed_at DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_llm_costs_tenant_cost_center ON llm_costs(tenant_id, cost_center)")
            _ensure_tenant_rls(conn, "llm_costs", "tenant_id")
            _ensure_tenant_rls(conn, "llm_cost_budgets", "tenant_id")
            conn.commit()

    def record_cost(self, record: LLMCostRecord) -> None:
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """
                INSERT INTO llm_costs
                    (tenant_id, call_id, agent, session_id, provider, model,
                     input_tokens, output_tokens, cost_usd, priced, observed_at,
                     cost_center, allocation_tags)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, call_id) DO NOTHING
                """,
                (
                    record.tenant_id,
                    record.call_id,
                    record.agent,
                    record.session_id,
                    record.provider,
                    record.model,
                    record.input_tokens,
                    record.output_tokens,
                    record.cost_usd,
                    record.priced,
                    record.observed_at,
                    record.cost_center,
                    json.dumps(record.allocation_tags, sort_keys=True),
                ),
            )
            conn.commit()

    def list_records(self, tenant_id: str, *, limit: int = 1000) -> list[LLMCostRecord]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT tenant_id, call_id, agent, session_id, provider, model, "
                "input_tokens, output_tokens, cost_usd, priced, observed_at, "
                "cost_center, allocation_tags "
                "FROM llm_costs WHERE tenant_id = %s ORDER BY observed_at DESC LIMIT %s",
                (tenant_id, limit),
            ).fetchall()
        return [
            LLMCostRecord(
                r[0],
                r[1],
                r[2],
                r[3],
                r[4],
                r[5],
                int(r[6]),
                int(r[7]),
                float(r[8]),
                bool(r[9]),
                r[10],
                r[11] if len(r) > 11 and r[11] is not None else "",
                _decode_tags(r[12] if len(r) > 12 else None),
            )
            for r in rows
        ]

    def total_spend_by_cost_center(self, tenant_id: str, cost_center: str, *, since: str | None = None) -> float:
        sql = "SELECT COALESCE(SUM(cost_usd), 0.0) FROM llm_costs WHERE tenant_id = %s AND cost_center = %s"
        params: list[Any] = [tenant_id, cost_center]
        if since is not None:
            sql += " AND observed_at >= %s"
            params.append(since)
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(sql, params).fetchone()
        return round(float(row[0]), 6) if row else 0.0

    def total_spend(self, tenant_id: str, *, agent: str | None = None, since: str | None = None) -> float:
        sql = "SELECT COALESCE(SUM(cost_usd), 0.0) FROM llm_costs WHERE tenant_id = %s"
        params: list[Any] = [tenant_id]
        if agent:
            sql += " AND agent = %s"
            params.append(agent)
        if since is not None:
            sql += " AND observed_at >= %s"
            params.append(since)
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(sql, params).fetchone()
        return round(float(row[0]), 6) if row else 0.0

    def set_budget(self, budget: CostBudget) -> None:
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """
                INSERT INTO llm_cost_budgets (tenant_id, agent, limit_usd, updated_at, mode, cost_center, owner, workflow)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, agent, cost_center, owner, workflow)
                DO UPDATE SET limit_usd = EXCLUDED.limit_usd,
                              updated_at = EXCLUDED.updated_at,
                              mode = EXCLUDED.mode
                """,
                (
                    budget.tenant_id,
                    budget.agent,
                    budget.limit_usd,
                    budget.updated_at,
                    budget.mode,
                    budget.cost_center,
                    budget.owner,
                    budget.workflow,
                ),
            )
            conn.commit()

    def get_budget(
        self, tenant_id: str, agent: str = "", *, cost_center: str = "", owner: str = "", workflow: str = ""
    ) -> CostBudget | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT tenant_id, agent, limit_usd, updated_at, mode, cost_center, owner, workflow "
                "FROM llm_cost_budgets WHERE tenant_id = %s AND agent = %s AND cost_center = %s "
                "AND owner = %s AND workflow = %s",
                (tenant_id, agent, cost_center, owner, workflow),
            ).fetchone()
        if not row:
            return None
        return CostBudget(
            row[0],
            row[1],
            float(row[2]),
            row[3],
            row[4],
            row[5] if len(row) > 5 and row[5] is not None else "",
            row[6] if len(row) > 6 and row[6] is not None else "",
            row[7] if len(row) > 7 and row[7] is not None else "",
        )
