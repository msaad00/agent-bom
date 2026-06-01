"""Tenant-scoped LLM cost (FinOps) persistence and aggregation.

Token counts extracted from OpenTelemetry GenAI spans
(:func:`agent_bom.otel_ingest.parse_ml_api_spans`) are priced via
:mod:`agent_bom.cost_model` and persisted here so operators get per-agent /
per-model / per-provider spend attribution and budget enforcement — the
accountability layer commercial agent-runtime products charge for, kept open.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from collections import defaultdict
from dataclasses import asdict, dataclass
from typing import Any, Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version


@dataclass(frozen=True)
class LLMCostRecord:
    """One priced LLM API call."""

    tenant_id: str
    call_id: str
    agent: str
    session_id: str
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    priced: bool
    observed_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CostBudget:
    """A spend cap for a tenant (optionally scoped to one agent)."""

    tenant_id: str
    agent: str  # "" means tenant-wide
    limit_usd: float
    updated_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _rollup(records: list[LLMCostRecord], dimension: str) -> list[dict[str, Any]]:
    """Aggregate spend + tokens by one dimension (agent/model/provider)."""
    buckets: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"key": "", "calls": 0, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0, "unpriced_calls": 0}
    )
    for r in records:
        key = {"agent": r.agent, "model": r.model, "provider": r.provider}.get(dimension, r.agent) or "unknown"
        b = buckets[key]
        b["key"] = key
        b["calls"] += 1
        b["input_tokens"] += r.input_tokens
        b["output_tokens"] += r.output_tokens
        b["cost_usd"] = round(b["cost_usd"] + r.cost_usd, 6)
        if not r.priced:
            b["unpriced_calls"] += 1
    return sorted(buckets.values(), key=lambda b: b["cost_usd"], reverse=True)


class CostStore(Protocol):
    def record_cost(self, record: LLMCostRecord) -> None: ...

    def list_records(self, tenant_id: str, *, limit: int = 1000) -> list[LLMCostRecord]: ...

    def total_spend(self, tenant_id: str, *, agent: str | None = None) -> float: ...

    def set_budget(self, budget: CostBudget) -> None: ...

    def get_budget(self, tenant_id: str, agent: str = "") -> CostBudget | None: ...


def summarize(records: list[LLMCostRecord]) -> dict[str, Any]:
    """Build the spend report payload from a record list."""
    total = round(sum(r.cost_usd for r in records), 6)
    return {
        "total_cost_usd": total,
        "total_calls": len(records),
        "total_input_tokens": sum(r.input_tokens for r in records),
        "total_output_tokens": sum(r.output_tokens for r in records),
        "unpriced_calls": sum(1 for r in records if not r.priced),
        "by_agent": _rollup(records, "agent"),
        "by_model": _rollup(records, "model"),
        "by_provider": _rollup(records, "provider"),
    }


def budget_status(spend: float, budget: CostBudget | None) -> dict[str, Any]:
    """Return budget posture for a spend figure."""
    if budget is None:
        return {
            "configured": False,
            "limit_usd": None,
            "spend_usd": round(spend, 6),
            "remaining_usd": None,
            "exceeded": False,
            "utilization": None,
        }
    remaining = round(budget.limit_usd - spend, 6)
    return {
        "configured": True,
        "agent": budget.agent or None,
        "limit_usd": budget.limit_usd,
        "spend_usd": round(spend, 6),
        "remaining_usd": remaining,
        "exceeded": spend >= budget.limit_usd > 0,
        "utilization": round(spend / budget.limit_usd, 4) if budget.limit_usd > 0 else None,
    }


class InMemoryCostStore:
    def __init__(self) -> None:
        self._records: dict[str, list[LLMCostRecord]] = defaultdict(list)
        self._seen: dict[str, set[str]] = defaultdict(set)
        self._budgets: dict[tuple[str, str], CostBudget] = {}
        self._lock = threading.Lock()

    def record_cost(self, record: LLMCostRecord) -> None:
        with self._lock:
            if record.call_id in self._seen[record.tenant_id]:
                return
            self._seen[record.tenant_id].add(record.call_id)
            self._records[record.tenant_id].append(record)

    def list_records(self, tenant_id: str, *, limit: int = 1000) -> list[LLMCostRecord]:
        with self._lock:
            return list(self._records.get(tenant_id, []))[-limit:]

    def total_spend(self, tenant_id: str, *, agent: str | None = None) -> float:
        with self._lock:
            return round(
                sum(r.cost_usd for r in self._records.get(tenant_id, []) if agent in (None, "", r.agent) or r.agent == agent),
                6,
            )

    def set_budget(self, budget: CostBudget) -> None:
        with self._lock:
            self._budgets[(budget.tenant_id, budget.agent)] = budget

    def get_budget(self, tenant_id: str, agent: str = "") -> CostBudget | None:
        with self._lock:
            return self._budgets.get((tenant_id, agent))


class SQLiteCostStore:
    def __init__(self, db_path: str = "agent_bom.db") -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        conn: sqlite3.Connection = self._local.conn
        return conn

    def _init_db(self) -> None:
        ensure_sqlite_schema_version(self._conn, "llm_costs")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS llm_costs (
                tenant_id TEXT NOT NULL,
                call_id TEXT NOT NULL,
                agent TEXT NOT NULL,
                session_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                input_tokens INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                cost_usd REAL NOT NULL,
                priced INTEGER NOT NULL,
                observed_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, call_id)
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS llm_cost_budgets (
                tenant_id TEXT NOT NULL,
                agent TEXT NOT NULL DEFAULT '',
                limit_usd REAL NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, agent)
            )
            """
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_llm_costs_tenant_agent ON llm_costs(tenant_id, agent)")
        self._conn.commit()

    def record_cost(self, record: LLMCostRecord) -> None:
        self._conn.execute(
            """
            INSERT OR IGNORE INTO llm_costs
                (tenant_id, call_id, agent, session_id, provider, model, input_tokens, output_tokens, cost_usd, priced, observed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                int(record.priced),
                record.observed_at,
            ),
        )
        self._conn.commit()

    def list_records(self, tenant_id: str, *, limit: int = 1000) -> list[LLMCostRecord]:
        rows = self._conn.execute(
            "SELECT tenant_id, call_id, agent, session_id, provider, model, input_tokens, output_tokens, cost_usd, priced, observed_at "
            "FROM llm_costs WHERE tenant_id = ? ORDER BY observed_at DESC LIMIT ?",
            (tenant_id, limit),
        ).fetchall()
        return [LLMCostRecord(r[0], r[1], r[2], r[3], r[4], r[5], int(r[6]), int(r[7]), float(r[8]), bool(r[9]), r[10]) for r in rows]

    def total_spend(self, tenant_id: str, *, agent: str | None = None) -> float:
        if agent:
            row = self._conn.execute(
                "SELECT COALESCE(SUM(cost_usd), 0.0) FROM llm_costs WHERE tenant_id = ? AND agent = ?", (tenant_id, agent)
            ).fetchone()
        else:
            row = self._conn.execute("SELECT COALESCE(SUM(cost_usd), 0.0) FROM llm_costs WHERE tenant_id = ?", (tenant_id,)).fetchone()
        return round(float(row[0]), 6)

    def set_budget(self, budget: CostBudget) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO llm_cost_budgets (tenant_id, agent, limit_usd, updated_at) VALUES (?, ?, ?, ?)",
            (budget.tenant_id, budget.agent, budget.limit_usd, budget.updated_at),
        )
        self._conn.commit()

    def get_budget(self, tenant_id: str, agent: str = "") -> CostBudget | None:
        row = self._conn.execute(
            "SELECT tenant_id, agent, limit_usd, updated_at FROM llm_cost_budgets WHERE tenant_id = ? AND agent = ?",
            (tenant_id, agent),
        ).fetchone()
        return CostBudget(row[0], row[1], float(row[2]), row[3]) if row else None


_COST_STORE: CostStore | None = None


def get_cost_store() -> CostStore:
    global _COST_STORE
    if _COST_STORE is not None:
        return _COST_STORE
    if os.environ.get("AGENT_BOM_DB"):
        _COST_STORE = SQLiteCostStore(os.environ["AGENT_BOM_DB"])
    else:
        _COST_STORE = InMemoryCostStore()
    return _COST_STORE


def set_cost_store(store: CostStore | None) -> None:
    global _COST_STORE
    _COST_STORE = store
