"""Tenant-scoped LLM cost (FinOps) persistence and aggregation.

Token counts extracted from OpenTelemetry GenAI spans
(:func:`agent_bom.otel_ingest.parse_ml_api_spans`) are priced via
:mod:`agent_bom.cost_model` and persisted here so operators get per-agent /
per-model / per-provider spend attribution and budget enforcement — the
accountability layer commercial agent-runtime products charge for, kept open.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version
from agent_bom.storage.base import StorageSchema, TableSchema


@dataclass(frozen=True)
class LLMCostRecord:
    """One priced LLM API call.

    ``cost_center`` and ``allocation_tags`` carry the showback/chargeback
    dimension (#2925): which team / budget unit a call belongs to. Both are
    optional and default empty so older ingest paths and pre-migration rows
    stay valid — spend without an allocation simply rolls up under
    ``"unallocated"``.
    """

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
    cost_center: str = ""
    allocation_tags: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CostBudget:
    """A spend cap for a tenant (optionally scoped to one agent).

    ``mode`` controls whether the cap is advisory or blocking:
    - ``"report"`` (default): surfaced in budget posture only.
    - ``"enforce"``: the runtime relay fails calls closed once spend reaches
      the cap (pre-invocation enforcement), turning FinOps into a control.

    A budget may be scoped to any one of the mutually-exclusive dimensions
    ``agent`` / ``cost_center`` / ``owner`` (all empty = tenant-wide). ``owner``
    joins spend to the accountable human/team recorded on the governing
    blueprint header (#3909); ``workflow`` optionally narrows an owner budget to
    one governing blueprint. Owner spend is resolved from the blueprint that
    governs the agent — see :mod:`agent_bom.api.cost_owner`.
    """

    tenant_id: str
    agent: str  # "" means tenant-wide
    limit_usd: float
    updated_at: str
    mode: str = "report"  # report | enforce
    cost_center: str = ""  # "" means not scoped to a cost center (#2925)
    owner: str = ""  # "" means not scoped to an accountable owner (#3909)
    workflow: str = ""  # optional owner sub-scope: a single governing blueprint

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_UNALLOCATED = "unallocated"


def _decode_tags(raw: Any) -> dict[str, str]:
    """Parse a stored allocation_tags JSON blob into a string->string dict.

    Tolerant of NULL / malformed rows (pre-migration data) — those become {}.
    """
    if not raw:
        return {}
    try:
        parsed = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
    except (ValueError, TypeError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    return {str(k): str(v) for k, v in parsed.items()}


def _rollup(records: list[LLMCostRecord], dimension: str) -> list[dict[str, Any]]:
    """Aggregate spend + tokens by one dimension (agent/model/provider/cost_center)."""
    buckets: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"key": "", "calls": 0, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0, "unpriced_calls": 0}
    )
    for r in records:
        key = {
            "agent": r.agent,
            "model": r.model,
            "provider": r.provider,
            "cost_center": r.cost_center or _UNALLOCATED,
        }.get(dimension, r.agent) or "unknown"
        b = buckets[key]
        b["key"] = key
        b["calls"] += 1
        b["input_tokens"] += r.input_tokens
        b["output_tokens"] += r.output_tokens
        b["cost_usd"] = round(b["cost_usd"] + r.cost_usd, 6)
        if not r.priced:
            b["unpriced_calls"] += 1
    return sorted(buckets.values(), key=lambda b: b["cost_usd"], reverse=True)


def _rollup_by_tag(records: list[LLMCostRecord], tag_key: str) -> list[dict[str, Any]]:
    """Aggregate spend + tokens by the value of one allocation tag.

    A call with no value for ``tag_key`` rolls up under ``"unallocated"``. Used
    for freeform showback dimensions (``team``, ``project``, ``env`` …) beyond
    the first-class ``cost_center``.
    """
    buckets: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"key": "", "calls": 0, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0, "unpriced_calls": 0}
    )
    for r in records:
        key = (r.allocation_tags.get(tag_key) or "").strip() or _UNALLOCATED
        b = buckets[key]
        b["key"] = key
        b["calls"] += 1
        b["input_tokens"] += r.input_tokens
        b["output_tokens"] += r.output_tokens
        b["cost_usd"] = round(b["cost_usd"] + r.cost_usd, 6)
        if not r.priced:
            b["unpriced_calls"] += 1
    return sorted(buckets.values(), key=lambda b: b["cost_usd"], reverse=True)


# ── Portable schema seam (reference) ──────────────────────────────────────────
#
# Single source-of-truth schema for the llm_costs store, shared across backends.
# The SQLite and Postgres ``_init_db`` / ``_init_tables`` paths below remain the
# executed DDL (audited, with their additive migrations); this declaration mirrors
# them so a conformance/parity test can assert both backends cover the same logical
# columns and a new backend is a registration here rather than a fork. See
# ``agent_bom.storage.base.StorageSchema`` for the seam contract.
COST_STORAGE_SCHEMA = StorageSchema(
    component="llm_costs",
    tables=(
        TableSchema(
            name="llm_costs",
            columns=(
                "tenant_id",
                "call_id",
                "agent",
                "session_id",
                "provider",
                "model",
                "input_tokens",
                "output_tokens",
                "cost_usd",
                "priced",
                "observed_at",
                "cost_center",
                "allocation_tags",
            ),
            ddl_by_backend={
                "sqlite": (
                    "CREATE TABLE IF NOT EXISTS llm_costs (tenant_id TEXT NOT NULL, "
                    "call_id TEXT NOT NULL, agent TEXT NOT NULL, session_id TEXT NOT NULL, "
                    "provider TEXT NOT NULL, model TEXT NOT NULL, input_tokens INTEGER NOT NULL, "
                    "output_tokens INTEGER NOT NULL, cost_usd REAL NOT NULL, priced INTEGER NOT NULL, "
                    "observed_at TEXT NOT NULL, cost_center TEXT NOT NULL DEFAULT '', "
                    "allocation_tags TEXT NOT NULL DEFAULT '{}', PRIMARY KEY (tenant_id, call_id))"
                ),
                "postgres": (
                    "CREATE TABLE IF NOT EXISTS llm_costs (tenant_id TEXT NOT NULL, "
                    "call_id TEXT NOT NULL, agent TEXT NOT NULL, session_id TEXT NOT NULL, "
                    "provider TEXT NOT NULL, model TEXT NOT NULL, input_tokens INTEGER NOT NULL, "
                    "output_tokens INTEGER NOT NULL, cost_usd DOUBLE PRECISION NOT NULL, priced BOOLEAN NOT NULL, "
                    "observed_at TEXT NOT NULL, cost_center TEXT NOT NULL DEFAULT '', "
                    "allocation_tags TEXT NOT NULL DEFAULT '{}', PRIMARY KEY (tenant_id, call_id))"
                ),
            },
        ),
        TableSchema(
            name="llm_cost_budgets",
            columns=("tenant_id", "agent", "limit_usd", "updated_at", "mode", "cost_center", "owner", "workflow"),
            ddl_by_backend={
                "sqlite": (
                    "CREATE TABLE IF NOT EXISTS llm_cost_budgets (tenant_id TEXT NOT NULL, "
                    "agent TEXT NOT NULL DEFAULT '', limit_usd REAL NOT NULL, updated_at TEXT NOT NULL, "
                    "mode TEXT NOT NULL DEFAULT 'report', cost_center TEXT NOT NULL DEFAULT '', "
                    "owner TEXT NOT NULL DEFAULT '', workflow TEXT NOT NULL DEFAULT '', "
                    "PRIMARY KEY (tenant_id, agent, cost_center, owner, workflow))"
                ),
                "postgres": (
                    "CREATE TABLE IF NOT EXISTS llm_cost_budgets (tenant_id TEXT NOT NULL, "
                    "agent TEXT NOT NULL DEFAULT '', limit_usd DOUBLE PRECISION NOT NULL, updated_at TEXT NOT NULL, "
                    "mode TEXT NOT NULL DEFAULT 'report', cost_center TEXT NOT NULL DEFAULT '', "
                    "owner TEXT NOT NULL DEFAULT '', workflow TEXT NOT NULL DEFAULT '', "
                    "PRIMARY KEY (tenant_id, agent, cost_center, owner, workflow))"
                ),
            },
        ),
    ),
)


class CostStore(Protocol):
    def record_cost(self, record: LLMCostRecord) -> None: ...

    def list_records(self, tenant_id: str, *, limit: int = 1000) -> list[LLMCostRecord]: ...

    def total_spend(self, tenant_id: str, *, agent: str | None = None) -> float: ...

    def total_spend_by_cost_center(self, tenant_id: str, cost_center: str) -> float: ...

    def set_budget(self, budget: CostBudget) -> None: ...

    def get_budget(
        self, tenant_id: str, agent: str = "", *, cost_center: str = "", owner: str = "", workflow: str = ""
    ) -> CostBudget | None: ...


def _rollup_by_owner(records: list[LLMCostRecord], agent_owner: dict[str, str]) -> list[dict[str, Any]]:
    """Aggregate spend + tokens by the accountable owner governing each agent (#3909).

    ``agent_owner`` maps an agent name to the owner recorded on the blueprint
    that governs it. A call whose agent has no governing blueprint rolls up under
    ``"unattributed"`` so owner ROI reporting never silently drops spend.
    """
    buckets: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"key": "", "calls": 0, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0, "unpriced_calls": 0}
    )
    for r in records:
        key = (agent_owner.get(r.agent) or "").strip() or "unattributed"
        b = buckets[key]
        b["key"] = key
        b["calls"] += 1
        b["input_tokens"] += r.input_tokens
        b["output_tokens"] += r.output_tokens
        b["cost_usd"] = round(b["cost_usd"] + r.cost_usd, 6)
        if not r.priced:
            b["unpriced_calls"] += 1
    return sorted(buckets.values(), key=lambda b: b["cost_usd"], reverse=True)


def summarize_by_owner(records: list[LLMCostRecord], agent_owner: dict[str, str]) -> dict[str, Any]:
    """Owner-attributed spend report (#3909): total spend grouped by accountable owner."""
    return {
        "total_cost_usd": round(sum(r.cost_usd for r in records), 6),
        "by_owner": _rollup_by_owner(records, agent_owner),
    }


def check_owner_budget_enforcement(
    store: CostStore, tenant_id: str, owner: str, workflow: str, spend: float
) -> tuple[bool, CostBudget | None]:
    """Decide whether a call should block for exceeding an owner's budget (#3909).

    A ``(owner, workflow)`` enforce budget (owner scoped to one governing
    blueprint) wins; otherwise the owner-wide ``(owner, "")`` enforce budget
    applies. ``spend`` is the owner's aggregate spend, resolved by the caller
    from the blueprints that govern the owner's agents. Report-mode and missing
    budgets never block.
    """
    if not owner:
        return False, None
    budget: CostBudget | None = None
    if workflow:
        budget = store.get_budget(tenant_id, "", owner=owner, workflow=workflow)
    if budget is None or budget.mode != "enforce":
        owner_wide = store.get_budget(tenant_id, "", owner=owner)
        if owner_wide is not None and owner_wide.mode == "enforce":
            budget = owner_wide
        elif budget is None:
            budget = owner_wide
    if budget is None or budget.mode != "enforce":
        return False, budget
    return spend >= budget.limit_usd, budget


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
        "by_cost_center": _rollup(records, "cost_center"),
    }


def summarize_by_tag(records: list[LLMCostRecord], tag_key: str) -> dict[str, Any]:
    """Showback report sliced by one freeform allocation tag (#2925)."""
    return {
        "tag_key": tag_key,
        "total_cost_usd": round(sum(r.cost_usd for r in records), 6),
        "by_tag": _rollup_by_tag(records, tag_key),
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
        "cost_center": budget.cost_center or None,
        "owner": budget.owner or None,
        "workflow": budget.workflow or None,
        "mode": budget.mode,
        "limit_usd": budget.limit_usd,
        "spend_usd": round(spend, 6),
        "remaining_usd": remaining,
        # A zero budget is a valid hard cap — any spend exceeds it. The > 0 guard
        # belongs only on the utilization divide, not on the exceeded check.
        "exceeded": spend >= budget.limit_usd,
        "utilization": round(spend / budget.limit_usd, 4) if budget.limit_usd > 0 else None,
    }


class InMemoryCostStore:
    def __init__(self) -> None:
        self._records: dict[str, list[LLMCostRecord]] = defaultdict(list)
        self._seen: dict[str, set[str]] = defaultdict(set)
        self._budgets: dict[tuple[str, str, str, str, str], CostBudget] = {}
        self._lock = threading.Lock()

    def init_schema(self) -> None:
        """No-op: the in-memory backend has no persistent schema. Present so the
        in-memory store satisfies the shared
        :class:`agent_bom.storage.base.TenantScopedStore` contract."""

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

    def total_spend_by_cost_center(self, tenant_id: str, cost_center: str) -> float:
        with self._lock:
            return round(
                sum(r.cost_usd for r in self._records.get(tenant_id, []) if (r.cost_center or "") == cost_center),
                6,
            )

    def set_budget(self, budget: CostBudget) -> None:
        with self._lock:
            self._budgets[(budget.tenant_id, budget.agent, budget.cost_center, budget.owner, budget.workflow)] = budget

    def get_budget(
        self, tenant_id: str, agent: str = "", *, cost_center: str = "", owner: str = "", workflow: str = ""
    ) -> CostBudget | None:
        with self._lock:
            return self._budgets.get((tenant_id, agent, cost_center, owner, workflow))


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

    def init_schema(self) -> None:
        """Idempotently (re)create this store's tables. Satisfies the shared
        :class:`agent_bom.storage.base.TenantScopedStore` contract."""
        self._init_db()

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
                cost_center TEXT NOT NULL DEFAULT '',
                allocation_tags TEXT NOT NULL DEFAULT '{}',
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
                mode TEXT NOT NULL DEFAULT 'report',
                cost_center TEXT NOT NULL DEFAULT '',
                owner TEXT NOT NULL DEFAULT '',
                workflow TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (tenant_id, agent, cost_center, owner, workflow)
            )
            """
        )
        # Backfill mode for databases created before enforcement existed.
        budget_cols = [r[1] for r in self._conn.execute("PRAGMA table_info(llm_cost_budgets)").fetchall()]
        if "mode" not in budget_cols:
            self._conn.execute("ALTER TABLE llm_cost_budgets ADD COLUMN mode TEXT NOT NULL DEFAULT 'report'")
        # Allocation columns (#2925) added additively; pre-migration rows keep
        # an empty cost_center / '{}' tags and roll up under "unallocated".
        if "cost_center" not in budget_cols:
            self._conn.execute("ALTER TABLE llm_cost_budgets ADD COLUMN cost_center TEXT NOT NULL DEFAULT ''")
        # Owner/workflow scoping (#3909) widens the budget primary key so an
        # owner budget cannot collide with the tenant-wide row. SQLite cannot
        # ALTER a primary key, so migrate pre-owner databases by rebuilding the
        # table with the widened key and copying every existing budget across.
        if "owner" not in budget_cols:
            self._conn.executescript(
                """
                ALTER TABLE llm_cost_budgets RENAME TO llm_cost_budgets_pre_owner;
                CREATE TABLE llm_cost_budgets (
                    tenant_id TEXT NOT NULL,
                    agent TEXT NOT NULL DEFAULT '',
                    limit_usd REAL NOT NULL,
                    updated_at TEXT NOT NULL,
                    mode TEXT NOT NULL DEFAULT 'report',
                    cost_center TEXT NOT NULL DEFAULT '',
                    owner TEXT NOT NULL DEFAULT '',
                    workflow TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (tenant_id, agent, cost_center, owner, workflow)
                );
                INSERT INTO llm_cost_budgets (tenant_id, agent, limit_usd, updated_at, mode, cost_center)
                    SELECT tenant_id, agent, limit_usd, updated_at, mode, cost_center FROM llm_cost_budgets_pre_owner;
                DROP TABLE llm_cost_budgets_pre_owner;
                """
            )
        cost_cols = [r[1] for r in self._conn.execute("PRAGMA table_info(llm_costs)").fetchall()]
        if "cost_center" not in cost_cols:
            self._conn.execute("ALTER TABLE llm_costs ADD COLUMN cost_center TEXT NOT NULL DEFAULT ''")
        if "allocation_tags" not in cost_cols:
            self._conn.execute("ALTER TABLE llm_costs ADD COLUMN allocation_tags TEXT NOT NULL DEFAULT '{}'")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_llm_costs_tenant_agent ON llm_costs(tenant_id, agent)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_llm_costs_tenant_cost_center ON llm_costs(tenant_id, cost_center)")
        self._conn.commit()

    def record_cost(self, record: LLMCostRecord) -> None:
        self._conn.execute(
            """
            INSERT OR IGNORE INTO llm_costs
                (tenant_id, call_id, agent, session_id, provider, model, input_tokens, output_tokens,
                 cost_usd, priced, observed_at, cost_center, allocation_tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                record.cost_center,
                json.dumps(record.allocation_tags, sort_keys=True),
            ),
        )
        self._conn.commit()

    def list_records(self, tenant_id: str, *, limit: int = 1000) -> list[LLMCostRecord]:
        rows = self._conn.execute(
            "SELECT tenant_id, call_id, agent, session_id, provider, model, input_tokens, output_tokens, "
            "cost_usd, priced, observed_at, cost_center, allocation_tags "
            "FROM llm_costs WHERE tenant_id = ? ORDER BY observed_at DESC LIMIT ?",
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

    def total_spend_by_cost_center(self, tenant_id: str, cost_center: str) -> float:
        row = self._conn.execute(
            "SELECT COALESCE(SUM(cost_usd), 0.0) FROM llm_costs WHERE tenant_id = ? AND cost_center = ?",
            (tenant_id, cost_center),
        ).fetchone()
        return round(float(row[0]), 6)

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
            "INSERT OR REPLACE INTO llm_cost_budgets "
            "(tenant_id, agent, limit_usd, updated_at, mode, cost_center, owner, workflow) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
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
        self._conn.commit()

    def get_budget(
        self, tenant_id: str, agent: str = "", *, cost_center: str = "", owner: str = "", workflow: str = ""
    ) -> CostBudget | None:
        row = self._conn.execute(
            "SELECT tenant_id, agent, limit_usd, updated_at, mode, cost_center, owner, workflow "
            "FROM llm_cost_budgets WHERE tenant_id = ? AND agent = ? AND cost_center = ? AND owner = ? AND workflow = ?",
            (tenant_id, agent, cost_center, owner, workflow),
        ).fetchone()
        if not row:
            return None
        return CostBudget(
            row[0],
            row[1],
            float(row[2]),
            row[3],
            row[4] if len(row) > 4 and row[4] else "report",
            row[5] if len(row) > 5 and row[5] is not None else "",
            row[6] if len(row) > 6 and row[6] is not None else "",
            row[7] if len(row) > 7 and row[7] is not None else "",
        )


def check_budget_enforcement(store: CostStore, tenant_id: str, agent: str) -> tuple[bool, CostBudget | None, float]:
    """Decide whether a call should be blocked for exceeding an enforced budget.

    Returns ``(blocked, budget, spend)``. An agent-scoped enforce budget wins;
    otherwise the tenant-wide enforce budget applies. Report-mode budgets and
    missing budgets never block.
    """
    budget = store.get_budget(tenant_id, agent) if agent else None
    spend = store.total_spend(tenant_id, agent=agent or None)
    if budget is None or budget.mode != "enforce":
        tenant_budget = store.get_budget(tenant_id, "")
        if tenant_budget is not None and tenant_budget.mode == "enforce":
            budget = tenant_budget
            spend = store.total_spend(tenant_id, agent=None)
        elif budget is None or budget.mode != "enforce":
            return False, budget, spend
    blocked = budget is not None and budget.mode == "enforce" and spend >= budget.limit_usd
    return blocked, budget, spend


def check_cost_center_budget_enforcement(store: CostStore, tenant_id: str, cost_center: str) -> tuple[bool, CostBudget | None, float]:
    """Decide whether a call should block for exceeding a cost-center budget (#2925).

    A cost-center scoped enforce budget caps the aggregate spend of every call
    tagged to that ``cost_center``, independent of the per-agent / tenant caps.
    Report-mode and missing budgets never block.
    """
    if not cost_center:
        return False, None, 0.0
    budget = store.get_budget(tenant_id, "", cost_center=cost_center)
    spend = store.total_spend_by_cost_center(tenant_id, cost_center)
    if budget is None or budget.mode != "enforce":
        return False, budget, spend
    return spend >= budget.limit_usd, budget, spend


_COST_STORE: CostStore | None = None


def get_cost_store() -> CostStore:
    global _COST_STORE
    if _COST_STORE is not None:
        return _COST_STORE
    # Backend selection is centralized in the storage factory (Postgres → shared
    # SQLite → in-memory) so per-agent spend and budget enforcement land on the
    # same tier every other env-ladder store does, instead of a hand-rolled copy.
    from agent_bom.storage.base import BackendKind
    from agent_bom.storage.factory import resolve_backend

    selection = resolve_backend(mode="env")
    if selection.backend is BackendKind.POSTGRES:
        from agent_bom.api.postgres_cost import PostgresCostStore

        _COST_STORE = PostgresCostStore()
    elif selection.backend is BackendKind.SQLITE and selection.sqlite_path:
        _COST_STORE = SQLiteCostStore(selection.sqlite_path)
    else:
        _COST_STORE = InMemoryCostStore()
    return _COST_STORE


def set_cost_store(store: CostStore | None) -> None:
    global _COST_STORE
    _COST_STORE = store
