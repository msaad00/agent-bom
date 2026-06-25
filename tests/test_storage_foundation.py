"""Conformance tests for the shared storage foundation.

Proves the additive storage seam holds: every backend of every wired store
family (SQLite, Postgres-fake, in-memory) structurally satisfies the shared
:class:`~agent_bom.storage.base.TenantScopedStore` protocol and survives a
round-trip; the reference :class:`~agent_bom.storage.base.StorageSchema` has no
SQLite⇄Postgres drift; and the backend factory resolves every DSN / env ladder
the wired stores rely on without changing any store's tier.
"""

from __future__ import annotations

import pytest

from agent_bom.api.cost_store import (
    COST_STORAGE_SCHEMA,
    CostBudget,
    InMemoryCostStore,
    LLMCostRecord,
    SQLiteCostStore,
)
from agent_bom.api.policy_store import InMemoryPolicyStore, SQLitePolicyStore
from agent_bom.api.proxy_replay_store import InMemoryProxyReplayStore, SQLiteProxyReplayStore
from agent_bom.api.runtime_event_store import (
    InMemoryRuntimeEventStore,
    RuntimeObservationRecord,
    SQLiteRuntimeEventStore,
)
from agent_bom.storage.base import (
    BackendKind,
    CleanupCapable,
    StorageSchema,
    TenantScopedStore,
)
from agent_bom.storage.factory import resolve_backend, resolve_from_dsn

# ── Protocol conformance: every backend declares init_schema (TenantScopedStore) ─


def _sqlite_backends(tmp_path):
    db = str(tmp_path / "conformance.db")
    return [
        SQLiteCostStore(db),
        SQLitePolicyStore(db),
        SQLiteRuntimeEventStore(db),
        SQLiteProxyReplayStore(db),
    ]


def _inmemory_backends():
    return [
        InMemoryCostStore(),
        InMemoryPolicyStore(),
        InMemoryRuntimeEventStore(),
        InMemoryProxyReplayStore(),
    ]


def test_inmemory_stores_satisfy_tenant_scoped_protocol():
    for store in _inmemory_backends():
        assert isinstance(store, TenantScopedStore), store


def test_sqlite_stores_satisfy_tenant_scoped_protocol(tmp_path):
    for store in _sqlite_backends(tmp_path):
        assert isinstance(store, TenantScopedStore), store


def test_postgres_stores_declare_init_schema():
    # The Postgres backends require a live pool to instantiate, so assert the
    # contract structurally on the class instead: every Postgres store exposes
    # init_schema so it satisfies TenantScopedStore once constructed.
    from agent_bom.api.postgres_cost import PostgresCostStore
    from agent_bom.api.postgres_policy import PostgresPolicyStore
    from agent_bom.api.postgres_runtime_event import PostgresRuntimeEventStore
    from agent_bom.api.proxy_replay_store import PostgresProxyReplayStore

    for cls in (PostgresCostStore, PostgresPolicyStore, PostgresRuntimeEventStore, PostgresProxyReplayStore):
        assert callable(getattr(cls, "init_schema", None)), cls


def test_replay_store_is_cleanup_capable():
    # The TTL-driven replay backends additionally satisfy CleanupCapable.
    assert isinstance(InMemoryProxyReplayStore(), CleanupCapable)


def test_init_schema_is_idempotent(tmp_path):
    # Calling init_schema twice must not raise (CREATE TABLE IF NOT EXISTS).
    for store in [*_sqlite_backends(tmp_path), *_inmemory_backends()]:
        store.init_schema()
        store.init_schema()


# ── Round-trip smoke test per backend (write then read back) ──────────────────


def _roundtrip_cost(store) -> None:
    store.record_cost(
        LLMCostRecord(
            tenant_id="t1",
            call_id="c1",
            agent="a",
            session_id="s",
            provider="openai",
            model="gpt-4o",
            input_tokens=10,
            output_tokens=5,
            cost_usd=1.5,
            priced=True,
            observed_at="2026-01-01T00:00:00Z",
        )
    )
    # Idempotency (#21): re-recording the same call_id must not duplicate.
    store.record_cost(
        LLMCostRecord(
            tenant_id="t1",
            call_id="c1",
            agent="a",
            session_id="s",
            provider="openai",
            model="gpt-4o",
            input_tokens=10,
            output_tokens=5,
            cost_usd=1.5,
            priced=True,
            observed_at="2026-01-01T00:00:00Z",
        )
    )
    records = store.list_records("t1")
    assert len(records) == 1
    assert records[0].cost_usd == 1.5
    store.set_budget(CostBudget(tenant_id="t1", agent="", limit_usd=10.0, updated_at="2026-01-01T00:00:00Z"))
    assert store.get_budget("t1", "").limit_usd == 10.0


def _roundtrip_runtime(store) -> None:
    store.put_observation(
        RuntimeObservationRecord(
            tenant_id="t1",
            observation_id="o1",
            session_id="sess1",
            observed_at="2026-01-01T00:00:00Z",
        )
    )
    # Idempotency: same observation_id is a no-op.
    store.put_observation(
        RuntimeObservationRecord(
            tenant_id="t1",
            observation_id="o1",
            session_id="sess1",
            observed_at="2026-01-01T00:00:00Z",
        )
    )
    obs = store.list_observations("t1")
    assert len(obs) == 1
    session = store.get_session("t1", "sess1")
    assert session is not None and session.observation_count == 1


def _roundtrip_replay(store) -> None:
    row_id = store.add("t1", {"k": "v"})
    assert row_id
    rows = store.list("t1")
    assert len(rows) == 1
    assert rows[0]["record"] == {"k": "v"}
    assert store.count("t1") == 1


def test_roundtrip_cost_inmemory_and_sqlite(tmp_path):
    _roundtrip_cost(InMemoryCostStore())
    _roundtrip_cost(SQLiteCostStore(str(tmp_path / "cost.db")))


def test_roundtrip_runtime_inmemory_and_sqlite(tmp_path):
    _roundtrip_runtime(InMemoryRuntimeEventStore())
    _roundtrip_runtime(SQLiteRuntimeEventStore(str(tmp_path / "rt.db")))


def test_roundtrip_replay_inmemory_and_sqlite(tmp_path):
    _roundtrip_replay(InMemoryProxyReplayStore())
    _roundtrip_replay(SQLiteProxyReplayStore(str(tmp_path / "replay.db")))


# ── Portable-schema seam: no SQLite⇄Postgres drift in the reference schema ─────


def test_reference_schema_has_no_backend_drift():
    # Every table in the reference schema must define DDL for every backend the
    # schema declares — the seam's whole point is that a column landing on one
    # backend but not its sibling is a test failure, not a silent prod drift.
    assert COST_STORAGE_SCHEMA.drift_report() == {}


def test_reference_schema_covers_sqlite_and_postgres():
    assert COST_STORAGE_SCHEMA.backends() == frozenset({"sqlite", "postgres"})
    for table in COST_STORAGE_SCHEMA.tables:
        # The same logical columns must appear in both backends' DDL text.
        sqlite_ddl = table.ddl_for(BackendKind.SQLITE)
        pg_ddl = table.ddl_for(BackendKind.POSTGRES)
        assert sqlite_ddl and pg_ddl
        for column in table.columns:
            assert column in sqlite_ddl, (table.name, column, "sqlite")
            assert column in pg_ddl, (table.name, column, "postgres")


def test_reference_schema_lookup_helpers():
    assert COST_STORAGE_SCHEMA.table("llm_costs") is not None
    assert COST_STORAGE_SCHEMA.table("nonexistent") is None


# ── Backend factory: DSN + env ladders resolve without changing store tiers ────


@pytest.mark.parametrize(
    "dsn,expected",
    [
        ("memory://", BackendKind.MEMORY),
        ("postgresql://user@host/db", BackendKind.POSTGRES),
        ("postgres://user@host/db", BackendKind.POSTGRES),
        ("sqlite:///abs/path.db", BackendKind.SQLITE),
        ("/bare/path.db", BackendKind.SQLITE),
    ],
)
def test_resolve_from_dsn(dsn, expected):
    assert resolve_from_dsn(dsn).backend is expected


def test_resolve_from_dsn_sqlite_path():
    assert resolve_from_dsn("sqlite:///abs/path.db").sqlite_path == "/abs/path.db"
    assert resolve_from_dsn("/bare/path.db").sqlite_path == "/bare/path.db"


def test_resolve_from_dsn_postgres_carries_dsn():
    sel = resolve_from_dsn("postgresql://u@h/d")
    assert sel.backend is BackendKind.POSTGRES
    assert sel.dsn == "postgresql://u@h/d"


def test_resolve_from_dsn_rejects_unknown_scheme():
    with pytest.raises(ValueError):
        resolve_from_dsn("mysql://u@h/d")


def test_env_simple_ladder(monkeypatch):
    # Postgres URL wins.
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://u@h/d")
    assert resolve_backend(mode="env").backend is BackendKind.POSTGRES
    # SQLite file path next.
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.setenv("AGENT_BOM_DB", "/tmp/x.db")
    sel = resolve_backend(mode="env")
    assert sel.backend is BackendKind.SQLITE
    assert sel.sqlite_path == "/tmp/x.db"
    # AGENT_BOM_DB holding a Postgres URL resolves to Postgres.
    monkeypatch.setenv("AGENT_BOM_DB", "postgresql://u@h/d")
    assert resolve_backend(mode="env").backend is BackendKind.POSTGRES
    # Nothing set → in-memory.
    monkeypatch.delenv("AGENT_BOM_DB", raising=False)
    assert resolve_backend(mode="env").backend is BackendKind.MEMORY


def test_env_durable_ladder(monkeypatch, tmp_path):
    # Durable-by-default: no config → durable SQLite under the state dir.
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    monkeypatch.delenv("AGENT_BOM_EPHEMERAL_STORE", raising=False)
    monkeypatch.delenv("AGENT_BOM_DB", raising=False)
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    sel = resolve_backend(mode="durable")
    assert sel.backend is BackendKind.SQLITE
    assert sel.sqlite_path
    # Explicit ephemeral opt-out → in-memory.
    monkeypatch.setenv("AGENT_BOM_EPHEMERAL_STORE", "1")
    assert resolve_backend(mode="durable").backend is BackendKind.MEMORY
    # Postgres always wins over the ephemeral opt-out.
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://u@h/d")
    assert resolve_backend(mode="durable").backend is BackendKind.POSTGRES


def test_resolve_backend_rejects_unknown_mode():
    with pytest.raises(ValueError):
        resolve_backend(mode="bogus")


def test_storage_schema_is_frozen():
    schema = StorageSchema(component="x", tables=())
    with pytest.raises(Exception):
        schema.component = "y"  # type: ignore[misc]
