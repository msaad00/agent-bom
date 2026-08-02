"""One tenant may not overwrite the fleet identity of another (local stores).

The Postgres sibling of this contract lives in
``test_fleet_agents_tenant_scoped_key.py``: ``fleet_agents`` was keyed
``PRIMARY KEY (agent_id)`` with no tenant component, and there the second
tenant's registration was at least *rejected* loudly by row-level security.

``SQLiteFleetStore`` and ``InMemoryFleetStore`` had no tenant column and no
row-level security at all, so the same collision was worse: ``INSERT OR
REPLACE`` (and a plain dict assignment) silently *replaced* the first tenant's
row. ``canonical_ids.canonical_agent_id`` is a UUIDv5 over agent content with
no tenant component, so two customers running a stock agent of the same type
collide on sight and the later registration destroys the earlier one.

These tests are the cross-tenant isolation guard for the local stores: both
rows persist, neither leaks, same-tenant re-registration still upserts rather
than duplicating, and every predicate on ``agent_id`` carries the tenant.
"""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

import pytest

from agent_bom.api.fleet_store import (
    FleetAgent,
    FleetLifecycleState,
    InMemoryFleetStore,
    SQLiteFleetStore,
)

SHARED_ID = "CANON-AGENT-1"


def _agent(tenant: str, agent_id: str = SHARED_ID, *, name: str | None = None, trust: float = 0.0) -> FleetAgent:
    return FleetAgent(
        agent_id=agent_id,
        canonical_id=agent_id,
        name=name or f"stock-agent-{tenant}",
        agent_type="claude-desktop",
        lifecycle_state=FleetLifecycleState.DISCOVERED,
        trust_score=trust,
        tenant_id=tenant,
        created_at="2026-08-01T00:00:00Z",
        updated_at="2026-08-01T00:00:00Z",
    )


@pytest.fixture
def sqlite_store(tmp_path: Path):
    store = SQLiteFleetStore(str(tmp_path / "fleet.db"))
    yield store


@pytest.fixture(params=["sqlite", "memory"])
def store(request, tmp_path: Path):
    """Both local stores must satisfy the same contract."""
    if request.param == "sqlite":
        return SQLiteFleetStore(str(tmp_path / "fleet.db"))
    return InMemoryFleetStore()


# ── The shipped defect ───────────────────────────────────────────────────────


def test_two_tenants_register_the_same_agent_id(store):
    """The shipped defect: tenant B's registration destroyed tenant A's row."""
    store.put(_agent("tenant-a"))
    store.put(_agent("tenant-b"))

    seen_by_a = store.get(SHARED_ID, tenant_id="tenant-a")
    seen_by_b = store.get(SHARED_ID, tenant_id="tenant-b")

    assert seen_by_a is not None, "tenant A lost its agent to tenant B"
    assert seen_by_b is not None, "tenant B was denied registration of its own agent"
    assert seen_by_a.tenant_id == "tenant-a"
    assert seen_by_b.tenant_id == "tenant-b"
    assert seen_by_a.name == "stock-agent-tenant-a"
    assert seen_by_b.name == "stock-agent-tenant-b"


def test_each_tenants_fleet_view_shows_only_its_own_agent(store):
    store.put(_agent("tenant-a"))
    store.put(_agent("tenant-b"))

    listed_a = store.list_by_tenant("tenant-a")
    listed_b = store.list_by_tenant("tenant-b")

    assert [a.name for a in listed_a] == ["stock-agent-tenant-a"]
    assert [a.name for a in listed_b] == ["stock-agent-tenant-b"]
    assert len(store.list_all()) == 2, "one tenant's row was overwritten by the other"
    assert {row["tenant_id"]: row["agent_count"] for row in store.list_tenants()} == {
        "tenant-a": 1,
        "tenant-b": 1,
    }


def test_batch_put_keeps_both_tenants_copies(store):
    assert store.batch_put([_agent("tenant-a"), _agent("tenant-b")]) == 2

    assert store.get(SHARED_ID, tenant_id="tenant-a") is not None
    assert store.get(SHARED_ID, tenant_id="tenant-b") is not None
    assert len(store.list_all()) == 2


def test_same_tenant_re_registration_still_upserts(store):
    """Paired guard: tenant-scoping the key may not turn upsert into insert."""
    store.put(_agent("tenant-a", name="first", trust=1.0))
    store.put(_agent("tenant-a", name="second", trust=9.0))

    stored = store.get(SHARED_ID, tenant_id="tenant-a")
    assert stored is not None
    assert stored.name == "second"
    assert stored.trust_score == 9.0
    assert len(store.list_by_tenant("tenant-a")) == 1, "re-registration duplicated the agent"


def test_one_tenants_delete_does_not_remove_anothers_agent(store):
    store.put(_agent("tenant-a"))
    store.put(_agent("tenant-b"))

    assert store.delete(SHARED_ID, tenant_id="tenant-a") is True

    survivor = store.get(SHARED_ID, tenant_id="tenant-b")
    assert survivor is not None, "deleting tenant A's agent removed tenant B's"
    assert survivor.tenant_id == "tenant-b"


def test_get_by_canonical_id_is_tenant_scoped(store):
    store.put(_agent("tenant-a"))
    store.put(_agent("tenant-b"))

    assert store.get_by_canonical_id(SHARED_ID, "tenant-a").tenant_id == "tenant-a"
    assert store.get_by_canonical_id(SHARED_ID, "tenant-b").tenant_id == "tenant-b"


# ── update_state must carry the tenant ───────────────────────────────────────


def test_update_state_only_touches_the_calling_tenants_agent(store):
    """``agent_id`` is unique only WITHIN a tenant — an unscoped UPDATE is a
    cross-tenant write. Quarantining tenant A's agent must not quarantine
    every other tenant's copy of the same stock agent ID."""
    store.put(_agent("tenant-a"))
    store.put(_agent("tenant-b"))

    assert store.update_state(SHARED_ID, FleetLifecycleState.QUARANTINED, tenant_id="tenant-a") is True

    assert store.get(SHARED_ID, tenant_id="tenant-a").lifecycle_state == FleetLifecycleState.QUARANTINED
    assert store.get(SHARED_ID, tenant_id="tenant-b").lifecycle_state == FleetLifecycleState.DISCOVERED


def test_update_state_for_another_tenants_agent_reports_not_found(store):
    store.put(_agent("tenant-a"))

    assert store.update_state(SHARED_ID, FleetLifecycleState.APPROVED, tenant_id="tenant-b") is False
    assert store.get(SHARED_ID, tenant_id="tenant-a").lifecycle_state == FleetLifecycleState.DISCOVERED


def test_update_state_requires_a_tenant():
    """The tenant is keyword-only and mandatory: no caller can forget it."""
    import inspect

    from agent_bom.api.fleet_store import FleetStore
    from agent_bom.api.postgres_fleet_store import PostgresFleetStore
    from agent_bom.api.snowflake_store import SnowflakeFleetStore

    for owner in (FleetStore, InMemoryFleetStore, SQLiteFleetStore, PostgresFleetStore, SnowflakeFleetStore):
        parameter = inspect.signature(owner.update_state).parameters.get("tenant_id")
        assert parameter is not None, f"{owner.__name__}.update_state is not tenant-scoped"
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY, f"{owner.__name__}.update_state tenant_id must be keyword-only"
        assert parameter.default is inspect.Parameter.empty, f"{owner.__name__}.update_state tenant_id must be required"


# ── Schema authority ─────────────────────────────────────────────────────────


def test_the_sqlite_primary_key_is_tenant_scoped(sqlite_store):
    """A row-level fix alone is not enough — the physical key is what SQLite
    uses to resolve ``INSERT OR REPLACE``, and it is what silently deleted the
    first tenant's row."""
    conn = sqlite3.connect(sqlite_store._db_path)
    try:
        pk_columns = [row[1] for row in sorted(conn.execute("PRAGMA table_info(fleet_agents)").fetchall(), key=lambda r: r[5]) if row[5]]
        unique_indexes = [
            (row[1], [c[2] for c in conn.execute(f"PRAGMA index_info({row[1]!r})").fetchall()])
            for row in conn.execute("PRAGMA index_list(fleet_agents)").fetchall()
            if row[2]
        ]
    finally:
        conn.close()

    assert set(pk_columns) == {"tenant_id", "agent_id"}, f"fleet_agents primary key is {pk_columns}"
    for index_name, columns in unique_indexes:
        assert "tenant_id" in columns, f"{index_name} is a tenant-less unique key over {columns}"


def test_two_tenants_survive_at_the_row_level_in_sqlite(sqlite_store):
    sqlite_store.put(_agent("tenant-a"))
    sqlite_store.put(_agent("tenant-b"))

    conn = sqlite3.connect(sqlite_store._db_path)
    try:
        count = conn.execute("SELECT COUNT(*) FROM fleet_agents").fetchone()[0]
        tenants = sorted(r[0] for r in conn.execute("SELECT tenant_id FROM fleet_agents").fetchall())
    finally:
        conn.close()

    assert count == 2, "the second registration replaced the first tenant's row"
    assert tenants == ["tenant-a", "tenant-b"]


# ── Migration of pre-existing rows ───────────────────────────────────────────


def _legacy_fleet_db(path: Path, rows: list[tuple[str, str, str]]) -> None:
    """Build a fleet DB in the pre-tenant_id shape (agent_id-only primary key).

    ``rows`` is ``(agent_id, name, tenant_id_in_json)``; an empty tenant string
    writes JSON with no ``tenant_id`` key at all, which is what the very first
    rows written by the shipped store look like.
    """
    conn = sqlite3.connect(str(path))
    conn.execute("""
        CREATE TABLE fleet_agents (
            agent_id TEXT PRIMARY KEY,
            canonical_id TEXT NOT NULL DEFAULT '',
            name TEXT NOT NULL,
            lifecycle_state TEXT NOT NULL,
            trust_score REAL DEFAULT 0.0,
            updated_at TEXT NOT NULL,
            device_fingerprint TEXT NOT NULL DEFAULT '',
            data TEXT NOT NULL
        )
    """)
    for agent_id, name, tenant in rows:
        payload = _agent(tenant or "default", agent_id, name=name).model_dump()
        if not tenant:
            payload.pop("tenant_id")
        import json

        conn.execute(
            "INSERT INTO fleet_agents (agent_id, canonical_id, name, lifecycle_state, trust_score, updated_at, device_fingerprint, data)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (agent_id, agent_id, name, "approved", 7.0, "2026-08-01T00:00:00Z", "", json.dumps(payload)),
        )
    conn.commit()
    conn.close()


def test_pre_existing_rows_migrate_to_the_tenant_they_already_belonged_to(tmp_path: Path):
    """No row may be dropped by the rebuild. Each legacy row's tenant is the
    one already recorded in its own ``data`` payload."""
    db = tmp_path / "legacy.db"
    _legacy_fleet_db(db, [("a-1", "alpha", "tenant-a"), ("a-2", "beta", "tenant-b")])

    store = SQLiteFleetStore(str(db))

    assert len(store.list_all()) == 2, "the table rebuild dropped rows"
    assert store.get("a-1", tenant_id="tenant-a").name == "alpha"
    assert store.get("a-2", tenant_id="tenant-b").name == "beta"
    assert store.get("a-1", tenant_id="tenant-b") is None
    assert store.list_by_tenant("tenant-a") and store.list_by_tenant("tenant-b")


def test_pre_existing_rows_without_a_tenant_in_their_payload_land_on_default(tmp_path: Path):
    """A row written before ``tenant_id`` existed belongs to the implicit
    single tenant the deployment was running as: ``default``. Guessing anything
    else would hand one deployment's agents to a tenant that never owned them."""
    db = tmp_path / "legacy.db"
    _legacy_fleet_db(db, [("a-1", "alpha", "")])

    store = SQLiteFleetStore(str(db))

    assert len(store.list_all()) == 1
    assert store.get("a-1", tenant_id="default") is not None
    assert [a.agent_id for a in store.list_by_tenant("default")] == ["a-1"]


def test_migrated_store_then_accepts_a_second_tenants_same_agent_id(tmp_path: Path):
    """The rebuild must produce the *new* key, not merely copy rows across."""
    db = tmp_path / "legacy.db"
    _legacy_fleet_db(db, [(SHARED_ID, "alpha", "tenant-a")])

    store = SQLiteFleetStore(str(db))
    store.put(_agent("tenant-b"))

    assert store.get(SHARED_ID, tenant_id="tenant-a").name == "alpha"
    assert store.get(SHARED_ID, tenant_id="tenant-b").name == "stock-agent-tenant-b"
    assert len(store.list_all()) == 2


def test_migration_is_idempotent_across_reopens(tmp_path: Path):
    db = tmp_path / "legacy.db"
    _legacy_fleet_db(db, [("a-1", "alpha", "tenant-a")])

    SQLiteFleetStore(str(db))
    store = SQLiteFleetStore(str(db))
    reopened = SQLiteFleetStore(str(db))

    assert len(store.list_all()) == 1
    assert len(reopened.list_all()) == 1
    assert reopened.get("a-1", tenant_id="tenant-a") is not None


def test_migration_preserves_the_backfilled_device_fingerprint_column(tmp_path: Path):
    """The rebuild runs alongside the existing canonical-id/fingerprint
    backfills; none of them may be lost."""
    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(str(db))
    conn.execute("""
        CREATE TABLE fleet_agents (
            agent_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            lifecycle_state TEXT NOT NULL,
            trust_score REAL DEFAULT 0.0,
            updated_at TEXT NOT NULL,
            data TEXT NOT NULL
        )
    """)
    agent = _agent("tenant-a", "a-1", name="alpha")
    agent.device_fingerprint = "fp-123"
    conn.execute(
        "INSERT INTO fleet_agents (agent_id, name, lifecycle_state, trust_score, updated_at, data) VALUES (?, ?, ?, ?, ?, ?)",
        ("a-1", "alpha", "discovered", 0.0, "2026-08-01T00:00:00Z", agent.model_dump_json()),
    )
    conn.commit()
    conn.close()

    store = SQLiteFleetStore(str(db))

    stored = store.get("a-1", tenant_id="tenant-a")
    assert stored is not None
    assert stored.device_fingerprint == "fp-123"
    conn = sqlite3.connect(str(db))
    try:
        row = conn.execute("SELECT device_fingerprint, canonical_id, tenant_id FROM fleet_agents").fetchone()
    finally:
        conn.close()
    assert row[0] == "fp-123"
    assert row[1] == agent.canonical_id
    assert row[2] == "tenant-a"


def test_temp_files_are_not_left_behind_by_the_rebuild(tmp_path: Path):
    db = tmp_path / "legacy.db"
    _legacy_fleet_db(db, [("a-1", "alpha", "tenant-a")])

    SQLiteFleetStore(str(db))

    conn = sqlite3.connect(str(db))
    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()}
    finally:
        conn.close()
    assert not [t for t in tables if t.startswith("fleet_agents_")], f"rebuild left scratch tables behind: {tables}"


def test_file_permissions_survive_the_rebuild(tmp_path: Path):
    db = tmp_path / "legacy.db"
    _legacy_fleet_db(db, [("a-1", "alpha", "tenant-a")])

    SQLiteFleetStore(str(db))

    assert (db.stat().st_mode & 0o777) == 0o600


def test_sqlite_store_can_be_built_from_a_plain_temp_file():
    """Regression cover for the non-tmp_path construction used elsewhere."""
    handle = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    handle.close()
    path = Path(handle.name)
    try:
        store = SQLiteFleetStore(str(path))
        store.put(_agent("tenant-a"))
        assert store.get(SHARED_ID, tenant_id="tenant-a") is not None
    finally:
        path.unlink(missing_ok=True)
