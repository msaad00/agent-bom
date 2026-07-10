"""Durable-by-default control-plane lifecycle stores survive a restart.

A control plane must not lose issued agent identities, JIT grants, or runtime
sessions on a single-replica restart. These tests prove the new default (SQLite
under the state dir, no AGENT_BOM_DB / Postgres / ephemeral flag) persists state
across a simulated process restart — a fresh store instance pointed at the same
default path reads back what an earlier instance wrote.

The autouse conftest sets AGENT_BOM_EPHEMERAL_STORE=1 to keep the rest of the
suite isolated; these tests explicitly clear it (and pin a throwaway state dir)
so they exercise the real durable default rather than the test opt-out.
"""

from __future__ import annotations

import os

import pytest

from agent_bom.api import durable_store
from agent_bom.api.agent_identity_store import (
    get_agent_identity_store,
    hash_token,
    issue_identity,
    issue_jit_grant,
    set_agent_identity_store,
)
from agent_bom.api.runtime_event_store import (
    RuntimeObservationRecord,
    get_runtime_event_store,
    set_runtime_event_store,
)


@pytest.fixture()
def durable_state_dir(tmp_path, monkeypatch):
    """Pin a throwaway state dir and remove every backend override.

    Clears AGENT_BOM_EPHEMERAL_STORE (set by conftest for suite isolation) and
    AGENT_BOM_DB / AGENT_BOM_POSTGRES_URL so select_backend() resolves to the
    real durable SQLite default. Resets the store singletons before and after so
    nothing leaks across the simulated restart boundary.
    """
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    monkeypatch.delenv("AGENT_BOM_EPHEMERAL_STORE", raising=False)
    monkeypatch.delenv("AGENT_BOM_DB", raising=False)
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    set_agent_identity_store(None)
    set_runtime_event_store(None)
    try:
        yield tmp_path
    finally:
        set_agent_identity_store(None)
        set_runtime_event_store(None)


def test_default_backend_is_durable_sqlite(durable_state_dir):
    # Without any config the control plane must select a durable on-disk
    # backend, not in-memory — a restart must not drop issued tokens.
    assert durable_store.select_backend() == "sqlite"
    expected = str(durable_state_dir / durable_store.DEFAULT_STATE_DB_FILENAME)
    assert durable_store.sqlite_path() == expected


def test_issued_identity_survives_restart(durable_state_dir):
    # First "process": issue an identity through the default store.
    store = get_agent_identity_store()
    identity, raw = issue_identity(store, agent_id="agent-restart", tenant_id="t-durable")
    assert raw.startswith("abi_")

    # The durable file exists on disk.
    db_file = durable_state_dir / durable_store.DEFAULT_STATE_DB_FILENAME
    assert db_file.exists(), "durable default did not write a SQLite file"

    # Simulate a restart: drop the singleton and any thread-local connection so
    # the next get_*_store() opens a brand-new store against the same file.
    set_agent_identity_store(None)

    # Second "process": a fresh store reads the issued identity back.
    store2 = get_agent_identity_store()
    assert store2 is not store
    fetched = store2.get(identity.identity_id, tenant_id="t-durable")
    assert fetched is not None
    assert fetched.agent_id == "agent-restart"
    assert fetched.tenant_id == "t-durable"
    assert fetched.status == "active"
    # Token stays hash-only at rest; the raw token still resolves.
    assert fetched.token_hash == hash_token(raw)
    by_hash = store2.get_by_token_hash(hash_token(raw))
    assert by_hash is not None and by_hash.identity_id == identity.identity_id


def test_jit_grant_survives_restart(durable_state_dir):
    store = get_agent_identity_store()
    identity, _ = issue_identity(store, agent_id="agent-jit", tenant_id="t-jit")
    grant = issue_jit_grant(
        store,
        identity_id=identity.identity_id,
        agent_id="agent-jit",
        tenant_id="t-jit",
        tool_name="deploy",
        ttl_seconds=3600,
        approved_by="ops",
    )
    assert grant.status == "active"

    set_agent_identity_store(None)

    store2 = get_agent_identity_store()
    fetched = store2.get_jit_grant(grant.grant_id)
    assert fetched is not None
    assert fetched.tool_name == "deploy"
    assert fetched.status == "active"
    # The live grant is still resolvable for an authorization decision.
    active = store2.active_jit_grant("t-jit", identity.identity_id, "deploy")
    assert active is not None and active.grant_id == grant.grant_id


def test_runtime_session_survives_restart(durable_state_dir):
    store = get_runtime_event_store()
    store.put_observation(
        RuntimeObservationRecord(
            tenant_id="t-rt",
            observation_id="obs-1",
            session_id="sess-1",
            observed_at="2026-06-21T00:00:00+00:00",
            tool_name="search",
            agent_name="agent-rt",
        )
    )

    set_runtime_event_store(None)

    store2 = get_runtime_event_store()
    assert store2 is not store
    session = store2.get_session("t-rt", "sess-1")
    assert session is not None
    assert session.observation_count == 1
    observations = store2.list_observations("t-rt", session_id="sess-1")
    assert len(observations) == 1
    assert observations[0].tool_name == "search"


def test_postgres_url_routes_to_postgres_store(durable_state_dir, monkeypatch):
    # When a Postgres URL is configured the selector must pick the shared
    # Postgres-backed store (multi-replica), not the SQLite default. Patch the
    # store class so no real connection is attempted — we only assert routing.
    import agent_bom.api.agent_identity_store as ais
    import agent_bom.api.postgres_agent_identity as pai
    import agent_bom.api.postgres_runtime_event as pre
    import agent_bom.api.runtime_event_store as res

    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://unused/db")
    assert durable_store.select_backend() == "postgres"

    sentinel_identity = object()
    sentinel_runtime = object()
    monkeypatch.setattr(pai, "PostgresAgentIdentityStore", lambda *a, **k: sentinel_identity)
    monkeypatch.setattr(pre, "PostgresRuntimeEventStore", lambda *a, **k: sentinel_runtime)
    ais.set_agent_identity_store(None)
    res.set_runtime_event_store(None)

    assert ais.get_agent_identity_store() is sentinel_identity
    assert res.get_runtime_event_store() is sentinel_runtime


def test_postgres_stores_import_and_expose_store_protocol():
    # Smoke: the Postgres tiers import cleanly and expose the same method
    # surface the SQLite/in-memory tiers do, so the selector can swap them in.
    from agent_bom.api.postgres_agent_identity import PostgresAgentIdentityStore
    from agent_bom.api.postgres_runtime_event import PostgresRuntimeEventStore

    for method in ("put", "get", "get_by_token_hash", "list", "put_jit_grant", "active_jit_grant"):
        assert callable(getattr(PostgresAgentIdentityStore, method))
    for method in ("put_observation", "list_sessions", "get_session", "list_observations"):
        assert callable(getattr(PostgresRuntimeEventStore, method))


def test_ephemeral_opt_out_does_not_persist(durable_state_dir, monkeypatch):
    # With the explicit opt-out, the legacy in-memory behaviour returns: a fresh
    # store instance does NOT see what a prior instance issued.
    monkeypatch.setenv("AGENT_BOM_EPHEMERAL_STORE", "1")
    set_agent_identity_store(None)
    assert durable_store.select_backend() == "memory"

    store = get_agent_identity_store()
    identity, _ = issue_identity(store, agent_id="ephemeral", tenant_id="t-eph")
    set_agent_identity_store(None)

    store2 = get_agent_identity_store()
    assert store2.get(identity.identity_id, tenant_id="t-eph") is None
    # No durable file is created for the ephemeral tier.
    assert not (durable_state_dir / durable_store.DEFAULT_STATE_DB_FILENAME).exists()
    assert not os.path.exists(durable_state_dir / durable_store.DEFAULT_STATE_DB_FILENAME)
