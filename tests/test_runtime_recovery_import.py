"""Runtime recovery keeps complete session evidence and never runs retention."""

import os
from uuid import uuid4

import pytest

from agent_bom.api.runtime_event_store import RuntimeObservationRecord, SQLiteRuntimeEventStore
from agent_bom.api.storage.registry_import import import_registries, read_source

TABLES = ["runtime_observations", "runtime_sessions"]


def seed(path):
    store = SQLiteRuntimeEventStore(str(path))
    # Old observations are deliberate: recovery must not apply retention.
    record = RuntimeObservationRecord("source", "observation", "session", "2020-01-01T00:00:00Z", tool_name="read_file")
    store.put_observation(record)
    return record


def test_runtime_recovery_requires_complete_session_source(tmp_path):
    path = tmp_path / "runtime.db"
    seed(path)
    records = read_source(path, {"source": "target"}, TABLES)
    assert len(records) == 2


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires restricted-role Postgres")
def test_runtime_recovery_is_repeatable_and_does_not_prune(tmp_path, monkeypatch):
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.postgres_runtime_event import PostgresRuntimeEventStore
    from tests.test_postgres_job_evidence_revision import tenant_scope

    path = tmp_path / "runtime.db"
    seed(path)
    target = "recovery-" + uuid4().hex
    pool = _new_application_pool(min_size=1, max_size=2)

    def forbidden(*args, **kwargs):
        pytest.fail("Explicit recovery must not prune retained runtime evidence")

    monkeypatch.setattr("agent_bom.api.postgres_runtime_event.prune_runtime_observations_for_tenant", forbidden)
    try:
        dry = import_registries(path, {"source": target}, TABLES, pool=pool)
        assert dry["inserted"] == 2 and not dry["committed"]
        with tenant_scope(target):
            owner = PostgresRuntimeEventStore(pool=pool)
            assert owner.get_session(target, "session") is None
        applied = import_registries(path, {"source": target}, TABLES, apply=True, pool=pool)
        assert applied["committed"] and applied["inserted"] == 2
        repeated = import_registries(path, {"source": target}, TABLES, apply=True, pool=pool)
        assert repeated["unchanged"] == 2
        with tenant_scope(target):
            assert owner.get_session(target, "session").observation_count == 1
            assert owner.list_observations(target)[0].observed_at == "2020-01-01T00:00:00Z"
    finally:
        pool.close()


@pytest.mark.parametrize("damage", ["missing_observation", "orphan", "raw_payload", "secret_metadata"])
def test_runtime_recovery_refuses_incomplete_or_unsafe_sources(tmp_path, damage):
    import json
    import sqlite3

    path = tmp_path / "runtime.db"
    seed(path)
    with sqlite3.connect(path) as conn:
        if damage == "missing_observation":
            conn.execute("DELETE FROM runtime_observations")
        elif damage == "orphan":
            conn.execute("DELETE FROM runtime_sessions")
        else:
            payload = json.loads(conn.execute("SELECT data FROM runtime_observations").fetchone()[0])
            if damage == "raw_payload":
                payload["raw_payload_stored"] = True
            else:
                payload["metadata"] = {"tool_input": "private original arguments"}
            conn.execute("UPDATE runtime_observations SET data=?", (json.dumps(payload),))
    with pytest.raises(ValueError):
        read_source(path, {"source": "target"}, TABLES)


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires restricted-role Postgres")
def test_runtime_recovery_refuses_conflicting_session_and_preserves_other_tenant(tmp_path):
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.postgres_runtime_event import PostgresRuntimeEventStore
    from tests.test_postgres_job_evidence_revision import tenant_scope

    path = tmp_path / "runtime.db"
    seed(path)
    target = "recovery-" + uuid4().hex
    other = "other-" + uuid4().hex
    pool = _new_application_pool(min_size=1, max_size=2)
    try:
        with tenant_scope(other):
            owner = PostgresRuntimeEventStore(pool=pool)
            owner.put_observation(RuntimeObservationRecord(other, "observation", "session", "2026-10-01T00:00:00Z"))
        assert import_registries(path, {"source": target}, TABLES, apply=True, pool=pool)["committed"]
        with tenant_scope(target):
            owner.put_observation(RuntimeObservationRecord(target, "extra", "session", "2026-10-02T00:00:00Z"))
        receipt = import_registries(path, {"source": target}, TABLES, apply=True, pool=pool)
        assert receipt["conflicts"] == 1 and not receipt["committed"]
        with tenant_scope(target):
            assert owner.get_session(target, "session").observation_count == 2
        with tenant_scope(other):
            assert owner.get_session(other, "session").observation_count == 1
            assert owner.list_observations(other)[0].observed_at == "2026-10-01T00:00:00Z"
    finally:
        pool.close()
