"""A restarted worker reuses the durable current-estate projection only while its evidence is unchanged."""

import os
import stat

import pytest

from agent_bom.api.current_graph import CURRENT_PREFIX, CurrentGraphStore
from agent_bom.api.graph_store import SQLiteGraphStore
from tests.api import test_current_graph_estate as estate_helpers

estate = estate_helpers.estate
record = estate_helpers.record
TENANT = "history-tenant"


def _forbid_rebuild(store: CurrentGraphStore, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args, **kwargs):
        raise AssertionError("current-estate projection was rebuilt")

    monkeypatch.setattr(store, "_materialize", fail)


def _projections(store: CurrentGraphStore, tenant: str = TENANT) -> list[str]:
    return [row["scan_id"] for row in store._projection_store.list_snapshots(tenant_id=tenant)]


def test_restarted_worker_reuses_unchanged_projection_without_rebuilding(estate, monkeypatch):
    record(estate, 8, "repo-a", "package-a")
    first = CurrentGraphStore(estate[1], estate[0])
    before = first.snapshot_identity(tenant_id=TENANT, for_paging=True)
    assert before[0].startswith(CURRENT_PREFIX)

    restarted = CurrentGraphStore(estate[1], estate[0])
    _forbid_rebuild(restarted, monkeypatch)
    assert restarted.snapshot_identity(tenant_id=TENANT, for_paging=True) == before
    graph = restarted.load_graph(tenant_id=TENANT)
    assert set(graph.nodes) == {"package-a"}
    assert graph.scan_id == before[0]
    scan_id, _, nodes, total, _ = restarted.page_nodes(tenant_id=TENANT, limit=10)
    assert (scan_id, [node.id for node in nodes], total) == (before[0], ["package-a"], 1)
    stats = restarted.snapshot_stats(tenant_id=TENANT)
    assert stats["evidence_scope"] == "current_estate"
    assert stats["snapshot_generation"] == before[0].removeprefix(CURRENT_PREFIX)
    assert stats["collection_coverage"]["status"] == "unknown"


def test_reused_projection_never_serves_another_tenant(estate, monkeypatch):
    record(estate, 8, "repo-a", "tenant-a-package")
    tenant_a = CurrentGraphStore(estate[1], estate[0]).load_graph(tenant_id=TENANT).scan_id

    restarted = CurrentGraphStore(estate[1], estate[0])
    _forbid_rebuild(restarted, monkeypatch)
    assert set(restarted.load_graph(tenant_id=TENANT).nodes) == {"tenant-a-package"}
    monkeypatch.undo()
    other = restarted.load_graph(tenant_id="other-tenant")
    assert not other.nodes
    assert other.scan_id != tenant_a
    assert tenant_a not in _projections(restarted, "other-tenant")
    assert not restarted.page_nodes(tenant_id="other-tenant", scan_id=tenant_a, limit=10)[2]


def test_new_evidence_after_restart_rebuilds_and_retires_the_old_generation(estate):
    record(estate, 8, "repo-a", "package-a")
    first = CurrentGraphStore(estate[1], estate[0])
    old = first.snapshot_identity(tenant_id=TENANT, for_paging=True)[0]

    record(estate, 9, "repo-a", "package-b")
    restarted = CurrentGraphStore(estate[1], estate[0])
    graph = restarted.load_graph(tenant_id=TENANT)
    assert set(graph.nodes) == {"package-b"}
    assert graph.scan_id != old
    assert _projections(restarted) == [graph.scan_id]


def test_unstamped_persisted_projection_is_rebuilt_not_trusted(estate):
    import sqlite3

    record(estate, 8, "repo-a", "package-a")
    first = CurrentGraphStore(estate[1], estate[0])
    identity = first.snapshot_identity(tenant_id=TENANT, for_paging=True)
    with sqlite3.connect(first._cache_path) as conn:
        conn.execute("UPDATE graph_snapshots SET read_revision = 'torn' WHERE scan_id = ?", (identity[0],))

    restarted = CurrentGraphStore(estate[1], estate[0])
    assert restarted.snapshot_identity(tenant_id=TENANT, for_paging=True) == identity
    assert set(restarted.load_graph(tenant_id=TENANT).nodes) == {"package-a"}


def test_projection_cache_is_private_to_the_backing_store(estate, tmp_path):
    record(estate, 8, "repo-a", "package-a")
    store = CurrentGraphStore(estate[1], estate[0])
    store.load_graph(tenant_id=TENANT)
    cache_dir = os.path.dirname(store._cache_path)
    assert stat.S_IMODE(os.stat(cache_dir).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(store._cache_path).st_mode) == 0o600

    other = CurrentGraphStore(SQLiteGraphStore(str(tmp_path / "other-graph.db")), estate[0])
    assert other._cache_path != store._cache_path


def test_unwritable_cache_location_falls_back_to_a_private_temporary_cache(estate, monkeypatch, tmp_path):
    blocked = tmp_path / "not-a-directory"
    blocked.write_text("")
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(blocked))
    record(estate, 8, "repo-a", "package-a")
    store = CurrentGraphStore(estate[1], estate[0])
    assert not store._cache_path.startswith(str(blocked))
    assert set(store.load_graph(tenant_id=TENANT).nodes) == {"package-a"}


def test_non_durable_backing_store_keeps_a_process_private_cache(estate):
    from agent_bom.api.store import InMemoryJobStore

    class EphemeralGraphStore:
        def __init__(self, inner):
            self._inner = inner

        def __getattr__(self, name):
            return getattr(self._inner, name)

    record(estate, 8, "repo-a", "package-a")
    a = CurrentGraphStore(EphemeralGraphStore(estate[1]), estate[0])
    b = CurrentGraphStore(EphemeralGraphStore(estate[1]), InMemoryJobStore())
    assert a._cache_path != b._cache_path
