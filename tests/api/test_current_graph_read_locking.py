"""Current-estate reads share the projection; only resolve/retire is exclusive."""

import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout

import pytest
from starlette.exceptions import HTTPException

from agent_bom.api.current_graph import CurrentGraphStore
from tests.api import test_current_graph_estate as estate_helpers

estate = estate_helpers.estate
record = estate_helpers.record
TENANT = "history-tenant"


def _block_projection_reads(store: CurrentGraphStore, name: str) -> tuple[threading.Event, threading.Event]:
    entered, release = threading.Event(), threading.Event()
    reader = getattr(store._projection_store, name)

    def blocked(*args, **kwargs):
        entered.set()
        assert release.wait(10), "test never released the blocked reader"
        return reader(*args, **kwargs)

    setattr(store._projection_store, name, blocked)
    return entered, release


def test_concurrent_current_reads_do_not_queue_behind_a_slow_read(estate):
    record(estate, 8, "repo-a", "package-a")
    store = CurrentGraphStore(estate[1], estate[0])
    generation = store.latest_snapshot_id(tenant_id=TENANT)
    entered, release = _block_projection_reads(store, "attack_paths")
    with ThreadPoolExecutor(max_workers=2) as workers:
        slow = workers.submit(store.attack_paths, tenant_id=TENANT)
        assert entered.wait(5)
        try:
            page = workers.submit(store.page_nodes, tenant_id=TENANT, limit=10).result(timeout=5)
            stats = workers.submit(store.snapshot_stats, tenant_id=TENANT).result(timeout=5)
        except FutureTimeout:
            pytest.fail("a current-estate read waited for an unrelated in-flight read")
        finally:
            release.set()
        slow.result(timeout=5)
    assert page[0] == generation
    assert [node.id for node in page[2]] == ["package-a"]
    assert stats["snapshot_generation"] == generation.removeprefix("current-estate:")


def test_retirement_waits_for_active_readers_of_the_old_generation(estate):
    record(estate, 8, "repo-a", "package-a")
    store = CurrentGraphStore(estate[1], estate[0])
    old = store.latest_snapshot_id(tenant_id=TENANT)
    entered, release = _block_projection_reads(store, "load_graph")
    with ThreadPoolExecutor(max_workers=2) as workers:
        reading_old = workers.submit(store.load_graph, tenant_id=TENANT)
        assert entered.wait(5)
        record(estate, 9, "repo-a", "package-b")
        replacing = workers.submit(store.snapshot_identity, tenant_id=TENANT, for_paging=True)
        with pytest.raises(FutureTimeout):
            replacing.result(timeout=0.5)
        release.set()
        old_graph = reading_old.result(timeout=5)
        new_identity = replacing.result(timeout=5)
    assert old_graph.scan_id == old
    assert set(old_graph.nodes) == {"package-a"}
    assert new_identity[0] != old
    assert set(store.load_graph(tenant_id=TENANT).nodes) == {"package-b"}


def test_rebuild_requested_while_iterating_the_same_generation_is_a_conflict_not_a_deadlock(estate):
    record(estate, 8, "repo-a", "package-a")
    store = CurrentGraphStore(estate[1], estate[0])
    old = store.latest_snapshot_id(tenant_id=TENANT)
    nodes = store.iter_nodes(tenant_id=TENANT)
    first = next(nodes)
    record(estate, 9, "repo-a", "package-b")
    outcome: list[object] = []

    def rebuild_inside_iteration() -> None:
        try:
            outcome.append(store.load_graph(tenant_id=TENANT))
        except HTTPException as exc:
            outcome.append(exc.status_code)

    rebuild_inside_iteration()
    assert outcome == [409]
    assert getattr(first, "id", first) == "package-a" or "package-a" in str(first)
    assert list(nodes) == []
    assert store.latest_snapshot_id(tenant_id=TENANT) != old
