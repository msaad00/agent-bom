"""Read-path performance guards measured at composed-demo-estate scale.

Every assertion here was derived from a profile of the real routes against the
2,068-asset / 6,159-observation estate that ``build_demo_estate()`` composes,
not from intuition. Each test pins the *behaviour* that made a measured cost
avoidable, so a regression shows up as a failed contract rather than as a
slow demo nobody profiles again.
"""

from __future__ import annotations

import asyncio
import sqlite3
import time

import pytest
from starlette.testclient import TestClient

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph import EntityType, UnifiedGraph, UnifiedNode

# ---------------------------------------------------------------------------
# 1. /v1/demo-estate/story must not build the estate on the event loop
# ---------------------------------------------------------------------------


@pytest.fixture()
def story_client(monkeypatch: pytest.MonkeyPatch, tmp_path):
    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "story.db"))
    monkeypatch.setenv("AGENT_BOM_GRAPH_DB", str(tmp_path / "story-graph.db"))

    from agent_bom.api import server as api_server
    from agent_bom.api import stores as api_stores
    from agent_bom.api.routes import demo_estate as demo_routes

    api_server._runtime_api_key_seeded = False
    api_server._shutting_down = False
    original_job_store = api_stores._store
    original_graph_store = api_stores._graph_store
    api_stores._store = None
    api_stores._graph_store = None
    demo_routes.reset_demo_story_cache()
    try:
        with TestClient(api_server.app) as client:
            yield client
    finally:
        api_stores._store = original_job_store
        api_stores._graph_store = original_graph_store
        demo_routes.reset_demo_story_cache()

        from agent_bom.api.routes.proxy import _reset_proxy_runtime_for_tests

        _reset_proxy_runtime_for_tests()
        api_stores._get_firewall_decision_store().reset()


def test_demo_story_route_does_not_block_the_event_loop(story_client: TestClient) -> None:
    """The 1.6s estate build must run off-loop.

    Measured before the fix: one request stalled the loop for ~1,648 ms — the
    whole request duration — so four concurrent callers serialised into 6.6s on
    a single worker. The route is ``async def``; calling the synchronous builder
    inside it hands the loop no yield point at all.
    """
    from agent_bom.api.routes import demo_estate as demo_routes

    build_seconds = 1.0
    calls: list[str] = []
    real_builder = demo_routes.build_enterprise_demo_story

    def slow_builder(*, tenant_id: str):
        calls.append(tenant_id)
        # Stand in for the ~1.6s real build with a sleep long enough that an
        # on-loop call is unmistakable, without paying the real cost in CI.
        time.sleep(build_seconds)
        return real_builder(tenant_id=tenant_id)

    demo_routes.reset_demo_story_cache()

    # The request has to run on the SAME event loop as the heartbeat, so drive
    # the ASGI app directly. ``TestClient`` runs the app on its own private
    # loop in another thread, where a blocking route would never be observable.
    async def exercise() -> tuple[float, float]:
        import httpx

        from agent_bom.api.server import app

        stalls: list[float] = []
        stop = False

        async def heartbeat() -> None:
            while not stop:
                start = time.perf_counter()
                await asyncio.sleep(0.005)
                stalls.append(time.perf_counter() - start - 0.005)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://probe") as client:
            beat = asyncio.create_task(heartbeat())
            # Idle window first: whatever the loop suffers here is the machine,
            # not the route.
            await asyncio.sleep(0.25)
            idle = max(stalls) if stalls else 0.0
            stalls.clear()
            response = await client.get("/v1/demo-estate/story")
            stop = True
            await beat
        assert response.status_code == 200, response.text
        return max(stalls), idle

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(demo_routes, "build_enterprise_demo_story", slow_builder)
        worst_stall, noise_floor = asyncio.run(exercise())

    assert calls, "the builder should have run at least once"
    # Calibrated against this machine, not against a wall-clock constant. The
    # heartbeat measures scheduler starvation as well as loop blocking, and on a
    # CI box running the suite under xdist the ambient noise alone reached 542 ms
    # — enough to trip a fixed 500 ms ceiling while the offload was working
    # perfectly. Comparing the request's worst stall against the idle noise floor
    # measured moments earlier asks the question that actually matters: is the
    # loop worse off *because of the request*.
    ceiling = max(build_seconds * 0.5, noise_floor * 4)
    assert worst_stall < ceiling, (
        f"event loop stalled {worst_stall * 1000:.0f} ms during a {build_seconds * 1000:.0f} ms build "
        f"(idle noise floor {noise_floor * 1000:.0f} ms, ceiling {ceiling * 1000:.0f} ms) — "
        "the estate build is running on the loop"
    )


def test_demo_story_is_built_once_per_tenant_and_reused(story_client: TestClient) -> None:
    """The story is a deterministic fixture; rebuilding it every request is waste.

    ``build_enterprise_demo_story`` is a pure function of ``tenant_id`` (proven
    by its own ``story_content_hash``), so the second request must serve the
    cached value instead of paying the full correlate-and-hash pass again.
    """
    from agent_bom.api.routes import demo_estate as demo_routes

    demo_routes.reset_demo_story_cache()
    builds: list[str] = []
    real_builder = demo_routes.build_enterprise_demo_story

    def counting_builder(*, tenant_id: str):
        builds.append(tenant_id)
        return real_builder(tenant_id=tenant_id)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(demo_routes, "build_enterprise_demo_story", counting_builder)
        first = story_client.get("/v1/demo-estate/story")
        second = story_client.get("/v1/demo-estate/story")
        third = story_client.get("/v1/demo-estate/story")

    assert first.status_code == 200, first.text
    assert first.json() == second.json() == third.json()
    assert len(builds) == 1, f"expected one build for one tenant, got {len(builds)}"


def test_demo_story_cache_is_keyed_per_tenant(story_client: TestClient) -> None:
    """A cache that ignored the tenant would serve one tenant's estate to another.

    The payload embeds ``tenant_id`` and a tenant-specific ``estate_content_hash``,
    so a shared entry is a cross-tenant disclosure, not merely a stale read.
    """
    from agent_bom.api.routes import demo_estate as demo_routes

    demo_routes.reset_demo_story_cache()

    alpha = demo_routes._cached_demo_story("tenant-alpha")
    beta = demo_routes._cached_demo_story("tenant-beta")
    alpha_again = demo_routes._cached_demo_story("tenant-alpha")

    assert alpha.tenant_id == "tenant-alpha"
    assert beta.tenant_id == "tenant-beta"
    assert alpha.estate_content_hash != beta.estate_content_hash
    assert alpha_again.model_dump_json() == alpha.model_dump_json()
    assert "tenant-beta" not in alpha.model_dump_json()
    assert "tenant-alpha" not in beta.model_dump_json()


def test_demo_story_cache_is_bounded(story_client: TestClient) -> None:
    """``tenant_id`` is request-controlled, so an unbounded cache is a memory DoS."""
    from agent_bom.api.routes import demo_estate as demo_routes

    demo_routes.reset_demo_story_cache()
    assert demo_routes.DEMO_STORY_CACHE_MAXSIZE <= 32
    info = demo_routes._cached_demo_story.cache_info()
    assert info.maxsize == demo_routes.DEMO_STORY_CACHE_MAXSIZE


def test_demo_story_offload_cannot_starve_the_shared_thread_pool() -> None:
    """The offload needs its own limiter, not anyio's shared 40-token default.

    API-key verification offloads its scrypt through that same pool, so a burst
    of cold story requests holding a thread each while they queue on the build
    lock would starve authentication. Capping this route keeps the surplus
    waiting on the loop instead of on a worker thread.
    """
    import anyio
    import anyio.to_thread

    from agent_bom.api.routes import demo_estate as demo_routes

    limiter = demo_routes._STORY_THREAD_LIMITER
    assert isinstance(limiter, anyio.CapacityLimiter)

    async def default_pool_size() -> float:
        return anyio.to_thread.current_default_thread_limiter().total_tokens

    shared_tokens = asyncio.run(default_pool_size())
    assert limiter.total_tokens < shared_tokens, (
        f"story offload may take {limiter.total_tokens} of the shared pool's {shared_tokens} threads"
    )


# ---------------------------------------------------------------------------
# 2. One scrypt derivation per authenticated request
# ---------------------------------------------------------------------------


def test_authenticated_request_derives_the_key_hash_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """The rate limiter must reuse the API key the auth middleware already verified.

    Measured before the fix: two ~21.5 ms scrypt derivations per authenticated
    request — 43 ms of fixed cost on *every* route — because
    ``_resolve_tenant_scope`` skipped its short-circuit whenever the tenant was
    ``default``, which is the single-tenant and hosted-demo case.
    """
    from agent_bom.api.middleware import RateLimitMiddleware

    class _State:
        tenant_id = "default"
        auth_method = "api_key"

    class _Request:
        state = _State()

    verifies: list[str] = []

    def exploding_key_store():
        class _Store:
            def verify(self, raw_key: str):
                verifies.append(raw_key)
                return None

        return _Store()

    monkeypatch.setattr("agent_bom.api.middleware.get_key_store", exploding_key_store)

    middleware = RateLimitMiddleware.__new__(RateLimitMiddleware)
    resolved = asyncio.run(middleware._resolve_tenant_scope(_Request(), "raw-key"))

    assert resolved == "default"
    assert verifies == [], "the already-verified API key tenant must not be re-derived"


def test_non_api_key_auth_still_resolves_tenant_through_the_key_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The anonymous/demo deployment has no auth middleware — that verify must stay."""
    from agent_bom.api.middleware import RateLimitMiddleware

    class _State:
        tenant_id = "default"
        auth_method = "anonymous"

    class _Request:
        state = _State()

    verifies: list[str] = []

    def key_store():
        class _Key:
            tenant_id = "tenant-from-key"

        class _Store:
            def verify(self, raw_key: str):
                verifies.append(raw_key)
                return _Key()

        return _Store()

    monkeypatch.setattr("agent_bom.api.middleware.get_key_store", key_store)

    middleware = RateLimitMiddleware.__new__(RateLimitMiddleware)
    resolved = asyncio.run(middleware._resolve_tenant_scope(_Request(), "raw-key"))

    assert resolved == "tenant-from-key"
    assert verifies == ["raw-key"]


# ---------------------------------------------------------------------------
# 3. Node paging must be index-ordered, not sorted in a temp B-tree
# ---------------------------------------------------------------------------


PAGE_ORDER_SQL = """
SELECT id FROM graph_nodes
WHERE tenant_id = ? AND scan_id = ?
ORDER BY severity_id DESC, risk_score DESC, label ASC, id ASC
LIMIT 500 OFFSET 0
"""


def test_page_nodes_order_by_is_served_by_an_index(tmp_path) -> None:
    """``page_nodes`` sorts the whole snapshot per page without a matching index.

    Measured: ``USE TEMP B-TREE FOR ORDER BY`` on every page request. At 2,068
    nodes that is 0.6 ms, but the sort is O(N log N) over the *snapshot* for
    every page, which is the shape that previously cost 444 ms at 300k rows.
    """
    store = SQLiteGraphStore(tmp_path / "order.db")
    graph = UnifiedGraph(scan_id="order-scan", tenant_id="default")
    for i in range(200):
        graph.add_node(
            UnifiedNode(
                id=f"asset:{i}",
                entity_type=EntityType.RESOURCE,
                label=f"asset-{i}",
                severity=["critical", "high", "medium", "low", "info"][i % 5],
                risk_score=float(i % 17),
            )
        )
    store.save_graph(graph)

    conn = sqlite3.connect(tmp_path / "order.db")
    try:
        plan = [row[3] for row in conn.execute("EXPLAIN QUERY PLAN " + PAGE_ORDER_SQL, ("default", "order-scan"))]
    finally:
        conn.close()

    assert not any("TEMP B-TREE" in step for step in plan), f"node paging still sorts in a temp B-tree: {plan}"


def test_page_nodes_ordering_is_unchanged_by_the_index(tmp_path) -> None:
    """An index may only make the existing order cheaper — never reorder results."""
    store = SQLiteGraphStore(tmp_path / "stable.db")
    graph = UnifiedGraph(scan_id="stable-scan", tenant_id="default")
    for i in range(120):
        graph.add_node(
            UnifiedNode(
                id=f"asset:{i:03d}",
                entity_type=EntityType.RESOURCE,
                label=f"asset-{i:03d}",
                severity=["critical", "high", "medium", "low", "info"][i % 5],
                risk_score=float(i % 7),
            )
        )
    store.save_graph(graph)

    _scan, _created, nodes, total, _cursor = store.page_nodes(tenant_id="default", offset=0, limit=120)
    assert total == 120

    expected = sorted(nodes, key=lambda n: (-n.severity_id, -n.risk_score, n.label, n.id))
    assert [n.id for n in nodes] == [n.id for n in expected]


def test_full_cursor_walk_returns_every_node_exactly_once(tmp_path) -> None:
    """Keyset paging must not drop or duplicate rows under the new index order."""
    store = SQLiteGraphStore(tmp_path / "walk.db")
    graph = UnifiedGraph(scan_id="walk-scan", tenant_id="default")
    for i in range(250):
        graph.add_node(
            UnifiedNode(
                id=f"asset:{i:03d}",
                entity_type=EntityType.RESOURCE,
                label=f"asset-{i:03d}",
                severity=["critical", "high", "medium", "low", "info"][i % 5],
                risk_score=float(i % 11),
            )
        )
    store.save_graph(graph)

    seen: list[str] = []
    cursor: str | None = None
    for _ in range(20):
        _scan, _created, nodes, total, cursor = store.page_nodes(tenant_id="default", cursor=cursor, limit=40)
        seen.extend(n.id for n in nodes)
        if not cursor:
            break

    assert total == 250
    assert len(seen) == 250
    assert len(set(seen)) == 250


# ---------------------------------------------------------------------------
# 4. Response compression must not monopolise the event loop
# ---------------------------------------------------------------------------


def test_gzip_middleware_uses_a_balanced_compression_level() -> None:
    """Starlette defaults to level 9, which is CPU-quadratic for ~5% more ratio.

    Measured on the 2.7 MB ``/v1/graph?limit=5000`` payload: level 9 cost 32.5 ms
    of *event-loop* time (``GZipResponder.apply_compression`` is synchronous) for
    175.4 KB, while level 6 cost 17.7 ms for 185.2 KB.
    """
    from starlette.middleware.gzip import GZipMiddleware

    from agent_bom.api.server import app

    gzip_layers = [mw for mw in app.user_middleware if mw.cls is GZipMiddleware]
    assert gzip_layers, "the API should compress large graph payloads"
    level = gzip_layers[0].kwargs.get("compresslevel")
    assert level is not None, "compresslevel must be pinned, not left at Starlette's default of 9"
    assert 1 <= level <= 6, f"compresslevel {level} spends event-loop time for negligible ratio"
