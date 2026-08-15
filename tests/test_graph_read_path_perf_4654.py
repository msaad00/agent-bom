"""Read-path performance guards measured at composed-demo-estate scale.

Every assertion here was derived from a profile of the real routes against the
2,068-asset / 6,159-observation estate that ``build_demo_estate()`` composes,
not from intuition. Each test pins the *behaviour* that made a measured cost
avoidable, so a regression shows up as a failed contract rather than as a
slow demo nobody profiles again.
"""

from __future__ import annotations

import asyncio
import hashlib
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest
from starlette.testclient import TestClient

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph import EntityType, UnifiedGraph, UnifiedNode

# A regressed build blocks forever rather than slowly, so every handshake below
# is bounded. The bound exists to turn a deadlock into a named failure in
# seconds -- an earlier version of this suite hung CI for 25 minutes -- and is
# deliberately far above any real build (~1.6s), so it can never fire on a
# merely slow runner.
HANDSHAKE_TIMEOUT_S = 30.0


def _fast_demo_story(*, tenant_id: str):
    """Return a valid tenant-specific story without composing the full estate.

    This module verifies scheduling, cache, and graph-store behaviour.  Building
    the 2,000+ asset synthetic estate is covered by the enterprise-demo contract
    suites; repeating it for every cache key made these concurrency contracts
    contend with unrelated full-suite workers and time out on Python 3.11.
    """
    from agent_bom.demo_estate.enterprise_correlation import EnterpriseCorrelation
    from agent_bom.demo_estate.enterprise_findings import EstateFindingSummary
    from agent_bom.demo_estate.presentation import (
        EnterpriseDemoBounds,
        EnterpriseDemoListBound,
        EnterpriseDemoStory,
        EnterpriseDemoSummary,
    )

    estate_hash = hashlib.sha256(f"estate:{tenant_id}".encode()).hexdigest()
    story_hash = hashlib.sha256(f"story:{tenant_id}".encode()).hexdigest()
    observed_at = datetime(2026, 1, 1, tzinfo=UTC)
    primary = EnterpriseCorrelation(
        correlation_id=f"test-correlation:{tenant_id}",
        tenant_id=tenant_id,
        trace_id=f"test-trace:{tenant_id}",
        kind="test",
        outcome="observed",
        started_at=observed_at,
        ended_at=observed_at,
        event_ids=(),
        sources=(),
        asset_ids=(),
        asset_path=(),
        data_classifications=(),
        evidence_hashes=(),
        evidence_quality="complete",
    )
    empty_bound = EnterpriseDemoListBound(returned=0, total=0, limit=0, truncated=False)
    return EnterpriseDemoStory(
        disclosure="Synthetic test fixture.",
        estate_id=f"test-estate:{tenant_id}",
        estate_name="Test estate",
        tenant_id=tenant_id,
        estate_content_hash=estate_hash,
        story_content_hash=story_hash,
        summary=EnterpriseDemoSummary(
            assets=0,
            observations=0,
            evidence_sources=0,
            complete_sources=0,
            partial_sources=0,
            correlations=1,
            cross_source_correlations=0,
            snapshots=0,
            findings=0,
        ),
        bounds=EnterpriseDemoBounds(
            events=empty_bound,
            correlations=EnterpriseDemoListBound(returned=1, total=1, limit=1, truncated=False),
            findings=empty_bound,
        ),
        count_metadata={},
        primary_correlation=primary,
        events=(),
        correlations=(primary,),
        collection_health=(),
        finding_summary=EstateFindingSummary(
            total=0,
            by_severity={},
            assets_affected=0,
            assets_total=0,
            controls_evidenced=0,
            attack_paths_evidenced=0,
            identities_implicated=0,
        ),
    )


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
    monkeypatch.setattr(demo_routes, "build_enterprise_demo_story", _fast_demo_story)
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

    Asserted structurally rather than by timing or by a second event loop, after
    three versions that each failed for reasons unrelated to the code:

    * a fixed 500 ms ceiling lost to 542 ms of xdist scheduler noise;
    * a noise-calibrated ceiling lost to a 921 ms stall on a contended runner;
    * comparing against the pytest thread was vacuous, because ``TestClient``
      drives the app on its own loop in another thread;
    * driving a second loop with ``asyncio.run`` to capture the real loop thread
      hung CI for 25 minutes — the module-level ``CapacityLimiter`` binds to the
      loop that first uses it, so a second loop deadlocks against it.

    What this asserts instead: the offload is actually invoked, and the builder
    runs on a different thread than the caller. Work on a worker thread cannot
    block the loop, by construction, and removing the offload removes the call.
    """
    import threading

    import anyio.to_thread

    from agent_bom.api.routes import demo_estate as demo_routes

    caller_threads: list[int] = []
    build_threads: list[int] = []
    real_builder = demo_routes.build_enterprise_demo_story
    real_run_sync = anyio.to_thread.run_sync

    async def recording_run_sync(func, *args, **kwargs):
        # Runs on the event loop, so this is the thread a blocking build would
        # have occupied.
        caller_threads.append(threading.get_ident())
        return await real_run_sync(func, *args, **kwargs)

    def recording_builder(*, tenant_id: str):
        build_threads.append(threading.get_ident())
        return real_builder(tenant_id=tenant_id)

    demo_routes.reset_demo_story_cache()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(demo_routes.anyio.to_thread, "run_sync", recording_run_sync)
        mp.setattr(demo_routes, "build_enterprise_demo_story", recording_builder)
        response = story_client.get("/v1/demo-estate/story")

    assert response.status_code == 200, response.text
    assert build_threads, "the builder should have run at least once"
    assert caller_threads, (
        "the route never offloaded — anyio.to_thread.run_sync was not called, so the ~1.6s estate build ran inline on the event loop"
    )
    on_loop = [tid for tid in build_threads if tid in set(caller_threads)]
    assert not on_loop, f"the estate build ran on the calling (event-loop) thread {on_loop[0]} — it must be offloaded"


def test_event_loop_still_serves_requests_while_a_cold_story_builds(story_client: TestClient) -> None:
    """The loop must keep turning *during* the build, not merely dispatch it elsewhere.

    This is the assertion the thread-identity check above cannot make. Thread
    identity proves the offload was invoked; it stays green while the loop is
    parked for the whole build, which is exactly what was measured: a cold
    request spent 1,504 ms of its 2,013 ms with the loop unable to run (75%).
    A route could satisfy thread identity and still park the loop -- by awaiting
    the worker under a lock, or by holding any synchronous section around it.

    Proven by a handshake rather than a clock, because every timing form of this
    test failed for reasons unrelated to the code (see the docstring above):
    the builder blocks inside the worker thread until a *second, unrelated HTTP
    request* has completed. That second request can only complete if the event
    loop is still running while the build is in flight. If the build ever parks
    the loop, the two wait on each other and the bounded handshake reports a
    deadlock by name instead of hanging CI.

    There is no threshold to tune and no wall-clock comparison, so scheduler
    noise and runner contention cannot make it flake: a parked loop fails, a
    merely slow one passes.
    """
    from agent_bom.api.routes import demo_estate as demo_routes

    in_builder = threading.Event()
    loop_proved_alive = threading.Event()
    real_builder = demo_routes.build_enterprise_demo_story

    def handshaking_builder(*, tenant_id: str):
        in_builder.set()
        # Held inside the worker thread, mid-build. The loop must service the
        # probe request below while this blocks.
        if not loop_proved_alive.wait(timeout=HANDSHAKE_TIMEOUT_S):
            raise AssertionError(
                "the event loop never completed an unrelated request while the estate build was in flight "
                "— the build is parking the loop even though it runs on a worker thread"
            )
        return real_builder(tenant_id=tenant_id)

    demo_routes.reset_demo_story_cache()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(demo_routes, "build_enterprise_demo_story", handshaking_builder)
        with ThreadPoolExecutor(max_workers=1) as pool:
            story = pool.submit(story_client.get, "/v1/demo-estate/story")

            assert in_builder.wait(timeout=HANDSHAKE_TIMEOUT_S), "the estate build never started"
            # The build is running right now. If it owns the loop, this cannot
            # return -- and the builder above is still waiting on us.
            probe = story_client.get("/health")
            loop_proved_alive.set()

            response = story.result(timeout=HANDSHAKE_TIMEOUT_S)

    assert probe.status_code == 200, f"an unrelated request could not be served while the estate build was in flight: {probe.status_code}"
    assert response.status_code == 200, response.text


def test_story_route_occupies_at_most_one_worker_thread(story_client: TestClient) -> None:
    """The story path may hold ONE thread of anyio's shared pool, not two.

    Re-derived from measurement, because the reasoning that set this to 2 does
    not survive it. Two tokens were justified as backpressure that still left
    some concurrency available; but the build is pure Python under the GIL *and*
    ``_STORY_BUILD_LOCK`` serialises it, so a second token cannot produce a
    second build -- it can only park a second worker thread on that lock.
    Measured over an 8-tenant cold burst, 1 / 2 / 4 tokens are indistinguishable
    on every axis (wall 15.4 / 14.3 / 14.5 s; unrelated-route degradation
    12.8x / 13.4x / 13.0x), all within run-to-run noise. Identical throughput
    for fewer threads held is the whole case for one token.

    This asserts occupancy of the *offloaded path*, not of the builder.
    Counting inside the builder would be vacuous: the build lock pins that to 1
    whatever the limiter says, so such a test passes at any token count and
    proves nothing about the limiter at all.
    """
    from agent_bom.api.routes import demo_estate as demo_routes

    occupancy = 0
    peak = 0
    guard = threading.Lock()
    real_cache_or_build = demo_routes._cached_demo_story
    released = threading.Event()

    def counting_entry(tenant_id: str):
        nonlocal occupancy, peak
        with guard:
            occupancy += 1
            peak = max(peak, occupancy)
        try:
            # Hold the thread until every request has been dispatched, so any
            # sibling the limiter admits is guaranteed to overlap with this one.
            released.wait(timeout=2.0)
            return real_cache_or_build(tenant_id)
        finally:
            with guard:
                occupancy -= 1

    demo_routes.reset_demo_story_cache()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(demo_routes, "_cached_demo_story", counting_entry)
        with ThreadPoolExecutor(max_workers=6) as pool:
            responses = [pool.submit(story_client.get, "/v1/demo-estate/story") for _ in range(6)]
            released.set()
            codes = [r.result(timeout=HANDSHAKE_TIMEOUT_S).status_code for r in responses]

    assert codes == [200] * 6
    assert peak == 1, f"the story route held {peak} worker threads of the shared pool; one does all the work"


@pytest.fixture()
def two_tenant_keys():
    """Two real API keys bound to two tenants, through the genuine auth path.

    The tenant header alone is not enough: it is only honoured for an
    authenticated caller, so a cross-tenant test that used it would silently
    collapse into a single-tenant one.
    """
    from agent_bom.api import auth as api_auth
    from agent_bom.api.auth import KeyStore, Role, create_api_key_record

    original = api_auth._key_store
    api_auth._key_store = KeyStore()
    keys = {}
    for tenant in ("perf-alpha", "perf-beta"):
        raw = f"perf-key-{tenant}-0123456789abcdef"
        api_auth._key_store.add(create_api_key_record(raw, f"perf:{tenant}", Role.ADMIN, tenant_id=tenant))
        keys[tenant] = {"X-API-Key": raw}
    try:
        yield keys
    finally:
        api_auth._key_store = original


def test_warm_story_hit_does_not_wait_on_another_tenants_cold_build(
    story_client: TestClient,
    two_tenant_keys: dict[str, dict[str, str]],
) -> None:
    """A cache hit must not queue behind a build -- least of all a *different* tenant's.

    Measured before the fix: a warm read took 1,853 ms against 31 ms served
    alone (60x), because the single-flight build lock was acquired *around* the
    cache lookup rather than around the build. The cache existed to make warm
    reads instant and the lock placement threw that away; the audit recorded the
    same defect at 8,232 ms behind a deeper queue. Nothing about tenant beta's
    cold build is relevant to a value already computed for tenant alpha, so the
    coupling is not merely slow, it is a multi-tenant fairness bug.

    Handshake, not clock: beta's build blocks until alpha's warm read has
    returned. If the warm read waits on the build lock, the two deadlock and the
    bounded wait names the failure.
    """
    from agent_bom.api.routes import demo_estate as demo_routes

    alpha, beta = two_tenant_keys["perf-alpha"], two_tenant_keys["perf-beta"]

    demo_routes.reset_demo_story_cache()
    warm = story_client.get("/v1/demo-estate/story", headers=alpha)
    assert warm.status_code == 200, warm.text
    assert warm.json()["tenant_id"] == "perf-alpha"

    in_builder = threading.Event()
    warm_read_returned = threading.Event()
    real_builder = demo_routes.build_enterprise_demo_story

    def blocking_builder(*, tenant_id: str):
        # Only beta is cold; alpha must never reach the builder at all.
        assert tenant_id == "perf-beta", f"the warm tenant rebuilt its story: {tenant_id}"
        in_builder.set()
        if not warm_read_returned.wait(timeout=HANDSHAKE_TIMEOUT_S):
            raise AssertionError(
                "the warm cache hit for tenant alpha never completed while tenant beta was building "
                "— the build lock is being held across the cache lookup"
            )
        return real_builder(tenant_id=tenant_id)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(demo_routes, "build_enterprise_demo_story", blocking_builder)
        with ThreadPoolExecutor(max_workers=1) as pool:
            cold = pool.submit(story_client.get, "/v1/demo-estate/story", headers=beta)

            assert in_builder.wait(timeout=HANDSHAKE_TIMEOUT_S), "tenant beta's build never started"
            hit = story_client.get("/v1/demo-estate/story", headers=alpha)
            warm_read_returned.set()

            cold_response = cold.result(timeout=HANDSHAKE_TIMEOUT_S)

    assert hit.status_code == 200, hit.text
    assert hit.json()["tenant_id"] == "perf-alpha"
    assert hit.json() == warm.json()
    assert cold_response.status_code == 200, cold_response.text
    assert cold_response.json()["tenant_id"] == "perf-beta"


def test_warm_story_hit_is_served_without_a_worker_thread(story_client: TestClient) -> None:
    """A cache hit must be answered on the loop, not shipped to the thread pool.

    Offloading a dictionary lookup costs a limiter token and a thread hop for
    nothing, and -- while the limiter is saturated by cold builds -- makes warm
    reads queue behind them even once the lock no longer spans the lookup.
    """
    import anyio.to_thread

    from agent_bom.api.routes import demo_estate as demo_routes

    demo_routes.reset_demo_story_cache()
    first = story_client.get("/v1/demo-estate/story")
    assert first.status_code == 200, first.text

    offloads: list[object] = []
    real_run_sync = anyio.to_thread.run_sync

    async def counting_run_sync(func, *args, **kwargs):
        offloads.append(func)
        return await real_run_sync(func, *args, **kwargs)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(demo_routes.anyio.to_thread, "run_sync", counting_run_sync)
        warm = story_client.get("/v1/demo-estate/story")

    assert warm.status_code == 200, warm.text
    assert warm.json() == first.json()
    # Patching `anyio.to_thread.run_sync` mutates the shared module, so this sees
    # every offload in the request — including the framework's. Starlette 1.6.0
    # moved large-body gzip onto a worker thread ("compressing large chunks
    # inline would block the event loop"), which is the same rule this suite
    # exists to enforce; counting it as a violation would fail us for a
    # dependency doing the right thing. The claim is about OUR read path, so
    # narrow it to our own callables.
    ours = [getattr(func, "__name__", repr(func)) for func in offloads if getattr(func, "__module__", "").startswith("agent_bom")]
    assert ours == [], f"a warm cache hit still offloaded to a worker thread: {ours}"


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


def test_concurrent_cold_requests_for_one_tenant_build_it_once(story_client: TestClient) -> None:
    """Single-flight must hold under real concurrency, not just sequentially.

    The reuse test above issues its three requests one after another, so it is
    satisfied by the cache alone and says nothing about the lock. This drives
    several callers into the *same* cold tenant at once, which is the case the
    build lock exists for: without it -- or with the built value published after
    the lock is released rather than before -- each waiter re-peeks, still
    misses, and pays the full ~1.6s build again.

    Exercised through ``_cached_demo_story`` directly so it holds regardless of
    how many threads the route's limiter admits.

    The publish step is deliberately slowed. Left at native speed the defect is
    a genuine race that the winning thread almost always wins -- publishing
    nanoseconds after releasing the lock, before the OS has woken a waiter -- so
    the test passed against known-broken code. Widening that window makes the
    ordering the assertion, not the scheduler: with the publish inside the lock
    the delay merely holds the lock longer and one build still happens; with it
    outside, every waiter is guaranteed to observe the miss and rebuild.
    """
    import time

    from agent_bom.api.routes import demo_estate as demo_routes

    builds: list[str] = []
    guard = threading.Lock()
    real_builder = demo_routes.build_enterprise_demo_story
    real_remember = demo_routes._remember_demo_story
    start = threading.Barrier(4)

    def counting_builder(*, tenant_id: str):
        with guard:
            builds.append(tenant_id)
        return real_builder(tenant_id=tenant_id)

    def slow_remember(tenant_id: str, story) -> None:
        time.sleep(0.25)
        real_remember(tenant_id, story)

    def call() -> str:
        start.wait(timeout=HANDSHAKE_TIMEOUT_S)
        return demo_routes._cached_demo_story("stampede-tenant").estate_content_hash

    demo_routes.reset_demo_story_cache()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(demo_routes, "build_enterprise_demo_story", counting_builder)
        mp.setattr(demo_routes, "_remember_demo_story", slow_remember)
        with ThreadPoolExecutor(max_workers=4) as pool:
            hashes = [f.result(timeout=HANDSHAKE_TIMEOUT_S) for f in [pool.submit(call) for _ in range(4)]]

    assert len(set(hashes)) == 1, "concurrent callers disagreed on the estate they were served"
    assert builds == ["stampede-tenant"], f"expected one build for four concurrent callers, got {len(builds)}"


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
    """``tenant_id`` is request-controlled, so an unbounded cache is a memory DoS.

    Asserted by filling the cache past its bound and observing that it evicts,
    rather than by reading a ``maxsize`` attribute off the caching decorator.
    The old form only proved the decorator had been configured; it would have
    stayed green against any reimplementation that dropped the bound.
    """
    from agent_bom.api.routes import demo_estate as demo_routes

    demo_routes.reset_demo_story_cache()
    assert demo_routes.DEMO_STORY_CACHE_MAXSIZE <= 32

    overflow = demo_routes.DEMO_STORY_CACHE_MAXSIZE + 3
    for i in range(overflow):
        demo_routes._cached_demo_story(f"bounded-tenant-{i}")

    assert demo_routes.demo_story_cache_size() == demo_routes.DEMO_STORY_CACHE_MAXSIZE, (
        f"cache holds {demo_routes.demo_story_cache_size()} entries after {overflow} tenants"
    )

    demo_routes.reset_demo_story_cache()
    assert demo_routes.demo_story_cache_size() == 0


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


FULL_SNAPSHOT_SQL = "SELECT * FROM graph_nodes WHERE tenant_id = ? AND scan_id = ?"


def _node_graph(scan_id: str, count: int) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id=scan_id, tenant_id="default")
    for i in range(count):
        graph.add_node(
            UnifiedNode(
                id=f"asset:{i:05d}",
                entity_type=EntityType.RESOURCE,
                label=f"asset-{i:05d}",
                severity=["critical", "high", "medium", "low", "info"][i % 5],
                risk_score=float(i % 17),
            )
        )
    return graph


def test_full_snapshot_read_is_not_dragged_onto_the_paging_index(tmp_path) -> None:
    """The unordered full read must keep its rowid-ordered index.

    ``idx_gn_tenant_scan`` and ``idx_gn_tenant_scan_rank`` share the leading
    ``(tenant_id, scan_id)`` prefix, so both can serve the full-snapshot read.
    SQLite's own documentation says that without statistics "the choice of which
    index to use is arbitrary" -- and adding the paging index flipped that
    arbitrary choice the wrong way.

    It is the wrong way because the two indexes differ in *row order*, not just
    in width. Entries in the paging index are ordered by
    ``(severity_id, risk_score, label, id)``, so walking it to fetch the
    non-indexed columns visits the table in scattered rowid order; the shorter
    index is ordered by rowid within each snapshot and visits it sequentially.
    Measured at 300k rows: 533.8 ms -> 640.1 ms (+19.9%) purely from that flip.

    Asserted as a plan property rather than a duration, so it holds on any
    machine: the full-snapshot read may use the rowid-ordered index or scan the
    table, but it must not be answered through the paging index.
    """
    store = SQLiteGraphStore(tmp_path / "full.db")
    store.save_graph(_node_graph("full-scan", 400))

    conn = sqlite3.connect(tmp_path / "full.db")
    try:
        plan = [row[3] for row in conn.execute("EXPLAIN QUERY PLAN " + FULL_SNAPSHOT_SQL, ("default", "full-scan"))]
    finally:
        conn.close()

    assert not any("idx_gn_tenant_scan_rank" in step for step in plan), (
        f"the unordered full-snapshot read is being answered through the paging index: {plan}"
    )


def test_graph_store_records_query_planner_statistics(tmp_path) -> None:
    """The planner needs statistics for the two-index choice to stop being arbitrary.

    Both node reads are legitimate and neither index can serve both orders, so
    the fix is not a different index shape -- it is giving SQLite the numbers it
    needs to pick correctly per query. Without ``sqlite_stat1`` the tie-break is
    documented as arbitrary, which is not a property a read path can rest on.
    """
    store = SQLiteGraphStore(tmp_path / "stats.db")
    store.save_graph(_node_graph("stats-scan", 400))

    conn = sqlite3.connect(tmp_path / "stats.db")
    try:
        assert conn.execute("SELECT count(*) FROM sqlite_master WHERE name = 'sqlite_stat1'").fetchone()[0] == 1, (
            "the graph store never recorded planner statistics"
        )
        indexed = {row[0] for row in conn.execute("SELECT idx FROM sqlite_stat1 WHERE tbl = 'graph_nodes'")}
    finally:
        conn.close()

    assert {"idx_gn_tenant_scan", "idx_gn_tenant_scan_rank"} <= indexed, (
        f"both node indexes must carry statistics, got {sorted(i for i in indexed if i)}"
    )


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
