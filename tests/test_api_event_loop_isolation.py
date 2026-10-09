"""Aggregate page reads must not starve the event loop.

The dashboard fires its page reads at once. Each runs on a worker thread, but
the work is CPU-bound Python sharing one GIL with the event-loop thread, so
ten at a time left ``/health`` and ``/_next/static`` chunks waiting seconds.
"""

from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx
import pytest

_HEAVY_CALLS = 8
_BURN_SECONDS = 0.25


class _ConcurrencyProbe:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.active = 0
        self.peak = 0

    def __enter__(self) -> None:
        with self._lock:
            self.active += 1
            self.peak = max(self.peak, self.active)

    def __exit__(self, *_exc: object) -> None:
        with self._lock:
            self.active -= 1


def _burn(seconds: float) -> int:
    """Pure-Python CPU work: holds the GIL the way the aggregate folds do."""
    deadline = time.perf_counter() + seconds
    n = 0
    while time.perf_counter() < deadline:
        n += sum(i * i for i in range(200))
    return n


async def _probe(client: httpx.AsyncClient, path: str, stop: asyncio.Event, latencies: list[float]) -> None:
    while not stop.is_set():
        started = time.perf_counter()
        response = await client.get(path)
        latencies.append(time.perf_counter() - started)
        assert response.status_code == 200, (path, response.status_code)
        await asyncio.sleep(0.02)


@pytest.mark.asyncio
async def test_concurrent_heavy_reads_are_bounded_and_health_stays_fast() -> None:
    from agent_bom.api import heavy_read_gate
    from agent_bom.api.server import app
    from agent_bom.backpressure import reset_backpressure_for_tests

    reset_backpressure_for_tests()
    heavy_read_gate.reset()
    probe = _ConcurrencyProbe()

    def slow_counts(_request: Any) -> dict:
        with probe:
            _burn(_BURN_SECONDS)
        return {"total": 0}

    health: list[float] = []
    stop = asyncio.Event()
    with patch("agent_bom.api.routes.compliance._get_posture_counts_impl", slow_counts):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test", timeout=60) as client:
            assert (await client.get("/health")).status_code == 200  # first-request app setup is not under test
            health_task = asyncio.create_task(_probe(client, "/health", stop, health))
            responses = await asyncio.gather(*(client.get("/v1/posture/counts") for _ in range(_HEAVY_CALLS)))
            stop.set()
            await health_task

    assert [r.status_code for r in responses] == [200] * _HEAVY_CALLS
    assert probe.peak <= heavy_read_gate.concurrency() == 2, (
        f"{probe.peak} aggregate reads computed at once; the gate allows {heavy_read_gate.concurrency()}"
    )
    assert health, "the health probe never completed while heavy reads ran"
    assert max(health) < 1.0, f"/health took {max(health):.2f}s while heavy reads ran"


@pytest.mark.asyncio
async def test_gate_sheds_past_queue_bound_and_leaves_other_routes_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api import heavy_read_gate
    from agent_bom.api.server import app

    monkeypatch.setattr(heavy_read_gate, "_limits", lambda: (1, 1))
    heavy_read_gate.reset()
    release = threading.Event()
    entered = threading.Event()

    def blocked_counts(_request: Any) -> dict:
        entered.set()
        release.wait(10)
        return {"total": 0}

    try:
        with patch("agent_bom.api.routes.compliance._get_posture_counts_impl", blocked_counts):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test", timeout=30) as client:
                assert (await client.get("/health")).status_code == 200  # first-request app setup is not under test
                admitted = asyncio.create_task(client.get("/v1/posture/counts"))
                await asyncio.to_thread(entered.wait, 5)
                queued = asyncio.create_task(client.get("/v1/posture/counts"))
                await asyncio.sleep(0.05)
                shed = await client.get("/v1/posture/counts")
                # Ungated routes answer while the gate is full.
                health = await asyncio.wait_for(client.get("/health"), 2)
                release.set()
                first, second = await asyncio.gather(admitted, queued)
    finally:
        release.set()
        heavy_read_gate.reset()

    assert shed.status_code == 429
    assert shed.headers["retry-after"] == "1"
    assert health.status_code == 200
    assert first.status_code == 200 and second.status_code == 200


@pytest.mark.asyncio
async def test_build_assets_are_served_from_memory_after_first_read(tmp_path: Path) -> None:
    import anyio.to_thread
    from starlette.applications import Starlette
    from starlette.routing import Mount

    from agent_bom.api.dashboard_assets import InMemoryBuildAssets
    from agent_bom.api.middleware import TrustHeadersMiddleware

    chunk = tmp_path / "static" / "chunks" / "app-abc123.js"
    chunk.parent.mkdir(parents=True)
    chunk.write_bytes(b"console.log('hi');")
    (tmp_path.parent / "outside.js").write_bytes(b"secret")
    test_app = Starlette(routes=[Mount("/_next", InMemoryBuildAssets(directory=str(tmp_path)))])
    test_app.add_middleware(TrustHeadersMiddleware)

    hops = 0
    real_run_sync = anyio.to_thread.run_sync

    async def counting_run_sync(*args: Any, **kwargs: Any) -> Any:
        nonlocal hops
        hops += 1
        return await real_run_sync(*args, **kwargs)

    transport = httpx.ASGITransport(app=test_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        first = await client.get("/_next/static/chunks/app-abc123.js")
        with patch("anyio.to_thread.run_sync", counting_run_sync):
            second = await client.get("/_next/static/chunks/app-abc123.js")
        not_modified = await client.get("/_next/static/chunks/app-abc123.js", headers={"if-none-match": first.headers["etag"]})
        missing = await client.get("/_next/static/chunks/nope.js")
        escaped = await client.get("/_next/../outside.js")
        head = await client.head("/_next/static/chunks/app-abc123.js")

    assert first.status_code == 200 and first.content == b"console.log('hi');"
    assert first.headers["content-type"].startswith("text/javascript")
    assert second.status_code == 200 and second.content == first.content
    assert second.headers["etag"] == first.headers["etag"]
    assert second.headers["last-modified"] == first.headers["last-modified"]
    assert hops == 0, "a cached build asset still hopped to a worker thread"
    assert not_modified.status_code == 304
    assert first.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert missing.status_code == 404 and missing.headers["cache-control"] == "no-store"
    assert escaped.status_code == 404 and b"secret" not in escaped.content
    assert head.status_code == 200 and head.headers["content-length"] == str(len(b"console.log('hi');"))


def test_only_hashed_build_output_is_cacheable() -> None:
    from agent_bom.api.middleware import _is_hashed_build_asset

    assert _is_hashed_build_asset("GET", "/_next/static/chunks/a.js", 200)
    assert not _is_hashed_build_asset("GET", "/_next/static/chunks/a.js", 404)
    assert not _is_hashed_build_asset("POST", "/_next/static/chunks/a.js", 200)
    assert not _is_hashed_build_asset("GET", "/_next/data/page.json", 200)
    assert not _is_hashed_build_asset("GET", "/v1/findings", 200)
    assert not _is_hashed_build_asset("GET", "/index.html", 200)


def test_concurrent_read_scopes_share_one_payload_parse() -> None:
    from agent_bom.api.finding_read_context import finding_read_scope
    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
    from agent_bom.api.storage.jobs import parse_job_payload

    payload = ScanJob(
        job_id="shared-parse",
        tenant_id="tenant-a",
        status=JobStatus.DONE,
        created_at="2026-10-08T00:00:00+00:00",
        request=ScanRequest(),
        result={"findings": [{"id": str(i)} for i in range(200)]},
    ).model_dump_json()
    calls = 0
    real = ScanJob.model_validate_json.__func__  # type: ignore[attr-defined]

    def counting(cls: type[ScanJob], data: Any, *args: Any, **kwargs: Any) -> ScanJob:
        nonlocal calls
        calls += 1
        time.sleep(0.2)  # long enough that every scope arrives mid-parse
        return real(cls, data, *args, **kwargs)

    results: list[ScanJob] = []
    barrier = threading.Barrier(4)

    def scoped_read() -> None:
        barrier.wait()
        with finding_read_scope():
            job = parse_job_payload(payload)
            assert parse_job_payload(payload) is job
            results.append(job)
            barrier.wait()  # hold the scope until every reader has its object

    with patch.object(ScanJob, "model_validate_json", classmethod(counting)):
        threads = [threading.Thread(target=scoped_read) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        outside_a = parse_job_payload(payload)
        outside_b = parse_job_payload(payload)

    assert calls == 1 + 2, f"expected one shared parse plus two unscoped parses, saw {calls}"
    assert len(results) == 4 and all(job is results[0] for job in results)
    assert results[0].tenant_id == "tenant-a"
    assert outside_a is not outside_b and outside_a is not results[0]


@pytest.mark.asyncio
async def test_scheduler_polls_due_schedules_off_the_event_loop() -> None:
    from agent_bom.api.scheduler import scheduler_loop

    loop_thread = threading.get_ident()
    polled_on: list[int] = []

    class _Store:
        def list_due(self, _now_iso: str) -> list:
            polled_on.append(threading.get_ident())
            return []

    task = asyncio.create_task(scheduler_loop(_Store(), lambda *_a, **_k: "job", interval_seconds=0))
    for _ in range(100):
        if polled_on:
            break
        await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert polled_on, "scheduler never polled"
    assert loop_thread not in polled_on
