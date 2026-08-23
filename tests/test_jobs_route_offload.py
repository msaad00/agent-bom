"""``GET /v1/jobs`` must not run store work on the event loop.

The jobs list is polled by the dashboard activity feed every few seconds, and
its store calls include unbounded aggregates (``count_summary``,
``count_summary_by_status``). Running those inline on the event loop freezes
every unrelated route — ``/health`` included — for the duration of each poll.
Every other list route in this module already offloads to a worker thread.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# Long enough that an inline call is unmistakable, short enough to stay quick.
_BLOCKING_SECONDS = 0.4
_TICK_SECONDS = 0.01
# An offloaded call yields ~40 ticks; an inline one yields at most a couple.
_MIN_TICKS_WHILE_OFFLOADED = 5


def _completed_job():
    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest

    return ScanJob(
        job_id="job-offload",
        tenant_id="default",
        status=JobStatus.DONE,
        created_at="2026-08-23T00:00:00+00:00",
        request=ScanRequest(),
        result={"findings": []},
    )


def _blocking_store() -> MagicMock:
    store = MagicMock()

    def _slow_count(**_kwargs: Any) -> int:
        time.sleep(_BLOCKING_SECONDS)
        return 1

    store.count_summary.side_effect = _slow_count
    store.list_summary.return_value = []
    store.count_summary_by_status.return_value = {}
    return store


@pytest.mark.asyncio
async def test_list_jobs_keeps_the_event_loop_responsive() -> None:
    """A slow store read must not stall unrelated coroutines."""
    import httpx

    from agent_bom.api.server import app

    ticks = 0

    async def heartbeat() -> None:
        nonlocal ticks
        while True:
            await asyncio.sleep(_TICK_SECONDS)
            ticks += 1

    with patch("agent_bom.api.routes.scan._get_store", return_value=_blocking_store()):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            beat = asyncio.create_task(heartbeat())
            await asyncio.sleep(_TICK_SECONDS * 2)  # let the heartbeat settle
            before = ticks
            response = await client.get("/v1/jobs")
            observed = ticks - before
            beat.cancel()

    assert response.status_code == 200
    assert observed >= _MIN_TICKS_WHILE_OFFLOADED, (
        f"event loop advanced only {observed} tick(s) during a {_BLOCKING_SECONDS}s store read — the work ran inline"
    )


@pytest.mark.asyncio
async def test_list_jobs_response_contract_is_unchanged() -> None:
    """Offloading must not alter the payload the dashboard reads."""
    import httpx

    from agent_bom.api.server import app

    store = MagicMock()
    store.count_summary.return_value = 3
    store.list_summary.return_value = [{"job_id": "j-1"}, {"job_id": "j-2"}]
    store.count_summary_by_status.return_value = {"done": 2, "failed": 1}

    with patch("agent_bom.api.routes.scan._get_store", return_value=store):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/v1/jobs?limit=2")

    assert response.status_code == 200
    body = response.json()
    assert body["schema_version"] == "v1"
    assert body["count"] == 2
    assert body["total"] == 3
    assert body["limit"] == 2
    assert body["offset"] == 0
    assert body["status_counts"] == {"done": 2, "failed": 1}
    assert [job["job_id"] for job in body["jobs"]] == ["j-1", "j-2"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        "/v1/scan/job-offload",
        "/v1/scan/job-offload/status",
        "/v1/scan/job-offload/remediation",
        "/v1/scan/job-offload/skill-audit",
        "/v1/scan/job-offload/stream",
    ],
)
async def test_per_job_reads_keep_the_event_loop_responsive(path: str) -> None:
    """Every per-job route must offload a potentially remote durable read."""
    import httpx

    from agent_bom.api.server import app

    ticks = 0
    job = _completed_job()

    def slow_job_lookup(*_args: Any, **_kwargs: Any):
        time.sleep(_BLOCKING_SECONDS)
        return job

    async def heartbeat() -> None:
        nonlocal ticks
        while True:
            await asyncio.sleep(_TICK_SECONDS)
            ticks += 1

    with patch("agent_bom.api.routes.scan._job_for_request", side_effect=slow_job_lookup):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            beat = asyncio.create_task(heartbeat())
            await asyncio.sleep(_TICK_SECONDS * 2)
            before = ticks
            response = await client.get(path)
            observed = ticks - before
            beat.cancel()

    assert response.status_code == 200, response.text
    assert observed >= _MIN_TICKS_WHILE_OFFLOADED, f"{path} advanced only {observed} tick(s) during a {_BLOCKING_SECONDS}s job read"
