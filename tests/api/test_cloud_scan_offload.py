"""Cloud scan REST handlers must offload their blocking provider work off-loop.

``cloud_inventory`` and ``cloud_cis_benchmark`` call synchronous provider SDK
discovery / CIS evaluation. Run directly on the event loop those calls freeze
``/health`` and every unrelated request for the duration of a live scan. They
now funnel the synchronous body through ``anyio.to_thread.run_sync`` under an
adaptive-backpressure guard (the same idiom ``cloud_account_summary`` uses),
preserving the exact return payloads and error semantics.

These pin that the offload seam is actually taken and that the disabled-provider
payload shape is unchanged.
"""

from __future__ import annotations

import asyncio
import time

import anyio.to_thread
import pytest

from agent_bom.api.routes import cloud


def _spy_run_sync(monkeypatch):
    real = anyio.to_thread.run_sync
    offloaded: list[str] = []

    async def _spy(fn, /, *args, **kwargs):
        offloaded.append(getattr(fn, "__name__", repr(fn)))
        return await real(fn, *args, **kwargs)

    monkeypatch.setattr(cloud.anyio.to_thread, "run_sync", _spy)
    return offloaded


def test_cloud_inventory_offloads_provider_scan(monkeypatch):
    monkeypatch.setattr(cloud, "_tenant", lambda request: "t-inv")
    # No AGENT_BOM_*_INVENTORY flags set → providers self-report "disabled"
    # without touching the network, so the real builder runs off-loop.
    offloaded = _spy_run_sync(monkeypatch)

    result = asyncio.run(cloud.cloud_inventory(request=object(), provider="aws", region=""))

    assert "_build_inventory_payload" in offloaded, (
        f"cloud_inventory must offload its provider scan; saw {offloaded}"
    )
    assert result["schema_version"] == "cloud.inventory.summary.v1"
    assert result["tenant_id"] == "t-inv"
    assert result["status"] == "disabled"


def test_cloud_cis_benchmark_offloads_evaluation(monkeypatch):
    monkeypatch.setattr(cloud, "_tenant", lambda request: "t-cis")
    offloaded = _spy_run_sync(monkeypatch)

    # The benchmark evaluation must run in a worker thread (via _run_cis_benchmark),
    # not on the event loop. The offloaded builder's payload is returned unchanged.
    result = asyncio.run(
        cloud.cloud_cis_benchmark(
            request=object(),
            provider="aws",
            checks="",
            region="",
            profile="",
            subscription_id="",
            project_id="",
        )
    )

    assert "_run_cis_benchmark" in offloaded, (
        f"cloud_cis_benchmark must offload its evaluation; saw {offloaded}"
    )
    # The offloaded result flows back through unchanged: tenant scope is threaded
    # in and the canonical benchmark payload keys are present.
    assert result["tenant_id"] == "t-cis"
    assert "benchmark" in result and "evaluated" in result


def test_cloud_inventory_unsupported_provider_still_404_on_loop(monkeypatch):
    """Input validation stays on the loop (never reaches the offload)."""
    monkeypatch.setattr(cloud, "_tenant", lambda request: "t")
    offloaded = _spy_run_sync(monkeypatch)

    from fastapi import HTTPException

    try:
        asyncio.run(cloud.cloud_inventory(request=object(), provider="nope", region=""))
    except HTTPException as exc:
        assert exc.status_code == 404
    else:  # pragma: no cover
        raise AssertionError("expected 404 for unsupported provider")
    assert offloaded == [], "validation errors must not offload"


@pytest.mark.asyncio
async def test_slow_inventory_scan_keeps_event_loop_responsive(monkeypatch):
    """A slow provider scan must not pin the loop — the offload proves it.

    ``_build_inventory_payload`` is replaced with a blocking ``time.sleep``. While
    the inventory handler runs it, an unrelated trivial coroutine must still
    complete promptly. Run on the loop, the sleep would delay it by its full
    duration.
    """
    monkeypatch.setattr(cloud, "_tenant", lambda request: "t-slow")
    block_seconds = 0.5

    def _slow_build(tenant_id, selected, scoped_region):
        time.sleep(block_seconds)
        return {"schema_version": "cloud.inventory.summary.v1", "tenant_id": tenant_id, "status": "disabled"}

    monkeypatch.setattr(cloud, "_build_inventory_payload", _slow_build)

    loop = asyncio.get_running_loop()
    scan_task = asyncio.create_task(cloud.cloud_inventory(request=object(), provider="aws", region=""))
    await asyncio.sleep(0.05)  # let the offload hand the blocking body to a worker thread
    assert not scan_task.done(), "scan should still be in flight"

    started = loop.time()
    assert await asyncio.wait_for(_trivial(), timeout=0.15) == "responsive"
    assert loop.time() - started < block_seconds / 2, "event loop was blocked during the scan — offload ineffective"

    result = await scan_task
    assert result["status"] == "disabled"


async def _trivial() -> str:
    return "responsive"
