from __future__ import annotations

import asyncio

import pytest

from agent_bom.backpressure import (
    BackpressureRejectedError,
    adaptive_backpressure,
    describe_backpressure_posture,
    reset_backpressure_for_tests,
)


@pytest.fixture(autouse=True)
def _reset_backpressure(monkeypatch):
    reset_backpressure_for_tests()
    monkeypatch.delenv("AGENT_BOM_BACKPRESSURE_ENABLED", raising=False)
    monkeypatch.delenv("AGENT_BOM_BACKPRESSURE_GRAPH_CONCURRENCY", raising=False)
    monkeypatch.delenv("AGENT_BOM_BACKPRESSURE_GRAPH_P99_MS", raising=False)
    monkeypatch.delenv("AGENT_BOM_BACKPRESSURE_GRAPH_COOLDOWN_SECONDS", raising=False)
    monkeypatch.delenv("AGENT_BOM_BACKPRESSURE_GRAPH_MIN_SAMPLES", raising=False)
    yield
    reset_backpressure_for_tests()


@pytest.mark.asyncio
async def test_backpressure_records_normal_path_posture() -> None:
    async with adaptive_backpressure("graph"):
        await asyncio.sleep(0)

    posture = describe_backpressure_posture()
    graph = next(path for path in posture["paths"] if path["path"] == "graph")

    assert posture["status"] == "ready"
    assert graph["state"] == "closed"
    assert graph["completed"] == 1
    assert graph["rejected"] == 0


@pytest.mark.asyncio
async def test_backpressure_rejects_when_concurrency_is_saturated(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_BACKPRESSURE_GRAPH_CONCURRENCY", "1")

    async with adaptive_backpressure("graph"):
        with pytest.raises(BackpressureRejectedError) as exc:
            async with adaptive_backpressure("graph"):
                pass

    assert exc.value.reason == "concurrency_limit"
    posture = describe_backpressure_posture()
    graph = next(path for path in posture["paths"] if path["path"] == "graph")
    assert graph["rejected"] == 1


@pytest.mark.asyncio
async def test_backpressure_opens_after_p99_threshold_and_recovers(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_BACKPRESSURE_GRAPH_P99_MS", "1")
    monkeypatch.setenv("AGENT_BOM_BACKPRESSURE_GRAPH_MIN_SAMPLES", "1")
    monkeypatch.setenv("AGENT_BOM_BACKPRESSURE_GRAPH_COOLDOWN_SECONDS", "1")

    async with adaptive_backpressure("graph"):
        await asyncio.sleep(0.01)

    with pytest.raises(BackpressureRejectedError) as exc:
        async with adaptive_backpressure("graph"):
            pass

    assert exc.value.reason == "p99_latency_threshold"
    assert describe_backpressure_posture()["status"] == "active"

    await asyncio.sleep(1.05)
    async with adaptive_backpressure("graph"):
        pass

    posture = describe_backpressure_posture()
    graph = next(path for path in posture["paths"] if path["path"] == "graph")
    assert graph["state"] == "closed"
