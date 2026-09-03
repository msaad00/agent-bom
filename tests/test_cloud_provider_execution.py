from __future__ import annotations

import asyncio
import threading

import pytest


@pytest.mark.asyncio
async def test_timed_out_provider_call_stays_capacity_accounted_until_worker_finishes(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom import backpressure as provider_execution

    provider_execution.reset_provider_execution_for_tests()
    monkeypatch.setattr(provider_execution, "_provider_execution_capacity", lambda: 1)
    started = threading.Event()
    release = threading.Event()

    def _blocked() -> str:
        started.set()
        assert release.wait(timeout=2)
        return "done"

    with pytest.raises(provider_execution.ProviderExecutionTimeoutError):
        await provider_execution.run_provider_call(_blocked, timeout_seconds=0.01)

    assert started.is_set()
    assert provider_execution.provider_execution_status()["active"] == 1
    with pytest.raises(provider_execution.ProviderExecutionCapacityError):
        await provider_execution.run_provider_call(lambda: "must-not-run", timeout_seconds=0.1)

    release.set()
    await provider_execution.wait_for_provider_execution_idle_for_tests()
    assert provider_execution.provider_execution_status()["active"] == 0


@pytest.mark.asyncio
async def test_provider_call_runs_blocking_sdk_work_off_the_event_loop() -> None:
    from agent_bom import backpressure as provider_execution

    provider_execution.reset_provider_execution_for_tests()
    release = threading.Event()

    async def _release() -> None:
        await asyncio.sleep(0.01)
        release.set()

    release_task = asyncio.create_task(_release())
    result = await provider_execution.run_provider_call(lambda: release.wait(timeout=1) or "missed", timeout_seconds=0.5)
    await release_task

    assert result is True
