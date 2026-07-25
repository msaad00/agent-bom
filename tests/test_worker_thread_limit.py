"""Offloaded worker threads must not outnumber Postgres connections.

Route handlers offload synchronous store reads with ``anyio.to_thread``. AnyIO's
default limiter allows 40 concurrent threads while the connection pool defaults
to 20, so a burst of offloaded reads can park twice as many threads as there are
connections; the surplus blocks in the pool until it times out. One knob drives
both so the two can't drift apart.
"""

from __future__ import annotations

import anyio.to_thread
import pytest

from agent_bom import config


def test_worker_thread_limit_defaults_to_the_pool_ceiling() -> None:
    assert config.WORKER_THREAD_LIMIT == config.POSTGRES_POOL_MAX_SIZE


def test_worker_thread_limit_is_operator_overridable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_WORKER_THREAD_LIMIT", "7")
    import importlib

    reloaded = importlib.reload(config)
    try:
        assert reloaded.WORKER_THREAD_LIMIT == 7
    finally:
        monkeypatch.delenv("AGENT_BOM_WORKER_THREAD_LIMIT", raising=False)
        importlib.reload(config)


@pytest.mark.asyncio
async def test_applying_the_limit_caps_the_default_thread_limiter() -> None:
    """The limiter AnyIO hands to ``to_thread`` is capped, not left at 40."""
    from agent_bom.api.server import _apply_worker_thread_limit

    limiter = anyio.to_thread.current_default_thread_limiter()
    original = limiter.total_tokens
    try:
        limiter.total_tokens = 40  # AnyIO's default
        _apply_worker_thread_limit()
        assert anyio.to_thread.current_default_thread_limiter().total_tokens == config.WORKER_THREAD_LIMIT
    finally:
        limiter.total_tokens = original
