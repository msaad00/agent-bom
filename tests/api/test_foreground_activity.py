"""Deferrable background CPU work yields to in-flight interactive requests."""

import asyncio
import threading
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agent_bom.api import foreground_activity as fg


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.setattr(fg, "_in_flight", 0)
    monkeypatch.setattr(fg, "_last_activity", time.monotonic() - 3600)


def test_idle_process_does_not_defer():
    started = time.monotonic()
    assert fg.defer_until_idle(quiet=0.2, max_wait=5) is True
    assert time.monotonic() - started < 0.1


def test_waits_for_in_flight_request_and_then_a_quiet_window():
    fg._enter()
    released_at: list[float] = []

    def finish() -> None:
        time.sleep(0.3)
        released_at.append(time.monotonic())
        fg._leave()

    threading.Thread(target=finish).start()
    assert fg.defer_until_idle(quiet=0.2, max_wait=5) is True
    assert released_at, "background work ran while a request was in flight"
    assert time.monotonic() - released_at[0] >= 0.19


def test_constant_traffic_cannot_starve_background_work():
    fg._enter()
    try:
        started = time.monotonic()
        assert fg.defer_until_idle(quiet=0.1, max_wait=0.3) is False
        assert 0.25 <= time.monotonic() - started < 2
    finally:
        fg._leave()


def test_middleware_counts_api_requests_but_not_probes():
    seen: dict[str, int] = {}
    app = FastAPI()

    @app.get("/v1/thing")
    def thing() -> dict[str, int]:
        seen["api"] = fg._in_flight
        return {}

    @app.get("/readyz")
    def ready() -> dict[str, int]:
        seen["probe"] = fg._in_flight
        return {}

    app.add_middleware(fg.ForegroundActivityMiddleware)
    with TestClient(app) as client:
        assert client.get("/readyz").status_code == 200
        before = fg._last_activity
        assert client.get("/v1/thing").status_code == 200
    assert seen == {"probe": 0, "api": 1}
    assert fg._in_flight == 0
    assert fg._last_activity > before


def test_failed_request_still_leaves_the_in_flight_count():
    app = FastAPI()

    @app.get("/v1/boom")
    def boom() -> None:
        raise RuntimeError("boom")

    app.add_middleware(fg.ForegroundActivityMiddleware)
    with TestClient(app, raise_server_exceptions=False) as client:
        assert client.get("/v1/boom").status_code == 500
    assert fg._in_flight == 0


def test_campaign_reconciliation_poll_defers_to_foreground(monkeypatch):
    from agent_bom.api import campaign_reconciliation as cr

    order: list[str] = []
    monkeypatch.setattr(fg, "defer_until_idle", lambda **_: order.append("defer") or True)
    monkeypatch.setattr(cr, "reconcile_pending_campaigns", lambda: order.append("reconcile") or 0)
    cr.poll_campaign_reconciliation()
    assert order == ["defer", "reconcile"]


def test_demo_story_prewarm_waits_for_foreground_quiet_after_the_seed(monkeypatch):
    from agent_bom.demo_estate import boot_seed

    order: list[str] = []
    monkeypatch.setattr(boot_seed, "_run_boot_seed", lambda: order.append("seed"))
    monkeypatch.setattr(fg, "defer_until_idle", lambda **_: order.append("defer") or True)

    async def prewarm() -> None:
        order.append("prewarm")

    asyncio.run(boot_seed._seed_then(prewarm))
    assert order == ["seed", "defer", "prewarm"]
