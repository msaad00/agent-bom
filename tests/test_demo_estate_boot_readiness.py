"""Demo-estate seeding must not hold API startup hostage.

Liveness answers as soon as the process is up; readiness reports the seed in
flight and flips to ready once the showcase evidence has landed.
"""

from __future__ import annotations

import threading
import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def gated_demo_boot(monkeypatch: pytest.MonkeyPatch, tmp_path):
    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "demo-estate.db"))
    monkeypatch.setenv("AGENT_BOM_GRAPH_DB", str(tmp_path / "demo-graph.db"))
    monkeypatch.setenv("AGENT_BOM_DEMO_STORY_PREWARM", "0")

    from agent_bom.api import server as api_server
    from agent_bom.api import stores as api_stores
    from agent_bom.demo_estate import boot_seed, bootstrap

    release = threading.Event()
    started = threading.Event()
    calls: list[str] = []

    def slow_bootstrap(*, tenant_id: str = bootstrap.SHOWCASE_TENANT) -> dict:
        calls.append(tenant_id)
        started.set()
        release.wait(30)
        return {"enabled": True, "tenant_id": tenant_id, "seeded": True}

    monkeypatch.setattr(bootstrap, "maybe_bootstrap_demo_estate", slow_bootstrap)
    api_server._shutting_down = False
    original = (api_stores._store, api_stores._graph_store, api_stores._trend_store)
    api_stores._store = api_stores._graph_store = api_stores._trend_store = None
    try:
        yield api_server, boot_seed, release, started, calls
    finally:
        release.set()
        boot_seed.wait_for_demo_estate_boot_seed(30)
        api_stores._store, api_stores._graph_store, api_stores._trend_store = original
        bootstrap.reset_demo_estate_bootstrap_status()


def test_health_answers_while_demo_estate_seed_is_in_flight(gated_demo_boot) -> None:
    api_server, boot_seed, release, started, calls = gated_demo_boot
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT

    began = time.monotonic()
    with TestClient(api_server.app) as client:
        assert time.monotonic() - began < 10
        assert started.wait(10)

        assert client.get("/health").status_code == 200
        seeding = client.get("/readyz")
        assert seeding.status_code == 503
        assert seeding.json() == {"status": "not_ready", "reason": "demo_estate_seeding"}
        assert boot_seed.demo_estate_seeding() is True

        release.set()
        assert boot_seed.wait_for_demo_estate_boot_seed(10) is True

        ready = client.get("/readyz")
        assert ready.status_code == 200
        assert ready.json() == {"status": "ready"}
        assert boot_seed.demo_estate_seeding() is False
    assert calls == [SHOWCASE_TENANT]


def test_empty_posture_and_overview_say_the_demo_is_seeding(gated_demo_boot) -> None:
    """An empty estate mid-seed must not read as a product with no scans."""
    api_server, boot_seed, release, started, _calls = gated_demo_boot

    with TestClient(api_server.app) as client:
        assert started.wait(10)

        posture = client.get("/v1/posture").json()
        assert posture["no_data"] is True
        assert posture["demo_estate_seeding"] is True
        assert "seeding" in posture["summary"].lower()
        overview = client.get("/v1/overview")
        assert overview.status_code == 200
        assert overview.json()["demo_estate_seeding"] is True

        release.set()
        assert boot_seed.wait_for_demo_estate_boot_seed(10) is True

        settled = client.get("/v1/posture").json()
        assert settled["demo_estate_seeding"] is False
        assert settled["summary"] == "No completed scans available"
        assert client.get("/v1/overview").json()["demo_estate_seeding"] is False


def test_concurrent_bootstrap_callers_run_the_seed_once(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.demo_estate import bootstrap

    active = 0
    peak = 0
    guard = threading.Lock()

    def slow_disabled_check() -> bool:
        nonlocal active, peak
        with guard:
            active += 1
            peak = max(peak, active)
        time.sleep(0.05)
        with guard:
            active -= 1
        return False

    monkeypatch.setattr(bootstrap, "demo_estate_enabled", slow_disabled_check)
    threads = [threading.Thread(target=bootstrap.maybe_bootstrap_demo_estate) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(5)

    assert peak == 1
    bootstrap.reset_demo_estate_bootstrap_status()


def test_readiness_is_unaffected_outside_demo_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api.readiness import evaluate_control_plane_readiness
    from agent_bom.demo_estate import boot_seed

    monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    assert boot_seed.demo_estate_seeding() is False
    assert boot_seed.wait_for_demo_estate_boot_seed(0) is True
    assert evaluate_control_plane_readiness().reason != "demo_estate_seeding"
