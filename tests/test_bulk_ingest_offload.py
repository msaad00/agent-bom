"""Bulk ingest must run its blocking store writes off the event loop.

The read path (`/v1/findings`, `/v1/graph`) offloads sync psycopg work via
``anyio.to_thread`` so a single deep call cannot freeze ``/health`` and every
unrelated request. The bulk/connector WRITE path (`/v1/findings/bulk`) called
``hub_store.add`` / ``hub_store.upsert_current_batch`` directly on the loop.
This pins the offload so the write path matches the read path.
"""

from __future__ import annotations

from uuid import uuid4

from starlette.testclient import TestClient

from agent_bom.api import compliance_hub_store as hub_store_mod
from agent_bom.api.routes import scan as scan_routes
from agent_bom.api.server import app
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def setup_function() -> None:
    hub_store_mod.reset_compliance_hub_store()


def teardown_function() -> None:
    hub_store_mod.reset_compliance_hub_store()


def test_bulk_ingest_offloads_store_writes_to_thread(monkeypatch) -> None:
    client = TestClient(app)
    client.headers.update(proxy_headers(role="analyst", tenant=f"offload-{uuid4().hex}"))

    helper_calls: list[str] = []

    async def _recording_hub_store_call(fn, /, *args, **kwargs):
        helper_calls.append(getattr(fn, "__name__", repr(fn)))
        return fn(*args, **kwargs)

    monkeypatch.setattr(scan_routes, "_hub_store_call", _recording_hub_store_call)

    resp = client.post(
        "/v1/findings/bulk",
        json={
            "source": "agent-runtime",
            "schema_version": "v1",
            "findings": [
                {"id": "f-1", "title": "one", "severity": "high"},
                {"id": "f-2", "title": "two", "severity": "medium"},
            ],
        },
    )

    assert resp.status_code == 201, resp.text
    assert resp.json()["ingested"] == 2
    assert "_bulk_ingest_store_writes" in helper_calls, (
        f"bulk ingest must route its blocking store writes through the off-loop helper (mirroring the read path); saw {helper_calls}"
    )


def test_bulk_ingest_out_of_range_observed_at_returns_422(monkeypatch) -> None:
    """An observed_at outside the partition window is a clean 4xx, not a 500."""
    from agent_bom.api.hub_observations_partition import ObservationPartitionRangeError

    client = TestClient(app, raise_server_exceptions=False)
    client.headers.update(proxy_headers(role="analyst", tenant=f"range-{uuid4().hex}"))

    def _raise_range(*args, **kwargs):
        raise ObservationPartitionRangeError("2099-01-01T00:00:00Z", months_ahead=2, months_behind=120)

    monkeypatch.setattr(scan_routes, "_bulk_ingest_store_writes", _raise_range)

    resp = client.post(
        "/v1/findings/bulk",
        json={
            "source": "agent-runtime",
            "observed_at": "2099-01-01T00:00:00Z",
            "findings": [{"id": "f-1", "title": "one", "severity": "high"}],
        },
    )

    assert resp.status_code == 422, resp.text
