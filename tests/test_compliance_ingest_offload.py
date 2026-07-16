"""Compliance ingest (`/v1/compliance/ingest`) must offload its blocking writes.

Bulk ingest (`/v1/findings/bulk`) already funnels its blocking psycopg write
sequence through the shared ``hub_store_call`` / ``hub_ingest_store_writes``
off-loop seam. The compliance ingest route ran the identical sequence directly
on the event loop, so a concurrent CI SARIF/CDX/CSV import froze ``/health`` and
every unrelated request. This pins:

- the route routes its store writes through the shared off-loop helper,
- an out-of-partition-window ``observed_at`` is a clean 422 (not a raw 500),
- the ``hub_store_call`` seam actually keeps the event loop responsive while a
  blocking store write is in flight (behavioral, not just routing).
"""

from __future__ import annotations

import asyncio
import json
import time
from uuid import uuid4

import pytest
from starlette.testclient import TestClient

from agent_bom.api import compliance_hub_store as hub_store_mod
from agent_bom.api import hub_ingest as hub_ingest_mod
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


def _sarif_content() -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "external-secrets",
                            "rules": [
                                {
                                    "id": "SECRET-AWS-ACCESS-KEY",
                                    "shortDescription": {"text": "AWS access key"},
                                    "properties": {"tags": ["secret", "CWE-798"]},
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "SECRET-AWS-ACCESS-KEY",
                            "level": "error",
                            "message": {"text": "Hardcoded AWS access key"},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/cfg.py"}}}],
                            "properties": {"security-severity": "9.5"},
                        }
                    ],
                }
            ],
        }
    )


def test_compliance_ingest_offloads_store_writes_to_thread(monkeypatch) -> None:
    client = TestClient(app)
    client.headers.update(proxy_headers(role="admin", tenant=f"cmpl-offload-{uuid4().hex}"))

    helper_calls: list[str] = []
    real_call = hub_ingest_mod.hub_store_call

    async def _recording_hub_store_call(fn, /, *args, **kwargs):
        helper_calls.append(getattr(fn, "__name__", repr(fn)))
        return await real_call(fn, *args, **kwargs)

    monkeypatch.setattr(hub_ingest_mod, "hub_store_call", _recording_hub_store_call)

    resp = client.post(
        "/v1/compliance/ingest",
        json={"format": "sarif", "content": _sarif_content()},
    )

    assert resp.status_code == 201, resp.text
    assert resp.json()["ingested"] == 1
    assert "hub_ingest_store_writes" in helper_calls, (
        f"compliance ingest must route its blocking store writes through the off-loop helper; saw {helper_calls}"
    )


def test_compliance_ingest_out_of_range_observed_at_returns_422(monkeypatch) -> None:
    """An observed_at outside the partition window is a clean 422, not a 500."""
    from agent_bom.api.hub_observations_partition import ObservationPartitionRangeError

    client = TestClient(app, raise_server_exceptions=False)
    client.headers.update(proxy_headers(role="admin", tenant=f"cmpl-range-{uuid4().hex}"))

    def _raise_range(*args, **kwargs):
        raise ObservationPartitionRangeError("2099-01-01T00:00:00Z", months_ahead=2, months_behind=120)

    monkeypatch.setattr(hub_ingest_mod, "hub_ingest_store_writes", _raise_range)

    resp = client.post(
        "/v1/compliance/ingest",
        json={"format": "sarif", "content": _sarif_content(), "observed_at": "2099-01-01T00:00:00Z"},
    )

    assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_hub_store_call_keeps_event_loop_responsive() -> None:
    """The off-loop seam must run blocking work in a worker thread.

    A blocking store write (simulated by ``time.sleep``) is put in flight via the
    real ``hub_store_call`` (``anyio.to_thread``). While it runs, the event loop
    must still schedule and complete unrelated coroutines promptly — proving the
    write does not pin the loop. Run directly on the loop, the trivial coroutine
    below could not complete until the full block elapsed.
    """
    block_seconds = 0.5

    def _slow_blocking_write() -> str:
        time.sleep(block_seconds)
        return "written"

    loop = asyncio.get_running_loop()
    write_task = asyncio.create_task(hub_ingest_mod.hub_store_call(_slow_blocking_write))
    # Let the offload hand the blocking call to a worker thread.
    await asyncio.sleep(0.05)
    assert not write_task.done(), "blocking write should still be in flight"

    async def _trivial() -> str:
        return "responsive"

    started = loop.time()
    result = await asyncio.wait_for(_trivial(), timeout=0.15)
    elapsed = loop.time() - started

    assert result == "responsive"
    assert elapsed < block_seconds / 2, (
        f"event loop was blocked for {elapsed:.3f}s while a store write was in flight — offload is not effective"
    )
    assert await write_task == "written"
