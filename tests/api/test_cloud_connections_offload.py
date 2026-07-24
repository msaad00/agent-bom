"""Cloud-connection test/scan handlers must offload their blocking broker work.

``test_connection`` brokers real provider network I/O and ``scan_connection``
runs a full inventory + CIS cloud scan. Run directly on the event loop those
synchronous calls freeze ``/health`` and every unrelated request for the whole
broker exchange / scan (measured: one POST /test against a black-holed endpoint
froze the API for 10+ seconds). They now funnel the synchronous body through
``anyio.to_thread.run_sync`` under an adaptive-backpressure guard — the same
idiom the sibling cloud/governance routes use — preserving the exact success
payloads and 502 failure semantics, and shedding bursts with a 429 instead of
marking the connection errored.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from types import SimpleNamespace

import anyio.to_thread
import pytest

from agent_bom.api.routes import cloud_connections
from agent_bom.backpressure import BackpressureRejectedError


def _record(provider: str = "aws") -> SimpleNamespace:
    return SimpleNamespace(
        id="conn-1",
        tenant_id="t-conn",
        provider=provider,
        to_public_dict=lambda: {"id": "conn-1", "provider": provider},
    )


@pytest.fixture()
def wired(monkeypatch):
    """Neutralize store/audit plumbing and spy on the offload seam."""
    record = _record()
    monkeypatch.setattr(cloud_connections, "_require_connection", lambda request, connection_id: record)
    monkeypatch.setattr(cloud_connections, "_reject_showcase_connection", lambda record: None)
    monkeypatch.setattr(cloud_connections, "_mark_connection", lambda record, **kwargs: None)
    monkeypatch.setattr(cloud_connections, "log_action", lambda *args, **kwargs: None)
    monkeypatch.setattr(cloud_connections, "_actor", lambda request: "test")

    real = anyio.to_thread.run_sync
    offloaded: list[str] = []

    async def _spy(fn, /, *args, **kwargs):
        offloaded.append(getattr(fn, "__name__", repr(fn)))
        return await real(fn, *args, **kwargs)

    monkeypatch.setattr(cloud_connections.anyio.to_thread, "run_sync", _spy)
    return record, offloaded


def test_test_connection_offloads_broker(monkeypatch, wired):
    record, offloaded = wired
    monkeypatch.setattr(cloud_connections, "_test_connection_broker", lambda record: None)

    result = asyncio.run(cloud_connections.test_connection(request=object(), connection_id="conn-1"))

    assert len(offloaded) == 1, f"test_connection must offload the broker call exactly once; saw {offloaded}"
    assert result["status"] == "ok"
    assert result["connection_id"] == "conn-1"


def test_scan_connection_offloads_scan(monkeypatch, wired):
    record, offloaded = wired
    monkeypatch.setattr(
        cloud_connections,
        "_run_connection_scan",
        lambda record, tenant_id: {"scan_id": "s-1", "status": "completed"},
    )

    result = asyncio.run(cloud_connections.scan_connection(request=object(), connection_id="conn-1"))

    assert len(offloaded) == 1, f"scan_connection must offload the scan exactly once; saw {offloaded}"
    assert result["scan_id"] == "s-1"
    assert result["connection"] == record.to_public_dict()


def test_test_connection_failure_still_502_and_marks_error(monkeypatch, wired):
    record, offloaded = wired
    marks: list[dict] = []
    monkeypatch.setattr(cloud_connections, "_mark_connection", lambda record, **kwargs: marks.append(kwargs))

    def _boom(record):
        raise RuntimeError("broker down")

    monkeypatch.setattr(cloud_connections, "_test_connection_broker", _boom)

    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(cloud_connections.test_connection(request=object(), connection_id="conn-1"))

    assert exc_info.value.status_code == 502
    assert len(offloaded) == 1, "the failing broker call must still run off-loop"
    assert marks and marks[0]["status"] == cloud_connections.STATUS_ERROR


def test_scan_connection_backpressure_shed_is_429_not_error(monkeypatch, wired):
    record, offloaded = wired
    marks: list[dict] = []
    monkeypatch.setattr(cloud_connections, "_mark_connection", lambda record, **kwargs: marks.append(kwargs))

    @contextlib.asynccontextmanager
    async def _shedding(path):
        raise BackpressureRejectedError(path, "concurrency limit", 7)
        yield  # pragma: no cover

    monkeypatch.setattr(cloud_connections, "adaptive_backpressure", _shedding)

    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(cloud_connections.scan_connection(request=object(), connection_id="conn-1"))

    assert exc_info.value.status_code == 429
    assert (exc_info.value.headers or {}).get("Retry-After") == "7"
    assert offloaded == [], "a shed request must never reach the broker"
    assert marks == [], "a shed request must not flip the connection to error"


def test_create_connection_scan_on_create_uses_backpressure(monkeypatch):
    """auto_scan_on_create must share the cloud_connection_scan backpressure lane."""
    from agent_bom.api.connection_store import InMemoryConnectionStore, set_connection_store
    from agent_bom.api.routes.cloud_connections import CloudConnectionCreate

    store = InMemoryConnectionStore()
    set_connection_store(store)
    monkeypatch.setattr(cloud_connections, "connections_key_configured", lambda: True)
    monkeypatch.setattr(cloud_connections, "encrypt_secret", lambda value: f"enc:{value}")
    monkeypatch.setattr(cloud_connections, "log_action", lambda *a, **k: None)
    monkeypatch.setattr(cloud_connections, "_actor", lambda request: "tester")
    monkeypatch.setattr(cloud_connections, "_tenant", lambda request: "tenant-bp")
    monkeypatch.setattr(
        cloud_connections,
        "_run_connection_scan",
        lambda record, tenant_id: {"scan_id": "s-create", "status": "completed"},
    )

    paths: list[str] = []

    @contextlib.asynccontextmanager
    async def _track(path):
        paths.append(path)
        yield

    monkeypatch.setattr(cloud_connections, "adaptive_backpressure", _track)

    body = CloudConnectionCreate(
        provider="aws",
        display_name="bp-conn",
        role_ref="arn:aws:iam::123456789012:role/agent-bom-readonly",
        external_id="ext-secret",
        regions=["us-east-1"],
        auto_scan_on_create=True,
    )
    result = asyncio.run(cloud_connections.create_connection(request=object(), body=body))

    assert paths == ["cloud_connection_scan"]
    assert result["status"] == "active"
    assert result["last_scan_id"] == "s-create"
    fetched = store.get("tenant-bp", result["id"])
    assert fetched is not None
    assert fetched.status == "active"


def test_create_connection_scan_on_create_backpressure_shed_is_429(monkeypatch):
    """Shed on create leaves the row pending and returns 429 (retry via POST …/scan)."""
    from fastapi import HTTPException

    from agent_bom.api.connection_store import InMemoryConnectionStore, set_connection_store
    from agent_bom.api.routes.cloud_connections import CloudConnectionCreate

    store = InMemoryConnectionStore()
    set_connection_store(store)
    monkeypatch.setattr(cloud_connections, "connections_key_configured", lambda: True)
    monkeypatch.setattr(cloud_connections, "encrypt_secret", lambda value: f"enc:{value}")
    monkeypatch.setattr(cloud_connections, "log_action", lambda *a, **k: None)
    monkeypatch.setattr(cloud_connections, "_actor", lambda request: "tester")
    monkeypatch.setattr(cloud_connections, "_tenant", lambda request: "tenant-bp")

    scanned: list[str] = []
    monkeypatch.setattr(
        cloud_connections,
        "_run_connection_scan",
        lambda record, tenant_id: scanned.append(record.id) or {"scan_id": "x"},
    )

    @contextlib.asynccontextmanager
    async def _shedding(path):
        raise BackpressureRejectedError(path, "concurrency limit", 5)
        yield  # pragma: no cover

    monkeypatch.setattr(cloud_connections, "adaptive_backpressure", _shedding)

    body = CloudConnectionCreate(
        provider="aws",
        display_name="bp-shed",
        role_ref="arn:aws:iam::123456789012:role/agent-bom-readonly",
        external_id="ext-secret",
        regions=["us-east-1"],
        auto_scan_on_create=True,
    )
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(cloud_connections.create_connection(request=object(), body=body))

    assert exc_info.value.status_code == 429
    assert (exc_info.value.headers or {}).get("Retry-After") == "5"
    assert scanned == []
    rows = store.list_for_tenant("tenant-bp")
    assert len(rows) == 1
    assert rows[0].status == "pending"


@pytest.mark.asyncio
async def test_slow_connection_test_keeps_event_loop_responsive(monkeypatch, wired):
    """A hung broker endpoint must not pin the loop — the offload proves it."""
    record, offloaded = wired
    block_seconds = 0.5

    def _slow_broker(record):
        time.sleep(block_seconds)

    monkeypatch.setattr(cloud_connections, "_test_connection_broker", _slow_broker)

    loop = asyncio.get_running_loop()
    test_task = asyncio.create_task(cloud_connections.test_connection(request=object(), connection_id="conn-1"))
    await asyncio.sleep(0.05)  # let the offload hand the blocking body to a worker thread
    assert not test_task.done(), "connection test should still be in flight"

    started = loop.time()
    assert await asyncio.wait_for(_trivial(), timeout=0.15) == "responsive"
    assert loop.time() - started < block_seconds / 2, "event loop was blocked during the broker test — offload ineffective"

    result = await test_task
    assert result["status"] == "ok"


async def _trivial() -> str:
    return "responsive"
