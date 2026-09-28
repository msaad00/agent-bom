"""Characterize tenant audit recovery across cancellation and reconstruction."""

import asyncio

import pytest

from agent_bom.gateway_server import build_control_plane_audit_sink


@pytest.mark.asyncio
async def test_cancelled_tenant_delivery_replays_same_batch_after_reconstruction(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    started = asyncio.Event()
    attempts = []

    async def interrupted(payload, headers):
        attempts.append((payload, headers))
        started.set()
        await asyncio.Event().wait()

    first = build_control_plane_audit_sink("https://control.example", "first-credential", tenant_id="tenant-a", sender=interrupted)
    event = {"tenant_id": "tenant-a", "action": "gateway.policy_blocked", "event_id": "decision-one"}
    task = asyncio.create_task(first(event))
    await asyncio.wait_for(started.wait(), timeout=5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await first.aclose()

    async def acknowledge(payload, headers):
        attempts.append((payload, headers))
        return {"accepted_alert_count": len(payload["alerts"]), "durable_accepted_count": len(payload["alerts"])}

    other = build_control_plane_audit_sink("https://control.example", "other-credential", tenant_id="tenant-b", sender=acknowledge)
    assert await other.flush_once()
    assert len(attempts) == 1
    restarted = build_control_plane_audit_sink("https://control.example", "rotated-credential", tenant_id="tenant-a", sender=acknowledge)
    assert await restarted.flush_once()
    assert attempts[0][0] == attempts[1][0]
    assert attempts[1][1]["Authorization"] == "Bearer rotated-credential"
    assert restarted.health()["backlog_bytes"] == 0
    assert await restarted.flush_once()
    assert len(attempts) == 2
    await restarted.aclose()
    await other.aclose()
