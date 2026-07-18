"""Governance / Cortex REST handlers must offload their blocking Snowflake work.

Every handler in ``routes/governance.py`` mines Snowflake ACCESS_HISTORY /
QUERY_HISTORY / usage history synchronously. Run directly on the event loop
those blocking calls freeze ``/health`` and every unrelated request for the
whole mining run. They now funnel the synchronous body through
``anyio.to_thread.run_sync`` under an adaptive-backpressure guard, preserving the
exact return payloads and error semantics.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import anyio.to_thread
import pytest

from agent_bom.api.routes import governance


@pytest.fixture()
def offload_spy(monkeypatch):
    real = anyio.to_thread.run_sync
    offloaded: list[object] = []

    async def _spy(fn, /, *args, **kwargs):
        offloaded.append(fn)
        return await real(fn, *args, **kwargs)

    monkeypatch.setattr(governance.anyio.to_thread, "run_sync", _spy)
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acct-test")
    return offloaded


def test_governance_report_offloads(monkeypatch, offload_spy):
    report = SimpleNamespace(to_dict=lambda: {"report": "ok"})
    monkeypatch.setattr("agent_bom.cloud.discover_governance", lambda **kw: report)

    result = asyncio.run(governance.governance_report(days=30))

    assert result == {"report": "ok"}
    assert offload_spy, "governance_report must offload its Snowflake mining"


def test_governance_findings_offloads(monkeypatch, offload_spy):
    report = SimpleNamespace(findings=[], warnings=[])
    monkeypatch.setattr("agent_bom.cloud.discover_governance", lambda **kw: report)

    result = asyncio.run(governance.governance_findings(days=30))

    assert result["total"] == 0
    assert offload_spy, "governance_findings must offload its Snowflake mining"


def test_activity_timeline_offloads(monkeypatch, offload_spy):
    timeline = SimpleNamespace(to_dict=lambda: {"events": []})
    monkeypatch.setattr("agent_bom.cloud.discover_activity", lambda **kw: timeline)

    result = asyncio.run(governance.activity_timeline(days=30))

    assert result == {"events": []}
    assert offload_spy, "activity_timeline must offload its Snowflake mining"


def test_cortex_telemetry_offloads(monkeypatch, offload_spy):
    conn = SimpleNamespace(close=lambda: None)
    monkeypatch.setattr("agent_bom.cloud.snowflake._get_connection", lambda: conn)
    monkeypatch.setattr(
        "agent_bom.cloud.snowflake_observability.get_cortex_telemetry",
        lambda c, **kw: {"agents": []},
    )

    result = asyncio.run(governance.cortex_telemetry(hours=24))

    assert result == {"agents": []}
    assert offload_spy, "cortex_telemetry must offload its Snowflake mining"


def test_cortex_agent_telemetry_offloads(monkeypatch, offload_spy):
    conn = SimpleNamespace(close=lambda: None)
    monkeypatch.setattr("agent_bom.cloud.snowflake._get_connection", lambda: conn)
    monkeypatch.setattr(
        "agent_bom.cloud.snowflake_observability.get_cortex_telemetry",
        lambda c, **kw: {"agent": kw.get("agent_name")},
    )

    result = asyncio.run(governance.cortex_agent_telemetry(name="acme", hours=24))

    assert result == {"agent": "acme"}
    assert offload_spy, "cortex_agent_telemetry must offload its Snowflake mining"


def test_cortex_health_offloads(monkeypatch, offload_spy):
    conn = SimpleNamespace(close=lambda: None)
    monkeypatch.setattr("agent_bom.cloud.snowflake._get_connection", lambda: conn)
    monkeypatch.setattr(
        "agent_bom.cloud.snowflake._mine_cortex_agent_usage",
        lambda c, days=1: ([], []),
    )
    monkeypatch.setattr(
        "agent_bom.cloud.snowflake_observability.aggregate_agent_metrics",
        lambda records, hours=24: [],
    )
    monkeypatch.setattr(
        "agent_bom.cloud.snowflake_observability.assess_agent_health",
        lambda m: m,
    )

    result = asyncio.run(governance.cortex_health())

    assert result == {"agents": [], "warnings": []}
    assert offload_spy, "cortex_health must offload its Snowflake mining"


def test_governance_report_missing_account_stays_on_loop(monkeypatch, offload_spy):
    """Env-var validation is a clean 400 on the loop, never reaching the offload."""
    monkeypatch.delenv("SNOWFLAKE_ACCOUNT", raising=False)
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(governance.governance_report(days=30))
    assert exc_info.value.status_code == 400
    assert offload_spy == [], "validation errors must not offload"
