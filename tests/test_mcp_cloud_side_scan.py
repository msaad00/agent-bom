"""Tests for the MCP cloud_side_scan tool (#4158 Wave 2).

Headless MCP surface over the shipped cross-cloud ``run_provider_side_scan``
executor. Verifies fail-closed validation, honest disabled/unavailable
envelopes, tenant routing through ``resolve_mcp_tool_tenant_id`` (never a raw
env read), durable-store read-back, and server-card/registration wiring.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from agent_bom.cloud.side_scan_lifecycle import (
    CleanupStatus,
    ExecutionStatus,
    SQLiteSideScanStateStore,
    new_side_scan_execution,
)
from agent_bom.cloud.side_scan_targets import (
    SIDE_SCAN_STATE_DB_ENV,
    CloudSideScanExecutionResult,
    side_scan_state_db_path,
)
from agent_bom.mcp_tools.side_scan import cloud_side_scan_impl


def _truncate(text: str) -> str:
    return text


def _run(**kwargs) -> dict:
    return json.loads(asyncio.run(cloud_side_scan_impl(_truncate_response=_truncate, **kwargs)))


@pytest.fixture()
def state_db(tmp_path, monkeypatch):
    monkeypatch.setenv(SIDE_SCAN_STATE_DB_ENV, str(tmp_path / "side_scan_state.db"))
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "tenant-a")
    return tmp_path


def _valid(**overrides) -> dict:
    base = dict(
        provider="gcp",
        target_id="projects/proj/zones/us-central1-a/disks/os",
        account_id="proj",
        location="us-central1-a",
        collector_id="collector-vm",
    )
    base.update(overrides)
    return base


def test_rejects_unsupported_provider(state_db) -> None:
    result = _run(**_valid(provider="aws"))
    assert result["status"] == "rejected"
    assert "azure" in result["error"] and "gcp" in result["error"]


def test_rejects_missing_arguments(state_db) -> None:
    result = _run(provider="gcp", target_id="", account_id="", location="", collector_id="")
    assert result["status"] == "rejected"
    assert "target_id" in result["error"]


def test_azure_requires_collector_resource_group(state_db) -> None:
    result = _run(
        provider="azure",
        target_id="/subscriptions/S/resourceGroups/RG/providers/Microsoft.Compute/disks/os",
        account_id="S",
        location="eastus",
        collector_id="collector-vm",
    )
    assert result["status"] == "rejected"
    assert "collector_resource_group" in result["error"]


def test_disabled_returns_honest_envelope(state_db, monkeypatch) -> None:
    from agent_bom.cloud.side_scan import SideScanDisabledError

    async def _raise(**kwargs):
        raise SideScanDisabledError("Disk side-scan is opt-in and currently OFF.")

    # The impl imports run_provider_side_scan lazily from the targets module.
    import agent_bom.cloud.side_scan_targets as targets

    monkeypatch.setattr(targets, "run_provider_side_scan", _raise)
    result = _run(**_valid())
    assert result["status"] == "disabled"
    assert "evidence" not in result
    assert "AGENT_BOM_SIDESCAN" in result["enable"]


def test_unavailable_on_config_error(state_db, monkeypatch) -> None:
    from agent_bom.cloud.side_scan import SideScanConfigError

    async def _raise(**kwargs):
        raise SideScanConfigError("GCP Persistent Disk side-scan requires the gcp extra.")

    import agent_bom.cloud.side_scan_targets as targets

    monkeypatch.setattr(targets, "run_provider_side_scan", _raise)
    result = _run(**_valid())
    assert result["status"] == "unavailable"
    assert "gcp extra" in result["reason"]


def test_success_reads_durable_record(state_db, monkeypatch) -> None:
    async def _fake(**kwargs):
        store = SQLiteSideScanStateStore(side_scan_state_db_path())
        record = store.create_or_get(
            new_side_scan_execution(
                tenant_id=kwargs["tenant_id"],
                provider=kwargs["provider"],
                account_id=kwargs["account_id"],
                target_id=kwargs["target_id"],
                collector_id=kwargs["collector_id"],
                idempotency_key=kwargs["idempotency_key"],
            )
        )
        running = record.transition(status=ExecutionStatus.RUNNING, phase="scanning")
        store.save(running, expected_version=record.state_version)
        done = running.transition(
            status=ExecutionStatus.SCAN_COMPLETE,
            phase="finished",
            cleanup_status=CleanupStatus.COMPLETE,
            vulnerability_count=2,
        )
        store.save(done, expected_version=running.state_version)
        return [
            CloudSideScanExecutionResult(
                provider=kwargs["provider"],
                target_type="persistent_disk",
                target_id=kwargs["target_id"],
                account_id=kwargs["account_id"],
                location=kwargs["location"],
                vulnerability_count=2,
                cleaned_up=True,
            )
        ]

    import agent_bom.cloud.side_scan_targets as targets

    monkeypatch.setattr(targets, "run_provider_side_scan", _fake)
    result = _run(**_valid())
    assert result["status"] == "scan_complete"
    assert result["tenant_id"] == "tenant-a"  # routed via resolve_mcp_tool_tenant_id
    assert result["evidence"]["clean_workload_assertion"] is False
    assert result["execution"]["counts"]["vulnerability_count"] == 2


def test_advertised_on_server_card_and_registered() -> None:
    from agent_bom.mcp_server_metadata import (
        _TOOL_CAPABILITY_CLASSES,
        registered_mcp_tool_decorator_names,
        server_card_tool_names,
    )

    assert "cloud_side_scan" in server_card_tool_names()
    assert "cloud_side_scan" in registered_mcp_tool_decorator_names()
    assert "cloud_side_scan" in _TOOL_CAPABILITY_CLASSES
