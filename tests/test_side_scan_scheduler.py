"""Tests for the CWPP cross-cloud side-scan scheduler auto-trigger (#4158 Stage 4).

The on-demand surfaces (CLI ``cloud side-scan``, ``POST /v1/cloud/side-scan``,
MCP ``cloud_side_scan``, UI ``/cwpp``) all drive the shipped
``run_provider_side_scan`` executor. This module adds the missing periodic
trigger so a configured target keeps evaluating on a cadence without a manual
call — the same "connect once, keeps evaluating" contract the cloud-connection
and findings-export schedulers already ship.

Covered invariants:

* **Opt-in, off by default.** With ``AGENT_BOM_SIDESCAN_SCHEDULER`` unset the
  entrypoint runs nothing — never a surprise cloud write.
* **Enabled iterates every configured target** and calls the executor once per
  target, off the event loop.
* **Honest terminal state** — disabled / unavailable / failed / the durable
  lifecycle status — is surfaced per target; cleanup is reported from the
  executor's result. No false clean.
* **Config parsing** from a JSON file path or inline JSON, fail-soft on
  missing/invalid, provider + required-field validation.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from agent_bom.api.side_scan_scheduler import (
    ScheduledSideScanTarget,
    load_scheduled_targets,
    run_scheduled_side_scan_once,
    schedule_provider_side_scans,
    sidescan_scheduler_enabled,
)

_AZURE_TARGET = ScheduledSideScanTarget(
    provider="azure",
    target_id="/subscriptions/s/disks/disk-1",
    account_id="sub-1",
    location="eastus",
    collector_id="collector-vm",
    tenant_id="tenant-a",
    collector_resource_group="collectors",
)
_GCP_TARGET = ScheduledSideScanTarget(
    provider="gcp",
    target_id="disk-2",
    account_id="proj-1",
    location="us-central1-a",
    collector_id="collector-inst",
    tenant_id="tenant-b",
)


# ── Opt-in gate ─────────────────────────────────────────────────────────────
def test_scheduler_disabled_by_default(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_SIDESCAN_SCHEDULER", raising=False)
    assert sidescan_scheduler_enabled() is False


@pytest.mark.parametrize("value", ["1", "true", "YES", "on", "enabled"])
def test_scheduler_enable_flag_truthy(monkeypatch, value):
    monkeypatch.setenv("AGENT_BOM_SIDESCAN_SCHEDULER", value)
    assert sidescan_scheduler_enabled() is True


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off"])
def test_scheduler_enable_flag_falsy(monkeypatch, value):
    monkeypatch.setenv("AGENT_BOM_SIDESCAN_SCHEDULER", value)
    assert sidescan_scheduler_enabled() is False


def test_schedule_off_runs_nothing(monkeypatch):
    """Opt-in-off: the entrypoint must not touch the executor at all."""
    monkeypatch.delenv("AGENT_BOM_SIDESCAN_SCHEDULER", raising=False)
    called: list[ScheduledSideScanTarget] = []

    def _runner(target: ScheduledSideScanTarget) -> dict[str, Any]:
        called.append(target)
        return {"status": "scan_complete"}

    outcomes = asyncio.run(schedule_provider_side_scans(targets=[_AZURE_TARGET, _GCP_TARGET], runner=_runner))
    assert outcomes == []
    assert called == []


# ── Enabled: iterate every configured target + call executor ────────────────
def test_schedule_enabled_iterates_all_targets(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_SIDESCAN_SCHEDULER", "1")
    called: list[ScheduledSideScanTarget] = []

    def _runner(target: ScheduledSideScanTarget) -> dict[str, Any]:
        called.append(target)
        return {"status": "scan_complete", "provider": target.provider, "target_id": target.target_id}

    outcomes = asyncio.run(schedule_provider_side_scans(targets=[_AZURE_TARGET, _GCP_TARGET], runner=_runner))
    assert {c.target_id for c in called} == {"/subscriptions/s/disks/disk-1", "disk-2"}
    assert len(outcomes) == 2
    assert {o["provider"] for o in outcomes} == {"azure", "gcp"}


def test_schedule_enabled_loads_targets_from_config_when_none_passed(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_BOM_SIDESCAN_SCHEDULER", "1")
    targets_file = tmp_path / "targets.json"
    targets_file.write_text(
        json.dumps(
            [
                {
                    "provider": "gcp",
                    "target_id": "disk-9",
                    "account_id": "proj-9",
                    "location": "us-central1-a",
                    "collector_id": "c-9",
                    "tenant_id": "tenant-z",
                }
            ]
        )
    )
    monkeypatch.setenv("AGENT_BOM_SIDESCAN_SCHEDULER_TARGETS", str(targets_file))
    seen: list[str] = []

    def _runner(target: ScheduledSideScanTarget) -> dict[str, Any]:
        seen.append(target.target_id)
        return {"status": "scan_complete"}

    asyncio.run(schedule_provider_side_scans(runner=_runner))
    assert seen == ["disk-9"]


def test_schedule_no_targets_is_noop(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_SIDESCAN_SCHEDULER", "1")
    monkeypatch.delenv("AGENT_BOM_SIDESCAN_SCHEDULER_TARGETS", raising=False)
    calls: list[Any] = []
    outcomes = asyncio.run(schedule_provider_side_scans(runner=lambda t: calls.append(t) or {"status": "x"}))
    assert outcomes == []
    assert calls == []


def test_one_failing_target_does_not_sink_the_others(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_SIDESCAN_SCHEDULER", "1")

    def _runner(target: ScheduledSideScanTarget) -> dict[str, Any]:
        if target.provider == "azure":
            raise RuntimeError("boom")
        return {"status": "scan_complete", "provider": target.provider}

    outcomes = asyncio.run(schedule_provider_side_scans(targets=[_AZURE_TARGET, _GCP_TARGET], runner=_runner))
    statuses = {o["provider"]: o for o in outcomes if "provider" in o}
    # gcp still ran to completion
    assert statuses["gcp"]["status"] == "scan_complete"
    # azure surfaced as a failed outcome, not a raised exception
    assert any(o.get("status") == "failed" for o in outcomes)


# ── run_scheduled_side_scan_once: maps kwargs, honest states, cleanup ───────
def test_runner_maps_kwargs_and_reports_cleanup(monkeypatch, tmp_path):
    captured: dict[str, Any] = {}

    class _FakeResult:
        cleaned_up = True

    async def _fake_run_provider_side_scan(**kwargs):
        captured.update(kwargs)
        return [_FakeResult()]

    monkeypatch.setattr(
        "agent_bom.cloud.side_scan_targets.run_provider_side_scan",
        _fake_run_provider_side_scan,
    )
    state_db = tmp_path / "state.db"
    outcome = run_scheduled_side_scan_once(_AZURE_TARGET, state_db_path=state_db)

    assert captured["provider"] == "azure"
    assert captured["target_id"] == "/subscriptions/s/disks/disk-1"
    assert captured["account_id"] == "sub-1"
    assert captured["location"] == "eastus"
    assert captured["collector_id"] == "collector-vm"
    assert captured["tenant_id"] == "tenant-a"
    assert captured["collector_resource_group"] == "collectors"
    # idempotency key threaded so the pre-created execution row and the executor
    # row coalesce (retry-safe) and the durable record is readable afterwards.
    assert captured["idempotency_key"]
    assert outcome["provider"] == "azure"
    assert outcome["target_id"] == "/subscriptions/s/disks/disk-1"
    assert outcome["cleaned_up"] is True
    assert outcome["execution_id"]


def test_runner_disabled_executor_reports_disabled(monkeypatch, tmp_path):
    from agent_bom.cloud.side_scan import SideScanDisabledError

    async def _fake(**kwargs):
        raise SideScanDisabledError("off")

    monkeypatch.setattr("agent_bom.cloud.side_scan_targets.run_provider_side_scan", _fake)
    outcome = run_scheduled_side_scan_once(_GCP_TARGET, state_db_path=tmp_path / "s.db")
    assert outcome["status"] == "disabled"
    assert outcome["provider"] == "gcp"


def test_runner_config_error_reports_unavailable(monkeypatch, tmp_path):
    from agent_bom.cloud.side_scan import SideScanConfigError

    async def _fake(**kwargs):
        raise SideScanConfigError("missing sdk")

    monkeypatch.setattr("agent_bom.cloud.side_scan_targets.run_provider_side_scan", _fake)
    outcome = run_scheduled_side_scan_once(_AZURE_TARGET, state_db_path=tmp_path / "s.db")
    assert outcome["status"] == "unavailable"


def test_runner_unexpected_error_reports_failed_not_raised(monkeypatch, tmp_path):
    async def _fake(**kwargs):
        raise RuntimeError("kaboom")

    monkeypatch.setattr("agent_bom.cloud.side_scan_targets.run_provider_side_scan", _fake)
    outcome = run_scheduled_side_scan_once(_GCP_TARGET, state_db_path=tmp_path / "s.db")
    assert outcome["status"] == "failed"


# ── Config loading + validation ─────────────────────────────────────────────
def test_load_targets_unset_is_empty(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_SIDESCAN_SCHEDULER_TARGETS", raising=False)
    assert load_scheduled_targets() == []


def test_load_targets_inline_json(monkeypatch):
    monkeypatch.setenv(
        "AGENT_BOM_SIDESCAN_SCHEDULER_TARGETS",
        json.dumps(
            [
                {
                    "provider": "azure",
                    "target_id": "d1",
                    "account_id": "sub",
                    "location": "eastus",
                    "collector_id": "c",
                    "tenant_id": "t",
                    "collector_resource_group": "rg",
                }
            ]
        ),
    )
    targets = load_scheduled_targets()
    assert len(targets) == 1
    assert targets[0].provider == "azure"
    assert targets[0].collector_resource_group == "rg"


def test_load_targets_from_file_path(monkeypatch, tmp_path):
    path = tmp_path / "t.json"
    path.write_text(
        json.dumps(
            [
                {
                    "provider": "gcp",
                    "target_id": "d1",
                    "account_id": "proj",
                    "location": "us-central1-a",
                    "collector_id": "c",
                    "tenant_id": "t",
                }
            ]
        )
    )
    monkeypatch.setenv("AGENT_BOM_SIDESCAN_SCHEDULER_TARGETS", str(path))
    targets = load_scheduled_targets()
    assert len(targets) == 1 and targets[0].provider == "gcp"


def test_load_targets_invalid_json_is_empty(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_SIDESCAN_SCHEDULER_TARGETS", "{not json")
    assert load_scheduled_targets() == []


def test_load_targets_skips_invalid_provider_and_missing_fields(monkeypatch):
    monkeypatch.setenv(
        "AGENT_BOM_SIDESCAN_SCHEDULER_TARGETS",
        json.dumps(
            [
                {"provider": "aws", "target_id": "x", "account_id": "a", "location": "z", "collector_id": "c", "tenant_id": "t"},
                {"provider": "azure", "target_id": "x", "account_id": "a", "location": "z", "collector_id": "c", "tenant_id": "t"},  # no RG
                {"provider": "gcp", "account_id": "a", "location": "z", "collector_id": "c", "tenant_id": "t"},  # no target_id
                {"provider": "gcp", "target_id": "ok", "account_id": "a", "location": "z", "collector_id": "c", "tenant_id": "t"},
            ]
        ),
    )
    targets = load_scheduled_targets()
    assert [t.target_id for t in targets] == ["ok"]
