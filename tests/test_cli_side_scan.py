"""Tests for the ``agent-bom cloud side-scan`` CLI command.

The side-scan engine (:mod:`agent_bom.cloud.side_scan`) was fully built and
unit-tested but had no CLI caller, so it was unreachable. These tests pin the
new command's plumbing:

- the command invokes ``run_side_scan`` with the option values mapped to kwargs,
- results render in a Rich table (metadata only — secret type/location, never
  values),
- a disabled opt-in flag surfaces the actionable message and exits non-zero
  (never a raw traceback).

``run_side_scan`` is monkeypatched throughout — no real AWS, no asyncio plumbing
under test beyond the command's own ``asyncio.run`` call.
"""

from __future__ import annotations

from click.testing import CliRunner

import agent_bom.cli._cloud_group as cg
from agent_bom.cloud.side_scan import (
    SideScanDisabledError,
    SideScanResult,
    SideScanSecret,
)


def test_side_scan_invokes_run_side_scan_with_mapped_kwargs(monkeypatch):
    captured: dict = {}

    async def fake_run_side_scan(**kwargs):
        captured.update(kwargs)
        return [
            SideScanResult(
                instance_id="i-target",
                volume_id="vol-target",
                snapshot_id="snap-1",
                vulnerability_count=2,
                cleaned_up=True,
            )
        ]

    monkeypatch.setattr("agent_bom.cloud.side_scan.run_side_scan", fake_run_side_scan)

    result = CliRunner().invoke(
        cg.side_scan_cmd,
        [
            "--volume-id",
            "vol-target",
            "--instance-id",
            "i-target",
            "--collector-instance-id",
            "i-collector",
            "--availability-zone",
            "us-east-1a",
            "--region",
            "us-east-1",
            "--no-secrets",
            "--no-sweep-orphans",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["volume_id"] == "vol-target"
    assert captured["instance_id"] == "i-target"
    assert captured["collector_instance_id"] == "i-collector"
    assert captured["availability_zone"] == "us-east-1a"
    assert captured["region"] == "us-east-1"
    # --no-secrets -> scan_secrets_enabled=False; --no-sweep-orphans -> sweep_orphans=False
    assert captured["scan_secrets_enabled"] is False
    assert captured["sweep_orphans"] is False
    # Summary table rendered the volume + cleanup status.
    assert "vol-target" in result.output
    assert "snap-1" in result.output


def test_side_scan_defaults_enable_secrets_and_sweep(monkeypatch):
    captured: dict = {}

    async def fake_run_side_scan(**kwargs):
        captured.update(kwargs)
        return []

    monkeypatch.setattr("agent_bom.cloud.side_scan.run_side_scan", fake_run_side_scan)

    result = CliRunner().invoke(cg.side_scan_cmd, ["--volume-id", "vol-x"])
    assert result.exit_code == 0, result.output
    assert captured["scan_secrets_enabled"] is True
    assert captured["sweep_orphans"] is True
    # No targets -> a clear, non-crashing note.
    assert "No target volumes resolved" in result.output


def test_side_scan_renders_redacted_secrets_only(monkeypatch):
    async def fake_run_side_scan(**kwargs):
        return [
            SideScanResult(
                volume_id="vol-target",
                snapshot_id="snap-1",
                secrets=[
                    SideScanSecret(
                        secret_type="aws_access_key",
                        file_path="/app/app.env",
                        line_number=1,
                        severity="high",
                        category="cloud",
                    )
                ],
                cleaned_up=True,
            )
        ]

    monkeypatch.setattr("agent_bom.cloud.side_scan.run_side_scan", fake_run_side_scan)
    result = CliRunner().invoke(cg.side_scan_cmd, ["--volume-id", "vol-target"])
    assert result.exit_code == 0, result.output
    assert "aws_access_key" in result.output
    assert "/app/app.env" in result.output


def test_side_scan_disabled_flag_exits_nonzero_with_actionable_message(monkeypatch):
    async def fake_run_side_scan(**kwargs):
        raise SideScanDisabledError(
            "Disk side-scan is opt-in and currently OFF. To enable it, set AGENT_BOM_SIDESCAN=1, "
            "apply the scoped snapshot role, and provide an in-account collector instance."
        )

    monkeypatch.setattr("agent_bom.cloud.side_scan.run_side_scan", fake_run_side_scan)
    result = CliRunner().invoke(cg.side_scan_cmd, ["--volume-id", "vol-x"])

    assert result.exit_code != 0
    assert "AGENT_BOM_SIDESCAN" in result.output
    assert "opt-in" in result.output.lower()
    # Never a raw traceback.
    assert "Traceback" not in result.output


def test_side_scan_command_registered_on_group():
    assert "side-scan" in cg.cloud_group.commands
