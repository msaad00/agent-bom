"""Cross-surface honesty contracts for the three source-analysis lanes."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.mcp_server_metadata import build_server_card
from agent_bom.mcp_tools.scanning import code_scan_impl
from agent_bom.sast import SASTExecutionStatus, SASTScanError
from agent_bom.scanners.registry import list_registered_scanners


def test_cli_help_distinguishes_native_semgrep_and_external_sarif_lanes() -> None:
    runner = CliRunner()

    native = runner.invoke(main, ["code", "--help"])
    scan = runner.invoke(main, ["scan", "--help-all"])

    assert native.exit_code == 0, native.output
    assert "native AST" in native.output
    assert "AI-component" in native.output
    assert "does not execute Semgrep" in native.output

    assert scan.exit_code == 0, scan.output
    assert "--code PATH" in scan.output
    assert "Execute Semgrep" in scan.output
    assert "--external-scan" in scan.output
    assert "tool-agnostic" in scan.output
    assert "SARIF" in scan.output


def test_scanner_registry_keeps_three_distinct_driver_contracts() -> None:
    drivers = {driver.name: driver for driver in list_registered_scanners()}

    assert drivers["code-native"].capabilities.network_access is False
    assert drivers["code-native"].input_types == ("code_path",)
    assert drivers["sast-semgrep"].capabilities.network_access is True
    assert "sarif" in drivers["sast-semgrep"].input_types  # compatibility input remains supported
    assert drivers["external-scan-ingest"].capabilities.network_access is False
    assert "sarif" in drivers["external-scan-ingest"].input_types
    assert "semgrep" not in drivers["external-scan-ingest"].summary.lower()


def test_mcp_catalog_distinguishes_semgrep_execution_from_generic_sarif_ingest() -> None:
    tools = {tool["name"]: tool for tool in build_server_card()["tools"]}

    assert "Execute Semgrep" in tools["code_scan"]["description"]
    assert "findings, clean, skipped, or failed" in tools["code_scan"]["description"]
    assert "tool-agnostic SARIF" in tools["ingest_external_scan"]["description"]
    assert "Semgrep SARIF" not in tools["ingest_external_scan"]["description"]


def test_mcp_code_scan_returns_typed_sanitized_skip(monkeypatch, tmp_path: Path) -> None:
    secret = "token=do-not-return"

    def skip(*_args, **_kwargs):
        raise SASTScanError(
            f"semgrep unavailable: {secret}",
            execution_status=SASTExecutionStatus.SKIPPED,
            reason_code="semgrep_unavailable",
        )

    monkeypatch.setattr("agent_bom.sast.scan_code", skip)
    payload = asyncio.run(
        code_scan_impl(
            path=str(tmp_path),
            _safe_path=Path,
            _truncate_response=lambda value: value,
        )
    )
    result = json.loads(payload)

    assert result["scanner_driver_id"] == "sast-semgrep"
    assert result["execution_status"] == "skipped"
    assert result["status_reason"] == "semgrep_unavailable"
    assert secret not in json.dumps(result)


def test_mcp_code_scan_returns_typed_sanitized_failure(monkeypatch, tmp_path: Path) -> None:
    secret = "connection=do-not-return"

    def fail(*_args, **_kwargs):
        raise RuntimeError(secret)

    monkeypatch.setattr("agent_bom.sast.scan_code", fail)
    payload = asyncio.run(
        code_scan_impl(
            path=str(tmp_path),
            _safe_path=Path,
            _truncate_response=lambda value: value,
        )
    )
    result = json.loads(payload)

    assert result["execution_status"] == "failed"
    assert result["status_reason"] == "unexpected_failure"
    assert result["status_detail"] == "SAST execution failed."
    assert secret not in json.dumps(result)
