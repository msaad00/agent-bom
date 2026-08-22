"""CLI, MCP, and REST expose one canonical package-check contract."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.models import Package


def _malicious_scan(packages: list[Package], **_kwargs):
    for package in packages:
        package.is_malicious = True
        package.malicious_reason = "Dependency confusion risk"


def test_cli_and_mcp_share_canonical_malicious_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    async def malicious_scan(packages: list[Package], **kwargs):
        _malicious_scan(packages, **kwargs)

    monkeypatch.setattr("agent_bom.scanners.scan_packages", malicious_scan)
    cli = CliRunner().invoke(
        main,
        ["check", "internal-lib@1.0.0", "--ecosystem", "pypi", "--offline", "--format", "json"],
    )
    assert cli.exit_code == 1, cli.output
    cli_payload = json.loads(cli.output)

    from agent_bom.mcp_tools.scanning import check_impl

    mcp_payload = json.loads(
        asyncio.run(
            check_impl(
                package="internal-lib@1.0.0",
                ecosystem="pypi",
                offline=True,
                _validate_ecosystem=lambda ecosystem: ecosystem,
                _truncate_response=lambda response: response,
            )
        )
    )

    for field in (
        "canonical_verdict",
        "package_canonical_id",
        "lookup_mode",
        "is_malicious",
        "malicious_reason",
        "vulnerability_count",
        "vulnerability_details",
    ):
        assert cli_payload[field] == mcp_payload[field]


@pytest.mark.asyncio
async def test_rest_threads_offline_mode_into_shared_check(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api.routes.scan import PackageCheckRequest, check_package
    from agent_bom.mcp_tools import scanning

    expected = {
        "canonical_verdict": "clean",
        "package_canonical_id": "package-id",
        "lookup_mode": "offline",
        "is_malicious": False,
        "vulnerability_count": 0,
        "vulnerability_details": [],
        "status": "clean",
    }
    implementation = AsyncMock(return_value=json.dumps(expected))
    monkeypatch.setattr(scanning, "check_impl", implementation)

    payload = await check_package(
        PackageCheckRequest(package="six", version="1.16.0", ecosystem="pypi", offline=True)
    )

    assert payload == expected
    assert implementation.await_args.kwargs["offline"] is True
