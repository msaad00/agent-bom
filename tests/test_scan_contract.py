"""Shared scan option contract tests."""

from __future__ import annotations

from agent_bom.api.models import ScanRequest
from agent_bom.scan_contract import ScanConfig, scan_config_from_api_request


def test_scan_config_to_api_payload_uses_supported_fields_only() -> None:
    config = ScanConfig(
        project=".",
        demo=True,
        offline=True,
        enrich=True,
        compliance=True,
        resolve_transitive=True,
        max_depth=7,
        blast_radius_depth=4,
        quiet=True,
    )

    assert config.to_api_payload() == {
        "agent_projects": ["."],
        "offline": True,
        "enrich": True,
    }


def test_scan_config_from_api_request_maps_overlap() -> None:
    request = ScanRequest(agent_projects=["/repo"], offline=True, enrich=True, images=["example:latest"])

    config = scan_config_from_api_request(request, quiet=True)

    assert config.project == "/repo"
    assert config.offline is True
    assert config.enrich is True
    assert config.quiet is True
    assert config.demo is False
    assert config.compliance is False


def test_cli_scan_runner_reexports_shared_scan_config() -> None:
    from agent_bom.cli._scan_runner import ScanConfig as RunnerScanConfig

    assert RunnerScanConfig is ScanConfig
