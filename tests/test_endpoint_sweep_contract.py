from __future__ import annotations

import json
from unittest.mock import patch

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.evidence.scan_run import ScanOutcome, ScanRun, ScanScope, ScanScopeStatus


def test_requested_incomplete_scope_downgrades_scan_and_serializes_reason() -> None:
    run = ScanRun(
        scopes=[
            ScanScope(name="agents_mcp", status=ScanScopeStatus.COMPLETE, item_count=0),
            ScanScope(
                name="os_packages",
                status=ScanScopeStatus.UNSUPPORTED,
                message="Host package inventory is not implemented for this platform.",
            ),
        ]
    )

    assert run.outcome is ScanOutcome.PARTIAL
    assert run.to_dict()["requested_scope_count"] == 2
    assert run.to_dict()["complete_scope_count"] == 1
    assert run.to_dict()["incomplete_scope_count"] == 1
    assert run.to_dict()["scopes"] == [
        {
            "name": "agents_mcp",
            "status": "complete",
            "requested": True,
            "item_count": 0,
            "message": "",
        },
        {
            "name": "os_packages",
            "status": "unsupported",
            "requested": True,
            "item_count": None,
            "message": "Host package inventory is not implemented for this platform.",
        },
    ]


def test_unrequested_skipped_scope_does_not_downgrade_complete_scan() -> None:
    run = ScanRun(scopes=[ScanScope(name="mcp_containers", status="skipped", requested=False)])

    assert run.outcome is ScanOutcome.COMPLETE


def test_workstation_preset_on_macos_reports_unsupported_package_scope(tmp_path) -> None:
    output = tmp_path / "workstation.json"

    with (
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.endpoint.scope.platform.system", return_value="Darwin"),
        patch("agent_bom.parsers.browser_extensions.discover_browser_extensions", return_value=[]),
    ):
        result = CliRunner().invoke(
            main,
            [
                "scan",
                "--preset",
                "workstation",
                "--no-scan",
                "--offline",
                "--format",
                "json",
                "--output",
                str(output),
            ],
        )

    assert result.exit_code == 1, result.output
    payload = json.loads(output.read_text())
    scopes = {scope["name"]: scope for scope in payload["scan_run"]["scopes"]}
    assert payload["scan_run"]["outcome"] == "partial"
    assert scopes["agents_mcp"]["status"] == "complete"
    assert scopes["browser_extensions"]["status"] == "complete"
    assert scopes["os_packages"]["status"] == "unsupported"
    assert scopes["context_graph"]["status"] == "complete"
    assert "mcp_processes" in scopes
    assert "mcp_containers" in scopes
    assert "processes" not in scopes
    assert "containers" not in scopes
    assert "not implemented for macOS" in scopes["os_packages"]["message"]


def test_workstation_is_a_documented_scan_preset() -> None:
    result = CliRunner().invoke(main, ["scan", "--help"])

    assert result.exit_code == 0
    assert "workstation" in result.output


def test_workstation_project_scan_also_collects_ambient_endpoint_surfaces(tmp_path) -> None:
    output = tmp_path / "workstation.json"
    project = tmp_path / "project"
    project.mkdir()

    with (
        patch("agent_bom.cli.agents.discover_all", side_effect=[[], []]) as discover,
        patch("agent_bom.endpoint.scope.platform.system", return_value="Darwin"),
        patch("agent_bom.parsers.browser_extensions.discover_browser_extensions", return_value=[]),
    ):
        result = CliRunner().invoke(
            main,
            [
                "scan",
                str(project),
                "--preset",
                "workstation",
                "--no-scan",
                "--offline",
                "--format",
                "json",
                "--output",
                str(output),
            ],
        )

    assert result.exit_code == 1, result.output
    assert discover.call_count == 2
    assert discover.call_args_list[0].kwargs["project_dir"] == str(project)
    assert discover.call_args_list[1].kwargs["project_dir"] is None
    assert discover.call_args_list[1].kwargs["include_processes"] is True
    assert discover.call_args_list[1].kwargs["include_containers"] is True


def test_push_normalization_preserves_scope_truth_and_derives_partial() -> None:
    from agent_bom.api.models import PushPayload
    from agent_bom.api.routes.observability import _normalize_pushed_report

    payload = PushPayload.model_validate(
        {
            "source_id": "endpoint-1",
            "scan_run": {
                "outcome": "complete",
                "scopes": [
                    {"name": "agents_mcp", "status": "complete", "item_count": 2},
                    {
                        "name": "os_packages",
                        "status": "unsupported",
                        "message": "Host package inventory is unavailable.",
                    },
                ],
            },
        }
    )

    normalized = _normalize_pushed_report(payload, fallback_scan_id="scan-1")

    assert normalized["scan_run"]["outcome"] == "partial"
    assert normalized["scan_run"]["scopes"][1] == {
        "name": "os_packages",
        "status": "unsupported",
        "requested": True,
        "item_count": None,
        "message": "Host package inventory is unavailable.",
    }
