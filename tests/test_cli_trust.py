"""Tests for the operator trust boundary CLI."""

from __future__ import annotations

import json

from click.testing import CliRunner

from agent_bom.cli import main


def test_trust_command_outputs_json_contract() -> None:
    result = CliRunner().invoke(main, ["trust", "--format", "json"])

    assert result.exit_code == 0
    body = json.loads(result.output)
    assert body["default_posture"]["hidden_telemetry"] is False
    assert body["default_posture"]["mandatory_hosted_control_plane"] is False
    assert body["credential_evidence"]["stores_matched_value"] is False
    assert body["credential_evidence"]["stores_matched_prefix"] is False
    assert "attack_path" in body["redacted_evidence_context"]["allowed_context"]
    assert "raw_response_body" in body["redacted_evidence_context"]["never_show"]
    assert body["network_boundaries"]["telemetry"] == "none"
    assert body["storage_boundaries"]["secret_values"] == "never_stored"
    assert body["auth_boundaries"]["scim"]["payload_tenant_attributes_ignored"] is True
    assert body["extension_boundaries"]["connectors"]["default_posture"] == "agentless_read_only"
    assert body["extension_boundaries"]["plugins_and_skills"]["default_posture"] == "disabled_until_scoped_by_operator"
    assert {mode["mode"] for mode in body["modes"]} >= {
        "local_discovery",
        "project_scan",
        "cloud_inventory",
        "endpoint_fleet",
        "api_ui_control_plane",
        "proxy_gateway",
    }


def test_trust_command_console_summarizes_operator_controls() -> None:
    result = CliRunner().invoke(main, ["trust"])

    assert result.exit_code == 0
    assert "Data access boundaries" in result.output
    assert "credential values stored: False" in result.output
    assert "Network Boundaries" in result.output
    assert "telemetry: none" in result.output
    assert "Storage Boundaries" in result.output
    assert "secret_values: never_stored" in result.output
    assert "Auth Boundaries" in result.output
    assert "payload_tenant_attributes_ignored=True" in result.output
    assert "Extension Boundaries" in result.output
    assert "default_posture=agentless_read_only" in result.output
    assert "disable_vulnerability_network: --offline" in result.output
