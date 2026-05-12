"""Regression tests for remaining CLI P1 audit polish."""

from __future__ import annotations

import json

from click.testing import CliRunner

from agent_bom.cli import main


def test_did_you_mean_top_level_typo() -> None:
    result = CliRunner().invoke(main, ["scna"])
    assert result.exit_code == 2
    assert "Did you mean 'scan'" in result.output


def test_did_you_mean_nested_mcp_typo() -> None:
    result = CliRunner().invoke(main, ["mcp", "scna"])
    assert result.exit_code == 2
    assert "Did you mean 'scan'" in result.output


def test_did_you_mean_nested_profiles_typo() -> None:
    result = CliRunner().invoke(main, ["profiles", "useeee"])
    assert result.exit_code == 2
    assert "Did you mean 'use'" in result.output


def test_scan_inventory_stdin_sentinel_loads_json_payload() -> None:
    payload = '{"agents":[{"name":"stdin-agent","agent_type":"custom","mcp_servers":[]}]}'
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            ["scan", "--inventory", "-", "--no-scan", "-f", "json"],
            input=payload,
        )
        assert result.exit_code == 0, result.output
        with open("agent-bom-report.json", encoding="utf-8") as report_file:
            body = json.load(report_file)
        assert body["agents"][0]["name"] == "stdin-agent"


def test_discovery_banner_deferred_until_after_inventory_validation() -> None:
    result = CliRunner().invoke(main, ["scan", "--inventory", "/tmp/__does_not_exist_agent_bom.json"])
    assert result.exit_code != 0
    assert "Discovery" not in result.output
    assert "Inventory file not found" in result.output


def test_policy_templates_is_deprecated_alias(tmp_path) -> None:
    out = tmp_path / "policy.json"
    result = CliRunner().invoke(main, ["policy", "templates", "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert "deprecated" in result.output.lower()
    assert out.exists()


def test_policy_template_singular_is_canonical(tmp_path) -> None:
    out = tmp_path / "policy.json"
    result = CliRunner().invoke(main, ["policy", "template", "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert "deprecated" not in result.output.lower()
    assert out.exists()


def test_mcp_inventory_format_json_flag_works(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("agent_bom.cli._inventory.discover_all", lambda **_: [])
    result = CliRunner().invoke(main, ["mcp", "inventory", "-f", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert "discovery_completeness" in payload


def test_mcp_inventory_json_alias_emits_deprecation(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("agent_bom.cli._inventory.discover_all", lambda **_: [])
    result = CliRunner().invoke(main, ["mcp", "inventory", "--json"])
    assert result.exit_code == 0, result.output
    assert "deprecated" in result.output.lower()
