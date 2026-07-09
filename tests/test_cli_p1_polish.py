"""Regression tests for remaining CLI P1 audit polish."""

from __future__ import annotations

import json
from pathlib import Path

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
        body = json.loads(result.stdout)
        assert body["agents"][0]["name"] == "stdin-agent"
        assert not (Path("agent-bom-report.json")).exists()


def test_agents_json_output_path_is_honored() -> None:
    payload = '{"agents":[{"name":"file-agent","agent_type":"custom","mcp_servers":[]}]}'
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            ["agents", "--inventory", "-", "--no-scan", "-f", "json", "-o", "requested.json"],
            input=payload,
        )
        assert result.exit_code == 0, result.output
        assert result.stdout == ""
        assert Path("requested.json").exists()
        assert not Path("agent-bom-report.json").exists()
        body = json.loads(Path("requested.json").read_text())
        assert body["agents"][0]["name"] == "file-agent"


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


def test_mcp_inventory_demo_shows_bundled_inventory() -> None:
    """`mcp inventory --demo` is a working alias for the bundled demo inventory.

    Previously this errored with "No such option '--demo'"; now it loads the
    same DEMO_INVENTORY as `agent-bom agents --demo`.
    """
    result = CliRunner().invoke(main, ["mcp", "inventory", "--demo", "-f", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    names = {a["name"] for a in payload.get("agents", [])}
    assert {"cursor", "claude-desktop"} <= names


def test_check_no_version_warns_loudly_on_stderr() -> None:
    """A version-less `check` must surface a loud NOT-scanned warning, not a
    silent skip on stdout that reads like a clean result."""
    result = CliRunner().invoke(main, ["check", "requests"])
    assert result.exit_code == 2
    # Click 8.2+ captures stderr separately; the warning must be there.
    assert result.stdout == ""
    assert "WARNING" in result.stderr
    assert "NOT scanned" in result.stderr


def test_resolve_output_path_accepts_short_form_extensions(capsys) -> None:
    """`--format cyclonedx -o x.cdx` (and `.spdx`) auto-completes to the
    canonical multi-part suffix instead of hard-erroring."""
    from agent_bom.cli.agents._output import _resolve_output_path

    assert _resolve_output_path("out.cdx", "cyclonedx") == "out.cdx.json"
    assert _resolve_output_path("out.spdx", "spdx") == "out.spdx.json"
    assert _resolve_output_path("out.spdx2", "spdx2") == "out.spdx2.json"


def test_resolve_output_path_still_rejects_unrelated_extension() -> None:
    """The short-form alias must not mask a genuinely wrong extension."""
    import pytest

    from agent_bom.cli.agents._output import _resolve_output_path

    with pytest.raises(SystemExit) as exc:
        _resolve_output_path("out.png", "cyclonedx")
    assert exc.value.code == 2
