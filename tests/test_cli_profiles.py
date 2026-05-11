from __future__ import annotations

import click
import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.cli._profiles import apply_scan_profile_defaults, load_active_profile, set_current_profile


def test_profile_loader_uses_current_profile(monkeypatch, tmp_path):
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
current_profile = "prod"

[profiles.prod]
tenant_id = "team-a"
format = "json"
output = "reports/prod.json"
push_api_key_env = "AGENT_BOM_PUSH_TOKEN_PROD"
"""
    )
    monkeypatch.setenv("AGENT_BOM_CONFIG", str(config_path))
    monkeypatch.setenv("AGENT_BOM_PUSH_TOKEN_PROD", "secret-token")

    name, profile = load_active_profile()

    assert name == "prod"
    assert profile["tenant_id"] == "team-a"


def test_missing_active_profile_lists_available_profiles(monkeypatch, tmp_path):
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
[profiles.dev]
tenant_id = "default"

[profiles.prod]
tenant_id = "team-a"
"""
    )
    monkeypatch.setenv("AGENT_BOM_CONFIG", str(config_path))
    monkeypatch.setenv("AGENT_BOM_PROFILE", "missing")

    with pytest.raises(click.ClickException) as excinfo:
        load_active_profile()

    message = str(excinfo.value)
    assert "Profile 'missing' was not found" in message
    assert "Available profiles: dev, prod" in message


def test_scan_profile_defaults_do_not_override_explicit_cli_flags(monkeypatch, tmp_path):
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
current_profile = "prod"

[profiles.prod]
format = "json"
output = "profile.json"
push_url = "https://control-plane.example"
push_api_key_env = "AGENT_BOM_PUSH_TOKEN_PROD"
"""
    )
    monkeypatch.setenv("AGENT_BOM_CONFIG", str(config_path))
    monkeypatch.setenv("AGENT_BOM_PUSH_TOKEN_PROD", "secret-token")

    @click.command()
    @click.option("--output")
    @click.option("--format", "output_format", default="console")
    def _profile_default_test(output: str | None, output_format: str) -> None:
        values = apply_scan_profile_defaults(
            output=output,
            output_format=output_format,
            preset=None,
            nvd_api_key=None,
            push_url=None,
            push_api_key=None,
            clickhouse_url=None,
        )
        assert values == (
            "explicit.sarif",
            "sarif",
            None,
            None,
            "https://control-plane.example",
            "secret-token",
            None,
        )

    result = CliRunner().invoke(_profile_default_test, ["--output", "explicit.sarif", "--format", "sarif"])

    assert result.exit_code == 0, result.output


def test_scan_profile_output_does_not_shadow_explicit_format(monkeypatch, tmp_path):
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
current_profile = "prod"

[profiles.prod]
format = "json"
output = "profile.json"
"""
    )
    monkeypatch.setenv("AGENT_BOM_CONFIG", str(config_path))

    @click.command()
    @click.option("--output")
    @click.option("--format", "output_format", default="console")
    def _profile_default_test(output: str | None, output_format: str) -> None:
        values = apply_scan_profile_defaults(
            output=output,
            output_format=output_format,
            preset=None,
            nvd_api_key=None,
            push_url=None,
            push_api_key=None,
            clickhouse_url=None,
        )
        assert values[:2] == (None, "sarif")

    result = CliRunner().invoke(_profile_default_test, ["--format", "sarif"])

    assert result.exit_code == 0, result.output


def test_scan_profile_format_does_not_shadow_explicit_output(monkeypatch, tmp_path):
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
current_profile = "prod"

[profiles.prod]
format = "json"
output = "profile.json"
"""
    )
    monkeypatch.setenv("AGENT_BOM_CONFIG", str(config_path))

    @click.command()
    @click.option("--output")
    @click.option("--format", "output_format", default="console")
    def _profile_default_test(output: str | None, output_format: str) -> None:
        values = apply_scan_profile_defaults(
            output=output,
            output_format=output_format,
            preset=None,
            nvd_api_key=None,
            push_url=None,
            push_api_key=None,
            clickhouse_url=None,
        )
        assert values[:2] == ("report.sarif", "console")

    result = CliRunner().invoke(_profile_default_test, ["--output", "report.sarif"])

    assert result.exit_code == 0, result.output


def test_profiles_group_lists_and_switches_current_profile(monkeypatch, tmp_path):
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
current_profile = "dev"

[profiles.dev]
tenant_id = "default"
format = "console"

[profiles.prod]
tenant_id = "team-a"
format = "json"
"""
    )
    monkeypatch.setenv("AGENT_BOM_CONFIG", str(config_path))

    list_result = CliRunner().invoke(main, ["profiles", "list"])
    assert list_result.exit_code == 0
    assert "* dev" in list_result.output
    assert "  prod" in list_result.output

    set_current_profile(config_path, "prod")
    show_result = CliRunner().invoke(main, ["profiles", "show"])

    assert show_result.exit_code == 0
    assert "[prod]" in show_result.output
    assert "tenant_id = team-a" in show_result.output


def test_profiles_use_missing_profile_lists_available(monkeypatch, tmp_path):
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
[profiles.dev]
tenant_id = "default"

[profiles.prod]
tenant_id = "team-a"
"""
    )
    monkeypatch.setenv("AGENT_BOM_CONFIG", str(config_path))

    result = CliRunner().invoke(main, ["profiles", "use", "missing"])

    assert result.exit_code != 0
    assert "Profile 'missing' was not found" in result.output
    assert "Available profiles: dev, prod" in result.output
