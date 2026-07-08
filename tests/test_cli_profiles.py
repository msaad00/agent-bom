from __future__ import annotations

import click
import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.cli._profiles import (
    active_profile_banner,
    apply_scan_profile_defaults,
    default_config_path,
    load_active_profile,
    set_current_profile,
    write_profile_template,
)


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


def test_scan_profile_does_not_clobber_ctx_invoke_output(monkeypatch, tmp_path):
    """When a sibling command (`sbom`, `image`, `iac`) calls `scan` via
    ``ctx.invoke(..., output=...)``, Click reports the parameter source as
    DEFAULT even though the caller passed an explicit value. The profile
    default must not clobber the caller's value in that case — otherwise
    ``agent-bom sbom test.spdx.json -o custom.json`` silently writes to the
    profile-configured filename.
    """
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
current_profile = "prod"

[profiles.prod]
format = "json"
output = "agent-bom-report.json"
"""
    )
    monkeypatch.setenv("AGENT_BOM_CONFIG", str(config_path))

    @click.command()
    @click.option("--output")
    @click.option("--format", "output_format", default="console")
    def _inner(output: str | None, output_format: str) -> None:
        values = apply_scan_profile_defaults(
            output=output,
            output_format=output_format,
            preset=None,
            nvd_api_key=None,
            push_url=None,
            push_api_key=None,
            clickhouse_url=None,
        )
        # Caller-supplied output (ctx.invoke from sbom_cmd) must win even when
        # the click parameter source is DEFAULT.
        assert values[:2] == ("custom.json", "json")

    @click.command()
    @click.pass_context
    def _outer(ctx):
        ctx.invoke(_inner, output="custom.json", output_format="json")

    result = CliRunner().invoke(_outer)
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


def test_active_profile_banner_fires_on_auto_active_json_redirect():
    banner = active_profile_banner(
        "default",
        "json",
        "agent-bom-report.json",
        auto_active=True,
        user_chose=False,
    )
    assert banner == (
        "Profile 'default' active (format=json → agent-bom-report.json). "
        "Override with --format console."
    )


def test_active_profile_banner_silent_when_console_default():
    # A console-format profile does not redirect output — no banner.
    assert active_profile_banner("default", "console", None, auto_active=True, user_chose=False) is None


def test_active_profile_banner_silent_when_explicit_or_agent_mode():
    # Explicit --profile/env (not auto-active), explicit flag, or agent-mode all suppress.
    assert active_profile_banner("prod", "json", "r.json", auto_active=False, user_chose=False) is None
    assert active_profile_banner("prod", "json", "r.json", auto_active=True, user_chose=True) is None
    assert (
        active_profile_banner("prod", "json", "r.json", auto_active=True, user_chose=False, agent_mode=True) is None
    )


def test_scan_profile_defaults_emit_banner_on_silent_redirect(monkeypatch, tmp_path):
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
current_profile = "default"

[profiles.default]
format = "json"
output = "agent-bom-report.json"
"""
    )
    monkeypatch.setenv("AGENT_BOM_CONFIG", str(config_path))
    monkeypatch.delenv("AGENT_BOM_PROFILE", raising=False)
    monkeypatch.delenv("AGENT_BOM_AGENT_MODE", raising=False)

    @click.command()
    @click.option("--output")
    @click.option("--format", "output_format", default="console")
    @click.option("--quiet", is_flag=True)
    def _bare_scan(output, output_format, quiet):
        apply_scan_profile_defaults(
            output=output,
            output_format=output_format,
            preset=None,
            nvd_api_key=None,
            push_url=None,
            push_api_key=None,
            clickhouse_url=None,
        )

    runner = CliRunner()
    result = runner.invoke(_bare_scan, [])
    assert result.exit_code == 0, result.output
    assert "Profile 'default' active (format=json → agent-bom-report.json)" in result.stderr


def test_scan_profile_defaults_no_banner_with_explicit_profile_env(monkeypatch, tmp_path):
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
current_profile = "default"

[profiles.default]
format = "json"
output = "agent-bom-report.json"
"""
    )
    monkeypatch.setenv("AGENT_BOM_CONFIG", str(config_path))
    monkeypatch.setenv("AGENT_BOM_PROFILE", "default")  # explicit selection → no surprise

    @click.command()
    @click.option("--output")
    @click.option("--format", "output_format", default="console")
    def _bare_scan(output, output_format):
        apply_scan_profile_defaults(
            output=output,
            output_format=output_format,
            preset=None,
            nvd_api_key=None,
            push_url=None,
            push_api_key=None,
            clickhouse_url=None,
        )

    runner = CliRunner()
    result = runner.invoke(_bare_scan, [])
    assert result.exit_code == 0, result.output
    assert "active" not in result.stderr


def test_profiles_init_writes_console_default_template(monkeypatch, tmp_path):
    config_path = tmp_path / "config.toml"
    monkeypatch.setenv("AGENT_BOM_CONFIG", str(config_path))

    write_profile_template(default_config_path(), "default")
    text = config_path.read_text()

    # Console stays the default — the generated template must not manufacture the
    # silent-redirect footgun (format=json + output=file).
    assert 'format = "console"' in text
    assert '\noutput = ' not in text  # no active output redirect (commented only)
    assert '# output = "agent-bom-report.json"' in text

    # And a bare scan under this fresh template stays on the console with no banner.
    @click.command()
    @click.option("--output")
    @click.option("--format", "output_format", default="console")
    def _bare_scan(output, output_format):
        values = apply_scan_profile_defaults(
            output=output,
            output_format=output_format,
            preset=None,
            nvd_api_key=None,
            push_url=None,
            push_api_key=None,
            clickhouse_url=None,
        )
        assert values[:2] == (None, "console")

    monkeypatch.delenv("AGENT_BOM_PROFILE", raising=False)
    runner = CliRunner()
    result = runner.invoke(_bare_scan, [])
    assert result.exit_code == 0, result.output
    assert result.stderr == ""


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
