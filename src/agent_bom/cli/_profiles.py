"""CLI profile support for named operator contexts."""

from __future__ import annotations

import os
import re
import tomllib
from pathlib import Path
from typing import Any

import click

from agent_bom.cli._grouped_help import SuggestingGroup
from agent_bom.cli._tenant import TENANT_ENV_VAR

CONFIG_ENV_VAR = "AGENT_BOM_CONFIG"
PROFILE_ENV_VAR = "AGENT_BOM_PROFILE"
DEFAULT_CONFIG_PATH = Path("~/.agent-bom/config.toml")
_PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_INLINE_SECRET_KEYS = {
    "api_key",
    "push_api_key",
    "nvd_api_key",
    "token",
    "secret",
    "password",
}


def default_config_path() -> Path:
    """Return the operator config path, honoring the explicit env override."""
    configured = os.environ.get(CONFIG_ENV_VAR)
    return Path(configured).expanduser() if configured else DEFAULT_CONFIG_PATH.expanduser()


def load_profiles_config(path: Path | None = None) -> dict[str, Any]:
    """Load the profile config TOML file, returning an empty config if absent."""
    config_path = path or default_config_path()
    if not config_path.exists():
        return {}
    try:
        with config_path.open("rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise click.ClickException(f"Invalid profile config {config_path}: {exc}") from exc
    if not isinstance(data, dict):
        return {}
    return data


def _profiles(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw_profiles = data.get("profiles", {})
    if not isinstance(raw_profiles, dict):
        raise click.ClickException("Profile config must use a [profiles.<name>] table.")
    profiles: dict[str, dict[str, Any]] = {}
    for name, profile in raw_profiles.items():
        if not isinstance(name, str) or not _PROFILE_NAME_RE.match(name):
            raise click.ClickException(f"Invalid profile name: {name!r}")
        if not isinstance(profile, dict):
            raise click.ClickException(f"Profile {name!r} must be a TOML table.")
        _reject_inline_secrets(name, profile)
        profiles[name] = profile
    return profiles


def _available_profiles_message(profiles: dict[str, dict[str, Any]]) -> str:
    if not profiles:
        return "No profiles are configured."
    return f"Available profiles: {', '.join(sorted(profiles))}."


def _missing_profile_message(name: str, path: Path, profiles: dict[str, dict[str, Any]]) -> str:
    return (
        f"Profile {name!r} was not found in {path}. "
        f"{_available_profiles_message(profiles)} "
        "Run `agent-bom profiles list` to inspect configured profiles."
    )


def _reject_inline_secrets(name: str, profile: dict[str, Any]) -> None:
    for key in profile:
        key_lower = str(key).lower()
        if key_lower in _INLINE_SECRET_KEYS or (key_lower.endswith("_key") and not key_lower.endswith("_key_env")):
            raise click.ClickException(
                f"Profile {name!r} uses inline credential key {key!r}. "
                "Store credentials in environment variables and reference them with *_env fields."
            )


def resolve_profile_name(explicit: str | None = None, data: dict[str, Any] | None = None) -> str | None:
    """Resolve the active profile name from explicit input, env, then config."""
    for candidate in (explicit, os.environ.get(PROFILE_ENV_VAR), (data or {}).get("current_profile")):
        if isinstance(candidate, str) and candidate.strip():
            name = candidate.strip()
            if not _PROFILE_NAME_RE.match(name):
                raise click.ClickException(f"Invalid profile name: {name!r}")
            return name
    return None


def load_active_profile(explicit: str | None = None) -> tuple[str | None, dict[str, Any]]:
    """Load the active profile table.

    Missing config is a no-op unless the user explicitly selected a profile.
    """
    data = load_profiles_config()
    name = resolve_profile_name(explicit, data)
    if not name:
        return None, {}
    profiles = _profiles(data)
    if name not in profiles:
        raise click.ClickException(_missing_profile_message(name, default_config_path(), profiles))
    return name, profiles[name]


def apply_profile_environment(profile: dict[str, Any]) -> None:
    """Apply environment-only profile values without overriding the process env."""
    tenant_id = _string_value(profile, "tenant_id", "tenant")
    if tenant_id and not os.environ.get(TENANT_ENV_VAR):
        os.environ[TENANT_ENV_VAR] = tenant_id


def profile_default(
    ctx: click.Context | None,
    profile: dict[str, Any],
    param_name: str,
    current: Any,
    *keys: str,
) -> Any:
    """Return a profile value only when the current CLI value was not explicit."""
    if not profile:
        return current
    if ctx is not None:
        source = ctx.get_parameter_source(param_name)
        if source in {click.core.ParameterSource.COMMANDLINE, click.core.ParameterSource.ENVIRONMENT}:
            return current
    for key in keys or (param_name,):
        value = profile.get(key)
        if value is not None and value != "":
            return value
    return current


def profile_env_default(
    ctx: click.Context | None,
    profile: dict[str, Any],
    param_name: str,
    current: str | None,
    env_ref_key: str,
) -> str | None:
    """Resolve a profile default from an environment-variable reference."""
    if ctx is not None:
        source = ctx.get_parameter_source(param_name)
        if source in {click.core.ParameterSource.COMMANDLINE, click.core.ParameterSource.ENVIRONMENT}:
            return current
    env_name = _string_value(profile, env_ref_key)
    if not env_name:
        return current
    return os.environ.get(env_name) or current


def _string_value(profile: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = profile.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def apply_scan_profile_defaults(
    *,
    output: str | None,
    output_format: str,
    preset: str | None,
    nvd_api_key: str | None,
    push_url: str | None,
    push_api_key: str | None,
    clickhouse_url: str | None,
) -> tuple[str | None, str, str | None, str | None, str | None, str | None, str | None]:
    """Apply active profile defaults for the main scan command."""
    _name, profile = load_active_profile()
    if not profile:
        return output, output_format, preset, nvd_api_key, push_url, push_api_key, clickhouse_url
    apply_profile_environment(profile)
    ctx = click.get_current_context(silent=True)
    output_source = ctx.get_parameter_source("output") if ctx is not None else None
    format_source = ctx.get_parameter_source("output_format") if ctx is not None else None
    explicit_output = output_source in {click.core.ParameterSource.COMMANDLINE, click.core.ParameterSource.ENVIRONMENT}
    explicit_format = format_source in {click.core.ParameterSource.COMMANDLINE, click.core.ParameterSource.ENVIRONMENT}
    # When `scan` is invoked via ``ctx.invoke`` from a sibling command
    # (`sbom`, `image`, `iac`, …), Click reports the parameter source as
    # DEFAULT even though the caller passed an explicit value. Treat a
    # truthy caller value as a request to honor it; otherwise fall back to
    # the active profile default. Without this guard, a profile that pins
    # ``output = "agent-bom-report.json"`` overrides ``agent-bom sbom -o
    # custom.json`` because the source is DEFAULT.
    caller_supplied_output = bool(output)
    caller_supplied_format = bool(output_format) and output_format != "console"

    profile_output = (
        output
        if explicit_output or caller_supplied_output or (explicit_format and not explicit_output)
        else profile_default(ctx, profile, "output", output, "output")
    )
    profile_format = (
        output_format
        if explicit_format or caller_supplied_format or (explicit_output and not explicit_format)
        else profile_default(ctx, profile, "output_format", output_format, "format", "output_format")
    )

    return (
        profile_output,
        profile_format,
        profile_default(ctx, profile, "preset", preset, "preset"),
        profile_env_default(ctx, profile, "nvd_api_key", nvd_api_key, "nvd_api_key_env"),
        profile_default(ctx, profile, "push_url", push_url, "push_url"),
        profile_env_default(ctx, profile, "push_api_key", push_api_key, "push_api_key_env"),
        profile_default(ctx, profile, "clickhouse_url", clickhouse_url, "clickhouse_url"),
    )


def write_profile_template(path: Path, name: str, *, force: bool = False) -> None:
    """Create a safe starter profile config."""
    if not _PROFILE_NAME_RE.match(name):
        raise click.ClickException(f"Invalid profile name: {name!r}")
    if path.exists() and not force:
        raise click.ClickException(f"{path} already exists. Use --force to replace it.")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                f'current_profile = "{name}"',
                "",
                f"[profiles.{name}]",
                'tenant_id = "default"',
                'format = "json"',
                'output = "agent-bom-report.json"',
                'preset = "quick"',
                'push_url = ""',
                'push_api_key_env = "AGENT_BOM_PUSH_API_KEY"',
                'nvd_api_key_env = "NVD_API_KEY"',
                'clickhouse_url = ""',
                "",
            ]
        )
    )


def set_current_profile(path: Path, name: str) -> None:
    """Persist the current profile selection in the config file."""
    if not _PROFILE_NAME_RE.match(name):
        raise click.ClickException(f"Invalid profile name: {name!r}")
    data = load_profiles_config(path)
    profiles = _profiles(data)
    if name not in profiles:
        raise click.ClickException(_missing_profile_message(name, path, profiles))
    text = path.read_text()
    line = f'current_profile = "{name}"'
    if re.search(r"(?m)^current_profile\s*=", text):
        text = re.sub(r'(?m)^current_profile\s*=\s*["\'][^"\']*["\']\s*$', line, text, count=1)
    else:
        text = f"{line}\n{text}"
    path.write_text(text)


@click.group("profiles", cls=SuggestingGroup)
def profiles_group() -> None:
    """Manage named CLI profiles in ~/.agent-bom/config.toml."""


@profiles_group.command("path")
def profiles_path_cmd() -> None:
    """Print the active profile config path."""
    click.echo(str(default_config_path()))


@profiles_group.command("init")
@click.argument("name", default="default")
@click.option("--force", is_flag=True, help="Replace an existing config file.")
def profiles_init_cmd(name: str, force: bool) -> None:
    """Write a starter profile config."""
    path = default_config_path()
    write_profile_template(path, name, force=force)
    click.echo(f"Wrote {path}")


@profiles_group.command("list")
def profiles_list_cmd() -> None:
    """List configured profiles."""
    data = load_profiles_config()
    profiles = _profiles(data)
    current = resolve_profile_name(data=data)
    if not profiles:
        click.echo(f"No profiles found in {default_config_path()}")
        return
    for name in sorted(profiles):
        marker = "*" if name == current else " "
        tenant = _string_value(profiles[name], "tenant_id", "tenant") or "-"
        fmt = _string_value(profiles[name], "format", "output_format") or "-"
        click.echo(f"{marker} {name}\ttenant={tenant}\tformat={fmt}")


@profiles_group.command("show")
@click.argument("name", required=False)
def profiles_show_cmd(name: str | None) -> None:
    """Show one configured profile without resolving secret values."""
    data = load_profiles_config()
    resolved = resolve_profile_name(name, data)
    if not resolved:
        raise click.ClickException("No profile selected. Pass NAME or set current_profile.")
    profiles = _profiles(data)
    if resolved not in profiles:
        raise click.ClickException(_missing_profile_message(resolved, default_config_path(), profiles))
    click.echo(f"[{resolved}]")
    for key, value in sorted(profiles[resolved].items()):
        if str(key).endswith("_env"):
            click.echo(f"{key} = {value} (env ref)")
        else:
            click.echo(f"{key} = {value}")


@profiles_group.command("use")
@click.argument("name")
def profiles_use_cmd(name: str) -> None:
    """Set the current profile in the config file."""
    path = default_config_path()
    if not path.exists():
        raise click.ClickException(f"{path} does not exist. Run `agent-bom profiles init {name}` first.")
    set_current_profile(path, name)
    click.echo(f"Current profile: {name}")
