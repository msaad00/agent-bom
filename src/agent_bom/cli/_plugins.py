"""Plugin registry inspection commands."""

from __future__ import annotations

import json

import click

from agent_bom.cli._grouped_help import SuggestingGroup
from agent_bom.plugin_activation import plugin_activation_status
from agent_bom.plugin_entrypoints import plugin_registry_status


@click.group("plugins", cls=SuggestingGroup, invoke_without_command=True)
@click.pass_context
def plugins_group(ctx: click.Context) -> None:
    """Inspect extension plugin entry-point registrations."""

    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@plugins_group.command("status")
@click.option("-f", "--format", "output_format", type=click.Choice(["console", "json"]), default="console", show_default=True)
def plugins_status_cmd(output_format: str) -> None:
    """Show built-in plugin slots and installed entry-point declarations."""

    status = plugin_registry_status()
    if output_format == "json":
        click.echo(json.dumps(status, indent=2, sort_keys=True))
        return

    totals = status["totals"]
    click.echo("Plugin registry status")
    click.echo(f"  schema_version:        {status['schema_version']}")
    click.echo(f"  entrypoints_enabled:   {str(status['entrypoints_enabled']).lower()}")
    click.echo(f"  metadata_only:         {str(status['metadata_only']).lower()}")
    click.echo(f"  builtin_registrations: {totals['builtin_registrations']}")
    click.echo(f"  declared_entrypoints:  {totals['declared_entrypoints']}")
    click.echo("")
    for group in status["groups"]:
        click.echo(f"{group['group']}")
        click.echo(f"  {group['description']}")
        click.echo(
            f"  builtin={group['builtin_count']} declared_entrypoints={group['declared_entrypoint_count']} "
            f"activation_enabled={str(group.get('activation_enabled', False)).lower()}"
        )
        for entry in group["declared_entrypoints"]:
            value = f" -> {entry['value']}" if entry["value"] else ""
            distribution = f" ({entry['distribution']})" if entry["distribution"] else ""
            click.echo(f"  - {entry['name']}{value}{distribution}")
    if status["warnings"]:
        click.echo("")
        click.echo("Warnings:")
        for warning in status["warnings"]:
            click.echo(f"  - {warning}")


@plugins_group.command("activation")
@click.option("-f", "--format", "output_format", type=click.Choice(["console", "json"]), default="console", show_default=True)
def plugins_activation_cmd(output_format: str) -> None:
    """Show which discovered plugin groups are activated and bound at runtime."""

    status = plugin_activation_status()
    if output_format == "json":
        click.echo(json.dumps(status, indent=2, sort_keys=True))
        return

    click.echo("Plugin activation status")
    click.echo(f"  schema_version:      {status['schema_version']}")
    click.echo(f"  discovery_enabled:   {str(status['discovery_enabled']).lower()}")
    click.echo(f"  activated_plugins:   {status['totals']['activated_plugins']}")
    click.echo("")
    for group in status["groups"]:
        click.echo(f"{group['group']}")
        click.echo(f"  activation_env={group['activation_env']} enabled={str(group['enabled']).lower()}")
        for name in group["activated_plugins"]:
            click.echo(f"  - {name}")
    if status["warnings"]:
        click.echo("")
        click.echo("Warnings:")
        for warning in status["warnings"]:
            click.echo(f"  - {warning}")
