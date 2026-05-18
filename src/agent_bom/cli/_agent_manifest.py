"""Agent BOM manifest CLI."""

from __future__ import annotations

import json
from contextlib import nullcontext, redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

import click

from agent_bom.agent_manifest import build_local_agent_manifest
from agent_bom.cli._common import _build_agents_from_inventory, read_json_file_for_cli
from agent_bom.cli._inventory import _project_inventory_path
from agent_bom.discovery import discover_all


def _discover_manifest_agents(config: str | None, project: str | None):
    if config:
        config_path = Path(config)
        config_data = read_json_file_for_cli(config_path, label="MCP config")
        from agent_bom.discovery import parse_mcp_config
        from agent_bom.models import Agent, AgentType

        servers = parse_mcp_config(config_data, str(config_path))
        return (
            [
                Agent(
                    name=f"custom:{config_path.stem}",
                    agent_type=AgentType.CUSTOM,
                    config_path=str(config_path),
                    mcp_servers=servers,
                )
            ]
            if servers
            else []
        )

    project_inventory = _project_inventory_path(project)
    if project_inventory is not None:
        from agent_bom.inventory import load_inventory

        inventory_data = load_inventory(str(project_inventory))
        return _build_agents_from_inventory(inventory_data, str(project_inventory))

    return discover_all(project_dir=project)


@click.command("manifest")
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to a specific MCP config file.")
@click.option("--project", "-p", type=click.Path(exists=True), help="Project directory to inspect for agent inventory.")
@click.option("--tenant-id", default=None, help="Optional tenant identifier to stamp into the manifest.")
@click.option("--output", "-o", type=click.Path(dir_okay=False), help="Write the manifest JSON to a file instead of stdout.")
@click.option("--compact", is_flag=True, help="Emit compact JSON without indentation.")
def manifest_cmd(config: str | None, project: str | None, tenant_id: str | None, output: str | None, compact: bool) -> None:
    """Emit the canonical Agent BOM manifest for local agent/MCP posture."""

    with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
        agents = _discover_manifest_agents(config, project)

    payload = build_local_agent_manifest(agents, tenant_id=tenant_id)
    rendered = json.dumps(payload, separators=(",", ":") if compact else None, indent=None if compact else 2)

    if output:
        Path(output).write_text(rendered + "\n")
        click.echo(f"Wrote Agent BOM manifest to {output}")
        return
    with nullcontext():
        click.echo(rendered)
