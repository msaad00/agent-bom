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
@click.option("--agent-id", help="Export one agent BOM selected by its exact manifest ID, never its display name.")
@click.option("--single-agent", is_flag=True, help="Export a per-agent BOM when discovery contains exactly one agent.")
@click.option(
    "--validate", "validate_path", type=click.Path(exists=True, dir_okay=False), help="Validate a per-agent BOM file without discovery."
)
def manifest_cmd(
    config: str | None,
    project: str | None,
    tenant_id: str | None,
    output: str | None,
    compact: bool,
    agent_id: str | None,
    single_agent: bool,
    validate_path: str | None,
) -> None:
    """Emit the canonical Agent BOM manifest for local agent/MCP posture."""

    if validate_path:
        if any((config, project, tenant_id, output, compact, agent_id, single_agent)):
            raise click.UsageError("--validate cannot be combined with discovery or output options")
        from agent_bom.evidence.agent_bom import MAX_AGENT_BOM_BYTES, validate_agent_bom_json

        try:
            with Path(validate_path).open("rb") as handle:
                payload_bytes = handle.read(MAX_AGENT_BOM_BYTES + 1)
            document = validate_agent_bom_json(payload_bytes)
        except (OSError, ValueError):
            raise click.ClickException("Invalid per-agent BOM: check size, schema, evidence references, and content digest.") from None
        click.echo(f"Valid per-agent BOM: {document.snapshot_id} (integrity only; producer claims are not authenticated)")
        return
    if agent_id and single_agent:
        raise click.UsageError("Choose --agent-id or --single-agent")

    with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
        agents = list(_discover_manifest_agents(config, project))

    if agent_id or single_agent:
        from agent_bom.evidence.agent_bom import build_agent_bom

        selected = [agent for agent in agents if agent.stable_id == agent_id] if agent_id else agents
        if len(selected) != 1:
            raise click.ClickException("Expected exactly one agent. Run manifest without selection to inspect IDs, then use --agent-id.")
        try:
            payload = build_agent_bom(selected[0], tenant_id=tenant_id or "local").model_dump(mode="json")
        except ValueError:
            raise click.ClickException(
                "Cannot export per-agent BOM: inventory is invalid, conflicting, or exceeds profile bounds."
            ) from None
    else:
        payload = build_local_agent_manifest(agents, tenant_id=tenant_id)
    rendered = json.dumps(payload, separators=(",", ":") if compact else None, indent=None if compact else 2)
    if agent_id or single_agent:
        from agent_bom.evidence.agent_bom import MAX_AGENT_BOM_BYTES

        if len((rendered + "\n").encode("utf-8")) > MAX_AGENT_BOM_BYTES:
            raise click.ClickException("Per-agent BOM exceeds 8 MiB. Narrow the inventory before exporting.")

    if output:
        Path(output).write_text(rendered + "\n")
        click.echo(f"Wrote Agent BOM manifest to {output}")
        return
    with nullcontext():
        click.echo(rendered)
