"""CLI commands for the connect-once ITSM ticketing plane.

Thin surface over ``/v1/ticketing/tickets`` — the same connect-once actions the
REST API and the MCP ``create_ticket`` / ``sync_ticket_status`` tools expose. All
logic (connection resolution, idempotent filing, ITSM transport) lives in
``agent_bom.ticketing.service``; the CLI only renders what the API returns.

No credential, token, or base URL is ever passed here: auth and endpoint come
only from the stored, encrypted, tenant-scoped connection configured once in the
Connections hub. Filing a ticket therefore requires the API server plus a
ticketing connection for the tenant.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

import click

from agent_bom.cli._findings_group import (
    _common_api_options,
    _emit_json,
    _make_client,
    _run_request,
    _string,
)


def _print_tickets_table(payload: Mapping[str, object]) -> None:
    rows = payload.get("tickets")
    if not isinstance(rows, list):
        rows = []
    tenant = _string(payload.get("tenant_id")) or "-"
    noun = "ticket" if len(rows) == 1 else "tickets"
    click.echo(f"{len(rows)} {noun} (tenant {tenant})")
    click.echo("id\tprovider\tstatus\tkey\texternal_id\tconnection\turl")
    for item in rows:
        if not isinstance(item, dict):
            continue
        click.echo(
            "\t".join(
                [
                    _string(item.get("id")),
                    _string(item.get("provider")),
                    _string(item.get("status")),
                    _string(item.get("key")) or "-",
                    _string(item.get("external_id")) or "-",
                    _string(item.get("connection_id")) or "-",
                    _string(item.get("url")) or "-",
                ]
            )
        )


@click.group(name="ticket")
def ticket_cmd() -> None:
    """File and sync ITSM tickets for findings through a stored connection.

    Connect-once: configure a ticketing connection first (Connections hub / the
    ticketing API). These commands carry no credentials and require the API
    server.
    """


@ticket_cmd.command("list")
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table", show_default=True)
@_common_api_options
def list_tickets_cmd(
    api_url: str | None,
    api_key: str | None,
    bearer_token: str | None,
    tenant_id: str | None,
    output_format: str,
) -> None:
    """List filed finding→ticket links with their last-known ITSM status."""

    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    payload = _run_request(client, lambda api: api.list_tickets())
    if output_format == "json":
        _emit_json(payload)
    else:
        _print_tickets_table(payload)


@ticket_cmd.command("create")
@click.option(
    "--finding-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to a JSON file with the finding/issue object to file.",
)
@click.option(
    "--connection-id", "connection_id", default="", help="Stored ticketing connection id (uses the tenant's only one if omitted)."
)
@click.option("--project", default="", help="Target ITSM project/queue key (uses the connection default if omitted).")
@click.option("--finding-id", "finding_id", default="", help="Stable finding id for idempotency (derived from finding if omitted).")
@click.option("--issue-type", "issue_type", default="", help="ITSM issue type (provider default if omitted).")
@click.option("--source-url", "source_url", default="", help="Optional deep link back into agent-bom for provenance.")
@click.option("--format", "output_format", type=click.Choice(["json"]), default="json", show_default=True)
@_common_api_options
def create_ticket_cmd(
    api_url: str | None,
    api_key: str | None,
    bearer_token: str | None,
    tenant_id: str | None,
    finding_file: Path,
    connection_id: str,
    project: str,
    finding_id: str,
    issue_type: str,
    source_url: str,
    output_format: str,
) -> None:
    """File a ticket for a finding through the stored connection (idempotent)."""

    try:
        finding = json.loads(finding_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise click.ClickException(f"Could not read finding JSON from {finding_file}: {exc}") from exc
    if not isinstance(finding, dict):
        raise click.ClickException("The finding file must contain a single JSON object.")

    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    payload = _run_request(
        client,
        lambda api: api.create_ticket(
            finding=finding,
            connection_id=connection_id,
            project=project,
            finding_id=finding_id,
            issue_type=issue_type,
            source_url=source_url,
        ),
    )
    if output_format == "json":
        _emit_json(payload)


@ticket_cmd.command("sync")
@click.argument("ticket_id")
@click.option("--format", "output_format", type=click.Choice(["json"]), default="json", show_default=True)
@_common_api_options
def sync_ticket_cmd(
    api_url: str | None,
    api_key: str | None,
    bearer_token: str | None,
    tenant_id: str | None,
    ticket_id: str,
    output_format: str,
) -> None:
    """Refresh a filed ticket's status from its ITSM through the connection."""

    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    payload = _run_request(client, lambda api: api.sync_ticket(ticket_id))
    if output_format == "json":
        _emit_json(payload)


__all__ = ["ticket_cmd"]
