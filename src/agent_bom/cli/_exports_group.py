"""CLI commands for scheduled findings exports (destinations + schedules).

Thin surface over ``/v1/exports/destinations`` and ``/v1/exports/schedules`` —
the connect-once security-data-lake export plane. All logic (encryption at rest,
off-event-loop run, cron scheduling) lives in ``agent_bom.export`` and the
destination/schedule stores; the CLI only renders what the API returns.

Connect-once: a destination is configured with its stored, encrypted config and
every ``run`` streams findings **through** it — no per-action credential is ever
passed to these commands. Secret-bearing destinations (e.g. Snowflake) are
provisioned through the connect-once API/hub, not by handing a credential to the
CLI; ``destinations create`` here carries only non-secret config.
"""

from __future__ import annotations

import json

import click

from agent_bom.cli._findings_group import (
    _common_api_options,
    _emit_json,
    _make_client,
    _run_request,
    _string,
)
from agent_bom.client import JsonObject, JsonValue


def _emit_json_rows(rows: list[JsonObject]) -> None:
    click.echo(json.dumps(rows, indent=2, sort_keys=True))


def _print_destinations_table(rows: list[JsonObject]) -> None:
    noun = "destination" if len(rows) == 1 else "destinations"
    click.echo(f"{len(rows)} export {noun}")
    click.echo("id\tkind\tdisplay_name\tstatus\thas_secret\tlast_run_status\tlast_run_at")
    for item in rows:
        if not isinstance(item, dict):
            continue
        click.echo(
            "\t".join(
                [
                    _string(item.get("id")),
                    _string(item.get("kind")),
                    _string(item.get("display_name")),
                    _string(item.get("status")),
                    _string(item.get("has_secret")),
                    _string(item.get("last_run_status")) or "-",
                    _string(item.get("last_run_at")) or "-",
                ]
            )
        )


def _print_schedules_table(rows: list[JsonObject]) -> None:
    noun = "schedule" if len(rows) == 1 else "schedules"
    click.echo(f"{len(rows)} export {noun}")
    click.echo("id\tname\tcron\tdestination\tenabled\tnext_run")
    for item in rows:
        if not isinstance(item, dict):
            continue
        click.echo(
            "\t".join(
                [
                    _string(item.get("schedule_id") or item.get("id")),
                    _string(item.get("name")),
                    _string(item.get("cron_expression")),
                    _string(item.get("destination_id")),
                    _string(item.get("enabled")),
                    _string(item.get("next_run")) or "-",
                ]
            )
        )


def _parse_config(config: str | None) -> dict[str, JsonValue]:
    if not config:
        return {}
    try:
        parsed = json.loads(config)
    except json.JSONDecodeError as exc:
        raise click.ClickException(f"--config must be a JSON object: {exc}") from exc
    if not isinstance(parsed, dict):
        raise click.ClickException("--config must be a JSON object.")
    return parsed


@click.group(name="export")
def export_cmd() -> None:
    """Manage connect-once findings-export destinations and schedules.

    No per-action credential is passed to these commands; a run operates over a
    stored destination. Requires the API server.
    """


@export_cmd.group("destinations")
def destinations_group() -> None:
    """List, create, and run connect-once export destinations."""


@destinations_group.command("list")
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table", show_default=True)
@_common_api_options
def list_destinations_cmd(
    api_url: str | None,
    api_key: str | None,
    bearer_token: str | None,
    tenant_id: str | None,
    output_format: str,
) -> None:
    """List the tenant's export destinations and their last-run status."""

    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    rows = _run_request(client, lambda api: api.list_export_destinations())
    if output_format == "json":
        _emit_json_rows(rows)
    else:
        _print_destinations_table(rows)


@destinations_group.command("create")
@click.option("--kind", required=True, help="Destination kind: s3, azure-blob, gcs, clickhouse, snowflake, bigquery, or databricks.")
@click.option("--display-name", "display_name", required=True, help="Human-readable name for the destination.")
@click.option(
    "--config",
    default="",
    help="Non-secret destination config as a JSON object (bucket/prefix/region, warehouse coordinates, etc.).",
)
@click.option("--format", "output_format", type=click.Choice(["json"]), default="json", show_default=True)
@_common_api_options
def create_destination_cmd(
    api_url: str | None,
    api_key: str | None,
    bearer_token: str | None,
    tenant_id: str | None,
    kind: str,
    display_name: str,
    config: str,
    output_format: str,
) -> None:
    """Create a connect-once export destination (non-secret config only).

    Secret-bearing destinations (Snowflake / Databricks) are provisioned through
    the connect-once API/hub so no credential is passed here; this command
    surfaces the API's guidance if a secret is required.
    """

    parsed_config = _parse_config(config)
    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    payload = _run_request(
        client,
        lambda api: api.create_export_destination(kind=kind, display_name=display_name, config=parsed_config),
    )
    if output_format == "json":
        _emit_json(payload)


@destinations_group.command("run")
@click.argument("destination_id")
@click.option("--format", "output_format", type=click.Choice(["json"]), default="json", show_default=True)
@_common_api_options
def run_destination_cmd(
    api_url: str | None,
    api_key: str | None,
    bearer_token: str | None,
    tenant_id: str | None,
    destination_id: str,
    output_format: str,
) -> None:
    """Fire a one-off findings export to a stored destination now."""

    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    payload = _run_request(client, lambda api: api.run_export_destination(destination_id))
    if output_format == "json":
        _emit_json(payload)


@export_cmd.group("schedules")
def schedules_group() -> None:
    """List and create cron export schedules bound to a destination."""


@schedules_group.command("list")
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table", show_default=True)
@_common_api_options
def list_schedules_cmd(
    api_url: str | None,
    api_key: str | None,
    bearer_token: str | None,
    tenant_id: str | None,
    output_format: str,
) -> None:
    """List the tenant's export schedules."""

    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    rows = _run_request(client, lambda api: api.list_export_schedules())
    if output_format == "json":
        _emit_json_rows(rows)
    else:
        _print_schedules_table(rows)


@schedules_group.command("create")
@click.option("--name", required=True, help="Human-readable schedule name.")
@click.option("--cron", "cron_expression", required=True, help="Five-field cron expression.")
@click.option("--destination-id", "destination_id", required=True, help="Stored destination id to export to.")
@click.option("--sort", default="effective_reach", show_default=True, help="Findings sort applied to each export.")
@click.option("--severity", default=None, help="Optional minimum severity filter.")
@click.option("--since-days", "since_days", default=None, type=click.IntRange(min=1, max=3650), help="Optional lookback window in days.")
@click.option("--disabled", is_flag=True, help="Create the schedule disabled (default: enabled).")
@click.option("--format", "output_format", type=click.Choice(["json"]), default="json", show_default=True)
@_common_api_options
def create_schedule_cmd(
    api_url: str | None,
    api_key: str | None,
    bearer_token: str | None,
    tenant_id: str | None,
    name: str,
    cron_expression: str,
    destination_id: str,
    sort: str,
    severity: str | None,
    since_days: int | None,
    disabled: bool,
    output_format: str,
) -> None:
    """Create a cron export schedule bound to a stored destination."""

    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    payload = _run_request(
        client,
        lambda api: api.create_export_schedule(
            name=name,
            cron_expression=cron_expression,
            destination_id=destination_id,
            sort=sort,
            severity=severity,
            since_days=since_days,
            enabled=not disabled,
        ),
    )
    if output_format == "json":
        _emit_json(payload)


__all__ = ["export_cmd"]
