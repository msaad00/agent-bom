"""Endpoint connector CLI; delegates to the authenticated control-plane API."""

from __future__ import annotations

import json
import os
from pathlib import Path

import click

from agent_bom.cli._findings_group import _common_api_options, _emit_json, _make_client, _run_request
from agent_bom.connectors.endpoints.models import ConnectionCreate, ConnectionUpdate


@click.group("endpoints")
def endpoints_group() -> None:
    """Connect Jamf/Falcon, sync inventory, and export scoped device evidence."""


@endpoints_group.command("list")
@_common_api_options
def list_cmd(api_url: str | None, api_key: str | None, bearer_token: str | None, tenant_id: str | None) -> None:
    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    _emit_json(_run_request(client, lambda api: api.endpoint_connections()))


@endpoints_group.command("create")
@click.option("--config", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path), help="Non-secret connection JSON.")
@click.option("--secret-env", required=True, help="Environment variable containing the vendor client secret; never a literal secret.")
@_common_api_options
def create_cmd(
    config: Path, secret_env: str, api_url: str | None, api_key: str | None, bearer_token: str | None, tenant_id: str | None
) -> None:
    try:
        body = json.loads(config.read_text())
        body["client_secret"] = os.environ.get(secret_env, "")
        validated = ConnectionCreate.model_validate(body)
    except (OSError, ValueError, TypeError):
        raise click.ClickException("Invalid connection configuration or missing secret environment variable") from None
    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    body = validated.model_dump(mode="json", exclude={"client_secret"})
    body["client_secret"] = validated.client_secret.get_secret_value()
    _emit_json(_run_request(client, lambda api: api.create_endpoint_connection(body)))


@endpoints_group.command("sync")
@click.argument("connection_id")
@click.option("--restart", is_flag=True, help="Start a new collection while retaining prior run evidence.")
@click.option("--max-pages", type=click.IntRange(1, 20), default=5, show_default=True)
@_common_api_options
def sync_cmd(
    connection_id: str,
    restart: bool,
    max_pages: int,
    api_url: str | None,
    api_key: str | None,
    bearer_token: str | None,
    tenant_id: str | None,
) -> None:
    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    # Collection can take longer than the normal API read timeout.
    client._client.timeout = 180
    payload = _run_request(client, lambda api: api.sync_endpoint_connection(connection_id, restart=restart, max_pages=max_pages))
    _emit_json(payload)
    if payload.get("status") != "complete":
        raise click.exceptions.Exit(2)


@endpoints_group.command("devices")
@click.argument("connection_id")
@click.option("--limit", type=click.IntRange(1, 500), default=100)
@click.option("--offset", type=click.IntRange(min=0), default=0)
@_common_api_options
def devices_cmd(
    connection_id: str, limit: int, offset: int, api_url: str | None, api_key: str | None, bearer_token: str | None, tenant_id: str | None
) -> None:
    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    _emit_json(_run_request(client, lambda api: api.endpoint_devices(connection_id, limit=limit, offset=offset)))


@endpoints_group.command("bind-agent")
@click.argument("device_id")
@click.argument("agent_id")
@click.option("--retire", is_flag=True, help="Retire an operator-recorded association without erasing its audit trail.")
@_common_api_options
def bind_cmd(
    device_id: str, agent_id: str, retire: bool, api_url: str | None, api_key: str | None, bearer_token: str | None, tenant_id: str | None
) -> None:
    """Associate exact IDs in the same tenant. This is an operator assertion, not execution proof."""
    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    _emit_json(_run_request(client, lambda api: api.bind_endpoint_agent(device_id, agent_id, active=not retire)))


@endpoints_group.command("update")
@click.argument("connection_id")
@click.option("--enabled/--disabled", default=None, help="Enable collection or disable it while retaining evidence.")
@click.option("--secret-env", default=None, help="Environment variable holding the replacement vendor secret.")
@_common_api_options
def update_cmd(
    connection_id: str,
    enabled: bool | None,
    secret_env: str | None,
    api_url: str | None,
    api_key: str | None,
    bearer_token: str | None,
    tenant_id: str | None,
) -> None:
    if enabled is None and secret_env is None:
        raise click.ClickException("Specify --enabled, --disabled, or --secret-env")
    body: dict = {"enabled": enabled}
    if secret_env is not None:
        body["client_secret"] = os.environ.get(secret_env, "")
    try:
        ConnectionUpdate.model_validate(body)
    except ValueError:
        raise click.ClickException("Replacement secret environment variable is missing or invalid") from None
    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    _emit_json(_run_request(client, lambda api: api.update_endpoint_connection(connection_id, body)))
