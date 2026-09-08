"""Managed runtime profile operations and checkpointed gateway activity output."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import click
import httpx

from agent_bom.cli._findings_group import _common_api_options, _make_client
from agent_bom.client import AgentBomApiError


@click.group("profiles")
def runtime_profiles() -> None:
    """Manage tenant runtime profiles (separate from local CLI configurations)."""


def _profile_request(operation: str, api: dict[str, Any], *args: Any, **kwargs: Any) -> None:
    try:
        with _make_client(**api) as client:
            result = getattr(client, operation)(*args, **kwargs)
        click.echo(json.dumps(result, indent=2))
        if result.get("profile_allowed") is False:
            raise click.exceptions.Exit(1)
    except AgentBomApiError as exc:
        raise click.ClickException(f"Runtime profile request failed (HTTP {exc.status_code})") from None
    except (httpx.HTTPError, ValueError, OSError):
        raise click.ClickException("Runtime profile request unavailable or invalid; check API configuration and input") from None


@runtime_profiles.command("create")
@click.option("--file", "profile_file", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@_common_api_options
def create(profile_file: Path, **api: Any) -> None:
    """Create a managed assignment from JSON with identity_id and environment."""
    try:
        profile = json.loads(profile_file.read_text())
        if not isinstance(profile, dict):
            raise ValueError
    except (ValueError, OSError):
        raise click.ClickException("Profile file must contain a JSON object") from None
    _profile_request("create_runtime_profile", api, profile)


@runtime_profiles.command("list")
@_common_api_options
def list_profiles(**api: Any) -> None:
    """List tenant assignments with revisions, bindings and lifecycle state."""
    _profile_request("runtime_profiles", api)


def _context_options(fn: Any) -> Any:
    fn = click.argument("config_id")(fn)
    fn = click.option("--issuer", default="agent-bom", show_default=True)(fn)
    fn = click.option("--environment", required=True)(fn)
    return click.option("--scope", "granted_scopes", multiple=True, help="Hypothetical granted scope; repeatable.")(fn)


@runtime_profiles.command("validate")
@_context_options
@_common_api_options
def validate(config_id: str, issuer: str, environment: str, granted_scopes: tuple[str, ...], **api: Any) -> None:
    """Preview binding validity. Does not verify credentials or authorize calls."""
    _profile_request("validate_runtime_profile", api, config_id, issuer=issuer, environment=environment, granted_scopes=granted_scopes)


@runtime_profiles.command("test")
@_context_options
@click.option("--upstream", required=True)
@click.option("--tool", required=True)
@_common_api_options
def test_profile(
    config_id: str, issuer: str, environment: str, granted_scopes: tuple[str, ...], upstream: str, tool: str, **api: Any
) -> None:
    """Preview a tool target against the profile. No upstream execution or DLP test."""
    _profile_request(
        "test_runtime_profile",
        api,
        config_id,
        issuer=issuer,
        environment=environment,
        granted_scopes=granted_scopes,
        upstream=upstream,
        tool=tool,
    )


def _save_checkpoint(path: Path, binding: dict[str, str], cursor: str) -> None:
    """Atomic owner-only checkpoint, written after the output frame is flushed."""
    fd, temporary = tempfile.mkstemp(prefix=".activity-cursor-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump({**binding, "cursor": cursor}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@click.command("feed")
@_common_api_options
@click.option(
    "--cursor-file", required=True, type=click.Path(dir_okay=False, path_type=Path), help="Checkpoint bound to API URL and tenant."
)
@click.option("--follow", is_flag=True, help="Reconnect using the last fully printed batch cursor.")
@click.option("--limit", default=200, type=click.IntRange(1, 500), show_default=True)
def runtime_feed(cursor_file: Path, follow: bool, limit: int, **api: Any) -> None:
    """Print durable activity batches as JSON lines. Stops explicitly on any gap.

    A crash between output and checkpoint can replay a batch. Consumers should
    deduplicate event_id. Retention loss requires an explicit operator restart
    with a new cursor file; it is never silently skipped.
    """
    try:
        with _make_client(**api) as client:
            binding = {"api_url": client.base_url, "tenant_id": client.tenant_id or ""}
            cursor = None
            if cursor_file.exists():
                saved = json.loads(cursor_file.read_text())
                if (
                    not isinstance(saved, dict)
                    or any(saved.get(k) != v for k, v in binding.items())
                    or not isinstance(saved.get("cursor"), str)
                    or not saved["cursor"]
                ):
                    raise click.ClickException("Cursor file does not match this API and tenant, or is invalid")
                cursor = saved["cursor"]
            failures = 0
            while True:
                try:
                    for frame in client.gateway_activity(cursor=cursor, limit=limit):
                        event = frame["event"]
                        if event == "gap":
                            raise click.ClickException(
                                "Activity gap detected; checkpoint retained. Review retention before starting a new cursor file"
                            )
                        if event == "unavailable":
                            raise click.ClickException("Activity ledger unavailable; checkpoint retained")
                        if event in {"activity", "checkpoint"}:
                            click.echo(json.dumps(frame))
                            sys.stdout.flush()
                            _save_checkpoint(cursor_file, binding, frame["id"])
                            cursor = frame["id"]
                            failures = 0
                except httpx.TransportError:
                    failures += 1
                    if not follow or failures > 5:
                        raise
                if not follow:
                    return
                time.sleep(min(2**failures, 30))
    except AgentBomApiError as exc:
        message = (
            "Activity cursor expired; checkpoint retained"
            if exc.status_code == 410
            else f"Activity request failed (HTTP {exc.status_code}); checkpoint retained"
        )
        raise click.ClickException(message) from None
    except (httpx.HTTPError, ValueError, OSError):
        raise click.ClickException("Activity stream or checkpoint unavailable; last checkpoint retained") from None
