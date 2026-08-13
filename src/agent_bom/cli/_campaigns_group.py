"""CLI commands for risk / remediation campaigns.

Thin surface over the control-plane campaign API (``/v1/campaigns`` and
``/v1/campaigns/{id}/verify``). All business logic — membership derivation,
priority scoring, verification against the canonical findings spine — lives in
``agent_bom.api.routes.campaigns`` and the campaign store; the CLI only renders
what the API returns and is therefore tenant-scoped by the request headers.
"""

from __future__ import annotations

from collections.abc import Mapping

import click

from agent_bom.cli._findings_group import (
    _common_api_options,
    _emit_json,
    _make_client,
    _run_request,
    _string,
)


def _print_campaigns_table(payload: Mapping[str, object]) -> None:
    rows = payload.get("campaigns")
    if not isinstance(rows, list):
        rows = []
    tenant = _string(payload.get("tenant_id")) or "-"
    noun = "campaign" if len(rows) == 1 else "campaigns"
    total_findings = payload.get("total_findings")
    suffix = f", {total_findings} findings in window" if isinstance(total_findings, int) else ""
    click.echo(f"{len(rows)} {noun} (tenant {tenant}{suffix})")
    if payload.get("truncated"):
        click.echo("note: membership incomplete for this window; widen the scan window before verifying.")
    click.echo("id\tpriority\tseverity\tstate\tverification\towner\tsla_due_at\tfindings\ttitle")
    for item in rows:
        if not isinstance(item, dict):
            continue
        owner = _string(item.get("owner")) or "Unassigned"
        click.echo(
            "\t".join(
                [
                    _string(item.get("id")),
                    _string(item.get("priority_score")),
                    _string(item.get("severity")),
                    _string(item.get("state")),
                    _string(item.get("verification_status")),
                    owner,
                    _string(item.get("sla_due_at")) or "-",
                    _string(item.get("finding_count")),
                    _string(item.get("title")),
                ]
            )
        )


@click.group(name="campaigns")
def campaigns_cmd() -> None:
    """Inspect and verify risk/remediation campaigns from the control plane."""


@campaigns_cmd.command("list")
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table", show_default=True)
@_common_api_options
def list_campaigns_cmd(
    api_url: str | None,
    api_key: str | None,
    bearer_token: str | None,
    tenant_id: str | None,
    output_format: str,
) -> None:
    """List campaigns with owner, SLA, priority score, and workflow status."""

    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    payload = _run_request(client, lambda api: api.list_campaigns())
    if output_format == "json":
        _emit_json(payload)
    else:
        _print_campaigns_table(payload)


@campaigns_cmd.command("verify")
@click.argument("campaign_id")
@click.option(
    "--version",
    "version",
    type=int,
    required=True,
    help="Current campaign version, for optimistic concurrency (see the `version` column of `campaigns list`).",
)
@click.option("--format", "output_format", type=click.Choice(["json"]), default="json", show_default=True)
@_common_api_options
def verify_campaign_cmd(
    api_url: str | None,
    api_key: str | None,
    bearer_token: str | None,
    tenant_id: str | None,
    campaign_id: str,
    version: int,
    output_format: str,
) -> None:
    """Verify a campaign against the current findings spine and record its state."""

    client = _make_client(api_url, api_key, bearer_token, tenant_id)
    payload = _run_request(client, lambda api: api.verify_campaign(campaign_id, version=version))
    if output_format == "json":
        _emit_json(payload)


__all__ = ["campaigns_cmd"]
