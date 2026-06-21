"""Identity command group — non-human identity (NHI) governance.

Human-facing, read-only / reference-only views over the same NHI governance
the API exposes under ``/v1/identities/...``. These commands never read or
store secret material and never execute a revocation.

Usage::

    agent-bom identity credential-expiry         # expiring/overdue credentials
    agent-bom identity discover                   # discover Okta/Entra NHIs (gated)
    agent-bom identity access-review              # list recertification campaigns
    agent-bom identity access-review --campaign C # one campaign + its items
"""

from __future__ import annotations

import json
from typing import Optional

import click

from agent_bom.cli._grouped_help import SuggestingGroup

_DEFAULT_TENANT = "default"

# Per-state colour for the compact credential-expiry table.
_STATE_STYLE = {
    "expired": "bold red",
    "overdue": "bold red",
    "rotation_due": "yellow",
    "near_expiry": "yellow",
    "unknown_age": "dim",
    "ok": "green",
}


@click.group("identity", cls=SuggestingGroup)
def identity_group() -> None:
    """Non-human identity governance — credentials, discovery, access reviews.

    Read-only and reference-only. Mirrors the API's ``/v1/identities`` and
    ``/v1/auth/secrets/credential-expiry`` surfaces. Discovery is gated behind
    the ``AGENT_BOM_OKTA_DISCOVERY`` / ``AGENT_BOM_ENTRA_DISCOVERY`` flags and
    never runs a network call for a provider whose flag is off. No secret value
    is ever printed and no revocation is ever executed.

    \b
    Subcommands:
      credential-expiry   Expiring / overdue credential posture
      discover            Discover Okta / Entra NHIs (gated, reference-only)
      access-review       List or get NHI recertification campaigns
    """


@click.command("credential-expiry")
@click.option(
    "--no-control-plane",
    is_flag=True,
    help="Exclude configured control-plane secrets (evaluate only discovered NHIs).",
)
@click.option(
    "--include-discovered/--no-include-discovered",
    default=True,
    show_default=True,
    help="Fold gated Okta/Entra NHI credentials into the posture.",
)
@click.option("-f", "--format", "output_format", type=click.Choice(["console", "json"]), default="console")
def credential_expiry_cmd(no_control_plane: bool, include_discovered: bool, output_format: str) -> None:
    """Show expiring, overdue, and rotation-due credentials (never secret values)."""
    from agent_bom.api.credential_expiry import describe_credential_expiry_posture

    discovered = _discover_nhi_credentials() if include_discovered else None
    report = describe_credential_expiry_posture(
        discovered,
        include_control_plane=not no_control_plane,
    )

    if output_format == "json":
        click.echo(json.dumps(report, indent=2, sort_keys=True))
        return

    from rich.console import Console
    from rich.table import Table

    con = Console()
    status = report.get("status", "unknown")
    status_style = {"blocked": "bold red", "attention_required": "yellow", "ok": "green"}.get(status, "dim")
    con.print(
        f"\n  [bold]Credential expiry posture[/bold] [dim]· "
        f"{report.get('evaluated', 0)} evaluated[/dim] · [{status_style}]{status}[/{status_style}]"
    )
    con.print(f"  [dim]{report.get('message', '')}[/dim]")

    action = report.get("action_required") or []
    if not action:
        con.print("  [green]No credentials require attention.[/green]\n")
        return

    table = Table()
    table.add_column("Credential")
    table.add_column("Provider")
    table.add_column("State")
    table.add_column("Age (d)", justify="right")
    table.add_column("Expires in (d)", justify="right")
    for item in action:
        state = str(item.get("state", ""))
        style = _STATE_STYLE.get(state, "")
        table.add_row(
            str(item.get("name") or item.get("id") or "—"),
            str(item.get("provider") or "—"),
            f"[{style}]{state}[/{style}]" if style else state,
            "—" if item.get("age_days") is None else str(item["age_days"]),
            "—" if item.get("days_until_expiry") is None else str(item["days_until_expiry"]),
        )
    con.print(table)
    con.print()


def _discover_nhi_credentials() -> list[dict[str, object]]:
    """Run gated Okta/Entra NHI discovery and return reference-only cred dicts.

    Reuses the same discovery the API uses; each provider stays gated by its own
    env flag, so a disabled provider contributes nothing and runs no network
    call. Never returns secret material.
    """
    from agent_bom.graph.nhi_overlay import merge_discovery_results
    from agent_bom.identity import (
        discover_entra_non_human_identities,
        discover_okta_non_human_identities,
    )

    merged = merge_discovery_results([discover_okta_non_human_identities(), discover_entra_non_human_identities()])
    return list(merged.get("identities", []))


@click.command("discover")
@click.option(
    "--provider",
    type=click.Choice(["okta", "entra", "all"]),
    default="all",
    show_default=True,
    help="Restrict discovery to one identity provider.",
)
@click.option("-f", "--format", "output_format", type=click.Choice(["console", "json"]), default="console")
def discover_cmd(provider: str, output_format: str) -> None:
    """Discover Okta / Entra non-human identities (gated, reference-only)."""
    from agent_bom.graph.nhi_overlay import merge_discovery_results
    from agent_bom.identity import (
        discover_entra_non_human_identities,
        discover_okta_non_human_identities,
    )

    results = []
    requested: list[str] = []
    if provider in ("okta", "all"):
        results.append(discover_okta_non_human_identities())
        requested.append("okta")
    if provider in ("entra", "all"):
        results.append(discover_entra_non_human_identities())
        requested.append("entra")
    merged = merge_discovery_results(results)
    # The merge layer can only name a provider once it has identities; label the
    # empty/disabled ones from the request order so the compact view stays clear.
    providers = [
        {**p, "provider": p.get("provider") or requested[i]} if i < len(requested) else p for i, p in enumerate(merged["providers"])
    ]
    report = {
        "schema_version": "identity.nhi.discovery.v1",
        "status": merged["status"],
        "providers": providers,
        "count": len(merged["identities"]),
        "identities": merged["identities"],
        "warnings": merged["warnings"],
    }

    if output_format == "json":
        click.echo(json.dumps(report, indent=2, sort_keys=True))
        return

    from rich.console import Console
    from rich.table import Table

    con = Console()
    con.print(f"\n  [bold]NHI discovery[/bold] [dim]· {report['count']} identities[/dim]")

    prov_bits = []
    for prov in report["providers"]:
        pstatus = prov.get("status")
        tag = "disabled" if pstatus == "disabled" else str(pstatus)
        prov_bits.append(f"{prov.get('provider')}={tag}({prov.get('count', 0)})")
    con.print("  [dim]providers:[/dim] " + (", ".join(prov_bits) if prov_bits else "none"))

    if report["count"] == 0:
        if all(p.get("status") == "disabled" for p in report["providers"]):
            con.print(
                "  [yellow]Discovery is disabled.[/yellow] Enable with "
                "[cyan]AGENT_BOM_OKTA_DISCOVERY=1[/cyan] / [cyan]AGENT_BOM_ENTRA_DISCOVERY=1[/cyan].\n"
            )
        else:
            con.print("  [dim]No non-human identities discovered.[/dim]\n")
        return

    table = Table()
    table.add_column("Identity")
    table.add_column("Type")
    table.add_column("Provider")
    table.add_column("Status")
    table.add_column("Expires")
    for ident in report["identities"]:
        table.add_row(
            str(ident.get("name") or ident.get("identity_id") or "—"),
            str(ident.get("identity_type") or "—"),
            str(ident.get("provider") or "—"),
            str(ident.get("status") or "—"),
            str(ident.get("credential_expires_at") or "—"),
        )
    con.print(table)
    con.print()


@click.command("access-review")
@click.option("--tenant", default=_DEFAULT_TENANT, show_default=True, help="Tenant to list campaigns for.")
@click.option("--campaign", "campaign_id", default=None, help="Show one campaign and its review items.")
@click.option("--limit", default=200, show_default=True, help="Max campaigns to list.")
@click.option("-f", "--format", "output_format", type=click.Choice(["console", "json"]), default="console")
def access_review_cmd(tenant: str, campaign_id: Optional[str], limit: int, output_format: str) -> None:
    """List access-review campaigns, or show one with its review items."""
    from agent_bom.api.access_review import get_access_review_store, refresh_campaign_status

    store = get_access_review_store()

    if campaign_id:
        campaign = refresh_campaign_status(store, tenant_id=tenant, campaign_id=campaign_id)
        if campaign is None:
            report: dict[str, object] = {
                "schema_version": "identity.access_review.v1",
                "tenant_id": tenant,
                "found": False,
                "campaign": None,
                "items": [],
            }
        else:
            items = store.list_items(campaign_id, tenant)
            report = {
                "schema_version": "identity.access_review.v1",
                "tenant_id": tenant,
                "found": True,
                "campaign": campaign.to_public_dict(),
                "count": len(items),
                "items": [i.to_public_dict() for i in items],
            }
        if output_format == "json":
            click.echo(json.dumps(report, indent=2, sort_keys=True))
            return
        _render_one_campaign(report)
        return

    bounded = max(1, min(limit, 1000))
    campaigns = store.list_campaigns(tenant, limit=bounded)
    refreshed = [refresh_campaign_status(store, tenant_id=tenant, campaign_id=c.campaign_id) or c for c in campaigns]
    report = {
        "schema_version": "identity.access_review.v1",
        "tenant_id": tenant,
        "count": len(refreshed),
        "campaigns": [c.to_public_dict() for c in refreshed],
    }

    if output_format == "json":
        click.echo(json.dumps(report, indent=2, sort_keys=True))
        return

    from rich.console import Console
    from rich.table import Table

    con = Console()
    con.print(f"\n  [bold]Access-review campaigns[/bold] [dim]· tenant {tenant} · {report['count']} total[/dim]")
    if not refreshed:
        con.print("  [dim]No access-review campaigns. Create one via the API or MCP.[/dim]\n")
        return
    table = Table()
    table.add_column("Campaign")
    table.add_column("Name")
    table.add_column("Status")
    table.add_column("Items", justify="right")
    table.add_column("Decided", justify="right")
    table.add_column("Due")
    for c in refreshed:
        d = c.to_public_dict()
        table.add_row(
            str(d.get("campaign_id")),
            str(d.get("name")),
            _status_styled(str(d.get("status"))),
            str(d.get("item_count", 0)),
            str(d.get("decided_count", 0)),
            str(d.get("due_at") or "—"),
        )
    con.print(table)
    con.print()


def _status_styled(status: str) -> str:
    style = {"completed": "green", "overdue": "bold red", "in_progress": "yellow", "open": "cyan"}.get(status, "")
    return f"[{style}]{status}[/{style}]" if style else status


def _render_one_campaign(report: dict) -> None:
    from rich.console import Console
    from rich.table import Table

    con = Console()
    if not report.get("found"):
        con.print(f"\n  [yellow]Access-review campaign not found[/yellow] [dim](tenant {report.get('tenant_id')})[/dim]\n")
        return
    campaign = report["campaign"]
    con.print(
        f"\n  [bold]{campaign.get('name')}[/bold] [dim]· {campaign.get('campaign_id')}[/dim] · "
        f"{_status_styled(str(campaign.get('status')))}"
    )
    con.print(
        f"  [dim]items {campaign.get('item_count', 0)} · decided {campaign.get('decided_count', 0)} · "
        f"due {campaign.get('due_at') or '—'}[/dim]"
    )
    items = report.get("items") or []
    if not items:
        con.print("  [dim]No review items.[/dim]\n")
        return
    table = Table()
    table.add_column("Subject")
    table.add_column("Type")
    table.add_column("Provider")
    table.add_column("Perms", justify="right")
    table.add_column("Privileged")
    table.add_column("Decision")
    for item in items:
        table.add_row(
            str(item.get("subject_name") or item.get("subject_id") or "—"),
            str(item.get("subject_type") or "—"),
            str(item.get("provider") or "—"),
            str(item.get("permission_count", 0)),
            "yes" if item.get("privileged") else "—",
            str(item.get("decision") or "pending"),
        )
    con.print(table)
    con.print()


identity_group.add_command(credential_expiry_cmd, "credential-expiry")
identity_group.add_command(discover_cmd, "discover")
identity_group.add_command(access_review_cmd, "access-review")
