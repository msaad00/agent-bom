"""agent-claw — Fleet governance and control plane for AI agents.

Manages AI agent fleets at scale: discovery, lifecycle, trust scoring,
scheduling, reporting, and integrations with Jira/Slack/ServiceNow/SIEM.

Entry point: ``agent-claw`` (registered in pyproject.toml).
"""

from __future__ import annotations

import sys
from collections import OrderedDict

import click

from agent_bom import __version__
from agent_bom.cli._entry import make_entry_point
from agent_bom.cli._grouped_help import GroupedGroup, SuggestingGroup

# ── Help categories ──────────────────────────────────────────────────────────

CLAW_CATEGORIES: OrderedDict[str, list[str]] = OrderedDict(
    [
        ("Fleet", ["fleet"]),
        ("Server", ["serve", "api"]),
        ("Scheduling", ["schedule"]),
        ("Reporting", ["report"]),
        ("Integrations", ["connectors"]),
    ]
)

# ── Click group ──────────────────────────────────────────────────────────────


@click.group(
    cls=GroupedGroup,
    command_categories=CLAW_CATEGORIES,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.version_option(
    version=__version__,
    prog_name="agent-claw",
    message=(f"agent-claw {__version__}\nPython {sys.version.split()[0]} · {sys.platform}\nPart of: https://github.com/msaad00/agent-bom"),
)
def claw():
    """agent-claw — Fleet governance and control plane for AI agents.

    \b
    Manage and govern your AI agent fleet at scale:
    · Fleet lifecycle        · Trust scoring       · Scheduling
    · API server             · Dashboards          · SIEM integration

    \b
    Quick start:
      agent-claw serve                           API + dashboard
      agent-claw api                             REST API headless
      agent-claw fleet sync                      discovery → fleet
      agent-claw schedule add -n nightly -c "0 2 * * *"
      agent-claw report analytics --days 30

    \b
    Docs: https://github.com/msaad00/agent-bom
    """
    pass


# ── Fleet command group (new) ────────────────────────────────────────────────


@click.group("fleet", cls=SuggestingGroup, invoke_without_command=True)
@click.pass_context
def fleet_group(ctx: click.Context) -> None:
    """Manage AI agent fleet — discovery, lifecycle, trust scoring.

    \b
    Subcommands:
      sync       Run discovery and sync results into fleet registry
      list       List fleet agents with filtering
      stats      Fleet-wide statistics
      reconcile-k8s  Compare Kubernetes inventory snapshots
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@click.command("sync")
@click.option(
    "--project",
    "project_dir",
    type=click.Path(exists=True, file_okay=False),
    default=None,
    help="Restrict discovery to a project directory",
)
@click.option(
    "--push-url",
    default=None,
    envvar="AGENT_BOM_PUSH_URL",
    metavar="URL",
    help="Control-plane fleet sync URL (full /v1/fleet/sync or API base URL)",
)
@click.option(
    "--push-api-key",
    default=None,
    envvar="AGENT_BOM_PUSH_API_KEY",
    metavar="TOKEN",
    help="Bearer token for fleet sync",
)
@click.option("--source-id", default=None, envvar="AGENT_BOM_PUSH_SOURCE_ID", help="Stable endpoint source identifier")
@click.option("--quiet", "-q", is_flag=True)
def fleet_sync_cmd(project_dir: str | None, push_url: str | None, push_api_key: str | None, source_id: str | None, quiet: bool) -> None:
    """Run agent discovery and sync results into the fleet registry."""
    from rich.console import Console

    from agent_bom.fleet.sync_client import run_fleet_sync

    con = Console(stderr=True, quiet=quiet)
    try:
        result = run_fleet_sync(
            push_url=push_url,
            api_key=push_api_key,
            project_dir=project_dir,
            source_id=source_id,
        )
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    except RuntimeError as exc:
        raise click.ClickException(str(exc)) from exc

    if not quiet:
        con.print(
            "[green]Fleet sync complete[/green] "
            f"discovered={result.get('discovered', 0)} "
            f"synced={result.get('synced', 0)} "
            f"new={result.get('new', 0)} "
            f"updated={result.get('updated', 0)} "
            f"source_id={result.get('source_id', '')}"
        )


@click.command("list")
@click.option("--state", default=None, help="Filter by lifecycle state")
@click.option("--environment", default=None, help="Filter by environment")
@click.option("--quiet", "-q", is_flag=True)
def fleet_list_cmd(state, environment, quiet) -> None:
    """List fleet agents with optional filtering."""
    from rich.console import Console

    con = Console(stderr=True, quiet=quiet)
    con.print("[dim]Fleet list requires the API server. Start with:[/dim]")
    con.print("  [cyan]agent-bom api[/cyan]")
    con.print("  [cyan]curl http://localhost:8422/v1/fleet[/cyan]")
    raise click.ClickException("fleet list is not available as a local-only command; call the API endpoint instead")


@click.command("stats")
@click.option("--quiet", "-q", is_flag=True)
def fleet_stats_cmd(quiet) -> None:
    """Fleet-wide statistics (by state, environment, trust score)."""
    from rich.console import Console

    con = Console(stderr=True, quiet=quiet)
    con.print("[dim]Fleet stats requires the API server. Start with:[/dim]")
    con.print("  [cyan]agent-bom api[/cyan]")
    con.print("  [cyan]curl http://localhost:8422/v1/fleet/stats[/cyan]")
    raise click.ClickException("fleet stats is not available as a local-only command; call the API endpoint instead")


fleet_group.add_command(fleet_sync_cmd, "sync")
fleet_group.add_command(fleet_list_cmd, "list")
fleet_group.add_command(fleet_stats_cmd, "stats")


@click.command("reconcile-k8s")
@click.option("--previous", type=click.Path(exists=True), required=True, help="Previous inventory JSON snapshot")
@click.option("--current", type=click.Path(exists=True), required=True, help="Current inventory JSON snapshot")
@click.option("--stale-after-seconds", type=int, default=6 * 60 * 60, show_default=True)
@click.option("--json", "as_json", is_flag=True, help="Emit the reconciliation contract as JSON")
def fleet_reconcile_k8s_cmd(previous: str, current: str, stale_after_seconds: int, as_json: bool) -> None:
    """Compare Kubernetes inventory snapshots for continuous fleet reconciliation."""
    import json

    from rich.console import Console

    from agent_bom.fleet.k8s_reconcile import (
        load_k8s_inventory_snapshot,
        reconcile_k8s_inventory,
    )

    result = reconcile_k8s_inventory(
        load_k8s_inventory_snapshot(previous),
        load_k8s_inventory_snapshot(current),
        stale_after_seconds=stale_after_seconds,
    )
    if as_json:
        click.echo(json.dumps(result, indent=2, sort_keys=True))
        return

    con = Console()
    summary = result["summary"]
    con.print("[bold]Kubernetes inventory reconciliation[/bold]")
    con.print(
        "  "
        f"current={summary['current']} previous={summary['previous']} "
        f"added={summary['added']} changed={summary['changed']} "
        f"missing={summary['missing']} stale={summary['stale']}"
    )


fleet_group.add_command(fleet_reconcile_k8s_cmd, "reconcile-k8s")

# ── Connectors command (new) ─────────────────────────────────────────────────


@click.command("connectors")
@click.option("--quiet", "-q", is_flag=True)
def connectors_cmd(quiet) -> None:
    """Manage external integrations — Jira, Slack, ServiceNow, SIEM.

    \b
    Configure via .agent-bom.yaml or environment variables:
      AGENT_BOM_ALERT_WEBHOOK      Slack/Teams webhook URL
      JIRA_URL / JIRA_TOKEN        Jira integration
      SERVICENOW_INSTANCE          ServiceNow integration
    """
    from rich.console import Console

    con = Console(stderr=True, quiet=quiet)
    con.print("[dim]Connectors are configured via .agent-bom.yaml or env vars.[/dim]")
    con.print("  [cyan]agent-claw api[/cyan]")
    con.print("  [cyan]curl http://localhost:8422/v1/connectors[/cyan]")


# ── Register commands ────────────────────────────────────────────────────────

from agent_bom.cli._registry import schedule  # noqa: E402
from agent_bom.cli._report_group import report_group  # noqa: E402
from agent_bom.cli._server import api_cmd, serve_cmd  # noqa: E402

claw.add_command(fleet_group, "fleet")
claw.add_command(serve_cmd, "serve")
claw.add_command(api_cmd, "api")
claw.add_command(schedule, "schedule")
claw.add_command(report_group, "report")
claw.add_command(connectors_cmd, "connectors")

# ── Entry point ──────────────────────────────────────────────────────────────

claw_main = make_entry_point(claw, "agent-claw")
