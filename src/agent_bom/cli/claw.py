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
from agent_bom.cli._grouped_help import GroupedGroup

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


@click.group("fleet", invoke_without_command=True)
@click.pass_context
def fleet_group(ctx: click.Context) -> None:
    """Manage AI agent fleet — discovery, lifecycle, trust scoring.

    \b
    Subcommands:
      sync       Run discovery and sync results into fleet registry
      list       List fleet agents with filtering
      stats      Fleet-wide statistics
      state      Update agent lifecycle state
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@click.command("sync")
@click.option("--quiet", "-q", is_flag=True)
def fleet_sync_cmd(quiet: bool) -> None:
    """Run agent discovery and sync results into fleet registry."""
    from rich.console import Console

    con = Console(stderr=True, quiet=quiet)
    con.print("[dim]Fleet sync requires the API server. Start with:[/dim]")
    con.print("  [cyan]agent-claw api[/cyan]")
    con.print("  [cyan]curl -X POST http://localhost:8422/v1/fleet/sync[/cyan]")


@click.command("list")
@click.option("--state", default=None, help="Filter by lifecycle state")
@click.option("--environment", default=None, help="Filter by environment")
@click.option("--quiet", "-q", is_flag=True)
def fleet_list_cmd(state, environment, quiet) -> None:
    """List fleet agents with optional filtering."""
    from rich.console import Console

    con = Console(stderr=True, quiet=quiet)
    con.print("[dim]Fleet list requires the API server. Start with:[/dim]")
    con.print("  [cyan]agent-claw api[/cyan]")
    con.print("  [cyan]curl http://localhost:8422/v1/fleet[/cyan]")


@click.command("stats")
@click.option("--quiet", "-q", is_flag=True)
def fleet_stats_cmd(quiet) -> None:
    """Fleet-wide statistics (by state, environment, trust score)."""
    from rich.console import Console

    con = Console(stderr=True, quiet=quiet)
    con.print("[dim]Fleet stats requires the API server. Start with:[/dim]")
    con.print("  [cyan]agent-claw api[/cyan]")
    con.print("  [cyan]curl http://localhost:8422/v1/fleet/stats[/cyan]")


fleet_group.add_command(fleet_sync_cmd, "sync")
fleet_group.add_command(fleet_list_cmd, "list")
fleet_group.add_command(fleet_stats_cmd, "stats")

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
