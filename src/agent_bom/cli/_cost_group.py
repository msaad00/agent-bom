"""Cost command group — FinOps posture for LLM spend.

Human-facing, read-only views over the same cost store the API exposes under
``/v1/observability/costs``. No spend is mutated; these commands only report.

Usage::

    agent-bom cost forecast                 # burn rate + budget runway
    agent-bom cost forecast --agent planner  # scope to one agent
    agent-bom cost allocation                # by cost-center / allocation tag
    agent-bom cost chargeback                # alias for allocation
"""

from __future__ import annotations

import json
from typing import Optional

import click

from agent_bom.cli._grouped_help import SuggestingGroup

_DEFAULT_TENANT = "default"


@click.group("cost", cls=SuggestingGroup)
def cost_group() -> None:
    """LLM FinOps — spend forecast and chargeback rollups.

    Read-only posture over ingested OTel GenAI cost records (the same data the
    API serves at ``/v1/observability/costs``). Reference only — no spend or
    budget is modified.

    \b
    Subcommands:
      forecast     Burn rate + budget-runway projection
      allocation   Spend rollup by cost-center / allocation tag (alias: chargeback)
    """


def _money(value: Optional[float]) -> str:
    if value is None:
        return "—"
    return f"${value:,.2f}"


@click.command("forecast")
@click.option("--tenant", default=_DEFAULT_TENANT, show_default=True, help="Tenant to scope the forecast to.")
@click.option("--agent", default=None, help="Scope the forecast to one agent (otherwise tenant-wide).")
@click.option("--limit", default=10000, show_default=True, help="Max records to project from.")
@click.option("-f", "--format", "output_format", type=click.Choice(["console", "json"]), default="console")
def forecast_cmd(tenant: str, agent: Optional[str], limit: int, output_format: str) -> None:
    """Project burn rate and budget runway from recent LLM spend."""
    from agent_bom.api.cost_forecast import forecast_for_tenant

    report = forecast_for_tenant(tenant, agent=agent, limit=max(1, min(limit, 100000)))

    if output_format == "json":
        click.echo(json.dumps(report, indent=2, sort_keys=True))
        return

    from rich.console import Console
    from rich.table import Table

    con = Console()
    scope = f"agent [bold]{agent}[/bold]" if agent else "tenant-wide"
    con.print(f"\n  [bold]LLM spend forecast[/bold] [dim]· tenant {tenant} · {scope}[/dim]")

    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="dim")
    table.add_column()
    table.add_row("status", str(report.get("status", "unknown")))
    table.add_row("current spend", _money(report.get("current_spend_usd")))
    table.add_row("budget limit", _money(report.get("budget_limit_usd")))
    rate = report.get("burn_rate_usd_per_day")
    basis = report.get("burn_rate_basis")
    table.add_row("burn rate/day", _money(rate) + (f" [dim]({basis})[/dim]" if basis else ""))
    table.add_row("projected period spend", _money(report.get("projected_period_spend_usd")))
    days = report.get("days_remaining")
    table.add_row("days remaining", "—" if days is None else f"{days:g}")
    table.add_row("projected exhaustion", str(report.get("projected_exhaustion_at") or "—"))
    con.print(table)
    con.print()


@click.command("allocation")
@click.option("--tenant", default=_DEFAULT_TENANT, show_default=True, help="Tenant to scope the rollup to.")
@click.option("--tag", default=None, help="Add a showback slice by this freeform allocation tag (e.g. team, project).")
@click.option("--limit", default=10000, show_default=True, help="Max records to roll up.")
@click.option("-f", "--format", "output_format", type=click.Choice(["console", "json"]), default="console")
def allocation_cmd(tenant: str, tag: Optional[str], limit: int, output_format: str) -> None:
    """Show spend rolled up by cost-center (and optionally an allocation tag)."""
    from agent_bom.api.cost_store import get_cost_store, summarize, summarize_by_tag

    store = get_cost_store()
    records = store.list_records(tenant, limit=max(1, min(limit, 100000)))
    report = summarize(records)
    report["tenant_id"] = tenant
    if tag:
        report["tag_rollup"] = summarize_by_tag(records, tag.strip()[:60])

    if output_format == "json":
        click.echo(json.dumps(report, indent=2, sort_keys=True))
        return

    from rich.console import Console
    from rich.table import Table

    con = Console()
    con.print(
        f"\n  [bold]LLM spend allocation[/bold] [dim]· tenant {tenant} · "
        f"{report['total_calls']} calls · {_money(report['total_cost_usd'])} total[/dim]"
    )

    cc_table = Table(title="By cost center", title_justify="left", title_style="bold")
    cc_table.add_column("Cost center")
    cc_table.add_column("Calls", justify="right")
    cc_table.add_column("Cost", justify="right")
    for row in report["by_cost_center"]:
        cc_table.add_row(row["key"], str(row["calls"]), _money(row["cost_usd"]))
    if not report["by_cost_center"]:
        cc_table.add_row("[dim]no spend recorded[/dim]", "0", _money(0.0))
    con.print(cc_table)

    if tag:
        tag_table = Table(title=f"By tag: {tag}", title_justify="left", title_style="bold")
        tag_table.add_column("Value")
        tag_table.add_column("Calls", justify="right")
        tag_table.add_column("Cost", justify="right")
        for row in report["tag_rollup"]["by_tag"]:
            tag_table.add_row(row["key"], str(row["calls"]), _money(row["cost_usd"]))
        if not report["tag_rollup"]["by_tag"]:
            tag_table.add_row("[dim]no spend recorded[/dim]", "0", _money(0.0))
        con.print(tag_table)
    con.print()


cost_group.add_command(forecast_cmd, "forecast")
cost_group.add_command(allocation_cmd, "allocation")

# `chargeback` is an alias for `allocation` — same impl, finance-friendly name.
import copy as _copy  # noqa: E402

_chargeback_cmd = _copy.copy(allocation_cmd)
_chargeback_cmd.name = "chargeback"
cost_group.add_command(_chargeback_cmd, "chargeback")
