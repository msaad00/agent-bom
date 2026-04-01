"""Report command group — history, diff, analytics, and dashboards.

Usage::

    agent-bom report history             # list saved scan reports
    agent-bom report diff <a> <b>        # diff two scan reports
    agent-bom report rescan              # re-scan to verify remediation
    agent-bom report compliance-narrative report.json
    agent-bom report analytics           # query vulnerability trends
    agent-bom report dashboard           # launch interactive dashboard
"""

from __future__ import annotations

import click


@click.group("report", invoke_without_command=True)
@click.pass_context
def report_group(ctx: click.Context) -> None:
    """Reports — history, diff, analytics, and dashboards.

    \b
    Subcommands:
      history     List saved scan reports
      diff        Diff two scan reports
      rescan      Re-scan vulnerable packages to verify remediation
      compliance-narrative  Generate auditor-facing compliance narrative from a saved scan report
      analytics   Query vulnerability trends (ClickHouse)
      dashboard   Launch interactive Streamlit dashboard
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
