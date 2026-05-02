"""Report command group — history, diff, analytics, and dashboard helpers.

Usage::

    agent-bom report history             # list saved scan reports
    agent-bom report diff <a> <b>        # diff two scan reports or SBOMs
    agent-bom report rescan              # re-scan to verify remediation
    agent-bom report compliance-narrative report.json
    agent-bom report analytics           # query vulnerability trends
    agent-bom serve                      # launch bundled API + Next.js dashboard
    agent-bom report dashboard           # legacy Streamlit compatibility dashboard
"""

from __future__ import annotations

import click


@click.group("report", invoke_without_command=True)
@click.pass_context
def report_group(ctx: click.Context) -> None:
    """Reports — history, diff, analytics, and dashboard helpers.

    \b
    Subcommands:
      history     List saved scan reports
      diff        Diff two scan reports or CycloneDX/SPDX SBOMs
      rescan      Re-scan vulnerable packages to verify remediation
      compliance-narrative  Generate auditor-facing compliance narrative from a saved scan report
      analytics   Query vulnerability trends (ClickHouse)
      dashboard   Launch legacy Streamlit compatibility dashboard; use `agent-bom serve` for the bundled Next.js UI
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
