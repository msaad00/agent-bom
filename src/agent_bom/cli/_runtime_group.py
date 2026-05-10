"""Runtime command group — proxy and audit MCP traffic.

Usage::

    agent-bom runtime                    # show runtime subcommands
    agent-bom runtime proxy "npx srv"    # MCP traffic enforcement proxy
    agent-bom runtime audit              # replay proxy audit log
"""

from __future__ import annotations

import click

from agent_bom.cli._grouped_help import SuggestingGroup


@click.group("runtime", cls=SuggestingGroup, invoke_without_command=True)
@click.pass_context
def runtime_group(ctx: click.Context) -> None:
    """Runtime enforcement — proxy and audit MCP traffic.

    \b
    Subcommands:
      proxy       Run MCP server through security proxy
      audit       View and analyze proxy audit log

    Hidden compatibility commands:
      protect     Runtime protection engine (8 behavioral detectors)
      configure   Auto-configure proxy for discovered servers
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
