"""Runtime command group — proxy, protect, watch, and audit MCP traffic.

Usage::

    agent-bom runtime                    # show runtime subcommands
    agent-bom runtime proxy "npx srv"    # MCP traffic enforcement proxy
    agent-bom runtime protect            # standalone protection engine
    agent-bom runtime watch              # filesystem watch on MCP configs
    agent-bom runtime audit              # replay proxy audit log
    agent-bom runtime configure          # auto-configure proxy for servers
"""

from __future__ import annotations

import click


@click.group("runtime", invoke_without_command=True)
@click.pass_context
def runtime_group(ctx: click.Context) -> None:
    """Runtime enforcement — proxy, protect, watch, and audit MCP traffic.

    \b
    Subcommands:
      proxy       Run MCP server through security proxy
      protect     Runtime protection engine (7 behavioral detectors)
      watch       Watch MCP configs for drift and alert
      audit       View and analyze proxy audit log
      configure   Auto-configure proxy for discovered servers
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
