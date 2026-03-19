"""Policy command group — templates and remediation.

Usage::

    agent-bom policy template            # generate starter policy file
    agent-bom policy apply <scan.json>   # apply remediation fixes
"""

from __future__ import annotations

import click


@click.group("policy", invoke_without_command=True)
@click.pass_context
def policy_group(ctx: click.Context) -> None:
    """Policy management — templates and remediation.

    \b
    Subcommands:
      template    Generate a starter policy file with common rules
      apply       Apply remediation fixes from scan result JSON
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
