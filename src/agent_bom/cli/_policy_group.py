"""Policy command group — checks, templates, and remediation.

Usage::

    agent-bom agents --policy policy.json     # evaluate scan results against policy
    agent-bom policy check pip flask 2.0.0    # pre-install package guard
    agent-bom policy template                 # generate starter policy file
    agent-bom policy apply <scan.json>        # apply remediation fixes
"""

from __future__ import annotations

import click


@click.group("policy", invoke_without_command=True)
@click.pass_context
def policy_group(ctx: click.Context) -> None:
    """Policy management — install guards, templates, and remediation.

    \b
    Subcommands:
      check       Pre-install package guard for pip/npm/npx packages
      template    Generate a starter policy file with common rules
      apply       Apply remediation fixes from scan result JSON

    \b
    Report policy gates run through:
      agent-bom agents --policy PATH
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
