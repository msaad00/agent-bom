"""MCP command group — discover, scan, and manage MCP agents and servers.

Usage::

    agent-bom mcp                    # discover + scan MCP agents
    agent-bom mcp inventory          # discover only, no CVE scan
    agent-bom mcp introspect         # live server tool listing
    agent-bom mcp registry           # browse server registry
    agent-bom mcp server             # start agent-bom as MCP server
"""

from __future__ import annotations

import click


@click.group("mcp", invoke_without_command=True)
@click.pass_context
def mcp_group(ctx: click.Context) -> None:
    """Discover, scan, and manage MCP agents and servers.

    Run without a subcommand to discover all MCP agents and scan for CVEs.

    \b
    Subcommands:
      inventory    Discover agents and servers (no CVE scan)
      introspect   Connect to live servers, list their tools
      registry     Browse the MCP server security registry
      server       Start agent-bom as an MCP server
    """
    if ctx.invoked_subcommand is None:
        # Default: run full MCP scan (same as `agent-bom scan` but MCP-focused)
        from agent_bom.cli.scan import scan

        ctx.invoke(scan)
