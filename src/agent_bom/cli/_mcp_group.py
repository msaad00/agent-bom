"""MCP command group — discover, scan, and manage MCP agents and servers.

Usage::

    agent-bom mcp                    # discover + scan MCP agents
    agent-bom mcp scan <server>      # audit a single MCP server package
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
      scan         Check a single MCP server package before adding it
      inventory    Discover agents and servers (no CVE scan)
      introspect   Connect to live servers, list their tools
      registry     Browse the MCP server security registry
      server       Start agent-bom as an MCP server
    """
    if ctx.invoked_subcommand is None:
        # Default: run full MCP scan (same as `agent-bom scan` but MCP-focused)
        from agent_bom.cli.agents import scan

        ctx.invoke(scan)


@mcp_group.command("scan")
@click.argument("server_spec")
@click.option(
    "--ecosystem",
    "-e",
    type=click.Choice(["npm", "pypi"]),
    help="Package ecosystem for the MCP server package when it cannot be inferred from the spec",
)
@click.option("--quiet", "-q", is_flag=True, help="Only print vuln count, no details")
@click.option("--no-color", is_flag=True, help="Disable colored output")
@click.option("--exit-zero", is_flag=True, help="Exit 0 even when vulnerabilities are found")
def mcp_scan_cmd(server_spec: str, ecosystem: str | None, quiet: bool, no_color: bool, exit_zero: bool) -> None:
    """Check a single MCP server package or npx/uvx spec before adding it."""
    from agent_bom.cli._check import check

    if not server_spec.strip():
        raise click.UsageError("MCP server package spec cannot be empty.")

    callback = check.callback
    if callback is None:
        raise click.ClickException("check command is unavailable")
    callback(
        package_spec=server_spec,
        ecosystem=ecosystem,
        quiet=quiet,
        no_color=no_color,
        output_format="console",
        output_path=None,
        exit_zero=exit_zero,
    )
