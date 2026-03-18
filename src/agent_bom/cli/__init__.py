"""CLI entry point for agent-bom.

This package splits the CLI into focused modules while preserving the
public API: ``main`` (click group), ``cli_main`` (entry point), and
backward-compatible imports used by tests.
"""

from __future__ import annotations

import sys
import threading

import click

from agent_bom import __version__
from agent_bom.cli._common import (
    BANNER,  # noqa: F401 — re-export for backward compatibility
    SEVERITY_ORDER,
    _build_agents_from_inventory,
    _check_for_update_bg,
    _check_optional_dep,
    _make_console,
    _print_update_notice,
    _update_check_done,
    _update_check_result,
    logger,
    sanitize_env_vars,
)

# Re-export discover_all so that patch("agent_bom.cli.discover_all") keeps
# working in existing tests — although the canonical import path for new
# code is ``agent_bom.discovery.discover_all``.
from agent_bom.discovery import discover_all  # noqa: F401

# ---------------------------------------------------------------------------
# Click group
# ---------------------------------------------------------------------------


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(
    version=__version__,
    prog_name="agent-bom",
    message=(f"agent-bom {__version__}\nPython {sys.version.split()[0]} · {sys.platform}\nDocs:  https://github.com/msaad00/agent-bom"),
)
def main():
    """agent-bom — Security scanner for AI infrastructure.

    \b
    Maps the full trust chain: agent → MCP server → packages → CVEs → blast radius.

    \b
    Quick start:
      agent-bom scan                        auto-detect + scan everything
      agent-bom check flask@2.0.0           pre-install CVE gate
      agent-bom mcp                         discover + scan MCP agents
      agent-bom image nginx:latest          container image scan
      agent-bom fs .                        filesystem / VM scan
      agent-bom iac Dockerfile              IaC misconfigurations
      agent-bom cloud aws                   cloud posture + CIS
      agent-bom run "npx/@mcp/server-fs /tmp" zero-config proxy launch
      agent-bom proxy "npx server"          runtime enforcement

    \b
    Docs:  https://github.com/msaad00/agent-bom
    """
    pass


# ---------------------------------------------------------------------------
# Register subcommands from each module
# ---------------------------------------------------------------------------

from agent_bom.cli.scan import scan  # noqa: E402

main.add_command(scan)

from agent_bom.cli._inventory import completions_cmd, inventory, validate, where  # noqa: E402

main.add_command(inventory)
main.add_command(validate)
main.add_command(where)
main.add_command(completions_cmd, "completions")

from agent_bom.cli._check import check, guard_cmd, verify  # noqa: E402

main.add_command(check)
main.add_command(verify)
main.add_command(guard_cmd, "guard")

from agent_bom.cli._history import diff_cmd, history_cmd, rescan_command  # noqa: E402

main.add_command(history_cmd, "history")
main.add_command(diff_cmd, "diff")
main.add_command(rescan_command, "rescan")

from agent_bom.cli._policy import apply_command, policy_template  # noqa: E402

main.add_command(policy_template, "policy-template")
main.add_command(apply_command, "apply")

from agent_bom.cli._server import api_cmd, mcp_server_cmd, serve_cmd  # noqa: E402

main.add_command(serve_cmd, "serve")
main.add_command(api_cmd, "api")
main.add_command(mcp_server_cmd, "mcp-server")

from agent_bom.cli._registry import registry, schedule  # noqa: E402

main.add_command(schedule)
main.add_command(registry)


from agent_bom.cli._runtime import (  # noqa: E402
    _NoOpDetector,
    audit_replay_cmd,
    protect_cmd,
    proxy_cmd,
    proxy_configure_cmd,
    watch_cmd,
)

main.add_command(proxy_cmd, "proxy")
main.add_command(proxy_configure_cmd, "proxy-configure")
main.add_command(protect_cmd, "protect")
main.add_command(watch_cmd, "watch")
main.add_command(audit_replay_cmd, "audit-replay")

from agent_bom.cli._analysis import (  # noqa: E402
    analytics_cmd,
    dashboard_cmd,
    graph_cmd,
    introspect_cmd,
)

main.add_command(analytics_cmd, "analytics")
main.add_command(graph_cmd, "graph")
main.add_command(dashboard_cmd, "dashboard")
main.add_command(introspect_cmd, "introspect")

from agent_bom.cli._db import db_cmd  # noqa: E402

main.add_command(db_cmd, "db")

# ---------------------------------------------------------------------------
# MCP command group — `agent-bom mcp [inventory|introspect|registry|server]`
# ---------------------------------------------------------------------------
from agent_bom.cli._mcp_group import mcp_group  # noqa: E402

mcp_group.add_command(inventory, "inventory")
mcp_group.add_command(introspect_cmd, "introspect")
mcp_group.add_command(registry, "registry")
mcp_group.add_command(mcp_server_cmd, "server")
mcp_group.add_command(where, "where")
main.add_command(mcp_group)

# ---------------------------------------------------------------------------
# Focused scan commands — `agent-bom image`, `agent-bom fs`, etc.
# ---------------------------------------------------------------------------
from agent_bom.cli._scan_commands import fs_cmd, iac_cmd, image_cmd, sbom_cmd  # noqa: E402

main.add_command(image_cmd)
main.add_command(fs_cmd)
main.add_command(iac_cmd)
main.add_command(sbom_cmd)

# ---------------------------------------------------------------------------
# Cloud command group — `agent-bom cloud [aws|azure|gcp]`
# ---------------------------------------------------------------------------
from agent_bom.cli._cloud_group import cloud_group  # noqa: E402

main.add_command(cloud_group)

# ---------------------------------------------------------------------------
# Run command — `agent-bom run <server>`
# ---------------------------------------------------------------------------
from agent_bom.cli.run import run_cmd  # noqa: E402

main.add_command(run_cmd, "run")


# ---------------------------------------------------------------------------
# Upgrade command
# ---------------------------------------------------------------------------


@main.command("upgrade")
@click.option("--check", "check_only", is_flag=True, help="Only check for updates, don't install.")
def upgrade_cmd(check_only: bool) -> None:
    """Check for and install the latest version of agent-bom."""
    import subprocess as sp
    import urllib.request

    from rich.console import Console

    def _ver_tuple(v: str) -> tuple[int, ...]:
        return tuple(int(x) for x in v.split(".") if x.isdigit())

    con = Console(stderr=True)
    con.print(f"  Current version: [bold]{__version__}[/bold]")

    try:
        from agent_bom.http_client import fetch_json

        data = fetch_json("https://pypi.org/pypi/agent-bom/json", timeout=5)
        latest = data["info"]["version"]
    except Exception:
        con.print("  [red]Could not reach PyPI to check for updates.[/red]")
        raise SystemExit(1)

    if _ver_tuple(latest) <= _ver_tuple(__version__):
        con.print(f"  Latest version:  [bold]{latest}[/bold]")
        con.print("  [green]You are up to date.[/green]")
        return

    con.print(f"  Latest version:  [bold yellow]{latest}[/bold yellow]")

    if check_only:
        con.print("\n  Run: [cyan]pip install --upgrade agent-bom[/cyan]")
        return

    con.print(f"\n  Upgrading agent-bom {__version__} → {latest}...")
    result = sp.run(
        [sys.executable, "-m", "pip", "install", "--upgrade", "agent-bom"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        con.print(f"  [green]Upgraded to agent-bom {latest}[/green]")
    else:
        con.print(f"  [red]Upgrade failed:[/red] {result.stderr.strip()[:200]}")
        con.print("  Try manually: [cyan]pip install --upgrade agent-bom[/cyan]")
        raise SystemExit(1)


# ---------------------------------------------------------------------------
# Backward-compatible re-exports used by tests
# ---------------------------------------------------------------------------
from agent_bom.cli._check import _parse_package_spec  # noqa: E402, F401

# _NoOpDetector is already imported above


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def cli_main() -> None:
    """Entry point with clean top-level error handling and update check.

    Catches unhandled Python exceptions and prints a user-friendly message
    instead of a raw traceback.  Pass --verbose to see the full traceback.
    Starts a background thread to check for newer versions on PyPI.
    """
    from rich.console import Console

    _t = threading.Thread(target=_check_for_update_bg, daemon=True)
    _t.start()

    try:
        main(standalone_mode=True)
    except SystemExit as exc:
        if exc.code == 0:
            _print_update_notice(Console(stderr=True))
        raise
    except KeyboardInterrupt:
        click.echo("\nInterrupted.", err=True)
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001
        verbose = "--verbose" in sys.argv or "-v" in sys.argv
        err_console = Console(stderr=True)
        err_console.print(f"\n[bold red]Error:[/bold red] {exc}")
        if verbose:
            err_console.print_exception(show_locals=False)
        else:
            err_console.print("[dim]Run with --verbose for full traceback.[/dim]")
        sys.exit(1)


__all__ = [
    "main",
    "cli_main",
    "scan",
    "_parse_package_spec",
    "_make_console",
    "_NoOpDetector",
    "discover_all",
]

if __name__ == "__main__":
    cli_main()  # pragma: no cover
