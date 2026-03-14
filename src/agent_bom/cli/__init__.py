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
    BANNER,
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
      agent-bom scan                        auto-discover local agents
      agent-bom check lodash@4.17.20        pre-install CVE check
      agent-bom scan --enrich               add NVD CVSS + EPSS + CISA KEV
      agent-bom scan -f html -o report.html --open   HTML dashboard
      agent-bom proxy --command "uvx ..."   runtime enforcement proxy
      agent-bom introspect --all            live server tool listing
      agent-bom api                         start REST API (port 8422)
      agent-bom serve                       API + dashboard (port 8422)

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
