"""CLI entry point for agent-bom.

This package splits the CLI into focused modules while preserving the
public API: ``main`` (click group), ``cli_main`` (entry point), and
backward-compatible imports used by tests.
"""

from __future__ import annotations

import sys

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

# ---------------------------------------------------------------------------
# Click group
# ---------------------------------------------------------------------------
from agent_bom.cli._grouped_help import GroupedGroup  # noqa: E402 — needed before group def

# Re-export discover_all so that patch("agent_bom.cli.discover_all") keeps
# working in existing tests — although the canonical import path for new
# code is ``agent_bom.discovery.discover_all``.
from agent_bom.discovery import discover_all  # noqa: F401


@click.group(cls=GroupedGroup, context_settings={"help_option_names": ["-h", "--help"]})
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
      agent-bom agents                      AI agent discovery + scan
      agent-bom image nginx:latest          container image scan
      agent-bom iac Dockerfile k8s/         IaC misconfigurations
      agent-bom cloud aws                   cloud posture + CIS
      agent-bom proxy "npx server"          MCP security proxy
      agent-bom check flask@2.0.0           pre-install CVE gate

    \b
    Docs:  https://github.com/msaad00/agent-bom
    """
    pass


# ---------------------------------------------------------------------------
# Register subcommands from each module
# ---------------------------------------------------------------------------

from agent_bom.cli.agents import scan as _agents_cmd  # noqa: E402

# 'agents' is the primary visible command.
main.add_command(_agents_cmd, "agents")

# 'scan' kept as hidden backward-compat CLI alias (50+ tests + CI use it).
# Clone the command object so hiding doesn't affect 'agents'.
import copy as _copy  # noqa: E402

_scan_hidden = _copy.copy(_agents_cmd)
_scan_hidden.hidden = True
_scan_hidden.name = "scan"
main.commands["scan"] = _scan_hidden

from agent_bom.cli._inventory import completions_cmd, inventory, validate, where  # noqa: E402

# inventory + where are under `mcp` group — no top-level duplicate
_validate_hidden = _copy.copy(validate)
_validate_hidden.hidden = True  # Use `mcp validate` or `iac validate`
_validate_hidden.name = "validate"
main.commands["validate"] = _validate_hidden
main.add_command(completions_cmd, "completions")

from agent_bom.cli._check import check, guard_cmd, verify  # noqa: E402

main.add_command(check)
main.add_command(verify)
# guard moved to policy check — keep hidden alias for backward compat
main.add_command(guard_cmd, "guard")
main.commands["guard"].hidden = True

from agent_bom.cli._history import diff_cmd, history_cmd, rescan_command  # noqa: E402

# history, diff, rescan moved to `report` group (Batch 3)
from agent_bom.cli._policy import apply_command, policy_template  # noqa: E402

# ---------------------------------------------------------------------------
# Policy command group — `agent-bom policy [template|apply]`
# ---------------------------------------------------------------------------
from agent_bom.cli._policy_group import policy_group  # noqa: E402

policy_group.add_command(policy_template, "template")
policy_group.add_command(apply_command, "apply")
policy_group.add_command(guard_cmd, "check")  # guard → policy check
main.add_command(policy_group)

from agent_bom.cli._server import api_cmd, mcp_server_cmd, serve_cmd  # noqa: E402

main.add_command(serve_cmd, "serve")
main.add_command(api_cmd, "api")
# mcp-server is under `mcp server` — no top-level duplicate

from agent_bom.cli._registry import registry, schedule  # noqa: E402

main.add_command(schedule)
main.add_command(registry)
main.commands["registry"].hidden = True  # Available under `mcp registry`


from agent_bom.cli._runtime import (  # noqa: E402
    _NoOpDetector,
    audit_replay_cmd,
    protect_cmd,
    proxy_cmd,
    proxy_configure_cmd,
    watch_cmd,
)

# ---------------------------------------------------------------------------
# Runtime command group — `agent-bom runtime [proxy|protect|watch|audit|configure]`
# ---------------------------------------------------------------------------
from agent_bom.cli._runtime_group import runtime_group  # noqa: E402

runtime_group.add_command(proxy_cmd, "proxy")
runtime_group.add_command(audit_replay_cmd, "audit")
# Deprecated — hidden but still work for backward compat
runtime_group.add_command(proxy_configure_cmd, "configure")
runtime_group.add_command(protect_cmd, "protect")
runtime_group.add_command(watch_cmd, "watch")
runtime_group.commands["configure"].hidden = True
runtime_group.commands["protect"].hidden = True
runtime_group.commands["watch"].hidden = True
main.add_command(runtime_group)
main.commands["runtime"].hidden = True  # Use proxy/audit directly

# Top-level shortcuts for primary runtime commands
main.add_command(proxy_cmd, "proxy")
main.add_command(audit_replay_cmd, "audit")

from agent_bom.cli._analysis import (  # noqa: E402
    analytics_cmd,
    dashboard_cmd,
    graph_cmd,
    introspect_cmd,
)

main.add_command(graph_cmd, "graph")
# introspect is under `mcp introspect` — no top-level duplicate

# ---------------------------------------------------------------------------
# Report command group — `agent-bom report [history|diff|rescan|analytics|dashboard]`
# ---------------------------------------------------------------------------
from agent_bom.cli._report_group import report_group  # noqa: E402

report_group.add_command(history_cmd, "history")
report_group.add_command(diff_cmd, "diff")
report_group.add_command(rescan_command, "rescan")
report_group.add_command(analytics_cmd, "analytics")
report_group.add_command(dashboard_cmd, "dashboard")
main.add_command(report_group)

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
mcp_group.add_command(validate, "validate")
main.add_command(mcp_group)

# ---------------------------------------------------------------------------
# Focused scan commands — `agent-bom image`, `agent-bom fs`, etc.
# ---------------------------------------------------------------------------
from agent_bom.cli._focused_commands import code_cmd, fs_cmd, iac_cmd, image_cmd, sbom_cmd, secrets_cmd  # noqa: E402

main.add_command(image_cmd)
main.add_command(fs_cmd)
main.add_command(iac_cmd)
main.add_command(sbom_cmd)
main.add_command(secrets_cmd)
main.add_command(code_cmd)

# ---------------------------------------------------------------------------
# Cloud command group — `agent-bom cloud [aws|azure|gcp]`
# ---------------------------------------------------------------------------
from agent_bom.cli._cloud_group import cloud_group  # noqa: E402

main.add_command(cloud_group)

# ---------------------------------------------------------------------------
# Fleet command group — `agent-bom fleet [sync|list|stats]`
# ---------------------------------------------------------------------------
from agent_bom.cli.claw import fleet_group  # noqa: E402

main.add_command(fleet_group, "fleet")

# ---------------------------------------------------------------------------
# Run command — `agent-bom run <server>` (hidden — use proxy instead)
# ---------------------------------------------------------------------------
from agent_bom.cli.run import run_cmd  # noqa: E402

main.add_command(run_cmd, "run")
main.commands["run"].hidden = True  # Use `proxy` instead

# ---------------------------------------------------------------------------
# Doctor / preflight command
# ---------------------------------------------------------------------------
from agent_bom.cli._doctor import doctor_cmd  # noqa: E402

main.add_command(doctor_cmd, "doctor")


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
import agent_bom.cli as _self_module  # noqa: E402
from agent_bom.cli._check import _parse_package_spec  # noqa: E402, F401

# _NoOpDetector is already imported above
# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
from agent_bom.cli._entry import make_entry_point  # noqa: E402

# Use lambda with module lookup so unittest.mock.patch("agent_bom.cli.main") works
cli_main = make_entry_point(lambda: _self_module.main, "agent-bom")


# Re-export 'scan' as the Click command for backward-compat imports.
# MUST be at the end — after all subpackage imports that might shadow
# the 'scan' name with the scan/ subpackage module.
scan = _agents_cmd  # noqa: F811


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
