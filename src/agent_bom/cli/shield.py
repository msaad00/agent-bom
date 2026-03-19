"""agent-shield — Runtime protection for AI agents.

Monitors MCP traffic in real-time with 7 behavioral detectors,
enforces security policies, and provides deep defense mode with
correlated threat scoring and automatic kill-switch.

Entry point: ``agent-shield`` (registered in pyproject.toml).
"""

from __future__ import annotations

import sys
from collections import OrderedDict

import click

from agent_bom import __version__
from agent_bom.cli._entry import make_entry_point
from agent_bom.cli._grouped_help import GroupedGroup

# ── Help categories ──────────────────────────────────────────────────────────

SHIELD_CATEGORIES: OrderedDict[str, list[str]] = OrderedDict(
    [
        ("Protection", ["proxy", "protect", "guard", "run"]),
        ("Monitoring", ["watch", "audit"]),
        ("Setup", ["configure"]),
    ]
)

# ── Click group ──────────────────────────────────────────────────────────────


@click.group(
    cls=GroupedGroup,
    command_categories=SHIELD_CATEGORIES,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.version_option(
    version=__version__,
    prog_name="agent-shield",
    message=(
        f"agent-shield {__version__}\nPython {sys.version.split()[0]} · {sys.platform}\nPart of: https://github.com/msaad00/agent-bom"
    ),
)
def shield():
    """agent-shield — Runtime protection for AI agents.

    \b
    Monitors MCP tool calls through 7 behavioral detectors:
    · Tool drift (rug pull)    · Shell injection     · Credential leaks
    · Rate limiting            · Attack sequences    · Response cloaking
    · Vector DB injection

    \b
    Quick start:
      agent-shield proxy "npx @mcp/server-fs /tmp"    proxy with audit
      agent-shield protect                             standalone monitor
      agent-shield protect --shield                    deep defense mode
      agent-shield run "npx @mcp/server-github"        zero-config proxy
      agent-shield watch                               config drift alerts

    \b
    Docs: https://github.com/msaad00/agent-bom
    """
    pass


# ── Register commands (reuse existing, zero duplication) ─────────────────────

from agent_bom.cli._check import guard_cmd  # noqa: E402
from agent_bom.cli._runtime import (  # noqa: E402
    audit_replay_cmd,
    protect_cmd,
    proxy_cmd,
    proxy_configure_cmd,
    watch_cmd,
)
from agent_bom.cli.run import run_cmd  # noqa: E402

shield.add_command(proxy_cmd, "proxy")
shield.add_command(protect_cmd, "protect")
shield.add_command(run_cmd, "run")
shield.add_command(guard_cmd, "guard")
shield.add_command(watch_cmd, "watch")
shield.add_command(audit_replay_cmd, "audit")
shield.add_command(proxy_configure_cmd, "configure")

# ── Entry point ──────────────────────────────────────────────────────────────

shield_main = make_entry_point(shield, "agent-shield")
