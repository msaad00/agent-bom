"""agent-shield — Runtime protection for AI agents.

Monitors MCP traffic in real-time with 7 inline proxy detectors,
enforces security policies, and provides audit replay for
runtime investigations.

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
        ("Runtime", ["proxy", "audit"]),
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
    MCP security proxy with 112 detection patterns across 7 inline detectors:
    · Tool drift (rug pull)    · Shell injection     · Credential leaks
    · Rate limiting            · Attack sequences    · Response cloaking
    · Vector DB injection

    \b
    Quick start:
      agent-shield proxy "npx @mcp/server-fs /tmp"    MCP proxy with audit
      agent-shield audit proxy-log.jsonl               replay audit logs

    \b
    Docs: https://github.com/msaad00/agent-bom
    """
    pass


# ── Register commands (reuse existing, zero duplication) ─────────────────────

from agent_bom.cli._runtime import (  # noqa: E402
    audit_replay_cmd,
    proxy_cmd,
)

shield.add_command(proxy_cmd, "proxy")
shield.add_command(audit_replay_cmd, "audit")

# ── Entry point ──────────────────────────────────────────────────────────────

shield_main = make_entry_point(shield, "agent-shield")
