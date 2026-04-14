"""Custom Click group that renders help with categorized commands."""

from __future__ import annotations

from collections import OrderedDict

import click

# Define command categories and which commands belong to each.
# Order matters — first match wins, unlisted commands go to "Other".
COMMAND_CATEGORIES: OrderedDict[str, list[str]] = OrderedDict(
    [
        (
            "Scanning",
            ["agents", "skills", "image", "fs", "iac", "sbom", "cloud", "check", "verify", "secrets", "code"],
        ),
        (
            "Runtime",
            ["proxy", "audit"],
        ),
        (
            "MCP",
            ["mcp", "where"],
        ),
        (
            "Reporting",
            ["graph", "mesh", "report"],
        ),
        (
            "Governance",
            ["policy", "fleet", "serve", "api", "schedule", "remediate"],
        ),
        (
            "Database",
            ["db"],
        ),
        (
            "Utilities",
            ["upgrade", "completions"],
        ),
    ]
)

CATEGORY_DESCRIPTIONS: dict[str, str] = {
    "Scanning": "Inventory, package, image, IaC, cloud, and skills scanning entry points.",
    "Runtime": "Live MCP enforcement, replay, and runtime monitoring surfaces.",
    "MCP": "Discovery, inventory, introspection, and MCP server operations.",
    "Reporting": "Graph, mesh, dashboard, history, and narrative reporting workflows.",
    "Governance": "Policy, fleet, API, scheduling, and operational control-plane commands.",
    "Database": "Local cache, vuln database, and framework catalog maintenance.",
    "Utilities": "Shell completions and upgrade helpers.",
    "Other": "Additional commands that do not fit a primary workflow bucket.",
}


class GroupedGroup(click.Group):
    """A Click group that displays commands organized by category.

    Pass ``command_categories`` to override the default category mapping.
    Each product (agent-bom, agent-shield, etc.) provides its own categories.
    """

    def __init__(self, *args, command_categories=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._command_categories = command_categories or COMMAND_CATEGORIES

    def format_commands(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        # Collect all available commands
        commands: dict[str, click.Command] = {}
        for subcommand in self.list_commands(ctx):
            cmd = self.get_command(ctx, subcommand)
            if cmd is None or cmd.hidden:
                continue
            # get_command returns BaseCommand but we need Command for get_short_help_str
            if not isinstance(cmd, click.Command):
                continue
            commands[subcommand] = cmd

        if not commands:
            return

        # Track which commands have been placed in a category
        placed: set[str] = set()

        for category, cmd_names in self._command_categories.items():
            rows: list[tuple[str, str]] = []
            for name in cmd_names:
                if name in commands:
                    cmd = commands[name]
                    help_text = cmd.get_short_help_str(limit=48)
                    rows.append((name, help_text))
                    placed.add(name)

            if rows:
                with formatter.section(category):
                    description = CATEGORY_DESCRIPTIONS.get(category)
                    if description:
                        formatter.write_text(description)
                    formatter.write_dl(rows)

        # Any commands not in a category go under "Other"
        other: list[tuple[str, str]] = []
        for name in sorted(commands):
            if name not in placed:
                help_text = commands[name].get_short_help_str(limit=48)
                other.append((name, help_text))

        if other:
            with formatter.section("Other"):
                description = CATEGORY_DESCRIPTIONS.get("Other")
                if description:
                    formatter.write_text(description)
                formatter.write_dl(other)

    def format_epilog(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        formatter.write_paragraph()
        formatter.write_text(
            "Navigation tips: start with `agent-bom doctor` for readiness, "
            "`agent-bom agents --demo` for a reproducible local run, and "
            "`agent-bom COMMAND --help` for command-specific flags."
        )
