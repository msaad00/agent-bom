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
            ["scan", "image", "fs", "iac", "sbom", "check", "guard", "verify"],
        ),
        (
            "MCP & AI Agents",
            ["mcp", "cloud", "run"],
        ),
        (
            "Runtime Enforcement",
            ["runtime", "proxy"],
        ),
        (
            "Reporting & Analysis",
            ["report", "graph"],
        ),
        (
            "Policy & Compliance",
            ["policy"],
        ),
        (
            "Infrastructure",
            ["serve", "api", "db", "schedule", "registry"],
        ),
        (
            "Utilities",
            ["upgrade", "validate", "completions"],
        ),
    ]
)


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
                    formatter.write_dl(rows)

        # Any commands not in a category go under "Other"
        other: list[tuple[str, str]] = []
        for name in sorted(commands):
            if name not in placed:
                help_text = commands[name].get_short_help_str(limit=48)
                other.append((name, help_text))

        if other:
            with formatter.section("Other"):
                formatter.write_dl(other)
