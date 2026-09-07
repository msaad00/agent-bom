"""The human help front door remains small without hiding supported commands."""

from collections import OrderedDict

import click
from click.testing import CliRunner

from agent_bom.cli._grouped_help import GroupedGroup


def test_overlapping_categories_render_each_command_once():
    group = GroupedGroup(
        name="example",
        command_categories=OrderedDict([("First", ["scan"]), ("Second", ["scan", "report"])]),
    )
    group.add_command(click.Command("scan", help="Scan a project."))
    group.add_command(click.Command("report", help="Read evidence."))
    output = CliRunner().invoke(group, ["--help"]).output
    assert output.count("\n  scan ") == 1
    assert output.index("scan ") < output.index("Second:")
    assert "\n  report " in output


def test_first_run_help_keeps_five_workflow_verbs_and_all_visible_commands():
    from agent_bom.cli import main

    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    start = result.output.split("Get started:", 1)[1].split("Scanning:", 1)[0]
    for command in ("connect", "scan", "graph", "report", "up"):
        assert f"\n  {command} " in start
    for command in ("quickstart", "demo", "doctor", "samples", "capabilities"):
        assert f"\n  {command} " not in start
    with main.make_context("agent-bom", [], resilient_parsing=True) as context:
        for name in main.list_commands(context):
            command = main.get_command(context, name)
            if command is not None and not command.hidden:
                assert result.output.count(f"\n  {name} ") == 1, name


def test_advanced_scan_help_is_discoverable_before_core_option_list():
    from agent_bom.cli import main

    result = CliRunner().invoke(main, ["scan", "--help"])
    assert result.exit_code == 0
    assert result.output.index("scan --help-all") < result.output.index("Core options:")
    assert "--jira-token" not in result.output
    full = CliRunner().invoke(main, ["scan", "--help-all"])
    assert full.exit_code == 0
    assert "--jira-token" in full.output
    assert "All options:" not in full.output
