from __future__ import annotations

import click
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.cli._interactive import run_interactive


def test_interactive_meta_commands():
    @click.group()
    def root() -> None:
        pass

    lines = iter(["help", "history", "last", "exit"])
    output: list[str] = []

    exit_code = run_interactive(
        root,
        input_fn=lambda _prompt: next(lines),
        output=output.append,
        history_enabled=False,
    )

    assert exit_code == 0
    assert any("Commands:" in line for line in output)
    assert any("No commands run yet." in line for line in output)
    assert any("Last exit code: 0" in line for line in output)


def test_interactive_routes_normal_commands():
    @click.group()
    def root() -> None:
        pass

    @root.command("ok")
    def ok_cmd() -> None:
        click.echo("ran ok")

    lines = iter(["ok", "history", "exit"])
    output: list[str] = []

    exit_code = run_interactive(
        root,
        input_fn=lambda _prompt: next(lines),
        output=output.append,
        history_enabled=False,
    )

    assert exit_code == 0
    assert any("ok" in line for line in output)


def test_interactive_command_is_visible_in_help():
    result = CliRunner().invoke(main, ["--help"])

    assert result.exit_code == 0
    assert "interactive" in result.output
