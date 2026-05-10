"""Interactive CLI shell."""

from __future__ import annotations

import shlex
from collections.abc import Callable, Sequence
from pathlib import Path

import click

PROMPT = "agent-bom> "
EXIT_COMMANDS = {"exit", "quit", ":q"}


def _history_path() -> Path:
    return Path("~/.agent-bom/history/interactive.history").expanduser()


def _make_prompt_reader(history_enabled: bool) -> Callable[[str], str]:
    try:
        from prompt_toolkit import prompt
        from prompt_toolkit.history import FileHistory
    except Exception:
        return input

    history = None
    if history_enabled:
        path = _history_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        history = FileHistory(str(path))

    def _read(prompt_text: str) -> str:
        return prompt(prompt_text, history=history)

    return _read


def _split_command(line: str) -> list[str]:
    try:
        return shlex.split(line)
    except ValueError as exc:
        raise click.ClickException(f"Could not parse command: {exc}") from exc


def _print_interactive_help(output: Callable[[str], None]) -> None:
    output("Commands:")
    output("  help                 show this help")
    output("  history              show commands from this session")
    output("  last                 show the last command exit code")
    output("  exit | quit | :q     leave interactive mode")
    output("")
    output("Run normal commands without the program name, for example:")
    output("  agents --demo --offline")
    output("  doctor")
    output("  report history")


def _invoke_root_command(root_command: click.Command, args: Sequence[str], output: Callable[[str], None]) -> int:
    if args and args[0] == "interactive":
        output("Already in interactive mode.")
        return 0
    try:
        root_command.main(args=list(args), prog_name="agent-bom", standalone_mode=False)
        return 0
    except click.ClickException as exc:
        exc.show()
        return int(getattr(exc, "exit_code", 1) or 1)
    except click.Abort:
        output("Aborted.")
        return 1
    except SystemExit as exc:
        code = exc.code
        return code if isinstance(code, int) else 1


def run_interactive(
    root_command: click.Command,
    *,
    input_fn: Callable[[str], str] | None = None,
    output: Callable[[str], None] = click.echo,
    history_enabled: bool = True,
) -> int:
    """Run the interactive shell and return the last command exit code."""
    read = input_fn or _make_prompt_reader(history_enabled)
    session_history: list[str] = []
    last_exit_code = 0

    output("agent-bom interactive. Type `help` for commands, `exit` to leave.")

    while True:
        try:
            line = read(PROMPT)
        except EOFError:
            output("")
            return last_exit_code
        except KeyboardInterrupt:
            output("")
            continue

        line = line.strip()
        if not line:
            continue

        try:
            args = _split_command(line)
        except click.ClickException as exc:
            exc.show()
            last_exit_code = 2
            continue

        command = args[0].lower() if args else ""
        if command in EXIT_COMMANDS:
            return last_exit_code
        if command in {"help", "?"}:
            _print_interactive_help(output)
            continue
        if command == "history":
            if not session_history:
                output("No commands run yet.")
            else:
                for index, item in enumerate(session_history, start=1):
                    output(f"{index:>3}  {item}")
            continue
        if command == "last":
            output(f"Last exit code: {last_exit_code}")
            continue

        session_history.append(line)
        last_exit_code = _invoke_root_command(root_command, args, output)


@click.command("interactive")
@click.option("--no-history", is_flag=True, help="Disable persistent prompt history for this session.")
def interactive_cmd(no_history: bool) -> None:
    """Start an interactive command shell."""
    import agent_bom.cli as cli_module

    exit_code = run_interactive(cli_module.main, history_enabled=not no_history)
    raise SystemExit(exit_code)
