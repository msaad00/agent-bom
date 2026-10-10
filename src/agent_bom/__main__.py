"""Console-script entry for ``agent-bom``.

Importing :mod:`agent_bom.cli` registers every command group, which costs
hundreds of milliseconds. A bare ``agent-bom --version`` needs none of it, so
it is answered here; every other invocation runs the full CLI unchanged.
"""

from __future__ import annotations

import sys

from agent_bom import __version__


def version_message() -> str:
    """The ``--version`` text, shared with the Click group's version option."""
    return (
        f"agent-bom {__version__}\n"
        "Open security scanner for AI infrastructure\n"
        f"Python {sys.version.split()[0]} · {sys.platform}\n"
        "Docs:  https://koda-ai-studio.github.io/agent-bom/"
    )


def cli_main() -> None:
    if sys.argv[1:] == ["--version"]:
        sys.stdout.write(version_message() + "\n")
        sys.stdout.flush()
        return
    from agent_bom.cli import cli_main as full_cli_main

    full_cli_main()


if __name__ == "__main__":
    cli_main()
