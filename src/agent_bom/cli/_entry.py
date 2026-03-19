"""Shared entry point factory for all agent-* CLI products.

Each product (agent-bom, agent-shield, agent-cloud, agent-iac, agent-claw)
gets its own Click group and ``*_main()`` function.  This module provides
the common wrapper logic: background update check, clean error handling,
and update notice — identical to the original ``cli_main()``.
"""

from __future__ import annotations

import sys
import threading
from typing import Callable

import click

from agent_bom.cli._common import (
    _check_for_update_bg,
    _print_update_notice,
)


def make_entry_point(
    group: click.Group | Callable[[], click.Group],
    product_name: str = "agent-bom",
) -> Callable[[], None]:
    """Create a ``*_main()`` entry point for a CLI product.

    Args:
        group: The Click group, or a zero-arg callable that returns it.
            Use a callable for test-patchability (lazy lookup).
        product_name: Display name for error messages (e.g. ``"agent-shield"``).

    Returns:
        A callable suitable for use as a ``[project.scripts]`` entry point.
    """

    def entry_main() -> None:
        from rich.console import Console

        _t = threading.Thread(target=_check_for_update_bg, daemon=True)
        _t.start()

        # Resolve the group — supports both direct reference and lazy callable
        _group = group() if callable(group) and not isinstance(group, click.Group) else group

        try:
            _group(standalone_mode=True)
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
            err_console.print(f"\n[bold red]{product_name} error:[/bold red] {exc}")
            if verbose:
                err_console.print_exception(show_locals=False)
            else:
                err_console.print("[dim]Run with --verbose for full traceback.[/dim]")
            sys.exit(1)

    entry_main.__doc__ = f"Entry point for {product_name}."
    return entry_main
