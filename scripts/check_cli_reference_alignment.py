#!/usr/bin/env python3
"""Fail fast when a new CLI root command is missing from the public reference.

Mirrors `tests/test_public_docs_cli_alignment.py::test_cli_reference_lists_all_visible_root_commands`
but is invoked from the fast Lint stage of CI so the failure surfaces in ~1
minute instead of waiting on the 6-8 minute test matrix to fail. Run via the
project's venv so click + the rest of the CLI imports cleanly.

Usage (CI):
    uv run python scripts/check_cli_reference_alignment.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    sys.path.insert(0, str(ROOT / "src"))
    try:
        from agent_bom.cli import main as cli_main
    except Exception as exc:  # noqa: BLE001
        print(
            f"check_cli_reference_alignment: failed to import CLI: {exc}\n"
            "Run inside the project venv (e.g. `uv run python scripts/check_cli_reference_alignment.py`).",
            file=sys.stderr,
        )
        return 2

    cli_reference_path = ROOT / "site-docs" / "reference" / "cli.md"
    if not cli_reference_path.exists():
        print(f"check_cli_reference_alignment: missing {cli_reference_path}", file=sys.stderr)
        return 2

    cli_reference = cli_reference_path.read_text(encoding="utf-8")
    visible_commands = sorted(name for name, command in cli_main.commands.items() if not getattr(command, "hidden", False))

    missing = [name for name in visible_commands if f"| `{name}` |" not in cli_reference]
    if missing:
        print(
            "check_cli_reference_alignment: site-docs/reference/cli.md is missing entries for:\n  "
            + "\n  ".join(f"- `{name}`" for name in missing)
            + "\n\nAdd a row of the form  | `<name>` | <one-line description> |"
            " under the appropriate section before committing.",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
