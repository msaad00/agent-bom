#!/usr/bin/env python3
"""Validate executable agent-bom command citations in shipped skills.

Only fenced code blocks and inline code spans are treated as executable
citations. This avoids false positives from prose such as "agent-bom receives
sanitized inventory".
"""

from __future__ import annotations

import re
import shlex
import sys
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
SKILL_GLOBS = ("integrations/**/SKILL.md",)
_FENCED_BLOCK_RE = re.compile(r"```(?:[a-zA-Z0-9_-]+)?\n(.*?)```", re.DOTALL)
_INLINE_CODE_RE = re.compile(r"`([^`\n]*agent-bom[^`\n]*)`")


def _visible_command_tree() -> dict[str, object]:
    sys.path.insert(0, str(ROOT / "src"))
    from agent_bom.cli import main as cli_main

    def walk(command: object) -> dict[str, object]:
        children = getattr(command, "commands", {})
        return {name: walk(child) for name, child in children.items() if not getattr(child, "hidden", False)}

    return walk(cli_main)


def _skill_paths() -> list[Path]:
    paths: set[Path] = set()
    for pattern in SKILL_GLOBS:
        paths.update(ROOT.glob(pattern))
    return sorted(paths)


def _commands_from_fenced_blocks(text: str) -> Iterable[str]:
    for block in _FENCED_BLOCK_RE.findall(text):
        for line in block.splitlines():
            stripped = line.strip()
            if stripped.startswith(("$ ", "# ")):
                stripped = stripped[2:].strip()
            if stripped.startswith("agent-bom ") or stripped.startswith("uvx agent-bom "):
                yield stripped


def _commands_from_inline_code(text: str) -> Iterable[str]:
    for match in _INLINE_CODE_RE.findall(text):
        stripped = match.strip()
        if stripped.startswith("agent-bom ") or stripped.startswith("uvx agent-bom "):
            yield stripped


def _command_tokens(command: str) -> list[str]:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return command.split()
    if tokens[:2] == ["uvx", "agent-bom"]:
        return tokens[2:]
    if tokens[:1] == ["agent-bom"]:
        return tokens[1:]
    return []


def _valid_command(tokens: list[str], tree: dict[str, object]) -> bool:
    if not tokens:
        return False
    current = tree
    matched = False
    for token in tokens:
        if token.startswith("-") or token.startswith("<") or token in {"|", "&&", ";"}:
            break
        if token not in current:
            break
        matched = True
        child = current[token]
        current = child if isinstance(child, dict) else {}
    return matched


def main() -> int:
    tree = _visible_command_tree()
    failures: list[str] = []
    for path in _skill_paths():
        text = path.read_text(encoding="utf-8")
        for command in [*_commands_from_fenced_blocks(text), *_commands_from_inline_code(text)]:
            tokens = _command_tokens(command)
            if not tokens or not re.match(r"^[a-z]", tokens[0]):
                continue
            if not _valid_command(tokens, tree):
                failures.append(f"{path.relative_to(ROOT)}: invalid command citation: `{command}`")

    if failures:
        print("check_skill_cli_citations: stale agent-bom command citations found:", file=sys.stderr)
        print("\n".join(f"  - {failure}" for failure in failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
