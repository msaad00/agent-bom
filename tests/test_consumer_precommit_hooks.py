"""Contracts for hooks installed into downstream repositories."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _hook(hook_id: str) -> dict[str, object]:
    hooks = yaml.safe_load((ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8"))
    matches = [hook for hook in hooks if hook.get("id") == hook_id]
    assert len(matches) == 1
    return matches[0]


def test_dependency_hook_scans_only_the_downstream_repository() -> None:
    hook = _hook("agent-bom-scan")

    assert hook["pass_filenames"] is False
    assert hook["args"][:2] == ["-p", "."]
    assert hook["args"][2:] == ["--fail-on-severity", "high"]
