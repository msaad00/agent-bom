"""Bootstrap helpers for operator-pull adapter scripts."""

from __future__ import annotations

import sys
from pathlib import Path


def add_repo_src_to_path(script_file: str) -> None:
    """Allow adapters to run from a source checkout before package install."""
    script_path = Path(script_file).resolve()
    adapter_dir = script_path.parent
    repo_src = script_path.parents[2] / "src"
    for path in (adapter_dir, repo_src):
        if path.exists() and str(path) not in sys.path:
            sys.path.insert(0, str(path))


def exit_for_missing_agent_bom(exc: ModuleNotFoundError) -> None:
    """Convert missing agent-bom imports into an actionable non-zero CLI error."""
    missing = exc.name or ""
    if missing == "agent_bom" or missing.startswith("agent_bom."):
        sys.stderr.write(
            "error: agent-bom is required to run this adapter. "
            "Run it from a source checkout or install with `pip install agent-bom`.\n"
        )
        raise SystemExit(2) from None
    raise exc
