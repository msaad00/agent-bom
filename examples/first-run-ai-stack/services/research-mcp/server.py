"""Tiny placeholder MCP-like server used by the first-run sample.

This file is intentionally not a real MCP implementation. It gives source
and dependency scanners something concrete to inspect without starting any
network service or requiring credentials.
"""

from pathlib import Path


def read_project_file(relative_path: str) -> str:
    base = Path(__file__).resolve().parents[2]
    target = (base / relative_path).resolve()
    if base not in target.parents and target != base:
        raise ValueError("path must stay inside the sample project")
    return target.read_text(encoding="utf-8")


def summarize_research_notes() -> dict[str, str]:
    prompt_path = Path(__file__).resolve().parents[2] / "prompts" / "agent-system-prompt.md"
    return {
        "source": str(prompt_path),
        "summary": prompt_path.read_text(encoding="utf-8").splitlines()[0],
    }
