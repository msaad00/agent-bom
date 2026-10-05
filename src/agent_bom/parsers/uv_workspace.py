"""Locate a uv workspace lock without treating unrelated child projects as members."""

from __future__ import annotations

import tomllib
from fnmatch import fnmatchcase
from pathlib import Path

from agent_bom.coverage import record_manifest_parse_warning
from agent_bom.parsers.file_limits import read_text_limited


def _matches(parts: tuple[str, ...], pattern: str) -> bool:
    """Match workspace globs by path segment (a single star cannot cross '/')."""
    patterns = tuple(pattern.removeprefix("./").rstrip("/").split("/"))

    # Maintain reachable path offsets instead of recursing on untrusted globs.
    # Memory is bounded by path depth, including consecutive recursive stars.
    positions = {0}
    for segment in patterns:
        if segment == "**":
            positions = set(range(min(positions), len(parts) + 1))
        else:
            positions = {index + 1 for index in positions if index < len(parts) and fnmatchcase(parts[index], segment)}
        if not positions:
            return False
    return len(parts) in positions


def uv_lock_owner(directory: Path) -> Path | None:
    """Return the local project or explicitly containing workspace, if present."""
    directory = directory.resolve()
    if (directory / "uv.lock").exists():
        return directory
    for candidate in (directory, *directory.parents):
        manifest = candidate / "pyproject.toml"
        if manifest.is_file():
            try:
                data = tomllib.loads(read_text_limited(manifest))
                workspace = data.get("tool", {}).get("uv", {}).get("workspace")
                if isinstance(workspace, dict):
                    if candidate == directory:
                        return candidate
                    relative = directory.relative_to(candidate).parts
                    members = workspace.get("members", [])
                    excludes = workspace.get("exclude", [])
                    if not isinstance(members, list) or not isinstance(excludes, list):
                        raise ValueError("invalid workspace membership")
                    included = any(isinstance(pattern, str) and _matches(relative, pattern) for pattern in members)
                    excluded = any(isinstance(pattern, str) and _matches(relative, pattern) for pattern in excludes)
                    return candidate if included and not excluded else None
            except (OSError, ValueError, AttributeError):
                record_manifest_parse_warning(
                    ecosystem="pypi", path=str(manifest), detail="Workspace metadata could not be read; Python coverage may be incomplete"
                )
                return None
        if (candidate / ".git").exists():
            break
    return None
