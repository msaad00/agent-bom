"""Private, deterministic labels for embedded filesystem occurrence coordinates."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable

_ABSOLUTE_PATH = re.compile(r"/|~/|[A-Za-z]:[\\/]")
_COORDINATE_END = re.compile(r"->|[\n\r<>]")
_PROGRESS_PREFIXES = (
    "Discovering MCP configs in ",
    "Loading inventory: ",
    "Scanning Terraform: ",
    "Scanning GitHub Actions: ",
    "Scanning Python agent project: ",
    "Scanning Jupyter notebooks: ",
    "Scanning filesystem: ",
    "Ingesting SBOM: ",
    "Ingesting external scan: ",
)
_VEX_SOURCE = re.compile(r" from (?=/|~/|[A-Za-z]:[\\/])")


def sanitize_filesystem_coordinate(value: str) -> str | None:
    # Consume each candidate path once, including malformed paths. Restarting
    # an unanchored path regex at every embedded fs:/ prefix is quadratic.
    cursor = 0
    copied = 0
    parts: list[str] = []
    while (start := value.find("fs:", cursor)) >= 0:
        path_start = start + 3
        cursor = path_start
        if (start and value[start - 1] not in ":>") or not _ABSOLUTE_PATH.match(value, path_start):
            continue
        end = _COORDINATE_END.search(value, path_start)
        if end is not None and end.group() != "->":
            cursor = end.end()
            continue
        path_end = end.start() if end else len(value)
        # This digest is a deterministic graph-coordinate pseudonym, never a
        # password verifier or authentication secret. Equality stays joinable;
        # guessing a known path remains possible, as with other stable IDs.
        digest = hashlib.sha256(value[path_start:path_end].encode()).hexdigest()[:24]  # lgtm[py/weak-sensitive-data-hashing]
        parts.extend((value[copied:path_start], f"path-{digest}"))
        copied = path_end
        cursor = end.end() if end else len(value)
    if not parts:
        return None
    parts.append(value[copied:])
    return "".join(parts)


def sanitize_progress_path(value: str, label: Callable[[object], str]) -> str:
    # Explicit progress grammar avoids treating package names and URLs as paths.
    # Reject line breaks once, before searching for a VEX source delimiter.
    if "\n" in value or "\r" in value:
        return value
    path_start: int | None = None
    for prefix in _PROGRESS_PREFIXES:
        if value.startswith(prefix):
            path_start = len(prefix)
            break
    if path_start is None and value.startswith("VEX applied: "):
        source = _VEX_SOURCE.search(value, len("VEX applied: "))
        if source is not None:
            path_start = source.end()
    if path_start is None or not _ABSOLUTE_PATH.match(value, path_start):
        return value
    suffix = "..." if value.endswith("...") else ""
    path = value[path_start : -len(suffix)] if suffix else value[path_start:]
    return f"{value[:path_start]}{label(path)}{suffix}"
