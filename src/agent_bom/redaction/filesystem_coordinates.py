"""Private, deterministic labels for embedded filesystem occurrence coordinates."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable

# Restrict the namespace: URL paths and package names are not local occurrences.
_COORDINATE = re.compile(r"(?P<prefix>(?:^|(?<=[:>]))fs:)(?P<path>(?:/|~/|[A-Za-z]:[\\/])[^\n\r<>]*?)(?=->|$)")


def sanitize_filesystem_coordinate(value: str) -> str | None:
    def replace(match: re.Match[str]) -> str:
        digest = hashlib.sha256(match["path"].encode()).hexdigest()[:24]
        return f"{match['prefix']}path-{digest}"

    result, count = _COORDINATE.subn(replace, value)
    return result if count else None


# Explicit scan-progress grammar avoids interpreting package names and URLs as
# local paths. This also protects already-persisted messages at projection time.
_PROGRESS_PATH = re.compile(
    r"^(?P<prefix>Discovering MCP configs in |Loading inventory: |"
    r"Scanning (?:Terraform|GitHub Actions|Python agent project|Jupyter notebooks|filesystem): |"
    r"Ingesting (?:SBOM|external scan): |VEX applied: .*? from )"
    r"(?P<path>(?:/|~/|[A-Za-z]:[\\/])[^\n\r]*?)(?P<suffix>\.\.\.)?$"
)


def sanitize_progress_path(value: str, label: Callable[[object], str]) -> str:
    match = _PROGRESS_PATH.fullmatch(value)
    if match is None:
        return value
    return f"{match['prefix']}{label(match['path'])}{match['suffix'] or ''}"
