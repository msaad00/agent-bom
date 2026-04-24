"""Bounded file reads for parser-controlled manifest inputs."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

DEFAULT_MAX_MANIFEST_BYTES = 100 * 1024 * 1024


class ManifestTooLargeError(OSError, ValueError):
    """Raised when an untrusted manifest exceeds the parser size limit."""


def max_manifest_bytes() -> int:
    raw = os.environ.get("AGENT_BOM_MAX_MANIFEST_BYTES", "").strip()
    if not raw:
        return DEFAULT_MAX_MANIFEST_BYTES
    try:
        parsed = int(raw)
    except ValueError:
        return DEFAULT_MAX_MANIFEST_BYTES
    return max(1, parsed)


def read_text_limited(path: Path, *, encoding: str = "utf-8", errors: str = "strict", max_bytes: int | None = None) -> str:
    limit = max_manifest_bytes() if max_bytes is None else max_bytes
    size = path.stat().st_size
    if size > limit:
        raise ManifestTooLargeError(f"{path.name} exceeds parser size limit ({limit} bytes)")
    with path.open("rb") as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise ManifestTooLargeError(f"{path.name} exceeds parser size limit ({limit} bytes)")
    return data.decode(encoding, errors=errors)


def read_json_limited(path: Path, *, encoding: str = "utf-8", errors: str = "strict", max_bytes: int | None = None) -> Any:
    return json.loads(read_text_limited(path, encoding=encoding, errors=errors, max_bytes=max_bytes))
