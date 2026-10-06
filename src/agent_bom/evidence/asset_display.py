"""Bounded source labels that omit private filesystem parents."""

import re
from collections.abc import Mapping
from typing import Any

from agent_bom.security import sanitize_path_label


def iac_source_label(name: str, evidence: Any) -> str | None:
    marker = sanitize_path_label(name)
    match = re.fullmatch(r"<path:([^<>/\\]{1,80})>", marker)
    label = match[1] if match is not None else None
    if label in {"path", ".", ".."}:
        label = None
    line = evidence.get("line_number") if isinstance(evidence, Mapping) else None
    if label and isinstance(line, int) and not isinstance(line, bool) and 0 < line <= 2**31 - 1:
        label = f"{label}:{line}"
    return label
