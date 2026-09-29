"""Shared contexts and line-lookup helpers for the Kubernetes manifest rules."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class K8sDocument:
    """One YAML document of a manifest."""

    doc: dict[str, Any]
    kind: Any
    name: Any
    name_lower: str
    content: str
    rel_path: str


@dataclass(frozen=True)
class K8sWorkload:
    """A workload document with a resolved pod spec."""

    kind: Any
    name: Any
    namespace: Any
    pod_spec: dict[str, Any]
    content: str
    rel_path: str


@dataclass(frozen=True)
class K8sContainer:
    """One container (or init container) of a workload."""

    workload: K8sWorkload
    container: dict[str, Any]
    cname: Any
    sec_ctx: dict[str, Any]


def find_line(content: str, key: str, value: Any, start_line: int = 1) -> int:
    """Best-effort line number search for a key-value pair in YAML text."""
    if isinstance(value, bool):
        val_str = "true" if value else "false"
    elif isinstance(value, int):
        val_str = str(value)
    else:
        val_str = str(value)
    pattern = rf"{re.escape(key)}\s*:\s*{re.escape(val_str)}"
    for i, line in enumerate(content.splitlines(), 1):
        if re.search(pattern, line):
            return i
    return start_line


def find_key_line(content: str, key: str, start_line: int = 1) -> int:
    """Best-effort line number search for a key in YAML text."""
    for i, line in enumerate(content.splitlines(), 1):
        if re.search(rf"\b{re.escape(key)}\s*:", line):
            return i
    return start_line
