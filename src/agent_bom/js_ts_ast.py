"""Deprecated shim — import from ``agent_bom.ast.js_ts`` instead.

The tree-sitter JS/TS engine now lives at ``agent_bom.ast.js_ts.engine``
with its public API on the ``agent_bom.ast.js_ts`` package. This module
remains so existing imports keep working; it delegates every attribute
lookup with a deprecation warning (deduplicated by the default filter).
"""

from __future__ import annotations

import warnings
from typing import Any


def __getattr__(name: str) -> Any:
    from agent_bom.ast.js_ts import engine

    value = getattr(engine, name)
    warnings.warn(
        "agent_bom.js_ts_ast is deprecated; import from agent_bom.ast.js_ts instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    return value


def __dir__() -> list[str]:
    from agent_bom.ast.js_ts import engine

    return sorted(set(dir(engine)))
