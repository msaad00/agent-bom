"""Deprecated shim for :mod:`agent_bom.ast.js_ts`.

The tree-sitter engine now lives at ``agent_bom.ast.js_ts.engine``. This
module remains for one compatibility window and delegates attribute lookups
with a deprecation warning.
"""

# ruff: noqa: F822 - __all__ names are resolved intentionally via __getattr__.

from __future__ import annotations

import warnings
from typing import Any

__all__ = [
    "JSImportRef",
    "JSTSAstAnalysis",
    "JSTSAstUnavailableError",
    "JSTSCallSite",
    "JSTSFunction",
    "JSTSToolRegistration",
    "analyze_js_ts_block",
]


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
