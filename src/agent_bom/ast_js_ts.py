"""Deprecated shim for :mod:`agent_bom.ast.js_ts`.

The JS/TS scanning facade now lives at ``agent_bom.ast.js_ts.facade``. This
module remains for one compatibility window and delegates attribute lookups
with a deprecation warning.
"""

from __future__ import annotations

import warnings
from typing import Any


def __getattr__(name: str) -> Any:
    from agent_bom.ast.js_ts import facade

    value = getattr(facade, name)
    warnings.warn(
        "agent_bom.ast_js_ts is deprecated; import from agent_bom.ast.js_ts instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    return value


def __dir__() -> list[str]:
    from agent_bom.ast.js_ts import facade

    return sorted(set(dir(facade)))
