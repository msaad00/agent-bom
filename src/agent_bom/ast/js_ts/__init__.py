"""Single public entry point for JS/TS AST analysis.

Import from this package — not from the submodules or the legacy top-level
module paths:

- File scanning with graceful regex fallback (works without tree-sitter):
  :func:`scan_js_ts_file`, :func:`build_js_ts_flow_findings`,
  :func:`build_js_ts_dependency_symbol_reach` (implemented in ``facade``).
- Raw tree-sitter parsing for callers that need the syntax tree directly:
  :func:`analyze_js_ts_block` and its dataclasses (implemented in
  ``engine``; raises :class:`JSTSAstUnavailableError` when the tree-sitter
  runtime is missing).

The legacy ``agent_bom.ast_js_ts`` and ``agent_bom.js_ts_ast`` module paths
are deprecated shims over this package.
"""

from __future__ import annotations

from agent_bom.ast.js_ts.engine import (
    JSImportRef,
    JSTSAstAnalysis,
    JSTSAstUnavailableError,
    JSTSCallSite,
    JSTSFunction,
    JSTSToolRegistration,
    analyze_js_ts_block,
)
from agent_bom.ast.js_ts.facade import (
    _JS_TS_EXTS,
    _js_ts_function_key,
    _npm_package_from_module,
    build_js_ts_dependency_symbol_reach,
    build_js_ts_flow_findings,
    scan_js_ts_file,
)

# Public aliases for helpers that grew up as module-private names.
JS_TS_EXTS = _JS_TS_EXTS
js_ts_function_key = _js_ts_function_key
npm_package_from_module = _npm_package_from_module

__all__ = [
    "JS_TS_EXTS",
    "JSImportRef",
    "JSTSAstAnalysis",
    "JSTSAstUnavailableError",
    "JSTSCallSite",
    "JSTSFunction",
    "JSTSToolRegistration",
    "analyze_js_ts_block",
    "build_js_ts_dependency_symbol_reach",
    "build_js_ts_flow_findings",
    "js_ts_function_key",
    "npm_package_from_module",
    "scan_js_ts_file",
]
