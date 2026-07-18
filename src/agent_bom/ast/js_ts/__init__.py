"""Single public entry point for JavaScript and TypeScript analysis.

The package exposes the scanner facade, including its regex fallback, and the
tree-sitter engine for callers that need syntax-tree details. The legacy
``agent_bom.ast_js_ts`` and ``agent_bom.js_ts_ast`` paths remain compatibility
shims for one deprecation window.
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

# Stable public aliases for helpers that were historically module-private.
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
