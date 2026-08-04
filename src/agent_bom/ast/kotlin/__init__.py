"""Single public entry point for Kotlin analysis.

Mirrors ``agent_bom.ast.js_ts``: the analyzer module holds the implementation
and this package exposes the stable names ``ast_analyzer`` imports.
"""

from __future__ import annotations

from agent_bom.ast.kotlin.analyzer import (
    KOTLIN_EXTS,
    _kotlin_function_key,
    build_kotlin_dependency_symbol_reach,
    kotlin_source_imports_mcp_module,
    scan_kotlin_file,
)

kotlin_function_key = _kotlin_function_key

__all__ = [
    "KOTLIN_EXTS",
    "build_kotlin_dependency_symbol_reach",
    "kotlin_function_key",
    "kotlin_source_imports_mcp_module",
    "scan_kotlin_file",
]
