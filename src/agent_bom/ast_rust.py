"""Rust analyzer helpers for MCP symbol-level reachability.

Regex-backed and conservative: only ``use``-proven crate aliases become
``dependency_symbol_reach`` rows. Unresolved MCP tool handlers and std/internal
crates are skipped so headless agents do not inherit false ``function_reachable``
upgrades at CVE join time.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

from agent_bom.ast_models import (
    CallEdge,
    DependencySymbolReach,
    DetectedGuardrail,
    ExtractedPrompt,
    FlowFinding,
    ToolSignature,
    _RustCallSite,
    _RustFileAnalysis,
    _RustFunctionAnalysis,
    _RustToolRegistration,
)
from agent_bom.ast_symbol_reach_guards import is_actionable_dependency_symbol, is_external_rust_crate

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

_MAX_FILE_SIZE = 512 * 1024
_RUST_USE_STMT_RE = re.compile(r"^\s*use\s+(?P<stmt>[^;]+);", re.MULTILINE)
_RUST_FN_RE = re.compile(r"(?:pub\s+)?(?:async\s+)?fn\s+(?P<name>\w+)\s*\(")
_RUST_CALL_RE = re.compile(r"\b(?P<name>\w+(?:::\w+)+|\w+\.\w+)\s*\(")
_RUST_CALL_SKIP = frozenset({"if", "for", "while", "match", "loop", "return", "let", "fn", "pub", "async", "move"})
_RUST_TOOL_ATTR_RE = re.compile(r"#\[\s*tool(?:\s*\([^)]*\))?\s*\]", re.IGNORECASE)
_RUST_DOT_TOOL_RE = re.compile(r'\.tool\s*\(\s*"(?P<name>[^"]+)"', re.IGNORECASE)
_RUST_ADD_TOOL_RE = re.compile(r'\b(?:add_tool|register_tool)\s*\(\s*"(?P<name>[^"]+)"', re.IGNORECASE)
_RUST_FRAMEWORK_HINTS: dict[str, str] = {
    "rmcp": "MCP",
    "mcp": "MCP",
    "modelcontextprotocol": "MCP",
}


def _line_number_from_index(source: str, index: int) -> int:
    return source[:index].count("\n") + 1


def _balanced_segment(source: str, open_index: int, *, open_char: str, close_char: str) -> tuple[str, int] | None:
    if open_index < 0 or open_index >= len(source) or source[open_index] != open_char:
        return None
    depth = 0
    in_quote = ""
    escaped = False
    for index in range(open_index, len(source)):
        char = source[index]
        if in_quote:
            if char == "\\" and not escaped:
                escaped = True
                continue
            if char == in_quote and not escaped:
                in_quote = ""
            escaped = False
            continue
        if char in {'"', "'"}:
            in_quote = char
            escaped = False
            continue
        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
            if depth == 0:
                return source[open_index : index + 1], index + 1
    return None


def _rust_crate_from_use_path(path: str) -> str | None:
    normalized = path.strip().strip("{}").split("::", 1)[0].strip()
    if not normalized or normalized in {"self", "super", "crate"}:
        return None
    return normalized


def _rust_use_bindings(source: str) -> dict[str, str]:
    """Map local Rust names to external crate identifiers."""
    bindings: dict[str, str] = {}
    for match in _RUST_USE_STMT_RE.finditer(source):
        stmt = match.group("stmt").strip()
        for item in stmt.split(","):
            item = item.strip()
            if not item:
                continue
            alias_match = re.match(r"(?P<path>[\w:]+)\s+as\s+(?P<alias>\w+)", item)
            if alias_match:
                crate = _rust_crate_from_use_path(alias_match.group("path"))
                if crate:
                    bindings[alias_match.group("alias")] = crate
                continue
            path_match = re.match(r"(?P<path>[\w:]+)", item)
            if not path_match:
                continue
            path = path_match.group("path")
            crate = _rust_crate_from_use_path(path)
            if not crate:
                continue
            bindings[crate] = crate
            tail = path.split("::")[-1]
            if tail and tail != crate:
                bindings[tail] = crate
    return bindings


def _rust_call_sites(body: str, *, line_offset: int) -> list[_RustCallSite]:
    sites: list[_RustCallSite] = []
    for match in _RUST_CALL_RE.finditer(body):
        name = match.group("name")
        if "." not in name and "::" not in name:
            continue
        head = name.split(".", 1)[0].split("::", 1)[0]
        if head in _RUST_CALL_SKIP:
            continue
        sites.append(
            _RustCallSite(
                name=name,
                line_number=line_offset + body[: match.start()].count("\n") + 1,
            )
        )
    return sites


def _rust_function_key(module_name: str, name: str) -> str:
    return f"{module_name}::{name}"


def _rust_function_display_name(module_name: str, name: str, name_counts: dict[str, int]) -> str:
    if name_counts.get(name, 0) > 1:
        return _rust_function_key(module_name, name)
    return name


def _collect_rust_functions(
    source: str,
    *,
    rel_path: str,
    module_name: str,
    bindings: dict[str, str],
) -> dict[str, _RustFunctionAnalysis]:
    functions: dict[str, _RustFunctionAnalysis] = {}
    for match in _RUST_FN_RE.finditer(source):
        name = match.group("name")
        brace_index = source.find("{", match.end())
        body_segment = _balanced_segment(source, brace_index, open_char="{", close_char="}") if brace_index >= 0 else None
        call_sites: list[_RustCallSite] = []
        if body_segment is not None:
            body_text, _ = body_segment
            body_line_offset = _line_number_from_index(source, brace_index) - 1
            call_sites = _rust_call_sites(body_text, line_offset=body_line_offset)
        functions[_rust_function_key(module_name, name)] = _RustFunctionAnalysis(
            name=name,
            line_number=_line_number_from_index(source, match.start()),
            file_path=rel_path,
            module_name=module_name,
            crate_bindings=dict(bindings),
            call_sites=call_sites,
        )
    return functions


def _collect_rust_tool_registrations(
    source: str,
    *,
    rel_path: str,
    module_name: str,
    bindings: dict[str, str],
    functions: dict[str, _RustFunctionAnalysis],
) -> list[_RustToolRegistration]:
    registrations: list[_RustToolRegistration] = []
    seen: set[tuple[str, int]] = set()

    for match in _RUST_DOT_TOOL_RE.finditer(source):
        tool_name = match.group("name").strip()
        if not tool_name:
            continue
        handler_key: str | None = None
        args_start = source.find("(", match.start())
        args_segment = _balanced_segment(source, args_start, open_char="(", close_char=")") if args_start >= 0 else None
        if args_segment is not None:
            args_text, _ = args_segment
            args = [part.strip() for part in args_text[1:-1].split(",") if part.strip()]
            for candidate in reversed(args[1:]):
                bare = candidate.strip().lstrip("&").split("::", 1)[-1]
                if re.fullmatch(r"[a-z]\w*", bare):
                    handler_key = _rust_function_key(module_name, bare)
                    break
        if handler_key is None or handler_key not in functions:
            continue
        key = (tool_name, match.start())
        if key in seen:
            continue
        seen.add(key)
        registrations.append(
            _RustToolRegistration(
                tool_name=tool_name,
                handler_name=handler_key,
                line_number=_line_number_from_index(source, match.start()),
                file_path=rel_path,
                module_name=module_name,
                crate_bindings=dict(bindings),
            )
        )

    for match in _RUST_ADD_TOOL_RE.finditer(source):
        tool_name = match.group("name").strip()
        if not tool_name:
            continue
        handler_key = None
        args_start = source.find("(", match.start())
        args_segment = _balanced_segment(source, args_start, open_char="(", close_char=")") if args_start >= 0 else None
        if args_segment is not None:
            args_text, _ = args_segment
            args = [part.strip() for part in args_text[1:-1].split(",") if part.strip()]
            for candidate in reversed(args[1:]):
                bare = candidate.strip().lstrip("&").split("::", 1)[-1]
                if re.fullmatch(r"[a-z]\w*", bare):
                    handler_key = _rust_function_key(module_name, bare)
                    break
        if handler_key is None or handler_key not in functions:
            continue
        key = (tool_name, match.start())
        if key in seen:
            continue
        seen.add(key)
        registrations.append(
            _RustToolRegistration(
                tool_name=tool_name,
                handler_name=handler_key,
                line_number=_line_number_from_index(source, match.start()),
                file_path=rel_path,
                module_name=module_name,
                crate_bindings=dict(bindings),
            )
        )

    for attr_match in _RUST_TOOL_ATTR_RE.finditer(source):
        fn_match = _RUST_FN_RE.search(source, attr_match.end())
        if not fn_match:
            continue
        fn_name = fn_match.group("name")
        tool_name = fn_name
        key = (tool_name, attr_match.start())
        if key in seen:
            continue
        seen.add(key)
        handler_key = _rust_function_key(module_name, fn_name)
        registrations.append(
            _RustToolRegistration(
                tool_name=tool_name,
                handler_name=handler_key,
                line_number=_line_number_from_index(source, attr_match.start()),
                file_path=rel_path,
                module_name=module_name,
                crate_bindings=dict(bindings),
            )
        )
    return registrations


def _resolve_rust_callee_key(
    call_name: str,
    *,
    current_module: str,
    functions: Mapping[str, _RustFunctionAnalysis],
) -> str | None:
    if "::" in call_name:
        parts = call_name.split("::")
        if len(parts) >= 2 and parts[0] in functions:
            return _rust_function_key(parts[0], parts[1])
    if "." in call_name:
        head = call_name.split(".", 1)[0]
        for function in functions.values():
            if function.name == head and function.module_name == current_module:
                return _rust_function_key(function.module_name, function.name)
    bare = call_name.split("(", 1)[0].strip()
    candidate = _rust_function_key(current_module, bare)
    if candidate in functions:
        return candidate
    return None


def _resolve_rust_external_dependency_symbol(
    function: _RustFunctionAnalysis,
    call_name: str,
) -> tuple[str, str, str] | None:
    """Resolve an external import call to ``(package, module, symbol)``."""
    if not call_name or ("." not in call_name and "::" not in call_name):
        return None
    if "::" in call_name:
        head, tail = call_name.split("::", 1)
        crate = function.crate_bindings.get(head)
        if crate is None or not is_external_rust_crate(crate):
            return None
        symbol = tail.split("::", 1)[0]
        if not is_actionable_dependency_symbol(symbol):
            return None
        return crate, crate, symbol
    head, tail = call_name.split(".", 1)
    crate = function.crate_bindings.get(head)
    if crate is None or not is_external_rust_crate(crate):
        return None
    symbol = tail.split(".", 1)[0]
    if not is_actionable_dependency_symbol(symbol):
        return None
    return crate, crate, symbol


def build_rust_dependency_symbol_reach(
    *,
    functions: Mapping[str, _RustFunctionAnalysis],
    tool_registrations: Sequence[_RustToolRegistration],
    max_depth: int = 4,
) -> list[DependencySymbolReach]:
    """Build bounded MCP tool-entrypoint -> crates.io dependency symbol reach."""
    if not functions or not tool_registrations:
        return []

    adjacency: dict[str, set[str]] = {name: set() for name in functions}
    name_counts: dict[str, int] = {}
    for function in functions.values():
        name_counts[function.name] = name_counts.get(function.name, 0) + 1

    for function_key, function in functions.items():
        for call_site in function.call_sites:
            callee_key = _resolve_rust_callee_key(
                call_site.name,
                current_module=function.module_name,
                functions=functions,
            )
            if callee_key and callee_key != function_key:
                adjacency[function_key].add(callee_key)

    reached: list[DependencySymbolReach] = []
    seen: set[tuple[str, str, str, str, int]] = set()

    def display_name(function_key: str) -> str:
        function = functions[function_key]
        return _rust_function_display_name(function.module_name, function.name, name_counts)

    for registration in tool_registrations:
        handler_key = registration.handler_name
        if handler_key not in functions:
            continue
        queue: list[tuple[str, list[str]]] = [(handler_key, [handler_key])]
        visited: set[str] = set()
        while queue:
            current_key, path = queue.pop(0)
            if len(path) > max_depth:
                continue
            if current_key in visited:
                continue
            visited.add(current_key)
            current = functions[current_key]
            for call_site in current.call_sites:
                external = _resolve_rust_external_dependency_symbol(current, call_site.name)
                if external is None:
                    continue
                package, module_name, symbol = external
                dedup_key = (registration.tool_name, module_name, symbol, current.file_path, call_site.line_number)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                reached.append(
                    DependencySymbolReach(
                        entrypoint=registration.tool_name,
                        package=package,
                        module=module_name,
                        symbol=symbol,
                        file_path=current.file_path,
                        line_number=call_site.line_number,
                        call_path=[registration.tool_name, *[display_name(name) for name in path], f"{module_name}::{symbol}"],
                        depth=max(0, len(path) - 1),
                        ecosystem="cargo",
                    )
                )
            for next_callee in sorted(adjacency.get(current_key, ())):
                queue.append((next_callee, [*path, next_callee]))

    return reached


def scan_rust_file(
    file_path: Path,
    rel_path: str,
) -> tuple[
    list[ExtractedPrompt],
    list[DetectedGuardrail],
    list[ToolSignature],
    list[FlowFinding],
    list[str],
    list[CallEdge],
    _RustFileAnalysis | None,
]:
    """Extract MCP/tool signals and call sites from Rust source files."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], [], [], [], [], [], None

    if len(source) > _MAX_FILE_SIZE:
        return [], [], [], [], [], [], None

    module_name = Path(rel_path).stem
    bindings = _rust_use_bindings(source)
    frameworks = sorted(
        {framework for crate, framework in _RUST_FRAMEWORK_HINTS.items() if any(crate in binding for binding in bindings.values())}
    )
    functions = _collect_rust_functions(source, rel_path=rel_path, module_name=module_name, bindings=bindings)
    tool_registrations = _collect_rust_tool_registrations(
        source,
        rel_path=rel_path,
        module_name=module_name,
        bindings=bindings,
        functions=functions,
    )
    tools: list[ToolSignature] = []
    for registration in tool_registrations:
        tools.append(
            ToolSignature(
                name=registration.tool_name,
                parameters=[],
                return_type="unknown",
                description="Rust MCP/tool registration",
                file_path=rel_path,
                line_number=registration.line_number,
                decorators=["rust-tool"],
                is_async=False,
            )
        )

    return (
        [],
        [],
        tools,
        [],
        frameworks,
        [],
        _RustFileAnalysis(
            module_name=module_name,
            functions=functions,
            tool_registrations=tool_registrations,
        ),
    )
