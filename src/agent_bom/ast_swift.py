"""Swift analyzer helpers for MCP SPM symbol-level reachability.

Regex-backed and conservative: Swift package identities must be declared in
``Package.resolved`` before ``import`` bindings are trusted. Unresolved MCP
tool handlers are dropped so headless agents do not inherit false
``function_reachable`` upgrades at CVE join time.
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
    _SwiftCallSite,
    _SwiftFileAnalysis,
    _SwiftFunctionAnalysis,
    _SwiftToolRegistration,
)
from agent_bom.ast_symbol_reach_guards import is_actionable_dependency_symbol, is_verified_swift_package

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

_MAX_FILE_SIZE = 512 * 1024
_SWIFT_IMPORT_RE = re.compile(r"^\s*import\s+(?P<module>\w+)", re.MULTILINE)
_SWIFT_FUNC_RE = re.compile(r"^\s*func\s+(?P<name>\w+)\s*\(", re.MULTILINE)
_SWIFT_MODULE_CALL_RE = re.compile(r"\b(?P<module>\w+)\.(?P<method>\w+)\s*\(")
_SWIFT_DOT_CALL_RE = re.compile(r"(?P<receiver>\w+)\.(?P<method>\w+)\s*\(")
_SWIFT_BARE_CALL_RE = re.compile(r"(?<![.\w\"])\b(?P<name>\w+)\s*\(")
_SWIFT_CALL_KEYWORDS = frozenset(
    {
        "if",
        "for",
        "while",
        "switch",
        "return",
        "guard",
        "catch",
        "func",
        "init",
        "let",
        "var",
        "try",
        "throw",
        "await",
        "async",
        "in",
        "where",
        "case",
        "server",
        "tool",
    },
)
_SWIFT_TOOL_RE = re.compile(
    r'\.(?:tool|registerTool|addTool)\s*\(\s*"(?P<name>[^"]+)"',
    re.IGNORECASE,
)
_SWIFT_HANDLER_RE = re.compile(
    r'\.(?:tool|registerTool|addTool)\s*\(\s*"[^"]+"\s*,\s*(?P<handler>\w+)',
    re.IGNORECASE,
)
_SWIFT_FRAMEWORK_HINTS: dict[str, str] = {
    "modelcontextprotocol": "MCP",
    "mcp": "MCP",
}


def _line_number_from_index(source: str, index: int) -> int:
    return source[:index].count("\n") + 1


def load_swift_package_map(project: Path) -> dict[str, str]:
    """Map Swift module names to declared SPM package identities."""
    from agent_bom.parsers.swift_parsers import parse_swift_packages

    mapping: dict[str, str] = {}
    for pkg in parse_swift_packages(project):
        name = pkg.name.strip()
        if not name:
            continue
        mapping[name.lower()] = name
        mapping[name] = name
        studly = "".join(part[:1].upper() + part[1:] for part in re.split(r"[-_.]+", name) if part)
        if studly:
            mapping[studly] = name
    return mapping


def _swift_package_for_module(module: str, package_map: Mapping[str, str]) -> str | None:
    token = (module or "").strip()
    if not token:
        return None
    for candidate in (token, token.lower()):
        package = package_map.get(candidate)
        if package and is_verified_swift_package(package, dict(package_map)):
            return package
    return None


def _swift_import_bindings(source: str, package_map: Mapping[str, str]) -> dict[str, str]:
    bindings: dict[str, str] = {}
    for match in _SWIFT_IMPORT_RE.finditer(source):
        module = match.group("module").strip()
        package = _swift_package_for_module(module, package_map)
        if not package:
            continue
        bindings[module] = package
        bindings[module.lower()] = package
    return bindings


def _swift_function_key(scope_name: str, name: str) -> str:
    return f"{scope_name}:{name}"


def _swift_function_body(source: str, func_start: int, func_end: int) -> tuple[str, int] | None:
    next_def = _SWIFT_FUNC_RE.search(source, func_end)
    body_end = next_def.start() if next_def else len(source)
    body_text = source[func_start:body_end]
    return body_text, _line_number_from_index(source, func_start)


def _swift_call_sites(body: str, *, line_offset: int) -> list[_SwiftCallSite]:
    sites: list[_SwiftCallSite] = []
    for match in _SWIFT_MODULE_CALL_RE.finditer(body):
        sites.append(
            _SwiftCallSite(
                name=f"{match.group('module')}.{match.group('method')}",
                line_number=line_offset + body[: match.start()].count("\n") + 1,
            ),
        )
    for match in _SWIFT_DOT_CALL_RE.finditer(body):
        if match.group("receiver") in {"if", "for", "while", "switch", "return", "let", "var"}:
            continue
        sites.append(
            _SwiftCallSite(
                name=f"{match.group('receiver')}.{match.group('method')}",
                line_number=line_offset + body[: match.start()].count("\n") + 1,
            ),
        )
    for match in _SWIFT_BARE_CALL_RE.finditer(body):
        name = match.group("name")
        if name in _SWIFT_CALL_KEYWORDS:
            continue
        sites.append(
            _SwiftCallSite(
                name=name,
                line_number=line_offset + body[: match.start()].count("\n") + 1,
            ),
        )
    return sites


def _collect_swift_functions(
    source: str,
    *,
    rel_path: str,
    scope_name: str,
    bindings: Mapping[str, str],
) -> dict[str, _SwiftFunctionAnalysis]:
    functions: dict[str, _SwiftFunctionAnalysis] = {}
    for match in _SWIFT_FUNC_RE.finditer(source):
        name = match.group("name")
        body_segment = _swift_function_body(source, match.start(), match.end())
        if body_segment is None:
            continue
        body_text, line_number = body_segment
        functions[_swift_function_key(scope_name, name)] = _SwiftFunctionAnalysis(
            name=name,
            line_number=line_number,
            file_path=rel_path,
            scope_name=scope_name,
            import_bindings=dict(bindings),
            call_sites=_swift_call_sites(body_text, line_offset=line_number),
        )
    return functions


def _collect_swift_tool_registrations(
    source: str,
    *,
    rel_path: str,
    scope_name: str,
    bindings: Mapping[str, str],
    functions: Mapping[str, _SwiftFunctionAnalysis],
) -> list[_SwiftToolRegistration]:
    registrations: list[_SwiftToolRegistration] = []
    seen: set[tuple[str, int]] = set()
    for match in _SWIFT_TOOL_RE.finditer(source):
        tool_name = match.group("name").strip()
        if not tool_name:
            continue
        window = source[match.start() : match.start() + 200]
        handler_match = _SWIFT_HANDLER_RE.search(window)
        handler_name = handler_match.group("handler") if handler_match else None
        handler_key = _swift_function_key(scope_name, handler_name) if handler_name else None
        if handler_key is None or handler_key not in functions:
            continue
        key = (tool_name, match.start())
        if key in seen:
            continue
        seen.add(key)
        registrations.append(
            _SwiftToolRegistration(
                tool_name=tool_name,
                handler_name=handler_key,
                line_number=_line_number_from_index(source, match.start()),
                file_path=rel_path,
                scope_name=scope_name,
                import_bindings=dict(bindings),
            ),
        )
    return registrations


def _resolve_swift_callee_key(
    call_name: str,
    *,
    scope_name: str,
    functions: Mapping[str, _SwiftFunctionAnalysis],
) -> str | None:
    if "." not in call_name:
        candidate = _swift_function_key(scope_name, call_name)
        return candidate if candidate in functions else None
    receiver, method = call_name.split(".", 1)
    if receiver in {"self", scope_name}:
        candidate = _swift_function_key(scope_name, method)
        if candidate in functions:
            return candidate
    return None


def _resolve_swift_external_dependency_symbol(
    function: _SwiftFunctionAnalysis,
    call_name: str,
    *,
    package_map: Mapping[str, str],
) -> tuple[str, str, str] | None:
    if "." not in call_name:
        return None
    head, symbol = call_name.split(".", 1)
    package = _swift_package_for_module(head, package_map) or function.import_bindings.get(head)
    if not package or not is_verified_swift_package(package, dict(package_map)):
        return None
    if not is_actionable_dependency_symbol(symbol):
        return None
    return package, package, symbol


def build_swift_dependency_symbol_reach(
    *,
    functions: Mapping[str, _SwiftFunctionAnalysis],
    tool_registrations: Sequence[_SwiftToolRegistration],
    package_map: Mapping[str, str],
    max_depth: int = 4,
) -> list[DependencySymbolReach]:
    if not functions or not tool_registrations or not package_map:
        return []

    adjacency: dict[str, set[str]] = {name: set() for name in functions}
    name_counts: dict[str, int] = {}
    for function in functions.values():
        name_counts[function.name] = name_counts.get(function.name, 0) + 1

    for function_key, function in functions.items():
        for call_site in function.call_sites:
            callee_key = _resolve_swift_callee_key(
                call_site.name,
                scope_name=function.scope_name,
                functions=functions,
            )
            if callee_key and callee_key != function_key:
                adjacency[function_key].add(callee_key)

    reached: list[DependencySymbolReach] = []
    seen: set[tuple[str, str, str, str, int]] = set()

    def display_name(function_key: str) -> str:
        function = functions[function_key]
        if name_counts.get(function.name, 0) > 1:
            return _swift_function_key(function.scope_name, function.name)
        return function.name

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
                external = _resolve_swift_external_dependency_symbol(
                    current,
                    call_site.name,
                    package_map=package_map,
                )
                if external is None:
                    continue
                package_name, module_name, symbol = external
                dedup_key = (
                    registration.tool_name,
                    module_name,
                    symbol,
                    current.file_path,
                    call_site.line_number,
                )
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                reached.append(
                    DependencySymbolReach(
                        entrypoint=registration.tool_name,
                        package=package_name,
                        module=module_name,
                        symbol=symbol,
                        file_path=current.file_path,
                        line_number=call_site.line_number,
                        call_path=[
                            registration.tool_name,
                            *[display_name(name) for name in path],
                            f"{module_name}.{symbol}",
                        ],
                        depth=max(0, len(path) - 1),
                        ecosystem="swift",
                    ),
                )
            for next_callee in sorted(adjacency.get(current_key, ())):
                queue.append((next_callee, [*path, next_callee]))

    return reached


def scan_swift_file(
    file_path: Path,
    rel_path: str,
    *,
    package_map: Mapping[str, str],
) -> tuple[
    list[ExtractedPrompt],
    list[DetectedGuardrail],
    list[ToolSignature],
    list[FlowFinding],
    list[str],
    list[CallEdge],
    _SwiftFileAnalysis | None,
]:
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], [], [], [], [], [], None

    if len(source) > _MAX_FILE_SIZE:
        return [], [], [], [], [], [], None

    scope_name = Path(rel_path).stem
    bindings = _swift_import_bindings(source, package_map)
    frameworks = sorted(
        {
            framework
            for prefix, framework in _SWIFT_FRAMEWORK_HINTS.items()
            if any(prefix in binding.lower() for binding in bindings.values())
        },
    )
    functions = _collect_swift_functions(
        source,
        rel_path=rel_path,
        scope_name=scope_name,
        bindings=bindings,
    )
    tool_registrations = _collect_swift_tool_registrations(
        source,
        rel_path=rel_path,
        scope_name=scope_name,
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
                description="Swift MCP/tool registration",
                file_path=rel_path,
                line_number=registration.line_number,
                decorators=["swift-tool"],
                is_async=False,
            ),
        )

    return (
        [],
        [],
        tools,
        [],
        frameworks,
        [],
        _SwiftFileAnalysis(
            scope_name=scope_name,
            functions=functions,
            tool_registrations=tool_registrations,
        ),
    )
