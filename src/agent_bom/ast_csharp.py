"""C# / NuGet analyzer helpers for MCP symbol-level reachability.

Regex-backed and conservative: NuGet package IDs must be declared in
``packages.lock.json`` or ``*.csproj`` before ``using`` / local-type bindings
are trusted. Unresolved MCP tool handlers are dropped so headless agents do
not inherit false ``function_reachable`` upgrades at CVE join time.
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
    _CSharpCallSite,
    _CSharpFileAnalysis,
    _CSharpMethodAnalysis,
    _CSharpToolRegistration,
)
from agent_bom.ast_signal_utils import _balanced_segment, _line_number_from_index
from agent_bom.ast_symbol_reach_guards import is_actionable_dependency_symbol, is_verified_nuget_package

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

_MAX_FILE_SIZE = 512 * 1024
_CS_USING_RE = re.compile(r"^\s*using\s+(?:static\s+)?(?P<path>[\w.]+)\s*;", re.MULTILINE)
_CS_USING_ALIAS_RE = re.compile(r"^\s*using\s+(?P<alias>[\w]+)\s*=\s*(?P<path>[\w.]+)\s*;", re.MULTILINE)
_CS_CLASS_RE = re.compile(r"\bclass\s+(?P<name>\w+)")
_CS_METHOD_RE = re.compile(
    r"(?:public|private|protected|internal)?\s*(?:static\s+)?(?:async\s+)?[\w<>\[\],\s.?]+\s+(?P<name>[A-Za-z]\w*)\s*\(",
    re.MULTILINE,
)
_CS_CALL_RE = re.compile(r"\b(?P<name>\w+(?:\.\w+)+)\s*\(")
_CS_CALL_SKIP = frozenset(
    {
        "if",
        "for",
        "while",
        "switch",
        "return",
        "new",
        "catch",
        "throw",
        "class",
        "public",
        "private",
        "protected",
        "internal",
        "static",
        "async",
        "void",
        "using",
        "await",
    }
)
_CS_ADD_TOOL_RE = re.compile(r'\.AddTool\s*\(\s*"(?P<name>[^"]+)"', re.IGNORECASE)
_CS_MCP_TOOL_ATTR_RE = re.compile(r"\[\s*McpServerTool(?:\s*\([^)]*\))?\s*\]", re.IGNORECASE)
_CS_LOCAL_BINDING_RE = re.compile(r"\b(?P<type>[\w.]+)\s+(?P<var>[a-z]\w*)\s*=\s*new\s+(?P<ctor>[\w.]+)")
_CS_FRAMEWORK_HINTS: dict[str, str] = {
    "modelcontextprotocol": "MCP",
    "microsoft.semantickernel": "SemanticKernel",
}


def load_nuget_namespace_map(project: Path) -> dict[str, str]:
    """Map C# namespace prefixes and aliases to declared NuGet package IDs."""
    from agent_bom.parsers.dotnet_parsers import parse_nuget_packages

    mapping: dict[str, str] = {}
    for pkg in parse_nuget_packages(project):
        package_id = pkg.name.strip()
        if not package_id:
            continue
        mapping[package_id] = package_id
        parts = package_id.split(".")
        for index in range(1, len(parts) + 1):
            prefix = ".".join(parts[:index])
            mapping.setdefault(prefix, package_id)
    return mapping


def _nuget_package_for_namespace(namespace: str, nuget_map: Mapping[str, str]) -> str | None:
    if not namespace or not nuget_map:
        return None
    if namespace in nuget_map:
        package_id = nuget_map[namespace]
        return package_id if is_verified_nuget_package(package_id, dict(nuget_map)) else None
    parts = namespace.split(".")
    for index in range(len(parts), 0, -1):
        prefix = ".".join(parts[:index])
        candidate_package_id = nuget_map.get(prefix)
        if candidate_package_id and is_verified_nuget_package(candidate_package_id, dict(nuget_map)):
            return candidate_package_id
    return None


def _csharp_using_bindings(source: str, nuget_map: Mapping[str, str]) -> dict[str, str]:
    bindings: dict[str, str] = {}
    for match in _CS_USING_ALIAS_RE.finditer(source):
        package_id = _nuget_package_for_namespace(match.group("path").strip(), nuget_map)
        if package_id:
            bindings[match.group("alias")] = package_id
    for match in _CS_USING_RE.finditer(source):
        namespace = match.group("path").strip()
        package_id = _nuget_package_for_namespace(namespace, nuget_map)
        if not package_id:
            continue
        bindings[namespace] = package_id
        simple = namespace.rsplit(".", 1)[-1]
        bindings[simple] = package_id
    return bindings


def _csharp_local_bindings(body: str, import_bindings: Mapping[str, str]) -> dict[str, str]:
    locals_map: dict[str, str] = {}
    for match in _CS_LOCAL_BINDING_RE.finditer(body):
        type_name = match.group("type").rsplit(".", 1)[-1]
        var_name = match.group("var")
        qualified_type = match.group("type")
        package_id = (
            import_bindings.get(type_name)
            or import_bindings.get(qualified_type)
            or (import_bindings.get(qualified_type.split(".", 1)[0]) if "." in qualified_type else None)
        )
        if package_id:
            locals_map[var_name] = package_id
    return locals_map


def _csharp_call_sites(body: str, *, line_offset: int) -> list[_CSharpCallSite]:
    sites: list[_CSharpCallSite] = []
    for match in _CS_CALL_RE.finditer(body):
        name = match.group("name")
        name_start = match.start("name")
        if re.search(r"\bnew\s*$", body[max(0, name_start - 8) : name_start]):
            continue
        head = name.split(".", 1)[0]
        if head in _CS_CALL_SKIP:
            continue
        sites.append(
            _CSharpCallSite(
                name=name,
                line_number=line_offset + body[: match.start()].count("\n") + 1,
            )
        )
    return sites


def _csharp_method_key(class_name: str, name: str) -> str:
    return f"{class_name}::{name}"


def _csharp_method_display_name(class_name: str, name: str, name_counts: dict[str, int]) -> str:
    if name_counts.get(name, 0) > 1:
        return _csharp_method_key(class_name, name)
    return name


def _collect_csharp_methods(
    source: str,
    *,
    rel_path: str,
    class_name: str,
    bindings: dict[str, str],
) -> dict[str, _CSharpMethodAnalysis]:
    methods: dict[str, _CSharpMethodAnalysis] = {}
    for match in _CS_METHOD_RE.finditer(source):
        name = match.group("name")
        name_start = match.start("name")
        if re.search(r"\bnew\s+(?:[\w.]+\s*)?$", source[max(0, name_start - 64) : name_start]):
            continue
        brace_index = source.find("{", match.end())
        body_segment = _balanced_segment(source, brace_index, open_char="{", close_char="}") if brace_index >= 0 else None
        call_sites: list[_CSharpCallSite] = []
        method_bindings = dict(bindings)
        if body_segment is not None:
            body_text, _ = body_segment
            body_line_offset = _line_number_from_index(source, brace_index) - 1
            call_sites = _csharp_call_sites(body_text, line_offset=body_line_offset)
            method_bindings.update(_csharp_local_bindings(body_text, bindings))
        methods[_csharp_method_key(class_name, name)] = _CSharpMethodAnalysis(
            name=name,
            line_number=_line_number_from_index(source, match.start()),
            file_path=rel_path,
            class_name=class_name,
            import_bindings=method_bindings,
            call_sites=call_sites,
        )
    return methods


def _collect_csharp_tool_registrations(
    source: str,
    *,
    rel_path: str,
    class_name: str,
    bindings: dict[str, str],
    methods: Mapping[str, _CSharpMethodAnalysis],
) -> list[_CSharpToolRegistration]:
    registrations: list[_CSharpToolRegistration] = []
    seen: set[tuple[str, int]] = set()

    for match in _CS_ADD_TOOL_RE.finditer(source):
        tool_name = match.group("name").strip()
        if not tool_name:
            continue
        handler_name: str | None = None
        args_start = source.find("(", match.start())
        args_segment = _balanced_segment(source, args_start, open_char="(", close_char=")") if args_start >= 0 else None
        if args_segment is not None:
            args_text, _ = args_segment
            ref_match = re.search(r"(?P<method>[A-Za-z]\w*)\s*[,)]", args_text.split(",", 1)[-1] if "," in args_text else args_text)
            if ref_match:
                candidate = ref_match.group("method")
                key = _csharp_method_key(class_name, candidate)
                if key in methods:
                    handler_name = key
        if handler_name is None:
            continue
        registration_key = (tool_name, match.start())
        if registration_key in seen:
            continue
        seen.add(registration_key)
        registrations.append(
            _CSharpToolRegistration(
                tool_name=tool_name,
                handler_name=handler_name,
                line_number=_line_number_from_index(source, match.start()),
                file_path=rel_path,
                class_name=class_name,
                import_bindings=dict(bindings),
            )
        )

    for attr_match in _CS_MCP_TOOL_ATTR_RE.finditer(source):
        method_match = _CS_METHOD_RE.search(source, attr_match.end())
        if not method_match:
            continue
        method_name = method_match.group("name")
        tool_name = method_name
        registration_key = (tool_name, attr_match.start())
        if registration_key in seen:
            continue
        seen.add(registration_key)
        handler_key = _csharp_method_key(class_name, method_name)
        if handler_key not in methods:
            continue
        registrations.append(
            _CSharpToolRegistration(
                tool_name=tool_name,
                handler_name=handler_key,
                line_number=_line_number_from_index(source, attr_match.start()),
                file_path=rel_path,
                class_name=class_name,
                import_bindings=dict(bindings),
            )
        )
    return registrations


def _resolve_csharp_callee_key(
    call_name: str,
    *,
    class_name: str,
    methods: Mapping[str, _CSharpMethodAnalysis],
) -> str | None:
    bare = call_name.split("(", 1)[0].strip()
    if "." in bare:
        _, tail = bare.split(".", 1)
        candidate = _csharp_method_key(class_name, tail)
        if candidate in methods:
            return candidate
    candidate = _csharp_method_key(class_name, bare)
    if candidate in methods:
        return candidate
    return None


def _resolve_csharp_external_dependency_symbol(
    method: _CSharpMethodAnalysis,
    call_name: str,
) -> tuple[str, str, str] | None:
    """Resolve an external import call to ``(package, module, symbol)``."""
    if not call_name or "." not in call_name:
        return None
    head, tail = call_name.split(".", 1)
    package_id = method.import_bindings.get(head)
    if not package_id or not is_verified_nuget_package(package_id, method.import_bindings):
        return None
    symbol = tail.split(".", 1)[0]
    if not is_actionable_dependency_symbol(symbol):
        return None
    return package_id, package_id, symbol


def build_csharp_dependency_symbol_reach(
    *,
    methods: Mapping[str, _CSharpMethodAnalysis],
    tool_registrations: Sequence[_CSharpToolRegistration],
    max_depth: int = 4,
) -> list[DependencySymbolReach]:
    """Build bounded MCP tool-entrypoint -> NuGet dependency symbol reach."""
    if not methods or not tool_registrations:
        return []

    adjacency: dict[str, set[str]] = {name: set() for name in methods}
    name_counts: dict[str, int] = {}
    for method in methods.values():
        name_counts[method.name] = name_counts.get(method.name, 0) + 1

    for method_key, method in methods.items():
        for call_site in method.call_sites:
            callee_key = _resolve_csharp_callee_key(
                call_site.name,
                class_name=method.class_name,
                methods=methods,
            )
            if callee_key and callee_key != method_key:
                adjacency[method_key].add(callee_key)

    reached: list[DependencySymbolReach] = []
    seen: set[tuple[str, str, str, str, int]] = set()

    def display_name(method_key: str) -> str:
        method = methods[method_key]
        return _csharp_method_display_name(method.class_name, method.name, name_counts)

    for registration in tool_registrations:
        handler_key = registration.handler_name
        if handler_key not in methods:
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
            current = methods[current_key]
            for call_site in current.call_sites:
                external = _resolve_csharp_external_dependency_symbol(current, call_site.name)
                if external is None:
                    continue
                package_id, module_name, symbol = external
                dedup_key = (registration.tool_name, module_name, symbol, current.file_path, call_site.line_number)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                reached.append(
                    DependencySymbolReach(
                        entrypoint=registration.tool_name,
                        package=package_id,
                        module=module_name,
                        symbol=symbol,
                        file_path=current.file_path,
                        line_number=call_site.line_number,
                        call_path=[registration.tool_name, *[display_name(name) for name in path], f"{module_name}.{symbol}"],
                        depth=max(0, len(path) - 1),
                        ecosystem="nuget",
                    )
                )
            for next_callee in sorted(adjacency.get(current_key, ())):
                queue.append((next_callee, [*path, next_callee]))

    return reached


def scan_csharp_file(
    file_path: Path,
    rel_path: str,
    *,
    nuget_map: Mapping[str, str],
) -> tuple[
    list[ExtractedPrompt],
    list[DetectedGuardrail],
    list[ToolSignature],
    list[FlowFinding],
    list[str],
    list[CallEdge],
    _CSharpFileAnalysis | None,
]:
    """Extract MCP/tool signals and call sites from C# source files."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], [], [], [], [], [], None

    if len(source) > _MAX_FILE_SIZE:
        return [], [], [], [], [], [], None

    class_match = _CS_CLASS_RE.search(source)
    class_name = class_match.group("name") if class_match else Path(rel_path).stem
    bindings = _csharp_using_bindings(source, nuget_map)
    frameworks = sorted(
        {framework for prefix, framework in _CS_FRAMEWORK_HINTS.items() if any(prefix in binding.lower() for binding in bindings.values())}
    )
    methods = _collect_csharp_methods(source, rel_path=rel_path, class_name=class_name, bindings=bindings)
    tool_registrations = _collect_csharp_tool_registrations(
        source,
        rel_path=rel_path,
        class_name=class_name,
        bindings=bindings,
        methods=methods,
    )
    tools: list[ToolSignature] = []
    for registration in tool_registrations:
        tools.append(
            ToolSignature(
                name=registration.tool_name,
                parameters=[],
                return_type="unknown",
                description="C# MCP/tool registration",
                file_path=rel_path,
                line_number=registration.line_number,
                decorators=["csharp-tool"],
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
        _CSharpFileAnalysis(
            class_name=class_name,
            functions=methods,
            tool_registrations=tool_registrations,
        ),
    )
