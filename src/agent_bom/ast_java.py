"""Java analyzer helpers for MCP symbol-level reachability.

Regex-backed and conservative: Maven coordinates must be declared in ``pom.xml``
before import/local-variable bindings are trusted. Heuristic group:artifact
invention and unresolved MCP tool handlers are dropped so headless agents do
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
    _JavaCallSite,
    _JavaFileAnalysis,
    _JavaMethodAnalysis,
    _JavaToolRegistration,
)
from agent_bom.ast_signal_utils import _balanced_segment, _line_number_from_index
from agent_bom.ast_symbol_reach_guards import is_actionable_dependency_symbol, is_verified_maven_coord

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

_MAX_FILE_SIZE = 512 * 1024
_JAVA_IMPORT_RE = re.compile(r"^\s*import\s+(?:static\s+)?(?P<path>[\w.]+)\s*;", re.MULTILINE)
_JAVA_CLASS_RE = re.compile(r"\bclass\s+(?P<name>\w+)")
_JAVA_METHOD_RE = re.compile(
    r"(?:public|private|protected)?\s*(?:static\s+)?[\w<>\[\],\s.?]+\s+(?P<name>[a-z]\w*)\s*\(",
    re.MULTILINE,
)
_JAVA_CALL_RE = re.compile(r"\b(?P<name>\w+(?:\.\w+)+|\w+)\s*\(")
_JAVA_CALL_SKIP = frozenset(
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
        "static",
        "void",
        "import",
    }
)
_JAVA_ADD_TOOL_RE = re.compile(r'\.addTool\s*\(\s*"(?P<name>[^"]+)"', re.IGNORECASE)
_JAVA_TOOL_ANNOTATION_RE = re.compile(r"@Tool\b")
_JAVA_LOCAL_BINDING_RE = re.compile(r"\b(?P<type>[\w.]+)\s+(?P<var>[a-z]\w*)\s*=\s*new\s+(?P<ctor>[\w.]+)")
_JAVA_FRAMEWORK_HINTS: dict[str, str] = {
    "modelcontextprotocol": "MCP",
    "io.modelcontextprotocol": "MCP",
}
_MAVEN_DEP_RE = re.compile(
    r"<dependency>[\s\S]*?<groupId>(?P<group>[^<]+)</groupId>[\s\S]*?<artifactId>(?P<artifact>[^<]+)</artifactId>",
    re.IGNORECASE,
)


def _maven_map_from_coord(coord: str) -> dict[str, str]:
    """Expand a ``groupId:artifactId`` coord into import-binding keys."""
    if not coord or ":" not in coord:
        return {}
    group, artifact = coord.split(":", 1)
    if not group or not artifact:
        return {}
    return {
        artifact: coord,
        group: coord,
        f"{group}.{artifact}": coord,
    }


def _load_maven_dependency_map(project: Path) -> dict[str, str]:
    """Map Java type prefixes and artifactIds to ``groupId:artifactId``."""
    mapping: dict[str, str] = {}
    pom = project / "pom.xml"
    if pom.is_file():
        try:
            text = pom.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        else:
            for match in _MAVEN_DEP_RE.finditer(text):
                group = match.group("group").strip()
                artifact = match.group("artifact").strip()
                if not group or not artifact:
                    continue
                mapping.update(_maven_map_from_coord(f"{group}:{artifact}"))
    if mapping:
        return mapping

    from agent_bom.parsers.compiled_parsers import parse_gradle_packages

    for pkg in parse_gradle_packages(project):
        if (pkg.ecosystem or "").lower() != "maven" or not pkg.name:
            continue
        mapping.update(_maven_map_from_coord(pkg.name.strip()))
    return mapping


def _java_local_bindings(body: str, import_bindings: Mapping[str, str]) -> dict[str, str]:
    locals_map: dict[str, str] = {}
    for match in _JAVA_LOCAL_BINDING_RE.finditer(body):
        type_name = match.group("type").rsplit(".", 1)[-1]
        var_name = match.group("var")
        coord = import_bindings.get(type_name) or import_bindings.get(match.group("type"))
        if coord:
            locals_map[var_name] = coord
    return locals_map


def _maven_coord_from_import(import_path: str, maven_map: Mapping[str, str]) -> str | None:
    if not maven_map:
        return None
    if import_path in maven_map:
        coord = maven_map[import_path]
        return coord if is_verified_maven_coord(coord, dict(maven_map)) else None
    parts = import_path.split(".")
    if len(parts) < 2:
        return None
    simple = parts[-1]
    prefix = ".".join(parts[:-1])
    for candidate in (prefix, simple, f"{prefix}.{simple}"):
        candidate_coord = maven_map.get(candidate)
        if candidate_coord and is_verified_maven_coord(candidate_coord, dict(maven_map)):
            return candidate_coord
    return None


def _java_import_bindings(source: str, maven_map: Mapping[str, str]) -> dict[str, str]:
    bindings: dict[str, str] = {}
    for match in _JAVA_IMPORT_RE.finditer(source):
        import_path = match.group("path").strip()
        coord = _maven_coord_from_import(import_path, maven_map)
        if not coord:
            continue
        simple = import_path.rsplit(".", 1)[-1]
        bindings[simple] = coord
        bindings[import_path] = coord
        prefix = import_path.rsplit(".", 1)[0] if "." in import_path else import_path
        bindings[prefix] = coord
    return bindings


def _java_call_sites(body: str, *, line_offset: int) -> list[_JavaCallSite]:
    sites: list[_JavaCallSite] = []
    for match in _JAVA_CALL_RE.finditer(body):
        name = match.group("name")
        if "." not in name:
            continue
        head = name.split(".", 1)[0]
        if head in _JAVA_CALL_SKIP:
            continue
        sites.append(
            _JavaCallSite(
                name=name,
                line_number=line_offset + body[: match.start()].count("\n") + 1,
            )
        )
    return sites


def _java_method_key(class_name: str, name: str) -> str:
    return f"{class_name}::{name}"


def _java_method_display_name(class_name: str, name: str, name_counts: dict[str, int]) -> str:
    if name_counts.get(name, 0) > 1:
        return _java_method_key(class_name, name)
    return name


def _collect_java_methods(
    source: str,
    *,
    rel_path: str,
    class_name: str,
    bindings: dict[str, str],
) -> dict[str, _JavaMethodAnalysis]:
    methods: dict[str, _JavaMethodAnalysis] = {}
    for match in _JAVA_METHOD_RE.finditer(source):
        name = match.group("name")
        if name in {"class", "if", "for", "while", "switch"}:
            continue
        brace_index = source.find("{", match.end())
        body_segment = _balanced_segment(source, brace_index, open_char="{", close_char="}") if brace_index >= 0 else None
        call_sites: list[_JavaCallSite] = []
        method_bindings = dict(bindings)
        if body_segment is not None:
            body_text, _ = body_segment
            body_line_offset = _line_number_from_index(source, brace_index) - 1
            call_sites = _java_call_sites(body_text, line_offset=body_line_offset)
            method_bindings.update(_java_local_bindings(body_text, bindings))
        methods[_java_method_key(class_name, name)] = _JavaMethodAnalysis(
            name=name,
            line_number=_line_number_from_index(source, match.start()),
            file_path=rel_path,
            class_name=class_name,
            import_bindings=method_bindings,
            call_sites=call_sites,
        )
    return methods


def _collect_java_tool_registrations(
    source: str,
    *,
    rel_path: str,
    class_name: str,
    bindings: dict[str, str],
    methods: dict[str, _JavaMethodAnalysis],
) -> list[_JavaToolRegistration]:
    registrations: list[_JavaToolRegistration] = []
    seen: set[tuple[str, int]] = set()

    for match in _JAVA_ADD_TOOL_RE.finditer(source):
        tool_name = match.group("name").strip()
        if not tool_name:
            continue
        key = (tool_name, match.start())
        if key in seen:
            continue
        seen.add(key)
        handler_name: str | None = None
        args_start = source.find("(", match.start())
        args_segment = _balanced_segment(source, args_start, open_char="(", close_char=")") if args_start >= 0 else None
        if args_segment is not None:
            args_text, _ = args_segment
            ref_match = re.search(r"::\s*(?P<method>[a-z]\w*)", args_text)
            if ref_match:
                handler_name = _java_method_key(class_name, ref_match.group("method"))
        if handler_name is None or handler_name not in methods:
            continue
        registrations.append(
            _JavaToolRegistration(
                tool_name=tool_name,
                handler_name=handler_name,
                line_number=_line_number_from_index(source, match.start()),
                file_path=rel_path,
                class_name=class_name,
                import_bindings=dict(bindings),
            )
        )

    for attr_match in _JAVA_TOOL_ANNOTATION_RE.finditer(source):
        method_match = _JAVA_METHOD_RE.search(source, attr_match.end())
        if not method_match:
            continue
        method_name = method_match.group("name")
        tool_name = method_name
        key = (tool_name, attr_match.start())
        if key in seen:
            continue
        seen.add(key)
        registrations.append(
            _JavaToolRegistration(
                tool_name=tool_name,
                handler_name=_java_method_key(class_name, method_name),
                line_number=_line_number_from_index(source, attr_match.start()),
                file_path=rel_path,
                class_name=class_name,
                import_bindings=dict(bindings),
            )
        )
    return registrations


def _resolve_java_callee_key(
    call_name: str,
    *,
    class_name: str,
    methods: Mapping[str, _JavaMethodAnalysis],
) -> str | None:
    bare = call_name.split("(", 1)[0].strip()
    if "." in bare:
        head, tail = bare.split(".", 1)
        candidate = _java_method_key(class_name, tail)
        if candidate in methods:
            return candidate
        candidate = _java_method_key(head, tail)
        if candidate in methods:
            return candidate
    candidate = _java_method_key(class_name, bare)
    if candidate in methods:
        return candidate
    return None


def _resolve_java_external_dependency_symbol(
    method: _JavaMethodAnalysis,
    call_name: str,
) -> tuple[str, str, str] | None:
    """Resolve an external import call to ``(package, module, symbol)``."""
    if not call_name or "." not in call_name:
        return None
    head, tail = call_name.split(".", 1)
    coord = method.import_bindings.get(head)
    if coord:
        symbol = tail.split(".", 1)[0]
        if not is_actionable_dependency_symbol(symbol):
            return None
        return coord, coord, symbol
    return None


def build_java_dependency_symbol_reach(
    *,
    methods: Mapping[str, _JavaMethodAnalysis],
    tool_registrations: Sequence[_JavaToolRegistration],
    max_depth: int = 4,
) -> list[DependencySymbolReach]:
    """Build bounded MCP tool-entrypoint -> Maven dependency symbol reach."""
    if not methods or not tool_registrations:
        return []

    adjacency: dict[str, set[str]] = {name: set() for name in methods}
    name_counts: dict[str, int] = {}
    for method in methods.values():
        name_counts[method.name] = name_counts.get(method.name, 0) + 1

    for method_key, method in methods.items():
        for call_site in method.call_sites:
            callee_key = _resolve_java_callee_key(
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
        return _java_method_display_name(method.class_name, method.name, name_counts)

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
                external = _resolve_java_external_dependency_symbol(current, call_site.name)
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
                        call_path=[registration.tool_name, *[display_name(name) for name in path], f"{module_name}.{symbol}"],
                        depth=max(0, len(path) - 1),
                        ecosystem="maven",
                    )
                )
            for next_callee in sorted(adjacency.get(current_key, ())):
                queue.append((next_callee, [*path, next_callee]))

    return reached


def scan_java_file(
    file_path: Path,
    rel_path: str,
    *,
    maven_map: Mapping[str, str],
) -> tuple[
    list[ExtractedPrompt],
    list[DetectedGuardrail],
    list[ToolSignature],
    list[FlowFinding],
    list[str],
    list[CallEdge],
    _JavaFileAnalysis | None,
]:
    """Extract MCP/tool signals and call sites from Java source files."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], [], [], [], [], [], None

    if len(source) > _MAX_FILE_SIZE:
        return [], [], [], [], [], [], None

    class_match = _JAVA_CLASS_RE.search(source)
    class_name = class_match.group("name") if class_match else Path(rel_path).stem
    bindings = _java_import_bindings(source, maven_map)
    frameworks = sorted(
        {framework for prefix, framework in _JAVA_FRAMEWORK_HINTS.items() if any(prefix in binding for binding in bindings.values())}
    )
    methods = _collect_java_methods(source, rel_path=rel_path, class_name=class_name, bindings=bindings)
    tool_registrations = _collect_java_tool_registrations(
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
                description="Java MCP/tool registration",
                file_path=rel_path,
                line_number=registration.line_number,
                decorators=["java-tool"],
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
        _JavaFileAnalysis(
            class_name=class_name,
            functions=methods,
            tool_registrations=tool_registrations,
        ),
    )
