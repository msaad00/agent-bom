"""Kotlin analyzer helpers for MCP symbol-level reachability.

Regex-backed and conservative, mirroring ``agent_bom.ast_java``: Maven
coordinates must be declared in ``pom.xml`` or a Gradle build before
import/local-variable bindings are trusted, and unresolved MCP tool handlers are
dropped so headless agents do not inherit false ``function_reachable`` upgrades
at CVE join time.

The registration idiom is ``addTool`` from ``io.modelcontextprotocol:kotlin-sdk``
(the official kotlin-sdk), which carries the tool name as a named argument:

    mcpServer.addTool(
        name = "example-tool",
        description = "An example tool",
    ) { request -> CallToolResult(...) }

``Server.addTools`` is the bulk sibling, and carries each name one level deeper:

    mcpServer.addTools(
        listOf(
            RegisteredTool(Tool("bulk-a", ToolSchema(), "Tool A")) { CallToolResult(...) },
        ),
    )

``addTool``/``addTools`` are ordinary-looking method names, so -- as the Swift
analyzer does with ``import MCP`` -- a registration is only trusted in a file
that imports an MCP module. ``addPrompt`` and ``addResource`` are sibling
registrations that declare no tool and are deliberately not matched.
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
    _KotlinCallSite,
    _KotlinFileAnalysis,
    _KotlinFunctionAnalysis,
    _KotlinToolRegistration,
)
from agent_bom.ast_signal_utils import _balanced_segment, _line_number_from_index
from agent_bom.ast_source_mask import mask_line_comments_and_strings
from agent_bom.ast_symbol_reach_guards import is_actionable_dependency_symbol

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

_MAX_FILE_SIZE = 512 * 1024
KOTLIN_EXTS = frozenset({".kt", ".kts"})

_KOTLIN_IMPORT_RE = re.compile(r"^\s*import\s+(?P<path>[\w.]+)(?:\s+as\s+(?P<alias>\w+))?", re.MULTILINE)
_KOTLIN_SCOPE_RE = re.compile(r"\b(?:class|object|interface)\s+(?P<name>\w+)")
_KOTLIN_FUN_RE = re.compile(r"\bfun\s+(?:<[^>]*>\s*)?(?:[\w.<>]+\.)?(?P<name>\w+)\s*\(", re.MULTILINE)
_KOTLIN_CALL_RE = re.compile(r"\b(?P<name>\w+(?:\.\w+)+)\s*\(")
_KOTLIN_CALL_SKIP = frozenset(
    {
        "if",
        "for",
        "while",
        "when",
        "return",
        "catch",
        "throw",
        "class",
        "object",
        "fun",
        "val",
        "var",
        "import",
        "package",
    }
)
# Only the call head is matched, so the scan can run over comment/string-masked
# text; the name literal is then read from the real source at the same offset.
_KOTLIN_ADD_TOOL_START_RE = re.compile(r"\.addTool\s*\(")
# ``public fun addTools(toolsToAdd: List<RegisteredTool>)`` is the bulk sibling
# of ``addTool``. Every name lives inside a ``Tool(...)`` nested two levels down,
# so the argument list is walked rather than read as one registration. ``\b``
# before ``Tool`` keeps ``RegisteredTool(`` from matching as the constructor, and
# the ``\(`` keeps ``ToolSchema()`` out.
_KOTLIN_ADD_TOOLS_START_RE = re.compile(r"\.addTools\s*\(")
_KOTLIN_REGISTERED_TOOL_START_RE = re.compile(r"\bRegisteredTool\s*\(")
_KOTLIN_TOOL_CTOR_START_RE = re.compile(r"\bTool\s*\(")
_KOTLIN_TOOL_NAME_ARG_RE = re.compile(r"""\bname\s*=\s*"(?P<name>[^"]*)\"""")
_KOTLIN_LEADING_STRING_RE = re.compile(r"""\s*"(?P<name>[^"]*)\"""")
_KOTLIN_LOCAL_BINDING_RE = re.compile(r"\b(?:val|var)\s+(?P<var>\w+)\s*(?::\s*(?P<type>[\w.]+))?\s*=\s*(?P<ctor>[\w.]+)\s*\(")
_KOTLIN_MCP_IMPORT_PREFIXES = ("io.modelcontextprotocol", "org.modelcontextprotocol")
_KOTLIN_FRAMEWORK_HINTS: dict[str, str] = {
    "modelcontextprotocol": "MCP",
    "com.anthropic": "Anthropic",
    "com.openai": "OpenAI",
    "dev.langchain4j": "LangChain",
}


def kotlin_source_imports_mcp_module(source: str) -> bool:
    """Return whether *source* imports an official MCP Kotlin SDK package."""
    return any(match.group("path").startswith(_KOTLIN_MCP_IMPORT_PREFIXES) for match in _KOTLIN_IMPORT_RE.finditer(source))


def _kotlin_import_bindings(source: str, maven_map: Mapping[str, str]) -> dict[str, str]:
    """Map Kotlin type names to the ``groupId:artifactId`` that declares them."""
    from agent_bom.ast_java import _maven_coord_from_import

    bindings: dict[str, str] = {}
    for match in _KOTLIN_IMPORT_RE.finditer(source):
        import_path = match.group("path").strip()
        coord = _maven_coord_from_import(import_path, maven_map)
        if not coord:
            continue
        simple = import_path.rsplit(".", 1)[-1]
        bindings[simple] = coord
        bindings[import_path] = coord
        if alias := match.group("alias"):
            bindings[alias] = coord
        if "." in import_path:
            bindings[import_path.rsplit(".", 1)[0]] = coord
    return bindings


def _kotlin_local_bindings(body: str, import_bindings: Mapping[str, str]) -> dict[str, str]:
    """Bind ``val client = HttpClient()`` locals to their declaring coordinate."""
    locals_map: dict[str, str] = {}
    for match in _KOTLIN_LOCAL_BINDING_RE.finditer(body):
        var_name = match.group("var")
        for candidate in (match.group("type"), match.group("ctor")):
            if not candidate:
                continue
            coord = import_bindings.get(candidate) or import_bindings.get(candidate.rsplit(".", 1)[-1])
            if coord:
                locals_map[var_name] = coord
                break
    return locals_map


def _kotlin_call_sites(body: str, *, line_offset: int) -> list[_KotlinCallSite]:
    masked = mask_line_comments_and_strings(body)
    sites: list[_KotlinCallSite] = []
    for match in _KOTLIN_CALL_RE.finditer(masked):
        name = match.group("name")
        if name.split(".", 1)[0] in _KOTLIN_CALL_SKIP:
            continue
        sites.append(
            _KotlinCallSite(
                name=name,
                line_number=line_offset + masked[: match.start()].count("\n") + 1,
            )
        )
    return sites


def _kotlin_function_key(scope_name: str, name: str) -> str:
    return f"{scope_name}::{name}"


def _kotlin_function_display_name(scope_name: str, name: str, name_counts: Mapping[str, int]) -> str:
    if name_counts.get(name, 0) > 1:
        return _kotlin_function_key(scope_name, name)
    return name


def _collect_kotlin_functions(
    source: str,
    *,
    rel_path: str,
    scope_name: str,
    bindings: Mapping[str, str],
) -> dict[str, _KotlinFunctionAnalysis]:
    functions: dict[str, _KotlinFunctionAnalysis] = {}
    masked = mask_line_comments_and_strings(source)
    for match in _KOTLIN_FUN_RE.finditer(masked):
        name = match.group("name")
        brace_index = masked.find("{", match.end())
        body_segment = _balanced_segment(masked, brace_index, open_char="{", close_char="}") if brace_index >= 0 else None
        call_sites: list[_KotlinCallSite] = []
        function_bindings = dict(bindings)
        if body_segment is not None:
            masked_body, _ = body_segment
            body_text = source[brace_index : brace_index + len(masked_body)]
            body_line_offset = _line_number_from_index(source, brace_index) - 1
            call_sites = _kotlin_call_sites(body_text, line_offset=body_line_offset)
            function_bindings.update(_kotlin_local_bindings(body_text, bindings))
        functions[_kotlin_function_key(scope_name, name)] = _KotlinFunctionAnalysis(
            name=name,
            line_number=_line_number_from_index(source, match.start()),
            file_path=rel_path,
            scope_name=scope_name,
            import_bindings=function_bindings,
            call_sites=call_sites,
        )
    return functions


def _kotlin_tool_name(source: str, masked: str, open_paren_index: int) -> str:
    """Return the tool name declared by the ``addTool`` call at *open_paren_index*."""
    segment = _balanced_segment(masked, open_paren_index, open_char="(", close_char=")")
    if segment is None:
        return ""
    masked_args, _ = segment
    args_text = source[open_paren_index : open_paren_index + len(masked_args)]
    # ``name = "…"`` is the README idiom; a leading string literal covers the
    # positional call Kotlin also allows.
    named = _KOTLIN_TOOL_NAME_ARG_RE.search(args_text)
    if named:
        return named.group("name").strip()
    leading = _KOTLIN_LEADING_STRING_RE.match(args_text, 1)
    return leading.group("name").strip() if leading else ""


def _register_kotlin_handler_lambda(
    source: str,
    masked: str,
    args_end: int,
    *,
    tool_name: str,
    rel_path: str,
    scope_name: str,
    bindings: Mapping[str, str],
    functions: dict[str, _KotlinFunctionAnalysis],
) -> str:
    """Register the trailing lambda at *args_end* as this tool's handler.

    The lambda has no declared name, so it becomes a synthetic ``tool:<name>``
    function. The key must be scope-qualified the same way real functions are,
    because ``ast_analyzer`` re-keys every function by ``(scope_name, name)``
    before resolving handlers.
    """
    handler_function_name = f"tool:{tool_name}"
    handler_name = _kotlin_function_key(scope_name, handler_function_name)
    brace_index = masked.find("{", args_end)
    # Only a lambda that follows the argument list on the same statement is this
    # tool's handler.
    if brace_index < 0 or masked[args_end:brace_index].strip():
        return handler_name
    body_segment = _balanced_segment(masked, brace_index, open_char="{", close_char="}")
    if body_segment is None:
        return handler_name
    masked_body, _ = body_segment
    body_text = source[brace_index : brace_index + len(masked_body)]
    handler_bindings = dict(bindings)
    handler_bindings.update(_kotlin_local_bindings(body_text, bindings))
    functions[handler_name] = _KotlinFunctionAnalysis(
        name=handler_function_name,
        line_number=_line_number_from_index(source, brace_index),
        file_path=rel_path,
        scope_name=scope_name,
        import_bindings=handler_bindings,
        call_sites=_kotlin_call_sites(body_text, line_offset=_line_number_from_index(source, brace_index) - 1),
    )
    return handler_name


def _collect_kotlin_tool_registrations(
    source: str,
    *,
    rel_path: str,
    scope_name: str,
    bindings: Mapping[str, str],
    functions: dict[str, _KotlinFunctionAnalysis],
) -> list[_KotlinToolRegistration]:
    """Collect ``addTool``/``addTools`` registrations and their lambda handlers."""
    registrations: list[_KotlinToolRegistration] = []
    seen: set[tuple[str, int]] = set()
    # Scan masked source so a commented-out or quoted registration is never a
    # live tool; masking preserves offsets, so names are read from the real text.
    masked = mask_line_comments_and_strings(source)

    def add(tool_name: str, *, registration_index: int, handler_name: str) -> None:
        key = (tool_name, registration_index)
        if key in seen:
            return
        seen.add(key)
        registrations.append(
            _KotlinToolRegistration(
                tool_name=tool_name,
                handler_name=handler_name,
                line_number=_line_number_from_index(source, registration_index),
                file_path=rel_path,
                scope_name=scope_name,
                import_bindings=dict(bindings),
            )
        )

    for match in _KOTLIN_ADD_TOOL_START_RE.finditer(masked):
        open_paren_index = match.end() - 1
        tool_name = _kotlin_tool_name(source, masked, open_paren_index)
        if not tool_name:
            continue
        handler_name = _kotlin_function_key(scope_name, f"tool:{tool_name}")
        call_segment = _balanced_segment(masked, open_paren_index, open_char="(", close_char=")")
        if call_segment is not None:
            _masked_args, args_end = call_segment
            handler_name = _register_kotlin_handler_lambda(
                source,
                masked,
                args_end,
                tool_name=tool_name,
                rel_path=rel_path,
                scope_name=scope_name,
                bindings=bindings,
                functions=functions,
            )
        add(tool_name, registration_index=match.start(), handler_name=handler_name)

    for match in _KOTLIN_ADD_TOOLS_START_RE.finditer(masked):
        call_segment = _balanced_segment(masked, match.end() - 1, open_char="(", close_char=")")
        if call_segment is None:
            continue
        masked_args, _ = call_segment
        args_offset = match.end() - 1
        for registered in _KOTLIN_REGISTERED_TOOL_START_RE.finditer(masked_args):
            registered_index = args_offset + registered.start()
            registered_segment = _balanced_segment(masked, args_offset + registered.end() - 1, open_char="(", close_char=")")
            if registered_segment is None:
                continue
            masked_registered_args, registered_end = registered_segment
            tool_ctor = _KOTLIN_TOOL_CTOR_START_RE.search(masked_registered_args)
            if tool_ctor is None:
                continue
            ctor_open_index = args_offset + registered.end() - 1 + tool_ctor.end() - 1
            tool_name = _kotlin_tool_name(source, masked, ctor_open_index)
            if not tool_name:
                continue
            handler_name = _register_kotlin_handler_lambda(
                source,
                masked,
                registered_end,
                tool_name=tool_name,
                rel_path=rel_path,
                scope_name=scope_name,
                bindings=bindings,
                functions=functions,
            )
            add(tool_name, registration_index=registered_index, handler_name=handler_name)
    return registrations


def _resolve_kotlin_callee_key(
    call_name: str,
    *,
    scope_name: str,
    functions: Mapping[str, _KotlinFunctionAnalysis],
) -> str | None:
    bare = call_name.split("(", 1)[0].strip()
    if "." in bare:
        head, tail = bare.split(".", 1)
        for candidate in (_kotlin_function_key(scope_name, tail), _kotlin_function_key(head, tail)):
            if candidate in functions:
                return candidate
    candidate = _kotlin_function_key(scope_name, bare)
    return candidate if candidate in functions else None


def _resolve_kotlin_external_dependency_symbol(
    function: _KotlinFunctionAnalysis,
    call_name: str,
) -> tuple[str, str, str] | None:
    """Resolve an external import call to ``(package, module, symbol)``."""
    if not call_name or "." not in call_name:
        return None
    head, tail = call_name.split(".", 1)
    coord = function.import_bindings.get(head)
    if not coord:
        return None
    symbol = tail.split(".", 1)[0]
    if not is_actionable_dependency_symbol(symbol):
        return None
    return coord, coord, symbol


def build_kotlin_dependency_symbol_reach(
    *,
    functions: Mapping[str, _KotlinFunctionAnalysis],
    tool_registrations: Sequence[_KotlinToolRegistration],
    max_depth: int = 4,
) -> list[DependencySymbolReach]:
    """Build bounded MCP tool-entrypoint -> Maven dependency symbol reach."""
    if not functions or not tool_registrations:
        return []

    adjacency: dict[str, set[str]] = {name: set() for name in functions}
    name_counts: dict[str, int] = {}
    for function in functions.values():
        name_counts[function.name] = name_counts.get(function.name, 0) + 1

    for function_key, function in functions.items():
        for call_site in function.call_sites:
            callee_key = _resolve_kotlin_callee_key(
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
        return _kotlin_function_display_name(function.scope_name, function.name, name_counts)

    for registration in tool_registrations:
        handler_key = registration.handler_name
        if handler_key not in functions:
            continue
        queue: list[tuple[str, list[str]]] = [(handler_key, [handler_key])]
        visited: set[str] = set()
        while queue:
            current_key, path = queue.pop(0)
            if len(path) > max_depth or current_key in visited:
                continue
            visited.add(current_key)
            current = functions[current_key]
            for call_site in current.call_sites:
                external = _resolve_kotlin_external_dependency_symbol(current, call_site.name)
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


def scan_kotlin_file(
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
    _KotlinFileAnalysis | None,
]:
    """Extract MCP/tool signals and call sites from Kotlin source files."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], [], [], [], [], [], None

    if len(source) > _MAX_FILE_SIZE:
        return [], [], [], [], [], [], None

    scope_match = _KOTLIN_SCOPE_RE.search(mask_line_comments_and_strings(source))
    scope_name = scope_match.group("name") if scope_match else Path(rel_path).stem
    bindings = _kotlin_import_bindings(source, maven_map)
    frameworks = sorted(
        {
            framework
            for prefix, framework in _KOTLIN_FRAMEWORK_HINTS.items()
            for match in _KOTLIN_IMPORT_RE.finditer(source)
            if prefix in match.group("path")
        }
    )
    functions = _collect_kotlin_functions(source, rel_path=rel_path, scope_name=scope_name, bindings=bindings)
    tool_registrations: list[_KotlinToolRegistration] = []
    if kotlin_source_imports_mcp_module(source):
        tool_registrations = _collect_kotlin_tool_registrations(
            source,
            rel_path=rel_path,
            scope_name=scope_name,
            bindings=bindings,
            functions=functions,
        )

    tools = [
        ToolSignature(
            name=registration.tool_name,
            parameters=[],
            return_type="unknown",
            description="Kotlin MCP/tool registration",
            file_path=rel_path,
            line_number=registration.line_number,
            decorators=["kotlin-tool"],
            is_async=False,
        )
        for registration in tool_registrations
    ]

    return (
        [],
        [],
        tools,
        [],
        frameworks,
        [],
        _KotlinFileAnalysis(
            scope_name=scope_name,
            functions=functions,
            tool_registrations=tool_registrations,
        ),
    )
