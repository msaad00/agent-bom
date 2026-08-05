"""Ruby analyzer helpers for MCP symbol-level reachability.

Regex-backed and conservative: gem names must be declared in ``Gemfile.lock``
(or ``Gemfile`` when no lock exists) before ``require`` bindings are trusted.
Unresolved MCP tool handlers are dropped so headless agents do not inherit
false ``function_reachable`` upgrades at CVE join time.

The official ``mcp`` gem documents three ways to define a tool, and all three
are matched: ``MCP::Server#define_tool`` with a block, ``MCP::Tool.define`` with
a block, and a subclass of ``MCP::Tool`` (whose name comes from ``tool_name``
when declared, and otherwise from the underscored class name -- the fallback
``lib/mcp/tool.rb`` itself applies). The block- and class-bodied forms have no
named handler to resolve, so they declare a tool without contributing a
reachability path, exactly as ``define_tool`` already did.
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
    _RubyCallSite,
    _RubyFileAnalysis,
    _RubyMethodAnalysis,
    _RubyToolRegistration,
)
from agent_bom.ast_signal_utils import _balanced_segment, _line_number_from_index
from agent_bom.ast_source_mask import mask_line_comments_and_strings
from agent_bom.ast_symbol_reach_guards import is_actionable_dependency_symbol, is_verified_ruby_gem

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

_MAX_FILE_SIZE = 512 * 1024
_RUBY_REQUIRE_RE = re.compile(r"""^\s*require(?:_relative)?\s+['"](?P<path>[^'"]+)['"]""", re.MULTILINE)
_RUBY_CLASS_RE = re.compile(r"\bclass\s+(?P<name>\w+)")
_RUBY_METHOD_RE = re.compile(r"^\s*def\s+(?P<name>[a-z]\w*)\s*(?:\(|$)", re.MULTILINE)
_RUBY_CALL_RE = re.compile(r"\b(?P<name>\w+(?:\.\w+)+)\s*(?:\(|\s|$)")
_RUBY_CALL_SKIP = frozenset(
    {
        "if",
        "for",
        "while",
        "unless",
        "until",
        "case",
        "when",
        "return",
        "yield",
        "raise",
        "rescue",
        "ensure",
        "class",
        "module",
        "def",
        "end",
        "do",
        "elsif",
        "else",
        "begin",
    }
)
_RUBY_LOCAL_BINDING_RE = re.compile(r"\b(?P<var>[a-z]\w*)\s*=\s*(?P<ctor>\w+)\.")
_RUBY_ADD_TOOL_RE = re.compile(
    r"""\.(?:add_tool|register_tool)\s*\(\s*['"](?P<name>[^'"]+)['"]""",
    re.IGNORECASE,
)
# The mcp gem registers with a keyword name and a block body, so neither the
# verb nor the positional-string shape above matches it.
_RUBY_DEFINE_TOOL_RE = re.compile(
    r"""\.define_tool\s*\(\s*name:\s*['"](?P<name>[^'"]+)['"]""",
)
# The call head alone, for scanning comment/string-masked source where the name
# literal has been blanked out; the name is then read from the real source.
_RUBY_DEFINE_TOOL_START_RE = re.compile(r"""\.define_tool\s*\(\s*name:\s*""")
# The mcp gem documents three ways to define a tool. ``Server#define_tool`` above
# is one; the other two are ``MCP::Tool.define`` with a block, and a subclass of
# ``MCP::Tool``.
_RUBY_TOOL_DEFINE_RE = re.compile(r"""\b(?P<qualifier>(?:\w+::)*)Tool\.define\s*\(\s*name:\s*['"](?P<name>[^'"]+)['"]""")
_RUBY_TOOL_DEFINE_START_RE = re.compile(r"""\b(?P<qualifier>(?:\w+::)*)Tool\.define\s*\(\s*name:\s*""")
_RUBY_CLASS_DECL_RE = re.compile(r"""^[ \t]*class\s+(?P<name>[\w:]+)\s*<\s*(?P<superclass>[\w:]+)""", re.MULTILINE)
_RUBY_TOOL_NAME_DECL_RE = re.compile(r"""^[ \t]*tool_name\s+['"](?P<name>[^'"]+)['"]""", re.MULTILINE)
# Masking blanks the opening quote too, so the head stops before the literal.
_RUBY_TOOL_NAME_DECL_START_RE = re.compile(r"""^[ \t]*tool_name[ \t]+""", re.MULTILINE)
_RUBY_MCP_REQUIRE_HEADS = frozenset({"mcp", "modelcontextprotocol"})
# ``MCP::Tool`` names the gem outright; a bare ``Tool`` is too ordinary a name to
# trust on its own, so it needs the file to require the gem -- the discriminator
# the Go analyzer applies to ``NewTool`` and Swift to ``Tool(name:)``.
_RUBY_MCP_QUALIFIER = "mcp::"
# lib/mcp/tool.rb: with no ``tool_name``, ``name_value`` falls back to
# ``StringUtils.handle_from_class_name``, which demodulizes then underscores the
# class name. These two substitutions are that method's, verbatim.
_RUBY_ACRONYM_BOUNDARY_RE = re.compile(r"(?<=[A-Z])(?=[A-Z][a-z])")
_RUBY_WORD_BOUNDARY_RE = re.compile(r"(?<=[a-z\d])(?=[A-Z])")
_RUBY_FRAMEWORK_HINTS: dict[str, str] = {
    "modelcontextprotocol": "MCP",
    "mcp": "MCP",
}


def _ruby_constant_for_gem(gem_name: str) -> str:
    parts = re.split(r"[-_.]+", gem_name.strip())
    return "".join((part[:1].upper() + part[1:]) if part else "" for part in parts)


def load_ruby_gem_map(project: Path) -> dict[str, str]:
    """Map Ruby require paths and constants to declared gem names."""
    from agent_bom.parsers.ruby_parsers import parse_ruby_packages

    mapping: dict[str, str] = {}
    for pkg in parse_ruby_packages(project):
        gem_name = pkg.name.strip()
        if not gem_name:
            continue
        mapping[gem_name.lower()] = gem_name
        mapping[gem_name] = gem_name
        mapping[_ruby_constant_for_gem(gem_name)] = gem_name
    return mapping


def _ruby_gem_for_require(path: str, gem_map: Mapping[str, str]) -> str | None:
    if not path or not gem_map:
        return None
    head = path.split("/", 1)[0].strip()
    if not head:
        return None
    for candidate in (head, head.lower(), _ruby_constant_for_gem(head)):
        gem_name = gem_map.get(candidate)
        if gem_name and is_verified_ruby_gem(gem_name, dict(gem_map)):
            return gem_name
    return None


def _ruby_require_bindings(source: str, gem_map: Mapping[str, str]) -> dict[str, str]:
    bindings: dict[str, str] = {}
    for match in _RUBY_REQUIRE_RE.finditer(source):
        gem_name = _ruby_gem_for_require(match.group("path").strip(), gem_map)
        if not gem_name:
            continue
        bindings[gem_name.lower()] = gem_name
        bindings[gem_name] = gem_name
        bindings[_ruby_constant_for_gem(gem_name)] = gem_name
    return bindings


def _ruby_local_bindings(body: str, import_bindings: Mapping[str, str]) -> dict[str, str]:
    locals_map: dict[str, str] = {}
    for match in _RUBY_LOCAL_BINDING_RE.finditer(body):
        ctor = match.group("ctor")
        var_name = match.group("var")
        gem_name = import_bindings.get(ctor) or import_bindings.get(ctor.lower())
        if gem_name:
            locals_map[var_name] = gem_name
    return locals_map


def _ruby_call_sites(body: str, *, line_offset: int) -> list[_RubyCallSite]:
    body = mask_line_comments_and_strings(body, hash_comments=True)
    sites: list[_RubyCallSite] = []
    for match in _RUBY_CALL_RE.finditer(body):
        name = match.group("name")
        name_start = match.start("name")
        if re.search(r"\.\s*$", body[max(0, name_start - 2) : name_start]):
            continue
        head = name.split(".", 1)[0]
        if head in _RUBY_CALL_SKIP:
            continue
        sites.append(
            _RubyCallSite(
                name=name,
                line_number=line_offset + body[: match.start()].count("\n") + 1,
            )
        )
    return sites


def _ruby_method_key(class_name: str, name: str) -> str:
    return f"{class_name}::{name}"


def _ruby_method_display_name(class_name: str, name: str, name_counts: dict[str, int]) -> str:
    if name_counts.get(name, 0) > 1:
        return _ruby_method_key(class_name, name)
    return name


def _ruby_method_body(source: str, method_start: int) -> tuple[str, int] | None:
    next_def = _RUBY_METHOD_RE.search(source, method_start + 1)
    body_end = next_def.start() if next_def else len(source)
    body_text = source[method_start:body_end]
    return body_text, _line_number_from_index(source, method_start)


def _collect_ruby_methods(
    source: str,
    *,
    rel_path: str,
    class_name: str,
    bindings: dict[str, str],
) -> dict[str, _RubyMethodAnalysis]:
    methods: dict[str, _RubyMethodAnalysis] = {}
    for match in _RUBY_METHOD_RE.finditer(source):
        name = match.group("name")
        body_segment = _ruby_method_body(source, match.end())
        call_sites: list[_RubyCallSite] = []
        method_bindings = dict(bindings)
        if body_segment is not None:
            body_text, body_line_offset = body_segment
            call_sites = _ruby_call_sites(body_text, line_offset=body_line_offset)
            method_bindings.update(_ruby_local_bindings(body_text, bindings))
        methods[_ruby_method_key(class_name, name)] = _RubyMethodAnalysis(
            name=name,
            line_number=_line_number_from_index(source, match.start()),
            file_path=rel_path,
            class_name=class_name,
            import_bindings=method_bindings,
            call_sites=call_sites,
        )
    return methods


def _resolve_ruby_tool_handler(args_text: str, *, class_name: str, methods: Mapping[str, _RubyMethodAnalysis]) -> str | None:
    method_match = re.search(r"method\s*\(\s*:(?P<method>\w+)\s*\)", args_text)
    if method_match:
        candidate = _ruby_method_key(class_name, method_match.group("method"))
        if candidate in methods:
            return candidate
    symbol_match = re.search(r"[, (]:(?P<method>\w+)\s*[,)]", args_text)
    if symbol_match:
        candidate = _ruby_method_key(class_name, symbol_match.group("method"))
        if candidate in methods:
            return candidate
    bare_match = re.search(r"[, (](?P<method>[a-z]\w*)\s*[,)]", args_text)
    if bare_match:
        candidate = _ruby_method_key(class_name, bare_match.group("method"))
        if candidate in methods:
            return candidate
    return None


def _collect_ruby_tool_registrations(
    source: str,
    *,
    rel_path: str,
    class_name: str,
    bindings: dict[str, str],
    methods: Mapping[str, _RubyMethodAnalysis],
    requires_mcp: bool,
) -> list[_RubyToolRegistration]:
    registrations: list[_RubyToolRegistration] = []
    seen: set[tuple[str, int]] = set()

    for match in _RUBY_ADD_TOOL_RE.finditer(source):
        tool_name = match.group("name").strip()
        if not tool_name:
            continue
        args_start = source.find("(", match.start())
        args_segment = _balanced_segment(source, args_start, open_char="(", close_char=")") if args_start >= 0 else None
        handler_name: str | None = None
        if args_segment is not None:
            args_text, _ = args_segment
            handler_name = _resolve_ruby_tool_handler(args_text, class_name=class_name, methods=methods)
        if handler_name is None:
            continue
        key = (tool_name, match.start())
        if key in seen:
            continue
        seen.add(key)
        registrations.append(
            _RubyToolRegistration(
                tool_name=tool_name,
                handler_name=handler_name,
                line_number=_line_number_from_index(source, match.start()),
                file_path=rel_path,
                class_name=class_name,
                import_bindings=dict(bindings),
            )
        )

    # The block body is the handler, so there is no method reference to resolve.
    # Matching on masked source keeps a commented-out registration out.
    masked = mask_line_comments_and_strings(source, hash_comments=True)
    for match in _RUBY_DEFINE_TOOL_START_RE.finditer(masked):
        name_match = _RUBY_DEFINE_TOOL_RE.match(source, match.start())
        tool_name = name_match.group("name").strip() if name_match else ""
        if not tool_name:
            continue
        key = (tool_name, match.start())
        if key in seen:
            continue
        seen.add(key)
        registrations.append(
            _RubyToolRegistration(
                tool_name=tool_name,
                handler_name=f"tool:{tool_name}",
                line_number=_line_number_from_index(source, match.start()),
                file_path=rel_path,
                class_name=class_name,
                import_bindings=dict(bindings),
            )
        )

    for match in _RUBY_TOOL_DEFINE_START_RE.finditer(masked):
        if match.group("qualifier").lower() != _RUBY_MCP_QUALIFIER and not requires_mcp:
            continue
        name_match = _RUBY_TOOL_DEFINE_RE.match(source, match.start())
        tool_name = name_match.group("name").strip() if name_match else ""
        if not tool_name:
            continue
        key = (tool_name, match.start())
        if key in seen:
            continue
        seen.add(key)
        registrations.append(
            _RubyToolRegistration(
                tool_name=tool_name,
                handler_name=f"tool:{tool_name}",
                line_number=_line_number_from_index(source, match.start()),
                file_path=rel_path,
                class_name=class_name,
                import_bindings=dict(bindings),
            )
        )

    for registration in _collect_ruby_tool_class_registrations(
        source,
        masked,
        rel_path=rel_path,
        bindings=bindings,
        requires_mcp=requires_mcp,
    ):
        key = (registration.tool_name, registration.line_number)
        if key in seen:
            continue
        seen.add(key)
        registrations.append(registration)
    return registrations


def ruby_source_requires_mcp(source: str) -> bool:
    """Return whether the file requires the official ``mcp`` gem."""
    for match in _RUBY_REQUIRE_RE.finditer(source):
        head = match.group("path").split("/", 1)[0].strip().lower()
        if head in _RUBY_MCP_REQUIRE_HEADS:
            return True
    return False


def _ruby_tool_name_from_class(class_name: str) -> str:
    """Derive the gem's default tool name from a ``MCP::Tool`` subclass name."""
    demodulized = class_name.split("::")[-1]
    underscored = _RUBY_WORD_BOUNDARY_RE.sub("_", _RUBY_ACRONYM_BOUNDARY_RE.sub("_", demodulized))
    return underscored.replace("-", "_").lower()


def _is_ruby_mcp_tool_superclass(superclass: str, *, requires_mcp: bool) -> bool:
    normalized = superclass.strip()
    if normalized.lower().endswith("::tool"):
        return normalized.lower().startswith(_RUBY_MCP_QUALIFIER)
    return normalized == "Tool" and requires_mcp


def _collect_ruby_tool_class_registrations(
    source: str,
    masked: str,
    *,
    rel_path: str,
    bindings: dict[str, str],
    requires_mcp: bool,
) -> list[_RubyToolRegistration]:
    """Collect ``class MyTool < MCP::Tool`` definitions as tool registrations."""
    registrations: list[_RubyToolRegistration] = []
    declarations = list(_RUBY_CLASS_DECL_RE.finditer(masked))
    for index, match in enumerate(declarations):
        if not _is_ruby_mcp_tool_superclass(match.group("superclass"), requires_mcp=requires_mcp):
            continue
        class_name = match.group("name")
        body_end = declarations[index + 1].start() if index + 1 < len(declarations) else len(masked)
        tool_name = _ruby_tool_name_from_class(class_name)
        # ``tool_name "…"`` inside the class body overrides the derived name. The
        # literal is blanked by masking, so the head is located in the masked
        # text and the name read from the real source at the same offset.
        declared = _RUBY_TOOL_NAME_DECL_START_RE.search(masked, match.end(), body_end)
        if declared is not None:
            explicit = _RUBY_TOOL_NAME_DECL_RE.match(source, declared.start())
            if explicit is not None and explicit.group("name").strip():
                tool_name = explicit.group("name").strip()
        if not tool_name:
            continue
        registrations.append(
            _RubyToolRegistration(
                tool_name=tool_name,
                handler_name=f"tool:{tool_name}",
                line_number=_line_number_from_index(source, match.start()),
                file_path=rel_path,
                class_name=class_name,
                import_bindings=dict(bindings),
            )
        )
    return registrations


def _resolve_ruby_callee_key(
    call_name: str,
    *,
    class_name: str,
    methods: Mapping[str, _RubyMethodAnalysis],
) -> str | None:
    bare = call_name.split("(", 1)[0].strip()
    if "." in bare:
        _, tail = bare.split(".", 1)
        candidate = _ruby_method_key(class_name, tail)
        if candidate in methods:
            return candidate
    candidate = _ruby_method_key(class_name, bare)
    if candidate in methods:
        return candidate
    return None


def _resolve_ruby_external_dependency_symbol(
    method: _RubyMethodAnalysis,
    call_name: str,
) -> tuple[str, str, str] | None:
    """Resolve an external require call to ``(package, module, symbol)``."""
    if not call_name or "." not in call_name:
        return None
    head, tail = call_name.split(".", 1)
    gem_name = method.import_bindings.get(head) or method.import_bindings.get(head.lower())
    if not gem_name or not is_verified_ruby_gem(gem_name, method.import_bindings):
        return None
    symbol = tail.split(".", 1)[0]
    if not is_actionable_dependency_symbol(symbol):
        return None
    return gem_name, gem_name, symbol


def build_ruby_dependency_symbol_reach(
    *,
    methods: Mapping[str, _RubyMethodAnalysis],
    tool_registrations: Sequence[_RubyToolRegistration],
    max_depth: int = 4,
) -> list[DependencySymbolReach]:
    """Build bounded MCP tool-entrypoint -> RubyGems dependency symbol reach."""
    if not methods or not tool_registrations:
        return []

    adjacency: dict[str, set[str]] = {name: set() for name in methods}
    name_counts: dict[str, int] = {}
    for method in methods.values():
        name_counts[method.name] = name_counts.get(method.name, 0) + 1

    for method_key, method in methods.items():
        for call_site in method.call_sites:
            callee_key = _resolve_ruby_callee_key(
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
        return _ruby_method_display_name(method.class_name, method.name, name_counts)

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
                external = _resolve_ruby_external_dependency_symbol(current, call_site.name)
                if external is None:
                    continue
                package_name, module_name, symbol = external
                dedup_key = (registration.tool_name, module_name, symbol, current.file_path, call_site.line_number)
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
                        ecosystem="rubygems",
                    )
                )
            for next_callee in sorted(adjacency.get(current_key, ())):
                queue.append((next_callee, [*path, next_callee]))

    return reached


def scan_ruby_file(
    file_path: Path,
    rel_path: str,
    *,
    gem_map: Mapping[str, str],
) -> tuple[
    list[ExtractedPrompt],
    list[DetectedGuardrail],
    list[ToolSignature],
    list[FlowFinding],
    list[str],
    list[CallEdge],
    _RubyFileAnalysis | None,
]:
    """Extract MCP/tool signals and call sites from Ruby source files."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], [], [], [], [], [], None

    if len(source) > _MAX_FILE_SIZE:
        return [], [], [], [], [], [], None

    class_match = _RUBY_CLASS_RE.search(source)
    class_name = class_match.group("name") if class_match else Path(rel_path).stem.capitalize()
    bindings = _ruby_require_bindings(source, gem_map)
    frameworks = sorted(
        {
            framework
            for prefix, framework in _RUBY_FRAMEWORK_HINTS.items()
            if any(prefix in binding.lower() for binding in bindings.values())
        }
    )
    methods = _collect_ruby_methods(source, rel_path=rel_path, class_name=class_name, bindings=bindings)
    tool_registrations = _collect_ruby_tool_registrations(
        source,
        rel_path=rel_path,
        class_name=class_name,
        bindings=bindings,
        methods=methods,
        requires_mcp=ruby_source_requires_mcp(source),
    )
    tools: list[ToolSignature] = []
    for registration in tool_registrations:
        tools.append(
            ToolSignature(
                name=registration.tool_name,
                parameters=[],
                return_type="unknown",
                description="Ruby MCP/tool registration",
                file_path=rel_path,
                line_number=registration.line_number,
                decorators=["ruby-tool"],
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
        _RubyFileAnalysis(
            class_name=class_name,
            functions=methods,
            tool_registrations=tool_registrations,
        ),
    )
