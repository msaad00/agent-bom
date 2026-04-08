"""Parser-backed JS/TS analysis helpers.

This module provides a small, focused AST layer for JavaScript and
TypeScript code blocks used in skills and future first-party SAST rules.
It intentionally starts with import/require resolution plus call-site
collection so higher layers can reason about dangerous capabilities using
real syntax trees instead of regexes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from tree_sitter import Language, Parser
    from tree_sitter import Node as TreeSitterNode
else:
    Language = Any
    Parser = Any
    TreeSitterNode = Any


class JSTSAstUnavailableError(RuntimeError):
    """Raised when the parser runtime is unavailable."""


@dataclass
class JSTSAstAnalysis:
    """Structured JS/TS AST analysis output."""

    call_names: set[str] = field(default_factory=set)
    function_aliases: dict[str, str] = field(default_factory=dict)
    namespace_aliases: dict[str, str] = field(default_factory=dict)
    imported_modules: set[str] = field(default_factory=set)
    functions: dict[str, "JSTSFunction"] = field(default_factory=dict)
    tool_registrations: list["JSTSToolRegistration"] = field(default_factory=list)


@dataclass
class JSTSCallSite:
    """A function or capability call found in JS/TS source."""

    name: str
    line_number: int


@dataclass
class JSTSFunction:
    """A lightweight JS/TS function inventory entry."""

    name: str
    line_number: int
    param_names: list[str] = field(default_factory=list)
    call_sites: list[JSTSCallSite] = field(default_factory=list)
    dangerous_call_sites: list[JSTSCallSite] = field(default_factory=list)


@dataclass
class JSTSToolRegistration:
    """A JS/TS MCP tool registration with its handler target."""

    tool_name: str
    handler_name: str
    line_number: int


_IMPORTABLE_SUBPROCESS_CALLS = {
    "exec",
    "execSync",
    "spawn",
    "spawnSync",
    "fork",
}

_IMPORTABLE_FILE_MUTATION_CALLS = {
    "writeFile",
    "writeFileSync",
    "appendFile",
    "appendFileSync",
    "unlink",
    "unlinkSync",
    "rm",
    "rmSync",
    "rename",
    "renameSync",
    "writeTextFile",
    "remove",
}

_DANGEROUS_CALL_PREFIXES = ("child_process.", "fs.", "Bun.", "Deno.")


def _load_tree_sitter_runtime() -> tuple[Any, Any, Any, Any]:
    try:
        import tree_sitter_javascript as _javascript
        import tree_sitter_typescript as _typescript
        from tree_sitter import Language as LanguageCls  # noqa: N813
        from tree_sitter import Parser as ParserCls  # noqa: N813
    except ImportError as exc:  # pragma: no cover - exercised through fallback path
        raise JSTSAstUnavailableError(
            "JS/TS AST analysis requires tree-sitter, tree-sitter-javascript, and tree-sitter-typescript."
        ) from exc

    return LanguageCls, ParserCls, _javascript, _typescript


@lru_cache(maxsize=4)
def _language_for_hint(language_hint: str) -> Language:
    language_cls, _parser_cls, javascript, typescript = _load_tree_sitter_runtime()
    hint = language_hint.lower().strip()
    if hint in {"typescript", "ts"}:
        return language_cls(typescript.language_typescript())
    if hint == "tsx":
        return language_cls(typescript.language_tsx())
    # tree-sitter-javascript handles both javascript and jsx.
    return language_cls(javascript.language())


def _iter_nodes(root: TreeSitterNode):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.named_children))


def _node_text(node: TreeSitterNode | None, source: bytes) -> str:
    if node is None:
        return ""
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _string_literal_value(node: TreeSitterNode | None, source: bytes) -> str:
    text = _node_text(node, source).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'", "`"}:
        return text[1:-1]
    return text


def _normalize_module_name(module_name: str) -> str:
    module_name = module_name.strip()
    if module_name.startswith("node:"):
        module_name = module_name[5:]
    return module_name


def _line_number(node: TreeSitterNode | None) -> int:
    if node is None or not hasattr(node, "start_point"):
        return 1
    return int(node.start_point[0]) + 1


def _canonical_function_call(module_name: str, imported_name: str) -> str | None:
    module_name = _normalize_module_name(module_name)
    imported_name = imported_name.strip()
    if module_name == "child_process" and imported_name in _IMPORTABLE_SUBPROCESS_CALLS:
        return f"child_process.{imported_name}"
    if module_name == "fs" and imported_name in _IMPORTABLE_FILE_MUTATION_CALLS:
        return f"fs.{imported_name}"
    if module_name == "fs/promises" and imported_name in _IMPORTABLE_FILE_MUTATION_CALLS:
        return f"fs.promises.{imported_name}"
    return None


def _canonical_namespace(module_name: str) -> str | None:
    module_name = _normalize_module_name(module_name)
    if module_name == "child_process":
        return "child_process"
    if module_name == "fs":
        return "fs"
    if module_name == "fs/promises":
        return "fs.promises"
    return None


def _identifier_like_text(node: TreeSitterNode | None, source: bytes) -> str:
    text = _node_text(node, source).strip()
    return text


def _expression_name(node: TreeSitterNode | None, source: bytes) -> str:
    if node is None:
        return ""
    if node.type in {"identifier", "property_identifier"}:
        return _node_text(node, source).strip()
    if node.type in {"member_expression", "subscript_expression"}:
        object_node = node.child_by_field_name("object")
        property_node = node.child_by_field_name("property")
        if object_node is None:
            named = node.named_children
            if named:
                object_node = named[0]
            if len(named) > 1:
                property_node = named[-1]
        object_name = _expression_name(object_node, source)
        property_name = _expression_name(property_node, source)
        if object_name and property_name:
            return f"{object_name}.{property_name}"
        return object_name or property_name
    if node.type in {"parenthesized_expression", "await_expression"} and node.named_children:
        return _expression_name(node.named_children[-1], source)
    return ""


def _canonicalize_reference_name(
    raw_name: str,
    function_aliases: dict[str, str],
    namespace_aliases: dict[str, str],
) -> str:
    raw_name = raw_name.strip()
    if not raw_name:
        return ""
    if raw_name in function_aliases:
        return function_aliases[raw_name]
    if "." not in raw_name:
        return raw_name
    base, remainder = raw_name.split(".", 1)
    if base in namespace_aliases:
        return f"{namespace_aliases[base]}.{remainder}"
    return raw_name


def _is_dangerous_reference(reference_name: str) -> bool:
    if reference_name in {"eval", "Function"}:
        return True
    return reference_name.startswith(_DANGEROUS_CALL_PREFIXES)


def _collect_import_aliases(root: TreeSitterNode, source: bytes, analysis: JSTSAstAnalysis) -> None:
    for node in _iter_nodes(root):
        if node.type != "import_statement":
            continue

        module_node = next((child for child in node.named_children if child.type == "string"), None)
        module_name = _string_literal_value(module_node, source)
        if not module_name:
            continue
        analysis.imported_modules.add(_normalize_module_name(module_name))

        clause = next((child for child in node.named_children if child.type == "import_clause"), None)
        if clause is None:
            continue

        for child in clause.named_children:
            if child.type == "named_imports":
                for spec in child.named_children:
                    if spec.type != "import_specifier":
                        continue
                    identifiers = [
                        _identifier_like_text(named_child, source)
                        for named_child in spec.named_children
                        if named_child.type in {"identifier", "property_identifier"}
                    ]
                    if not identifiers:
                        continue
                    imported_name = identifiers[0]
                    alias = identifiers[-1]
                    canonical = _canonical_function_call(module_name, imported_name)
                    if canonical:
                        analysis.function_aliases[alias] = canonical
            elif child.type == "namespace_import":
                alias_nodes = [
                    named_child for named_child in child.named_children if named_child.type in {"identifier", "property_identifier"}
                ]
                if not alias_nodes:
                    continue
                canonical = _canonical_namespace(module_name)
                if canonical:
                    analysis.namespace_aliases[_identifier_like_text(alias_nodes[-1], source)] = canonical
            elif child.type == "identifier":
                canonical = _canonical_namespace(module_name)
                if canonical:
                    analysis.namespace_aliases[_identifier_like_text(child, source)] = canonical


def _is_require_call(node: TreeSitterNode, source: bytes) -> bool:
    if node.type != "call_expression":
        return False
    return _expression_name(node.child_by_field_name("function"), source) == "require"


def _require_module_name(node: TreeSitterNode, source: bytes) -> str:
    arguments = node.child_by_field_name("arguments")
    if arguments is None:
        return ""
    string_arg = next((child for child in arguments.named_children if child.type == "string"), None)
    return _string_literal_value(string_arg, source)


def _collect_require_aliases(root: TreeSitterNode, source: bytes, analysis: JSTSAstAnalysis) -> None:
    for node in _iter_nodes(root):
        if node.type != "variable_declarator":
            continue

        value_node = node.child_by_field_name("value")
        name_node = node.child_by_field_name("name")
        if value_node is None or name_node is None or not _is_require_call(value_node, source):
            continue

        module_name = _require_module_name(value_node, source)
        if not module_name:
            continue
        analysis.imported_modules.add(_normalize_module_name(module_name))

        if name_node.type == "object_pattern":
            for child in name_node.named_children:
                if child.type == "pair_pattern":
                    identifiers = [
                        _identifier_like_text(named_child, source)
                        for named_child in child.named_children
                        if named_child.type in {"identifier", "property_identifier"}
                    ]
                    if not identifiers:
                        continue
                    imported_name = identifiers[0]
                    alias = identifiers[-1]
                    canonical = _canonical_function_call(module_name, imported_name)
                    if canonical:
                        analysis.function_aliases[alias] = canonical
                elif child.type in {"identifier", "shorthand_property_identifier_pattern"}:
                    imported_name = _identifier_like_text(child, source)
                    canonical = _canonical_function_call(module_name, imported_name)
                    if canonical:
                        analysis.function_aliases[imported_name] = canonical
        elif name_node.type == "identifier":
            canonical = _canonical_namespace(module_name)
            if canonical:
                analysis.namespace_aliases[_identifier_like_text(name_node, source)] = canonical


def _propagate_alias_assignments(root: TreeSitterNode, source: bytes, analysis: JSTSAstAnalysis) -> None:
    for node in _iter_nodes(root):
        if node.type != "variable_declarator":
            continue
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        if name_node is None or value_node is None or name_node.type != "identifier":
            continue
        if value_node.type == "call_expression" and _is_require_call(value_node, source):
            continue

        raw_name = _expression_name(value_node, source)
        canonical = _canonicalize_reference_name(raw_name, analysis.function_aliases, analysis.namespace_aliases)
        if canonical and _is_dangerous_reference(canonical):
            analysis.function_aliases[_identifier_like_text(name_node, source)] = canonical


def _collect_call_names(root: TreeSitterNode, source: bytes, analysis: JSTSAstAnalysis) -> None:
    for node in _iter_nodes(root):
        if node.type == "call_expression":
            raw_name = _expression_name(node.child_by_field_name("function"), source)
            canonical = _canonicalize_reference_name(raw_name, analysis.function_aliases, analysis.namespace_aliases)
            if canonical:
                analysis.call_names.add(canonical)
        elif node.type == "new_expression":
            constructor = _expression_name(node.child_by_field_name("constructor"), source)
            canonical = _canonicalize_reference_name(constructor, analysis.function_aliases, analysis.namespace_aliases)
            if canonical:
                analysis.call_names.add(canonical)


def _identifier_names(node: TreeSitterNode | None, source: bytes) -> list[str]:
    if node is None:
        return []
    names: list[str] = []
    for child in _iter_nodes(node):
        if child.type in {"identifier", "property_identifier", "shorthand_property_identifier_pattern"}:
            names.append(_identifier_like_text(child, source))
    return names


def _call_sites(root: TreeSitterNode | None, source: bytes, analysis: JSTSAstAnalysis) -> list[JSTSCallSite]:
    if root is None:
        return []
    call_sites: list[JSTSCallSite] = []
    for node in _iter_nodes(root):
        canonical = ""
        if node.type == "call_expression":
            raw_name = _expression_name(node.child_by_field_name("function"), source)
            canonical = _canonicalize_reference_name(raw_name, analysis.function_aliases, analysis.namespace_aliases)
        elif node.type == "new_expression":
            raw_name = _expression_name(node.child_by_field_name("constructor"), source)
            canonical = _canonicalize_reference_name(raw_name, analysis.function_aliases, analysis.namespace_aliases)
        if canonical:
            call_sites.append(JSTSCallSite(name=canonical, line_number=_line_number(node)))
    return call_sites


def _register_function(
    *,
    function_name: str,
    line_number: int,
    parameter_node: TreeSitterNode | None,
    body_node: TreeSitterNode | None,
    source: bytes,
    analysis: JSTSAstAnalysis,
) -> None:
    if not function_name or function_name in analysis.functions:
        return
    call_sites = _call_sites(body_node, source, analysis)
    analysis.functions[function_name] = JSTSFunction(
        name=function_name,
        line_number=line_number,
        param_names=_identifier_names(parameter_node, source),
        call_sites=call_sites,
        dangerous_call_sites=[site for site in call_sites if _is_dangerous_reference(site.name)],
    )


def _collect_functions(root: TreeSitterNode, source: bytes, analysis: JSTSAstAnalysis) -> None:
    for node in _iter_nodes(root):
        if node.type == "function_declaration":
            name_node = node.child_by_field_name("name")
            params_node = node.child_by_field_name("parameters")
            body_node = node.child_by_field_name("body")
            _register_function(
                function_name=_identifier_like_text(name_node, source),
                line_number=_line_number(node),
                parameter_node=params_node,
                body_node=body_node,
                source=source,
                analysis=analysis,
            )
            continue

        if node.type != "variable_declarator":
            continue
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        if name_node is None or value_node is None:
            continue
        if value_node.type not in {"arrow_function", "function", "function_expression"}:
            continue
        params_node = value_node.child_by_field_name("parameters")
        body_node = value_node.child_by_field_name("body")
        _register_function(
            function_name=_identifier_like_text(name_node, source),
            line_number=_line_number(name_node),
            parameter_node=params_node,
            body_node=body_node,
            source=source,
            analysis=analysis,
        )


def _collect_tool_registrations(root: TreeSitterNode, source: bytes, analysis: JSTSAstAnalysis) -> None:
    for node in _iter_nodes(root):
        if node.type != "call_expression":
            continue
        function_name = _expression_name(node.child_by_field_name("function"), source)
        if function_name.split(".")[-1] != "tool":
            continue

        args_node = node.child_by_field_name("arguments")
        if args_node is None:
            continue
        arguments = list(args_node.named_children)
        tool_name_node = next((child for child in arguments if child.type == "string"), None)
        tool_name = _string_literal_value(tool_name_node, source)
        if not tool_name:
            continue

        handler_name = f"tool:{tool_name}"
        if arguments:
            handler_node = arguments[-1]
            if handler_node.type in {"identifier", "property_identifier"}:
                handler_name = _identifier_like_text(handler_node, source)
            elif handler_node.type in {"arrow_function", "function", "function_expression"}:
                _register_function(
                    function_name=handler_name,
                    line_number=_line_number(handler_node),
                    parameter_node=handler_node.child_by_field_name("parameters"),
                    body_node=handler_node.child_by_field_name("body"),
                    source=source,
                    analysis=analysis,
                )

        analysis.tool_registrations.append(
            JSTSToolRegistration(
                tool_name=tool_name,
                handler_name=handler_name,
                line_number=_line_number(node),
            )
        )


def analyze_js_ts_block(source: str, *, language_hint: str = "javascript") -> JSTSAstAnalysis:
    """Parse a JS/TS block and return canonicalized capability + structure data."""
    _language_cls, parser_cls, _javascript, _typescript = _load_tree_sitter_runtime()
    parser = parser_cls(_language_for_hint(language_hint))
    source_bytes = source.encode("utf-8", errors="replace")
    tree = parser.parse(source_bytes)
    analysis = JSTSAstAnalysis()

    _collect_import_aliases(tree.root_node, source_bytes, analysis)
    _collect_require_aliases(tree.root_node, source_bytes, analysis)
    _propagate_alias_assignments(tree.root_node, source_bytes, analysis)
    _collect_functions(tree.root_node, source_bytes, analysis)
    _collect_tool_registrations(tree.root_node, source_bytes, analysis)
    _collect_call_names(tree.root_node, source_bytes, analysis)
    return analysis
