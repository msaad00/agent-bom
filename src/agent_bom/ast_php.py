"""PHP analyzer helpers for MCP Composer symbol-level reachability.

Regex-backed and conservative: Composer package names must be declared in
``composer.lock`` (or ``composer.json`` when no lock exists) before ``use``
bindings are trusted. Unresolved MCP tool handlers are dropped so headless
agents do not inherit false ``function_reachable`` upgrades at CVE join time.
"""

from __future__ import annotations

import json
import logging
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
    _PhpCallSite,
    _PhpFileAnalysis,
    _PhpMethodAnalysis,
    _PhpToolRegistration,
)
from agent_bom.ast_source_mask import mask_php_source
from agent_bom.ast_symbol_reach_guards import is_actionable_dependency_symbol, is_verified_composer_package

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

_MAX_FILE_SIZE = 512 * 1024
_PHP_USE_RE = re.compile(
    r"""^\s*use\s+(?P<import>[\w\\]+)(?:\s+as\s+(?P<alias>\w+))?;""",
    re.MULTILINE,
)
_PHP_CLASS_RE = re.compile(r"^\s*class\s+(?P<name>\w+)", re.MULTILINE)
_PHP_METHOD_RE = re.compile(
    r"^\s*(?:public|private|protected)?\s*function\s+(?P<name>\w+)\s*\(",
    re.MULTILINE,
)
_PHP_OBJECT_CALL_RE = re.compile(r"(?P<receiver>\$\w+|\w+)\s*->\s*(?P<method>\w+)\s*\(")
_PHP_STATIC_CALL_RE = re.compile(r"(?P<class>[\w\\]+)\s*::\s*(?P<method>\w+)\s*\(")
_PHP_NEW_BINDING_RE = re.compile(
    r"""(?P<var>\$\w+)\s*=\s*new\s+(?:\\)?(?P<class>[\w\\]+)\s*\(""",
)
_PHP_TOOL_RE = re.compile(
    r"""->(?:tool|registerTool|addTool)\s*\(\s*['"](?P<name>[^'"]+)['"]""",
    re.IGNORECASE,
)
_PHP_HANDLER_ARRAY_RE = re.compile(
    r"""\[\s*\$this\s*,\s*['"](?P<method>\w+)['"]\s*\]""",
    re.IGNORECASE,
)
_PHP_HANDLER_STRING_RE = re.compile(
    r"""->(?:tool|registerTool|addTool)\s*\(\s*['"][^'"]+['"]\s*,\s*['"](?P<method>\w+)['"]""",
    re.IGNORECASE,
)
_PHP_FRAMEWORK_HINTS: dict[str, str] = {
    "modelcontextprotocol": "MCP",
    "mcp": "MCP",
}

logger = logging.getLogger(__name__)

# Keys that carry a PSR-4/PSR-0 autoload namespace root (rather than a package
# name / vendor alias) inside the flat package map. The prefix keeps the map a
# plain ``dict[str, str]`` so ``is_verified_composer_package`` (which inspects
# ``.values()``) keeps working unchanged.
_PSR_ROOT_KEY = "\x00psr\x00"


def _line_number_from_index(source: str, index: int) -> int:
    return source[:index].count("\n") + 1


def _composer_autoload_roots(project: Path) -> dict[str, str]:
    """Map each package's PSR-4/PSR-0 namespace roots to its Composer name.

    Reads ``packages[].autoload`` from ``composer.lock`` so a ``use`` such as
    ``PhpParser\\ParserFactory`` resolves to ``nikic/php-parser`` even though
    the namespace head never matches the vendor segment. Prefixes are returned
    with the trailing ``\\`` stripped (PSR-0 underscore prefixes are kept).
    """
    lockfile = Path(project) / "composer.lock"
    if not lockfile.is_file():
        return {}
    try:
        data = json.loads(lockfile.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Cannot read %s for PSR-4 roots: %s", lockfile, exc)
        return {}

    roots: dict[str, str] = {}
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section, []):
            name = (pkg.get("name") or "").strip()
            if not name:
                continue
            autoload = pkg.get("autoload") or {}
            for scheme in ("psr-4", "psr-0"):
                namespaces = autoload.get(scheme) or {}
                if not isinstance(namespaces, dict):
                    continue
                for namespace in namespaces:
                    prefix = (namespace or "").rstrip("\\").strip()
                    if prefix:
                        roots.setdefault(prefix, name)
    return roots


def load_composer_package_map(project: Path) -> dict[str, str]:
    """Map PHP namespace prefixes and aliases to declared Composer packages."""
    from agent_bom.parsers.php_parsers import parse_php_packages

    mapping: dict[str, str] = {}
    for pkg in parse_php_packages(project):
        name = pkg.name.strip()
        if not name:
            continue
        mapping[name.lower()] = name
        mapping[name] = name
        vendor, _, _short = name.partition("/")
        if vendor:
            # Vendor-segment binding is a last-resort fallback only; PSR-4 roots
            # below take precedence. ``setdefault`` avoids a multi-package vendor
            # clobbering itself nondeterministically (finding #5).
            mapping.setdefault(vendor.lower(), name)

    for prefix, pkg_name in _composer_autoload_roots(project).items():
        mapping[_PSR_ROOT_KEY + prefix] = pkg_name

    return mapping


def _ns_matches_prefix(ns: str, prefix: str) -> bool:
    if ns == prefix:
        return True
    if ns.startswith(prefix + "\\"):
        return True
    # PSR-0 underscore-style roots (e.g. ``Twig_``) use ``_`` as the boundary.
    return prefix.endswith("_") and ns.startswith(prefix)


def _php_package_for_namespace(ns: str, package_map: Mapping[str, str]) -> str | None:
    ns = (ns or "").lstrip("\\").strip()
    if not ns:
        return None

    # Prefer a real PSR-4/PSR-0 autoload root, longest-prefix wins so nested
    # namespaces bind to the most specific declaring package.
    best_prefix: str | None = None
    best_pkg: str | None = None
    for key, pkg in package_map.items():
        if not key.startswith(_PSR_ROOT_KEY):
            continue
        prefix = key[len(_PSR_ROOT_KEY) :]
        if not _ns_matches_prefix(ns, prefix):
            continue
        if best_prefix is None or len(prefix) > len(best_prefix):
            best_prefix, best_pkg = prefix, pkg
    if best_pkg and is_verified_composer_package(best_pkg, dict(package_map)):
        return best_pkg

    # Fallback: legacy vendor-segment match for packages with no autoload roots.
    head = ns.split("\\", 1)[0].strip().lower()
    if not head:
        return None
    for pkg_name in set(package_map.values()):
        vendor = pkg_name.split("/", 1)[0].lower()
        if vendor == head and is_verified_composer_package(pkg_name, dict(package_map)):
            return pkg_name
    return None


def _php_use_bindings(source: str, package_map: Mapping[str, str]) -> dict[str, str]:
    bindings: dict[str, str] = {}
    for match in _PHP_USE_RE.finditer(source):
        imported = match.group("import").strip()
        alias = (match.group("alias") or imported.split("\\")[-1]).strip()
        package = _php_package_for_namespace(imported, package_map)
        if not package:
            continue
        bindings[alias] = package
        bindings[alias.lower()] = package
        bindings[imported.split("\\")[-1]] = package
    return bindings


def _php_local_bindings(body: str, import_bindings: Mapping[str, str]) -> dict[str, str]:
    locals_map: dict[str, str] = {}
    for match in _PHP_NEW_BINDING_RE.finditer(body):
        class_name = match.group("class").strip()
        short = class_name.split("\\")[-1]
        package = import_bindings.get(short) or import_bindings.get(short.lower())
        if package:
            locals_map[match.group("var")] = package
    return locals_map


def _php_method_key(class_name: str, name: str) -> str:
    return f"{class_name}::{name}"


def _php_class_spans(source: str) -> list[tuple[str, int]]:
    """Return ``(class_name, start_index)`` for every class declaration in order."""
    return [(match.group("name"), match.start()) for match in _PHP_CLASS_RE.finditer(source)]


def _php_class_at(spans: Sequence[tuple[str, int]], default_class: str, index: int) -> str:
    """Return the class enclosing ``index`` (the last class declared before it)."""
    name = default_class
    for class_name, start in spans:
        if start <= index:
            name = class_name
        else:
            break
    return name


def _php_method_body(source: str, method_start: int, method_end: int) -> tuple[str, int] | None:
    next_def = _PHP_METHOD_RE.search(source, method_end)
    body_end = next_def.start() if next_def else len(source)
    body_text = source[method_start:body_end]
    return body_text, _line_number_from_index(source, method_start)


def _php_call_sites(body: str, *, line_offset: int) -> list[_PhpCallSite]:
    sites: list[_PhpCallSite] = []
    # Blank comments, string literals and heredoc/nowdoc bodies so a
    # ``Class::method(`` token mentioned in text is never emitted as a call
    # site (a false ``function_reachable`` upgrade at CVE join time). Offsets
    # are preserved, so line numbers stay accurate.
    body = mask_php_source(body)
    for match in _PHP_OBJECT_CALL_RE.finditer(body):
        sites.append(
            _PhpCallSite(
                name=f"{match.group('receiver')}->{match.group('method')}",
                line_number=line_offset + body[: match.start()].count("\n") + 1,
            ),
        )
    for match in _PHP_STATIC_CALL_RE.finditer(body):
        sites.append(
            _PhpCallSite(
                name=f"{match.group('class')}::{match.group('method')}",
                line_number=line_offset + body[: match.start()].count("\n") + 1,
            ),
        )
    return sites


def _collect_php_methods(
    source: str,
    *,
    rel_path: str,
    default_class: str,
    class_spans: Sequence[tuple[str, int]],
    bindings: Mapping[str, str],
) -> dict[str, _PhpMethodAnalysis]:
    methods: dict[str, _PhpMethodAnalysis] = {}
    for match in _PHP_METHOD_RE.finditer(source):
        name = match.group("name")
        # Key each method to the class that actually encloses it so multi-class
        # files do not collapse every method under the first class declaration.
        class_name = _php_class_at(class_spans, default_class, match.start())
        body_segment = _php_method_body(source, match.start(), match.end())
        if body_segment is None:
            continue
        body_text, line_number = body_segment
        methods[_php_method_key(class_name, name)] = _PhpMethodAnalysis(
            name=name,
            line_number=line_number,
            file_path=rel_path,
            class_name=class_name,
            import_bindings=dict(bindings),
            local_bindings=_php_local_bindings(body_text, bindings),
            call_sites=_php_call_sites(body_text, line_offset=line_number),
        )
    return methods


def _resolve_php_tool_handler(
    source: str,
    *,
    class_name: str,
    methods: Mapping[str, _PhpMethodAnalysis],
) -> str | None:
    array_match = _PHP_HANDLER_ARRAY_RE.search(source)
    if array_match:
        return _php_method_key(class_name, array_match.group("method"))
    string_match = _PHP_HANDLER_STRING_RE.search(source)
    if string_match:
        return _php_method_key(class_name, string_match.group("method"))
    return None


def _collect_php_tool_registrations(
    source: str,
    *,
    rel_path: str,
    default_class: str,
    class_spans: Sequence[tuple[str, int]],
    bindings: Mapping[str, str],
    methods: Mapping[str, _PhpMethodAnalysis],
) -> list[_PhpToolRegistration]:
    registrations: list[_PhpToolRegistration] = []
    seen: set[tuple[str, int]] = set()
    for match in _PHP_TOOL_RE.finditer(source):
        tool_name = match.group("name").strip()
        if not tool_name:
            continue
        class_name = _php_class_at(class_spans, default_class, match.start())
        window = source[match.start() : match.start() + 240]
        handler_name = _resolve_php_tool_handler(window, class_name=class_name, methods=methods)
        if handler_name is None or handler_name not in methods:
            continue
        key = (tool_name, match.start())
        if key in seen:
            continue
        seen.add(key)
        registrations.append(
            _PhpToolRegistration(
                tool_name=tool_name,
                handler_name=handler_name,
                line_number=_line_number_from_index(source, match.start()),
                file_path=rel_path,
                class_name=class_name,
                import_bindings=dict(bindings),
            ),
        )
    return registrations


def _resolve_php_callee_key(
    call_name: str,
    *,
    class_name: str,
    methods: Mapping[str, _PhpMethodAnalysis],
) -> str | None:
    if "->" in call_name:
        _, method = call_name.split("->", 1)
        candidate = _php_method_key(class_name, method)
        if candidate in methods:
            return candidate
    if "::" in call_name:
        _, method = call_name.rsplit("::", 1)
        candidate = _php_method_key(class_name, method)
        if candidate in methods:
            return candidate
    return None


def _resolve_php_external_dependency_symbol(
    method: _PhpMethodAnalysis,
    call_name: str,
    *,
    package_map: Mapping[str, str],
) -> tuple[str, str, str] | None:
    symbol: str | None = None
    package: str | None = None

    if "->" in call_name:
        receiver, symbol = call_name.split("->", 1)
        package = method.local_bindings.get(receiver) or method.import_bindings.get(receiver.lstrip("$"))
    elif "::" in call_name:
        class_ref, symbol = call_name.rsplit("::", 1)
        package = _php_package_for_namespace(class_ref, package_map) or method.import_bindings.get(
            class_ref.split("\\")[-1],
        )

    if not package or not symbol or not is_verified_composer_package(package, dict(package_map)):
        return None
    if not is_actionable_dependency_symbol(symbol):
        return None
    return package, package, symbol


def build_php_dependency_symbol_reach(
    *,
    methods: Mapping[str, _PhpMethodAnalysis],
    tool_registrations: Sequence[_PhpToolRegistration],
    package_map: Mapping[str, str],
    max_depth: int = 4,
) -> list[DependencySymbolReach]:
    if not methods or not tool_registrations or not package_map:
        return []

    adjacency: dict[str, set[str]] = {name: set() for name in methods}
    name_counts: dict[str, int] = {}
    for method in methods.values():
        name_counts[method.name] = name_counts.get(method.name, 0) + 1

    for method_key, method in methods.items():
        for call_site in method.call_sites:
            callee_key = _resolve_php_callee_key(
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
        if name_counts.get(method.name, 0) > 1:
            return _php_method_key(method.class_name, method.name)
        return method.name

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
                external = _resolve_php_external_dependency_symbol(
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
                        ecosystem="composer",
                    ),
                )
            for next_callee in sorted(adjacency.get(current_key, ())):
                queue.append((next_callee, [*path, next_callee]))

    return reached


def scan_php_file(
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
    _PhpFileAnalysis | None,
]:
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], [], [], [], [], [], None

    if len(source) > _MAX_FILE_SIZE:
        logger.warning(
            "Skipping PHP reachability scan for %s: %d bytes exceeds %d-byte limit",
            rel_path,
            len(source),
            _MAX_FILE_SIZE,
        )
        return [], [], [], [], [], [], None

    class_spans = _php_class_spans(source)
    default_class = class_spans[0][0] if class_spans else Path(rel_path).stem
    class_name = default_class
    bindings = _php_use_bindings(source, package_map)
    frameworks = sorted(
        {
            framework
            for prefix, framework in _PHP_FRAMEWORK_HINTS.items()
            if any(prefix in binding.lower() for binding in bindings.values())
        },
    )
    methods = _collect_php_methods(
        source,
        rel_path=rel_path,
        default_class=default_class,
        class_spans=class_spans,
        bindings=bindings,
    )
    tool_registrations = _collect_php_tool_registrations(
        source,
        rel_path=rel_path,
        default_class=default_class,
        class_spans=class_spans,
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
                description="PHP MCP/tool registration",
                file_path=rel_path,
                line_number=registration.line_number,
                decorators=["php-tool"],
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
        _PhpFileAnalysis(
            class_name=class_name,
            functions=methods,
            tool_registrations=tool_registrations,
        ),
    )
