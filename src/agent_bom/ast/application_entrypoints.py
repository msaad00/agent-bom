"""Conservative discovery of externally invokable application entrypoints.

Application roots are deliberately separate from MCP/agent tools.  A symbol is
only promoted when source or packaging metadata provides concrete invocation
evidence; ordinary exported functions are not roots.
"""

from __future__ import annotations

import ast
import configparser
import re
import tomllib
from pathlib import Path
from typing import Iterable

from agent_bom.ast_models import ApplicationEntrypoint
from agent_bom.ast_source_mask import mask_line_comments_and_strings

_ROUTE_METHODS = frozenset({"delete", "get", "head", "options", "patch", "post", "put", "route", "websocket"})
_MAX_SOURCE_SIZE_BYTES = 2_000_000
_LANGUAGE_BY_SUFFIX = {
    ".cs": "csharp",
    ".go": "go",
    ".java": "java",
    ".js": "javascript_typescript",
    ".jsx": "javascript_typescript",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".php": "php",
    ".rb": "ruby",
    ".rs": "rust",
    ".swift": "swift",
    ".ts": "javascript_typescript",
    ".tsx": "javascript_typescript",
}


def _line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _code_matches(
    pattern: str | re.Pattern[str],
    source: str,
    masked_source: str,
    flags: int = 0,
) -> Iterable[re.Match[str]]:
    """Yield source matches whose span still contains executable code."""
    for match in re.finditer(pattern, source, flags):
        if any(not char.isspace() for char in masked_source[match.start() : match.end()]):
            yield match


def _expr_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _expr_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return _expr_name(node.func)
    return ""


def _python_entries(project: Path, path: Path, source: str) -> list[ApplicationEntrypoint]:
    try:
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, ValueError):
        return []
    rel = path.relative_to(project).as_posix()
    functions = {node.name: node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    imports: set[str] = set()
    imported_names: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".", 1)[0]
                imports.add(bound)
                imported_names[bound] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                bound = alias.asname or alias.name
                imported_names[bound] = f"{module}.{alias.name}" if module else alias.name

    instances: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if not isinstance(value, ast.Call):
            continue
        constructor = _expr_name(value.func)
        resolved = imported_names.get(constructor, constructor)
        framework = ""
        if resolved.endswith("FastAPI"):
            framework = "FastAPI"
        elif resolved.endswith("Flask"):
            framework = "Flask"
        elif resolved.endswith("Typer"):
            framework = "Typer"
        if not framework:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                instances[target.id] = framework

    entries: list[ApplicationEntrypoint] = []
    for node in functions.values():
        for decorator in node.decorator_list:
            name = _expr_name(decorator)
            if not name:
                continue
            owner, _, method = name.rpartition(".")
            framework = instances.get(owner, "")
            kind = ""
            if framework in {"FastAPI", "Flask"} and method in _ROUTE_METHODS:
                kind = "http_route"
            elif framework == "Typer" and method in {"callback", "command"}:
                kind = "cli_command"
            elif owner == "click" and "click" in imports and method in {"command", "group"}:
                framework = "Click"
                kind = "cli_command"
            if kind:
                entries.append(
                    ApplicationEntrypoint(
                        name=node.name,
                        handler=node.name,
                        kind=kind,
                        framework=framework,
                        language="python",
                        file_path=rel,
                        line_number=node.lineno,
                        provenance=f"decorator:{name}",
                    )
                )

    for node in ast.walk(tree):
        if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
            continue
        left = node.test.left
        comparators = node.test.comparators
        if not (
            isinstance(left, ast.Name)
            and left.id == "__name__"
            and comparators
            and isinstance(comparators[0], ast.Constant)
            and comparators[0].value == "__main__"
        ):
            continue
        for candidate in ast.walk(node):
            if not isinstance(candidate, ast.Call) or not isinstance(candidate.func, ast.Name):
                continue
            handler = candidate.func.id
            target_function = functions.get(handler)
            if target_function is None:
                continue
            entries.append(
                ApplicationEntrypoint(
                    name=handler,
                    handler=handler,
                    kind="language_main",
                    framework="Python",
                    language="python",
                    file_path=rel,
                    line_number=target_function.lineno,
                    provenance='guard:__name__ == "__main__"',
                )
            )
    return entries


def _regex_entry(
    *,
    project: Path,
    path: Path,
    source: str,
    language: str,
    kind: str,
    handler: str,
    framework: str,
    provenance: str,
    offset: int,
    name: str | None = None,
) -> ApplicationEntrypoint:
    return ApplicationEntrypoint(
        name=name or handler,
        handler=handler,
        kind=kind,
        framework=framework,
        language=language,
        file_path=path.relative_to(project).as_posix(),
        line_number=_line_number(source, offset),
        provenance=provenance,
    )


def _non_python_entries(project: Path, path: Path, source: str) -> list[ApplicationEntrypoint]:
    language = _LANGUAGE_BY_SUFFIX.get(path.suffix.lower())
    if language is None:
        return []
    entries: list[ApplicationEntrypoint] = []
    masked_source = mask_line_comments_and_strings(
        source,
        hash_comments=language in {"php", "ruby"},
        hash_attributes=language == "php",
        heredoc=language == "php",
        backtick_strings=language == "go",
        single_line_quotes=language == "javascript_typescript",
    )

    main_patterns: dict[str, tuple[re.Pattern[str], str]] = {
        "go": (re.compile(r"(?m)^\s*func\s+(main)\s*\("), "Go"),
        "rust": (re.compile(r"(?m)^\s*(?:pub\s+)?(?:async\s+)?fn\s+(main)\s*\("), "Rust"),
        "java": (re.compile(r"(?m)\bstatic\s+void\s+(main)\s*\("), "Java"),
        "kotlin": (re.compile(r"(?m)^\s*fun\s+(main)\s*\("), "Kotlin"),
        "csharp": (re.compile(r"(?m)\bstatic\s+(?:void|int|Task(?:<int>)?)\s+(Main)\s*\("), ".NET"),
        "swift": (re.compile(r"(?m)\bstatic\s+func\s+(main)\s*\("), "Swift"),
    }
    main_spec = main_patterns.get(language)
    if main_spec is not None:
        match = next(iter(_code_matches(main_spec[0], source, masked_source)), None)
        if match:
            entries.append(
                _regex_entry(
                    project=project,
                    path=path,
                    source=source,
                    language=language,
                    kind="language_main",
                    handler=match.group(1),
                    framework=main_spec[1],
                    provenance=f"declaration:{match.group(0).strip()}",
                    offset=match.start(),
                )
            )

    if language == "javascript_typescript":
        pattern = re.compile(
            r"(?m)\b(?P<owner>[A-Za-z_$][\w$]*)\.(?P<method>get|post|put|patch|delete|options|head|use)\s*\(\s*"
            r"(?P<quote>['\"])(?P<path>[^'\"]+)\3\s*,\s*(?P<handler>[A-Za-z_$][\w$]*)\s*\)"
        )
        for match in _code_matches(pattern, source, masked_source):
            entries.append(
                _regex_entry(
                    project=project,
                    path=path,
                    source=source,
                    language=language,
                    kind="http_route",
                    handler=match.group("handler"),
                    framework="Express-compatible router",
                    provenance=f"registration:{match.group('owner')}.{match.group('method')} {match.group('path')}",
                    offset=match.start(),
                    name=f"{match.group('method').upper()} {match.group('path')}",
                )
            )
    elif language == "go":
        for match in _code_matches(
            r"(?m)\b(?:http\.)?HandleFunc\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*([A-Za-z_]\w*)",
            source,
            masked_source,
        ):
            entries.append(
                _regex_entry(
                    project=project,
                    path=path,
                    source=source,
                    language=language,
                    kind="http_route",
                    handler=match.group(2),
                    framework="net/http",
                    provenance=f"registration:HandleFunc {match.group(1)}",
                    offset=match.start(),
                    name=f"HTTP {match.group(1)}",
                )
            )
    elif language in {"java", "kotlin"}:
        route_pattern = re.compile(
            r"(?ms)@(?P<annotation>GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping|GET|POST|PUT|PATCH|DELETE)"
            r"[^\n]*\n\s*(?:public\s+|private\s+|protected\s+)?(?:suspend\s+)?(?:[\w<>?,.\[\]]+\s+)?(?:fun\s+)?(?P<handler>\w+)\s*\("
        )
        for match in _code_matches(route_pattern, source, masked_source):
            entries.append(
                _regex_entry(
                    project=project,
                    path=path,
                    source=source,
                    language=language,
                    kind="http_route",
                    handler=match.group("handler"),
                    framework="Spring/JAX-RS",
                    provenance=f"annotation:@{match.group('annotation')}",
                    offset=match.start(),
                )
            )
    elif language == "csharp":
        for match in _code_matches(
            r"(?ms)\[(?P<annotation>HttpGet|HttpPost|HttpPut|HttpPatch|HttpDelete|Route)[^\]]*\]\s*"
            r"(?:public|internal|private|protected)\s+[\w<>?,.\[\]]+\s+(?P<handler>\w+)\s*\(",
            source,
            masked_source,
        ):
            entries.append(
                _regex_entry(
                    project=project,
                    path=path,
                    source=source,
                    language=language,
                    kind="http_route",
                    handler=match.group("handler"),
                    framework="ASP.NET",
                    provenance=f"attribute:[{match.group('annotation')}]",
                    offset=match.start(),
                )
            )
        for match in _code_matches(
            r"\bapp\.Map(?:Get|Post|Put|Patch|Delete)\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*([A-Za-z_]\w*)",
            source,
            masked_source,
        ):
            entries.append(
                _regex_entry(
                    project=project,
                    path=path,
                    source=source,
                    language=language,
                    kind="http_route",
                    handler=match.group(2),
                    framework="ASP.NET Minimal API",
                    provenance=f"registration:{match.group(0).split('(')[0]} {match.group(1)}",
                    offset=match.start(),
                )
            )
    elif language == "rust":
        rust_route_pattern = (
            r"(?ms)#\[(?P<method>get|post|put|patch|delete)\([^\]]*\)\]\s*"
            r"(?:pub\s+)?(?:async\s+)?fn\s+(?P<handler>\w+)\s*\("
        )
        for match in _code_matches(rust_route_pattern, source, masked_source):
            entries.append(
                _regex_entry(
                    project=project,
                    path=path,
                    source=source,
                    language=language,
                    kind="http_route",
                    handler=match.group("handler"),
                    framework="Rust web route",
                    provenance=f"attribute:#[{match.group('method')}]",
                    offset=match.start(),
                )
            )
    elif language == "php":
        for match in _code_matches(
            r"Route::(?P<method>get|post|put|patch|delete)\s*\(\s*['\"](?P<path>[^'\"]+)['\"]\s*,\s*"
            r"\[\s*(?P<class>\w+)::class\s*,\s*['\"](?P<handler>\w+)['\"]\s*\]",
            source,
            masked_source,
            re.IGNORECASE,
        ):
            handler = f"{match.group('class')}.{match.group('handler')}"
            entries.append(
                _regex_entry(
                    project=project,
                    path=path,
                    source=source,
                    language=language,
                    kind="http_route",
                    handler=handler,
                    framework="Laravel",
                    provenance=f"registration:Route::{match.group('method')} {match.group('path')}",
                    offset=match.start(),
                    name=f"{match.group('method').upper()} {match.group('path')}",
                )
            )
    elif language == "ruby":
        for match in _code_matches(
            r"(?m)^\s*(?P<method>get|post|put|patch|delete)\s+['\"](?P<path>[^'\"]+)['\"]\s*,\s*to:\s*['\"]"
            r"(?P<controller>[\w/]+)#(?P<handler>\w+)['\"]",
            source,
            masked_source,
        ):
            controller = "".join(part.capitalize() for part in match.group("controller").split("_")) + "Controller"
            handler = f"{controller}.{match.group('handler')}"
            entries.append(
                _regex_entry(
                    project=project,
                    path=path,
                    source=source,
                    language=language,
                    kind="http_route",
                    handler=handler,
                    framework="Rails",
                    provenance=f"registration:{match.group('method')} {match.group('path')}",
                    offset=match.start(),
                    name=f"{match.group('method').upper()} {match.group('path')}",
                )
            )
    elif language == "swift":
        for match in _code_matches(
            r"\bapp\.(?P<method>get|post|put|patch|delete)\s*\([^\n]*?use:\s*(?P<handler>\w+)",
            source,
            masked_source,
        ):
            entries.append(
                _regex_entry(
                    project=project,
                    path=path,
                    source=source,
                    language=language,
                    kind="http_route",
                    handler=match.group("handler"),
                    framework="Vapor",
                    provenance=f"registration:app.{match.group('method')}",
                    offset=match.start(),
                )
            )
    return entries


def _packaging_entries(project: Path) -> list[ApplicationEntrypoint]:
    scripts: list[tuple[str, str, str]] = []
    pyproject = project / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            project_scripts = data.get("project", {}).get("scripts", {})
            if isinstance(project_scripts, dict):
                scripts.extend((str(name), str(target), "pyproject.toml:[project.scripts]") for name, target in project_scripts.items())
        except (OSError, tomllib.TOMLDecodeError, UnicodeError):
            pass
    setup_cfg = project / "setup.cfg"
    if setup_cfg.is_file():
        parser = configparser.ConfigParser()
        try:
            parser.read(setup_cfg, encoding="utf-8")
            raw = parser.get("options.entry_points", "console_scripts", fallback="")
            for line in raw.splitlines():
                if "=" in line:
                    name, target = line.split("=", 1)
                    scripts.append((name.strip(), target.strip(), "setup.cfg:[options.entry_points]"))
        except (configparser.Error, OSError, UnicodeError):
            pass

    entries: list[ApplicationEntrypoint] = []
    for name, target, provenance in scripts:
        module, separator, handler = target.partition(":")
        handler = handler.split("[", 1)[0].strip()
        if not separator or not module or not handler or not re.fullmatch(r"[A-Za-z_]\w*", handler):
            continue
        candidate = project.joinpath(*module.split(".")).with_suffix(".py")
        if not candidate.is_file():
            package_candidate = project.joinpath(*module.split("."), "__init__.py")
            candidate = package_candidate if package_candidate.is_file() else candidate
        rel = candidate.relative_to(project).as_posix() if candidate.is_file() else module.replace(".", "/") + ".py"
        line_number = 1
        if candidate.is_file():
            try:
                parsed = ast.parse(candidate.read_text(encoding="utf-8"), filename=str(candidate))
                function = next(
                    (
                        node
                        for node in ast.walk(parsed)
                        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == handler
                    ),
                    None,
                )
                if function is not None:
                    line_number = function.lineno
            except (OSError, SyntaxError, UnicodeError, ValueError):
                pass
        entries.append(
            ApplicationEntrypoint(
                name=name,
                handler=handler,
                kind="console_script",
                framework="Python packaging",
                language="python",
                file_path=rel,
                line_number=line_number,
                provenance=f"metadata:{provenance}={target}",
            )
        )
    return entries


def detect_application_entrypoints(project: Path, source_files: Iterable[Path]) -> list[ApplicationEntrypoint]:
    """Return evidence-backed application roots in deterministic order."""
    root = project.resolve()
    entries = _packaging_entries(root)
    for raw_path in source_files:
        path = raw_path.resolve()
        try:
            path.relative_to(root)
            if path.stat().st_size > _MAX_SOURCE_SIZE_BYTES:
                continue
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError, ValueError):
            continue
        if path.suffix.lower() == ".py":
            entries.extend(_python_entries(root, path, source))
        else:
            entries.extend(_non_python_entries(root, path, source))

    deduped: list[ApplicationEntrypoint] = []
    seen: set[tuple[str, str, str, str, int]] = set()
    for entry in sorted(entries, key=lambda item: (item.file_path, item.line_number, item.kind, item.name, item.handler)):
        key = (entry.kind, entry.name, entry.handler, entry.file_path, entry.line_number)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(entry)
    return deduped
