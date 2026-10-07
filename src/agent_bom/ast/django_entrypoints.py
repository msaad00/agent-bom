"""Resolve statically registered Django URL handlers inside the scanned tree."""

from __future__ import annotations

import ast
from pathlib import Path

from agent_bom.ast.source_reader import parse_python_source
from agent_bom.ast_models import ApplicationEntrypoint
from agent_bom.parsers.file_limits import read_text_limited


def _imports(project: Path, path: Path, tree: ast.Module) -> dict[str, str]:
    imports: dict[str, str] = {}
    module = path.relative_to(project).with_suffix("").parts[:-1]
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom):
            base = ".".join((*module[: len(module) - node.level + 1], node.module or "")) if node.level else node.module or ""
            for alias in node.names:
                imports[alias.asname or alias.name] = ".".join(filter(None, (base, alias.name)))

    return imports


def django_entries(project: Path, path: Path, tree: ast.Module) -> list[ApplicationEntrypoint]:
    imports = _imports(project, path, tree)

    def name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return imports.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return f"{name(node.value)}.{node.attr}"
        return ""

    entries: list[ApplicationEntrypoint] = []
    registrations = [
        node.value
        for node in tree.body
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "urlpatterns" for t in node.targets)
    ]
    for registration in registrations:
        for call in ast.walk(registration):
            if not isinstance(call, ast.Call) or name(call.func) not in {"django.urls.path", "django.urls.re_path", "django.conf.urls.url"}:
                continue
            handler_node = call.args[1] if len(call.args) > 1 else next((kw.value for kw in call.keywords if kw.arg == "view"), None)
            if handler_node is None or isinstance(handler_node, ast.Call):
                continue  # Dynamic handlers / class-based dispatch require additional analysis.
            handler = name(handler_node)
            if not handler:
                continue
            target = path
            target_tree = tree
            if "." in handler:
                module_name, _, handler = handler.rpartition(".")
                target = project.joinpath(*module_name.split(".")).with_suffix(".py").resolve()
                if not target.is_relative_to(project.resolve()):
                    continue
                try:
                    target_tree = parse_python_source(read_text_limited(target, max_bytes=2_000_000))
                except (OSError, ValueError, SyntaxError):
                    continue
            function = next(
                (n for n in target_tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == handler), None
            )
            if function is not None:
                entries.append(
                    ApplicationEntrypoint(
                        name=handler,
                        handler=handler,
                        kind="http_route",
                        framework="Django",
                        language="python",
                        file_path=target.relative_to(project.resolve()).as_posix()
                        if target.is_absolute()
                        else target.relative_to(project).as_posix(),
                        line_number=function.lineno,
                        provenance=f"registration:{path.relative_to(project).as_posix()}:{call.lineno}:{name(call.func)}",
                    )
                )
    return entries
