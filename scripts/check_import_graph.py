#!/usr/bin/env python3
"""Measure the agent_bom import graph, deferred imports included.

Module-level cycles are only part of the picture: an import inside a function
body still couples two modules, it just defers the failure to call time. Every
import statement becomes an edge of one kind:

* ``module`` - executed when the module is imported;
* ``deferred`` - inside a function body, executed at call time;
* ``type`` - under ``if TYPE_CHECKING:``, never executed.

The runtime graph (``module`` + ``deferred``) measures the real coupling; its
largest strongly connected component (SCC) is the tangle size. The module-level
graph (``module`` + ``type``) is what a reader and a type checker see at the
top of each file; a cycle there means two modules define each other.

An edge points at the most specific module the statement names: ``from a.b
import c`` targets ``a.b.c`` when that is a module, otherwise ``a.b``. Parent
package ``__init__`` modules that Python also executes are not edges, so the
number measures the coupling the code wrote, not the package layout.

Gates (enforced from ``check_architecture.py``):

* ``DOMAIN_MODULES`` may not import ``FORBIDDEN_FOR_DOMAIN`` with any edge
  kind: domain code sits below graph, API, cloud, scanners and output, so the
  dependency can only point down (root/domain -> graph -> api).
* No module-level import cycle, annotation-only imports included.
* The largest runtime SCC is recorded in ``BASELINE`` and may only shrink.
"""

from __future__ import annotations

import argparse
import ast
import json
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

BASELINE = Path("scripts/import-graph-baseline.json")
PACKAGE = "agent_bom"
DOMAIN_MODULES = frozenset({"agent_bom.models", "agent_bom.finding"})
FORBIDDEN_FOR_DOMAIN = (
    "agent_bom.api",
    "agent_bom.cloud",
    "agent_bom.exploitability",
    "agent_bom.graph",
    "agent_bom.output",
    "agent_bom.scanners",
)

RUNTIME = frozenset({"module", "deferred"})
MODULE_LEVEL = frozenset({"module", "type"})

Edges = dict[str, dict[str, list[tuple[int, str]]]]


def module_name(source: Path, path: Path) -> str:
    parts = list(path.relative_to(source.parent).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _is_type_checking(test: ast.expr) -> bool:
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING")


def import_nodes(statements: list[ast.stmt], kind: str = "module") -> Iterator[tuple[ast.Import | ast.ImportFrom, str]]:
    """Yield every import statement with its edge kind."""
    for statement in statements:
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            yield statement, kind
            continue
        if isinstance(statement, ast.If) and _is_type_checking(statement.test):
            yield from import_nodes(statement.body, "type")
            yield from import_nodes(statement.orelse, kind)
            continue
        nested = "deferred" if kind == "module" and isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)) else kind
        blocks = [getattr(statement, name, None) for name in ("body", "orelse", "finalbody")]
        blocks += [child.body for child in [*getattr(statement, "handlers", []), *getattr(statement, "cases", [])]]
        for block in blocks:
            if isinstance(block, list):
                yield from import_nodes(block, nested)


def _targets(module: str, is_package: bool, node: ast.Import | ast.ImportFrom, known: set[str]) -> set[str]:
    def owner(name: str) -> str | None:
        while name and name not in known:
            name = name.rpartition(".")[0]
        return name or None

    if isinstance(node, ast.Import):
        names = [alias.name for alias in node.names]
    else:
        base = node.module or ""
        if node.level:
            anchor = module.split(".") if is_package else module.split(".")[:-1]
            anchor = anchor[: len(anchor) - node.level + 1]
            base = ".".join([*anchor, base]).rstrip(".")
        names = [f"{base}.{alias.name}" if f"{base}.{alias.name}" in known else base for alias in node.names]
    return {target for name in names if name.split(".")[0] == PACKAGE and (target := owner(name)) and target != module}


def build_graph(root: Path) -> Edges:
    source = root / "src" / PACKAGE
    files = {module_name(source, path): path for path in sorted(source.rglob("*.py"))}
    known = set(files)
    edges: Edges = {name: {} for name in files}
    for name, path in files.items():
        tree = ast.parse(path.read_text(), filename=str(path))
        for node, kind in import_nodes(tree.body):
            for target in _targets(name, path.name == "__init__.py", node, known):
                edges[name].setdefault(target, []).append((node.lineno, kind))
    return edges


def strongly_connected(graph: dict[str, set[str]]) -> list[list[str]]:
    """Tarjan's algorithm, iterative so a deep import chain cannot hit the recursion limit."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[list[str]] = []
    for start in sorted(graph):
        if start in index:
            continue
        work = [(start, iter(sorted(graph[start])))]
        index[start] = low[start] = len(index)
        stack.append(start)
        on_stack.add(start)
        while work:
            node, children = work[-1]
            child = next(children, None)
            if child is not None:
                if child not in index:
                    index[child] = low[child] = len(index)
                    stack.append(child)
                    on_stack.add(child)
                    work.append((child, iter(sorted(graph[child]))))
                elif child in on_stack:
                    low[node] = min(low[node], index[child])
                continue
            work.pop()
            if work:
                low[work[-1][0]] = min(low[work[-1][0]], low[node])
            if low[node] == index[node]:
                component = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    component.append(member)
                    if member == node:
                        break
                components.append(sorted(component))
    return sorted(components, key=lambda members: (-len(members), members))


def adjacency(edges: Edges, kinds: frozenset[str]) -> dict[str, set[str]]:
    return {
        name: {target for target, sites in targets.items() if any(kind in kinds for _, kind in sites)} for name, targets in edges.items()
    }


def cycles(graph: dict[str, set[str]]) -> list[list[str]]:
    return [component for component in strongly_connected(graph) if len(component) > 1]


def domain_errors(edges: Edges) -> list[str]:
    errors = []
    for module in sorted(DOMAIN_MODULES):
        for target, sites in sorted(edges.get(module, {}).items()):
            if any(target == banned or target.startswith(f"{banned}.") for banned in FORBIDDEN_FOR_DOMAIN):
                path = module.replace(".", "/") + ".py"
                errors.extend(f"src/{path}:{line}: domain module must not import {target}" for line, _ in sites)
    return errors


def measure(root: Path) -> dict:
    edges = build_graph(root)
    runtime = cycles(adjacency(edges, RUNTIME))
    return {
        "modules": len(edges),
        "max_scc": len(runtime[0]) if runtime else 1,
        "top_level_cycles": cycles(adjacency(edges, MODULE_LEVEL)),
        "domain_errors": domain_errors(edges),
    }


def trusted_max_scc(root: Path, ref: str) -> int | None:
    exists = subprocess.run(["git", "cat-file", "-e", f"{ref}:{BASELINE.as_posix()}"], cwd=root, capture_output=True)
    if exists.returncode:
        return None
    content = subprocess.check_output(["git", "show", f"{ref}:{BASELINE.as_posix()}"], cwd=root, text=True)
    return int(json.loads(content)["max_scc"])


def check(root: Path, base_ref: str | None = None, write_baseline: bool = False) -> tuple[list[str], dict]:
    result = measure(root)
    errors = list(result["domain_errors"])
    errors.extend(f"module-level import cycle: {' -> '.join(members)}" for members in result["top_level_cycles"])
    path = root / BASELINE
    recorded = json.loads(path.read_text())["max_scc"] if path.exists() else None
    if recorded is not None and result["max_scc"] > recorded:
        errors.append(f"import graph: largest strongly connected component {result['max_scc']} exceeds baseline {recorded}")
    if recorded is None and not write_baseline:
        errors.append(f"{BASELINE} missing; initialize with --write-baseline")
    if base_ref and recorded is not None and (trusted := trusted_max_scc(root, base_ref)) is not None and recorded > trusted:
        errors.append(f"{BASELINE}: max_scc {recorded} exceeds the trusted base value {trusted}")
    if write_baseline and not errors:
        path.write_text(json.dumps({"max_scc": result["max_scc"]}, indent=2) + "\n")
    return errors, result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--write-baseline", action="store_true", help="record the current largest SCC; never approves growth")
    parser.add_argument("--base-ref", help="trusted base commit whose baseline may not be exceeded")
    parser.add_argument("--json", action="store_true", help="print the measurement as JSON")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    errors, result = check(root, args.base_ref, args.write_baseline)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(
            f"import graph: {result['modules']} modules, largest SCC {result['max_scc']}, "
            f"{len(result['top_level_cycles'])} module-level cycles"
        )
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
