"""Per-extra import smoke: actually execute every extra-gated SDK import line.

The cloud/AI/identity SDKs live behind optional extras and are imported lazily
(inside functions), usually wrapped in ``try/except`` so a missing package
degrades gracefully. Because a normal PR test run does not install every extra,
those import lines never execute — and the ``except`` clause also hides a
symbol-move at runtime. So when a newer major version of a pinned SDK *moves or
removes a symbol from the import path* (e.g. ``azure-mgmt-resource`` 26.0.0
dropped the top-level ``ResourceManagementClient`` re-export, and
``azure-mgmt-managementgroups`` 2.0.0 renamed ``ManagementGroupsAPI`` ->
``ManagementGroupsMgmtClient``), CI stays green while a fresh install silently
loses that discovery path at runtime.

This guard scrapes every ``from <sdk> import <symbol>`` / ``import <sdk>.<sub>``
in ``src/agent_bom`` for the SDK packages behind an extra and *executes each
line outside its guard* — but only for the extras actually installed in the
current interpreter (``pytest.importorskip``). Run it under an env that installs
the cloud extras (see the ``sdk-import-smoke`` CI job) and the whole
symbol-move/rename defect class is caught before release.

Fallback groups (``try: <new path> except ImportError: <old path>``) are handled
specially: the two alternatives substitute for each other, so the group passes
when *at least one* alternative resolves. Standalone imports must resolve.
"""

from __future__ import annotations

import ast
import importlib
import importlib.util
from pathlib import Path
from typing import Any

import pytest

_SRC = Path(__file__).resolve().parents[1] / "src" / "agent_bom"
_REPO_ROOT = _SRC.parents[1]

# Top-level SDK package -> the optional extra that must provide it. Only imports
# whose top-level package is in this map are treated as extra-gated SDK imports.
_EXTRA_BY_TOP = {
    "azure": "azure",
    "boto3": "aws",
    "botocore": "aws",
    "google": "gcp",
    "googleapiclient": "gcp",
    "databricks": "databricks",
    "snowflake": "snowflake",
    "huggingface_hub": "huggingface",
    "wandb": "wandb",
    "openai": "openai",
    "litellm": "ai-enrich",
    "mcp": "mcp-server",
    "smithery": "mcp-server",
    "onelogin": "saml",
}

# Handler exception names that make a ``try`` an import-fallback / availability
# guard (catching a missing or moved symbol).
_IMPORT_GUARD_EXC = {"ImportError", "ModuleNotFoundError", "Exception", "BaseException"}


def _stmt_text(node: ast.stmt) -> list[str]:
    """One executable ``from x import y`` / ``import x`` string per bound name."""
    if isinstance(node, ast.ImportFrom):
        if node.level or not node.module:
            return []
        top = node.module.split(".")[0]
        if top not in _EXTRA_BY_TOP:
            return []
        return [f"from {node.module} import {a.name}" for a in node.names if a.name != "*"]
    if isinstance(node, ast.Import):
        return [f"import {a.name}" for a in node.names if a.name.split(".")[0] in _EXTRA_BY_TOP]
    return []


def _top_of(stmt: str) -> str:
    if stmt.startswith("from "):
        return stmt.split()[1].split(".")[0]
    return stmt.split()[1].split(".")[0]


def _find(module: str) -> Any:
    """``importlib.util.find_spec`` tolerating a missing parent namespace."""
    try:
        return importlib.util.find_spec(module)
    except (ImportError, ValueError):
        return None


def _sdk_present(stmt: str) -> bool:
    """Whether the gated SDK backing this import line is installed.

    The bare top-level (``google``) — and even ``google.cloud`` — are namespace
    packages importable via unrelated deps, so a shallow probe never skips when
    the SDK itself is absent. Probe precisely:
    - ``import a.b.c`` → the module ``a.b.c`` must be locatable.
    - ``from a.b import c`` → the from-module ``a.b`` must be locatable, and when
      it is only a namespace package (no real code), ``a.b.c`` must exist as a
      submodule (otherwise ``c`` is a symbol of an installed module — run it, so
      a moved/renamed symbol is caught rather than silently skipped).
    """
    parts = stmt.split()
    if stmt.startswith("from "):
        frm, name = parts[1], parts[3]
        spec = _find(frm)
        if spec is None:
            return False
        if spec.origin in (None, "namespace") and _find(f"{frm}.{name}") is None:
            return False
        return True
    return _find(parts[1]) is not None


def _handler_is_import_guard(handler: ast.ExceptHandler) -> bool:
    t = handler.type
    if t is None:  # bare except
        return True
    names: list[str] = []
    if isinstance(t, ast.Name):
        names = [t.id]
    elif isinstance(t, ast.Tuple):
        names = [e.id for e in t.elts if isinstance(e, ast.Name)]
    return any(n in _IMPORT_GUARD_EXC for n in names)


def _direct_sdk_stmts(body: list[ast.stmt]) -> list[str]:
    out: list[str] = []
    for node in body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            out.extend(_stmt_text(node))
    return out


class Group:
    """A set of import alternatives; passes when >=1 resolves. Standalone => 1."""

    __slots__ = ("top", "stmts", "file", "lineno", "fallback")

    def __init__(self, top: str, stmts: list[str], file: str, lineno: int, fallback: bool) -> None:
        self.top = top
        self.stmts = stmts
        self.file = file
        self.lineno = lineno
        self.fallback = fallback

    def __repr__(self) -> str:
        kind = "fallback" if self.fallback else "single"
        return f"{self.file}:{self.lineno} [{kind}] {' | '.join(self.stmts)}"


def _collect() -> list[Group]:
    groups: list[Group] = []
    grouped: set[tuple[str, int, int]] = set()  # (file, lineno, col) already in a fallback group

    files = sorted(_SRC.rglob("*.py"))
    # First pass: fallback groups (try body imports + ImportError-handler imports).
    trees: dict[str, ast.Module] = {}
    for py in files:
        rel = str(py.relative_to(_REPO_ROOT))
        try:
            tree = ast.parse(py.read_text(), filename=str(py))
        except SyntaxError:  # pragma: no cover
            continue
        trees[rel] = tree
        for node in ast.walk(tree):
            if not isinstance(node, ast.Try):
                continue
            body_stmts = _direct_sdk_stmts(node.body)
            handler_stmts: list[str] = []
            handler_nodes: list[ast.stmt] = []
            for h in node.handlers:
                if _handler_is_import_guard(h):
                    handler_stmts.extend(_direct_sdk_stmts(h.body))
                    handler_nodes.extend(n for n in h.body if isinstance(n, (ast.Import, ast.ImportFrom)))
            if not body_stmts or not handler_stmts:
                continue
            # Only merge alternatives that share a top-level package.
            tops = {_top_of(s) for s in body_stmts + handler_stmts}
            if len(tops) != 1:
                continue
            alt = body_stmts + handler_stmts
            groups.append(Group(tops.pop(), alt, rel, node.lineno, fallback=True))
            for n in node.body + handler_nodes:
                if isinstance(n, (ast.Import, ast.ImportFrom)):
                    grouped.add((rel, n.lineno, n.col_offset))

    # Second pass: standalone imports not already claimed by a fallback group.
    seen: set[str] = set()
    for rel, tree in trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            if (rel, node.lineno, node.col_offset) in grouped:
                continue
            for stmt in _stmt_text(node):
                if stmt in seen:
                    continue
                seen.add(stmt)
                groups.append(Group(_top_of(stmt), [stmt], rel, node.lineno, fallback=False))
    return groups


_GROUPS = _collect()


def test_scraper_found_the_expected_import_surface() -> None:
    # Guard against the ast scrape silently going empty (every case would then
    # vacuously skip). The real surface is well over 50 statements.
    total_stmts = sum(len(g.stmts) for g in _GROUPS)
    assert total_stmts > 40, f"only found {total_stmts} extra-gated SDK imports"
    tops = {g.top for g in _GROUPS}
    for expected in ("azure", "google", "botocore"):
        assert expected in tops, f"expected {expected} imports in the scrape"


@pytest.mark.parametrize("group", _GROUPS, ids=repr)
def test_extra_gated_sdk_import_executes(group: Group) -> None:
    """Execute the real import line(s) — skipped unless the extra is installed.

    A single (standalone) import must resolve. A fallback group passes when at
    least one alternative resolves.
    """
    # Skip only when the gated SDK sub-namespace is genuinely absent (a base
    # test env without this extra); a present namespace means we should execute
    # and catch a moved/renamed symbol.
    if not any(_sdk_present(stmt) for stmt in group.stmts):
        pytest.skip(f"{_EXTRA_BY_TOP[group.top]} extra not installed")
    errors: list[str] = []
    for stmt in group.stmts:
        try:
            exec(compile(stmt, group.file, "exec"), {})  # noqa: S102 — source-derived import line
            if group.fallback:
                return  # one alternative resolved — group is satisfied
        except ImportError as exc:
            errors.append(f"`{stmt}`: {type(exc).__name__}: {exc}")
    if errors:
        installed = importlib.import_module(group.top)
        version = getattr(installed, "__version__", "unknown")
        joined = "\n  ".join(errors)
        pytest.fail(f"{group.file}:{group.lineno} against {group.top}=={version}:\n  {joined}")
