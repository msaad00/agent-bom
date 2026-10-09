"""Decide whether a string-built SQL query can carry untrusted text.

The SQL-sink rule fires when ``execute()`` receives a dynamically built string.
Three shapes are dynamic in syntax only and never carry attacker text, so they
are not reported:

* a reviewer suppression on the query's lines: bare ``# nosec``, a ``# nosec``
  that names ``B608``, or ``# noqa: S608``;
* interpolation of bind-placeholder markers only (``?``, ``%s``, a separator
  ``join`` of them, or a local name only ever assigned such markers);
* interpolation of a module-level UPPER_CASE constant the function does not
  rebind.

Anything else interpolated (a parameter, attribute, call result or a name with
any non-placeholder assignment) keeps the query unsafe.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from dataclasses import dataclass, replace

_NOSEC_RE = re.compile(r"#\s*nosec\b(?P<rest>[^#]*)", re.IGNORECASE)
_BANDIT_ID_RE = re.compile(r"\bB\d{3}\b")
_NOQA_S608_RE = re.compile(r"#\s*noqa\s*:[^#]*\bS608\b", re.IGNORECASE)
_SQL_BANDIT_ID = "B608"
_CONSTANT_NAME_RE = re.compile(r"^_*[A-Z][A-Z0-9_]*$")
# A placeholder literal holds only bind markers plus list punctuation:
# "?", "%s", "(?, ?)", "?, ?".
_MARKER_TEXT_RE = re.compile(r"^[\s(),]*(?:(?:\?|%s)[\s(),]*)+$")
_SEPARATOR_RE = re.compile(r"^[\s,]*$")


def expr_uses_dynamic_string(expr: ast.AST | None) -> bool:
    """f-string, ``+``/``%`` string building, or ``str.format``."""
    if expr is None:
        return False
    if isinstance(expr, ast.JoinedStr):
        return True
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
        return True
    return isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format"


def _comment_suppresses_sql(comment: str) -> bool:
    if _NOQA_S608_RE.search(comment):
        return True
    match = _NOSEC_RE.search(comment)
    if match is None:
        return False
    named = set(_BANDIT_ID_RE.findall(match.group("rest").upper()))
    return not named or _SQL_BANDIT_ID in named


def sql_suppressed_lines(source: str) -> frozenset[int]:
    """1-based lines whose comment suppresses the SQL-construction rule."""
    if "nosec" not in source.lower() and "S608" not in source:
        return frozenset()
    lines: set[int] = set()
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.COMMENT and _comment_suppresses_sql(token.string):
                lines.add(token.start[0])
    except (tokenize.TokenError, SyntaxError):
        return frozenset()
    return frozenset(lines)


def module_constant_names(tree: ast.Module) -> frozenset[str]:
    """UPPER_CASE names bound at module level by assignment or import."""
    names: set[str] = set()
    for stmt in tree.body:
        targets: list[ast.AST] = []
        if isinstance(stmt, ast.Assign):
            targets = list(stmt.targets)
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            targets = [stmt.target]
        elif isinstance(stmt, ast.ImportFrom):
            names.update(alias.asname or alias.name for alias in stmt.names if _CONSTANT_NAME_RE.match(alias.asname or alias.name))
        names.update(target.id for target in targets if isinstance(target, ast.Name) and _CONSTANT_NAME_RE.match(target.id))
    return frozenset(names)


def _is_marker_literal(expr: ast.AST) -> bool:
    return isinstance(expr, ast.Constant) and isinstance(expr.value, str) and bool(_MARKER_TEXT_RE.match(expr.value))


def _is_marker_sequence(expr: ast.AST) -> bool:
    """``["?"] * n``, ``("?", "?")`` or ``"?" * n``."""
    if isinstance(expr, (ast.List, ast.Tuple)):
        return bool(expr.elts) and all(_is_marker_literal(elt) for elt in expr.elts)
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mult):
        return (
            _is_marker_sequence(expr.left)
            or _is_marker_literal(expr.left)
            or _is_marker_sequence(expr.right)
            or _is_marker_literal(expr.right)
        )
    return False


def _is_separator_join(expr: ast.AST) -> ast.AST | None:
    """Return the iterable of ``"<sep>".join(iterable)`` when sep is punctuation."""
    if not (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "join"):
        return None
    sep = expr.func.value
    if not (isinstance(sep, ast.Constant) and isinstance(sep.value, str) and _SEPARATOR_RE.match(sep.value)):
        return None
    return expr.args[0] if len(expr.args) == 1 and not expr.keywords else None


def _is_placeholder_expr(expr: ast.AST, placeholder_names: frozenset[str]) -> bool:
    if isinstance(expr, ast.Name):
        return expr.id in placeholder_names
    if _is_marker_literal(expr) or _is_marker_sequence(expr):
        return True
    if isinstance(expr, ast.IfExp):
        return _is_placeholder_expr(expr.body, placeholder_names) and _is_placeholder_expr(expr.orelse, placeholder_names)
    iterable = _is_separator_join(expr)
    if iterable is None:
        return False
    if isinstance(iterable, (ast.GeneratorExp, ast.ListComp)):
        return _is_placeholder_expr(iterable.elt, placeholder_names)
    return _is_marker_sequence(iterable) or (isinstance(iterable, ast.Name) and iterable.id in placeholder_names)


def _stored_names(node: ast.AST) -> list[ast.Name]:
    return [child for child in ast.walk(node) if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)]


def _node_lines(node: ast.AST) -> range:
    start = getattr(node, "lineno", 0)
    return range(start, (getattr(node, "end_lineno", None) or start) + 1)


@dataclass(frozen=True)
class ModuleSqlFacts:
    """Per-file inputs: suppression comments and module constants."""

    suppressed_lines: frozenset[int]
    constants: frozenset[str]

    @classmethod
    def from_source(cls, tree: ast.Module, source: str) -> ModuleSqlFacts:
        return cls(suppressed_lines=sql_suppressed_lines(source), constants=module_constant_names(tree))

    def for_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> FunctionSqlScope:
        args = node.args
        params = {arg.arg for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg] if arg is not None}
        placeholder_stores: set[int] = set()
        candidate_names: set[str] = set()
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                if _is_placeholder_expr(stmt.value, frozenset()):
                    placeholder_stores.add(id(stmt.targets[0]))
                    candidate_names.add(stmt.targets[0].id)
        stored = _stored_names(node)
        other_bound = params | {name.id for name in stored if id(name) not in placeholder_stores}
        local_names = frozenset(params | {name.id for name in stored})
        scope = FunctionSqlScope(self, frozenset(candidate_names - other_bound), local_names, frozenset())
        return replace(scope, unsafe_names=scope.unsafe_assigned_names(node))


@dataclass(frozen=True)
class FunctionSqlScope:
    """Per-function view used by the SQL sink check."""

    module: ModuleSqlFacts
    placeholder_names: frozenset[str]
    local_names: frozenset[str]
    unsafe_names: frozenset[str]

    def _suppressed(self, node: ast.AST) -> bool:
        return any(line in self.module.suppressed_lines for line in _node_lines(node))

    def _value_is_safe(self, expr: ast.AST) -> bool:
        if _is_placeholder_expr(expr, self.placeholder_names):
            return True
        if isinstance(expr, ast.Name):
            return expr.id in self.module.constants and expr.id not in self.local_names
        iterable = _is_separator_join(expr)
        return iterable is not None and isinstance(iterable, ast.Name) and self._value_is_safe(iterable)

    def _string_is_safe(self, expr: ast.AST) -> bool:
        if isinstance(expr, ast.Constant):
            return isinstance(expr.value, str)
        if isinstance(expr, ast.JoinedStr):
            return all(self._value_is_safe(part.value) for part in expr.values if isinstance(part, ast.FormattedValue))
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            return all(self._string_is_safe(side) or self._value_is_safe(side) for side in (expr.left, expr.right))
        return False

    def _assignment_is_unsafe(self, value: ast.AST, stmt: ast.AST) -> bool:
        return expr_uses_dynamic_string(value) and not self._string_is_safe(value) and not self._suppressed(stmt)

    def unsafe_assigned_names(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> frozenset[str]:
        names: set[str] = set()
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Assign) and self._assignment_is_unsafe(stmt.value, stmt):
                targets: list[ast.AST] = list(stmt.targets)
            elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None and self._assignment_is_unsafe(stmt.value, stmt):
                targets = [stmt.target]
            else:
                continue
            names.update(stored.id for target in targets for stored in _stored_names(target))
        return frozenset(names)

    def query_is_unsafe(self, call: ast.Call) -> bool:
        """True when the first ``execute`` argument may carry untrusted text."""
        query = call.args[0] if call.args else None
        if query is None or self._suppressed(call):
            return False
        if expr_uses_dynamic_string(query):
            return not self._string_is_safe(query)
        return isinstance(query, ast.Name) and query.id in self.unsafe_names
