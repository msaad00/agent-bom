#!/usr/bin/env python3
"""Exception-sanitization guard: keep raw exception text out of HTTP responses and logs.

Raw exception strings routinely carry secrets, ARNs, file paths, connection
strings, and stack detail. Surfacing them to an HTTP response body or a log line
leaks that data to API consumers and log sinks. The fix is the central
``agent_bom.security`` sanitizers (``sanitize_error`` for API responses,
``sanitize_text`` for logs) — see ``src/agent_bom/security.py``.

This guard fails CI/pre-commit when a *new* unsanitized pattern lands on the
API / cloud / runtime paths, so the release bar is enforced systemically rather
than relying on each exception source being safe.

Forbidden patterns (on the scanned trees):

  1. ``HTTPException(... detail=str(exc) ...)`` — raw exception in a response
     body. Use ``detail=sanitize_error(exc)`` (or ``sanitize_error(exc,
     generic=True)`` on auth/secret/encryption/session/broker paths).
  2. ``HTTPException(... detail=f"...{exc}..." ...)`` — same leak via f-string.
     Wrap the exception: ``detail=f"...{sanitize_error(exc)}..."``.
  3. ``logger.<level>(f"...{exc}...")`` — raw exception interpolated into a log
     f-string. Use lazy ``%s`` formatting with a sanitized value:
     ``logger.warning("...: %s", sanitize_text(exc))``.
  4. A caught exception passed as a lazy logger argument, implicit traceback
     capture via ``logger.exception(...)``, or explicit raw ``exc_info``.
     Shared log sinks receive exception messages and tracebacks, so use a fixed
     log message or ``sanitize_text(exc)`` without traceback capture.
  5. A caught exception object used anywhere in an API route's returned
     response payload. Return a fixed external message instead. This
     intentionally avoids relying on custom sanitizer modeling in static
     analyzers such as CodeQL.

Only the bare exception token (``{exc}``, ``{e}``, ``{err}``, ``{error}``,
``{ex}`` and their ``{exc!r}`` / ``{exc:...}`` forms) is flagged. Attribute
access such as ``{exc.status.value}`` (a safe enum) and structured payloads such
as ``graph.py``'s ``exc.to_dict()`` rate-limit body are intentionally NOT
matched, so the few safe call sites need no allowlist.

A genuine false positive can be silenced with a trailing ``# exc-safe: <why>``
pragma on the offending line.

Exit 0 = clean. Exit 1 = a violation. Pure stdlib so it runs anywhere in CI.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Subtrees the guard scans. Narrow and explicit: the paths where an exception
# can reach an external HTTP consumer or a shared log sink.
INCLUDE_DIRS: tuple[str, ...] = (
    "src/agent_bom/api",
    "src/agent_bom/cloud",
    "src/agent_bom/runtime",
)
INCLUDE_FILES: tuple[str, ...] = (
    "src/agent_bom/gateway_server.py",
    "src/agent_bom/proxy.py",
    "src/agent_bom/red_team_llm.py",
)

EXCLUDE_FRAGMENTS: tuple[str, ...] = (
    "/test",
    "test_",
    "_test.",
    "/tests/",
    "/fixtures/",
    "conftest.py",
)

# This guard names the patterns it forbids, so it must exempt itself.
SELF = "scripts/check_exception_sanitization.py"

PRAGMA = "exc-safe:"

# Common caught-exception variable names.
_EXC_VARS = r"(?:exc|e|err|error|ex)"

# Bare exception token inside an f-string field: {exc}, {exc!r}, {exc:...}.
# A leading attribute/index ({exc.status.value}) is deliberately excluded.
_EXC_FIELD = re.compile(r"\{" + _EXC_VARS + r"(?:![rsa])?(?::[^}]*)?\}")

# detail=str(exc) / detail=str(e) ...
_DETAIL_STR = re.compile(r"detail\s*=\s*str\(\s*" + _EXC_VARS + r"\s*\)")

# detail=f"...": flagged only if the f-string carries a bare exc field.
_DETAIL_FSTRING = re.compile(r"""detail\s*=\s*f["']""")

# logger.<level>(f"...": flagged only if the f-string carries a bare exc field.
# Matches log / logger / _log / _logger / self.logger and similar names.
_LOGGER_FSTRING = re.compile(
    r"""\b\w*log\w*\.(?:debug|info|warning|error|critical)\(\s*f["']""",
)

_LOG_METHODS = frozenset({"debug", "info", "warning", "error", "exception", "critical"})


def _iter_files() -> list[Path]:
    files: list[Path] = []
    for rel in INCLUDE_DIRS:
        base = REPO_ROOT / rel
        if base.is_dir():
            files.extend(sorted(base.rglob("*.py")))
    for rel in INCLUDE_FILES:
        path = REPO_ROOT / rel
        if path.is_file():
            files.append(path)
    out: list[Path] = []
    for path in files:
        posix = path.as_posix()
        if any(frag in posix for frag in EXCLUDE_FRAGMENTS):
            continue
        out.append(path)
    return out


def _scan_line(line: str) -> str | None:
    """Return a human reason if *line* violates the bar, else None."""
    if _DETAIL_STR.search(line):
        return "raw exception in HTTPException detail — use sanitize_error(exc)"
    if _DETAIL_FSTRING.search(line) and _EXC_FIELD.search(line):
        return "raw exception interpolated into HTTPException detail f-string — wrap with sanitize_error(exc)"
    if _LOGGER_FSTRING.search(line) and _EXC_FIELD.search(line):
        return "raw exception interpolated into a log f-string — use lazy %s with sanitize_text(exc)"
    return None


def _scan_returned_exception_flows(text: str, label: str) -> list[str]:
    """Flag caught exception objects that flow into a returned payload.

    ``sanitize_error(exc, generic=True)`` is safe at runtime, but external
    static analyzers cannot necessarily prove that a project-local sanitizer
    returns a constant. Keeping the exception object out of a response return
    entirely gives both runtime and static-analysis proof of the boundary.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []

    lines = text.splitlines()
    violations: list[str] = []
    for handler in (node for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)):
        if not handler.name:
            continue
        for node in ast.walk(handler):
            if not isinstance(node, ast.Return) or node.value is None:
                continue
            uses = [child for child in ast.walk(node.value) if isinstance(child, ast.Name) and child.id == handler.name]
            if not uses:
                continue
            start = max(1, node.lineno)
            end = min(len(lines), getattr(node, "end_lineno", node.lineno))
            if any(PRAGMA in lines[index - 1] for index in range(start, end + 1)):
                continue
            violations.append(
                f"{label}:{uses[0].lineno}: caught exception flows into returned response payload — return a fixed external message"
            )
    return violations


def _logger_receiver_name(node: ast.expr) -> str:
    """Return a dotted best-effort name for a logger receiver expression."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _logger_receiver_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _is_logger_call(node: ast.Call) -> bool:
    if not isinstance(node.func, ast.Attribute) or node.func.attr not in _LOG_METHODS:
        return False
    return "log" in _logger_receiver_name(node.func.value).lower()


def _call_has_pragma(node: ast.Call, lines: list[str]) -> bool:
    start = max(1, node.lineno)
    end = min(len(lines), getattr(node, "end_lineno", node.lineno))
    return any(PRAGMA in lines[index - 1] for index in range(start, end + 1))


def _contains_raw_caught_exception(node: ast.AST, caught_name: str) -> bool:
    """Return whether *node* carries the caught exception's raw value.

    Access to a structured attribute such as ``exc.status.value`` remains
    allowed, matching the response-flow contract. The central log sanitizer is
    the only call allowed to consume the exception object directly.
    """
    if isinstance(node, ast.Name):
        return node.id == caught_name
    if isinstance(node, ast.Attribute):
        return False
    if isinstance(node, ast.Call):
        name = ""
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            name = node.func.attr
        if name == "sanitize_text":
            return False
    return any(_contains_raw_caught_exception(child, caught_name) for child in ast.iter_child_nodes(node))


def _raw_exc_info(keyword: ast.keyword, caught_name: str | None) -> bool:
    if keyword.arg != "exc_info":
        return False
    value = keyword.value
    if isinstance(value, ast.Constant) and value.value in (False, None):
        return False
    if caught_name and _contains_raw_caught_exception(value, caught_name):
        return True
    # True, sys.exc_info(), exception tuples, and other dynamic expressions all
    # attach an unsanitized traceback to the shared log record.
    return True


def _scan_exception_logging_flows(text: str, label: str) -> list[str]:
    """Flag caught exceptions and tracebacks crossing shared logger boundaries."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []

    lines = text.splitlines()
    violations: dict[tuple[int, str], str] = {}
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        if not _is_logger_call(call) or _call_has_pragma(call, lines):
            continue
        method = call.func.attr if isinstance(call.func, ast.Attribute) else ""
        if method == "exception":
            reason = "logger.exception captures a raw exception traceback — use logger.error with fixed or sanitized detail"
        elif any(_raw_exc_info(keyword, None) for keyword in call.keywords):
            reason = "raw exc_info attached to log record — remove traceback capture and sanitize any exception detail"
        else:
            continue
        violations[(call.lineno, reason)] = f"{label}:{call.lineno}: {reason}"

    for handler in (node for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)):
        caught_name = handler.name
        for call in (node for node in ast.walk(handler) if isinstance(node, ast.Call)):
            if not _is_logger_call(call) or _call_has_pragma(call, lines):
                continue
            method = call.func.attr if isinstance(call.func, ast.Attribute) else ""
            if method == "exception" or any(_raw_exc_info(keyword, caught_name) for keyword in call.keywords):
                continue
            if caught_name and any(_contains_raw_caught_exception(argument, caught_name) for argument in call.args[1:]):
                reason = "caught exception passed as a lazy log argument — wrap it with sanitize_text(exc)"
            else:
                continue
            violations[(call.lineno, reason)] = f"{label}:{call.lineno}: {reason}"
    return list(violations.values())


def scan_text(text: str, label: str) -> list[str]:
    """Scan a blob of source. Used by the test-suite to feed deliberate samples."""
    violations: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if PRAGMA in line:
            continue
        reason = _scan_line(line)
        if reason:
            violations.append(f"{label}:{lineno}: {reason}")
    violations.extend(_scan_exception_logging_flows(text, label))
    if label == "sample.py" or label.startswith("src/agent_bom/api/routes/"):
        violations.extend(_scan_returned_exception_flows(text, label))
    return violations


def main() -> int:
    violations: list[str] = []
    for path in _iter_files():
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel == SELF:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        violations.extend(scan_text(text, rel))

    if violations:
        sys.stderr.write("Exception-sanitization guard found unsanitized exception text:\n\n")
        for item in violations:
            sys.stderr.write(f"  {item}\n")
        sys.stderr.write(
            "\nRoute raw exception text through agent_bom.security.sanitize_error "
            "(HTTP responses) or sanitize_text (logs). See scripts/check_exception_sanitization.py "
            "for the rule, or append '# exc-safe: <reason>' for a vetted exception.\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
