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
    r"""\b\w*log\w*\.(?:debug|info|warning|error|exception|critical)\(\s*f["']""",
)


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


def scan_text(text: str, label: str) -> list[str]:
    """Scan a blob of source. Used by the test-suite to feed deliberate samples."""
    violations: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if PRAGMA in line:
            continue
        reason = _scan_line(line)
        if reason:
            violations.append(f"{label}:{lineno}: {reason}")
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
