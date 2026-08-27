"""Tests for scripts/check_exception_sanitization.py — the release-bar guard that
keeps raw exception text out of HTTP response bodies and log lines on the
API / cloud / runtime paths.

Also asserts the sanitizer contracts the guard steers callers toward:
``sanitize_error`` (HTTP responses) and ``sanitize_text`` (logs) strip secrets,
paths, and credential-bearing URLs while ``generic=True`` collapses to a fixed
non-diagnostic message.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_exception_sanitization.py"


def _load_guard():
    spec = importlib.util.spec_from_file_location("check_exception_sanitization", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules["check_exception_sanitization"] = mod
    spec.loader.exec_module(mod)
    return mod


GUARD = _load_guard()


# ---------------------------------------------------------------------------
# The live tree must be clean end-to-end.
# ---------------------------------------------------------------------------
def test_current_tree_passes() -> None:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# Forbidden patterns are flagged.
# ---------------------------------------------------------------------------
def test_flags_detail_str_exc() -> None:
    out = GUARD.scan_text("    raise HTTPException(status_code=422, detail=str(exc)) from exc\n", "sample.py")
    assert len(out) == 1
    assert "sanitize_error" in out[0]


def test_flags_detail_fstring_exc() -> None:
    out = GUARD.scan_text('    raise HTTPException(status_code=400, detail=f"bad: {exc}") from exc\n', "sample.py")
    assert len(out) == 1
    assert "f-string" in out[0]


def test_flags_logger_fstring_exc() -> None:
    for line in (
        '    logger.warning(f"failed: {exc}")\n',
        '    _logger.error(f"oops {e}")\n',
        '    logger.debug(f"x {err!r}")\n',
    ):
        out = GUARD.scan_text(line, "sample.py")
        assert len(out) == 1, line
        assert "log f-string" in out[0]


def test_flags_caught_exception_passed_to_lazy_logger_formatting() -> None:
    source = """
try:
    connect()
except RuntimeError as exc:
    logger.warning("connection failed: %s", exc)
"""
    out = GUARD.scan_text(source, "sample.py")
    assert len(out) == 1
    assert "lazy log argument" in out[0]


def test_flags_logger_exception_implicit_traceback() -> None:
    source = """
try:
    connect()
except RuntimeError:
    logger.exception("connection failed")
"""
    out = GUARD.scan_text(source, "sample.py")
    assert len(out) == 1
    assert "logger.exception" in out[0]

    outside_handler = GUARD.scan_text('logger.exception("connection failed")\n', "sample.py")
    assert len(outside_handler) == 1
    assert "logger.exception" in outside_handler[0]


def test_flags_explicit_raw_exc_info() -> None:
    for statement in (
        'logger.error("connection failed", exc_info=True)',
        'logger.error("connection failed", exc_info=exc)',
    ):
        source = f"""
try:
    connect()
except RuntimeError as exc:
    {statement}
"""
        out = GUARD.scan_text(source, "sample.py")
        assert len(out) == 1, statement
        assert "exc_info" in out[0]

    outside_handler = GUARD.scan_text('logger.error("worker failed", exc_info=(kind, failure, traceback))\n', "sample.py")
    assert len(outside_handler) == 1
    assert "exc_info" in outside_handler[0]


def test_flags_exception_flow_into_returned_payload_even_through_custom_sanitizer() -> None:
    source = """
try:
    build_response()
except ValueError as exc:
    return {
        "available": False,
        "unavailable_reason": sanitize_error(exc, generic=True),
    }
"""
    out = GUARD.scan_text(source, "sample.py")
    assert len(out) == 1
    assert "returned response payload" in out[0]


# ---------------------------------------------------------------------------
# Safe patterns are NOT flagged.
# ---------------------------------------------------------------------------
def test_allows_sanitized_and_structured_forms() -> None:
    safe = """
    raise HTTPException(status_code=422, detail=sanitize_error(exc)) from exc
    raise HTTPException(status_code=400, detail=f"bad: {sanitize_error(exc)}") from exc
    raise HTTPException(status_code=503, detail=sanitize_error(exc, generic=True)) from exc
    logger.warning("failed: %s", sanitize_text(exc))
    logger.error("failed without exception detail")
    logger.error("failed without traceback", exc_info=False)
    raise HTTPException(status_code=409, detail=f"Cannot approve exception in {exc.status.value} state")
    return JSONResponse(status_code=429, content=exc.to_dict())
    """
    assert GUARD.scan_text(safe, "sample.py") == []


def test_allows_sanitized_logging_inside_exception_handler() -> None:
    source = """
try:
    connect()
except RuntimeError as exc:
    logger.warning("failed: %s", sanitize_text(exc))
    logger.warning("failed in state: %s", exc.status.value)
    logger.error("failed without traceback", exc_info=False)
"""
    assert GUARD.scan_text(source, "sample.py") == []


def test_pragma_silences_a_vetted_line() -> None:
    line = "    raise HTTPException(status_code=422, detail=str(exc))  # exc-safe: value is a fixed enum\n"
    assert GUARD.scan_text(line, "sample.py") == []

    source = """
try:
    connect()
except FixedMessageError:
    logger.exception("fixed library exception")  # exc-safe: exception type has constant text and no sensitive state
"""
    assert GUARD.scan_text(source, "sample.py") == []


# ---------------------------------------------------------------------------
# Sanitizer contracts the guard points callers to.
# ---------------------------------------------------------------------------
def test_sanitize_error_generic_is_fixed_message() -> None:
    from agent_bom.security import sanitize_error

    leaky = Exception("token=AKIASECRET arn:aws:kms:key /etc/agent-bom/master.pem")
    out = sanitize_error(leaky, generic=True)
    assert out == "An internal error occurred. Please contact support."
    assert "AKIASECRET" not in out and "master.pem" not in out


def test_sanitize_error_redacts_secret_but_keeps_safe_hint() -> None:
    from agent_bom.security import sanitize_error

    out = sanitize_error(ValueError("invalid region token=SECRET123 at /etc/conf https://h/p"))
    assert "invalid region" in out  # safe, user-facing validation hint survives
    assert "SECRET123" not in out
    assert "/etc/conf" not in out
    assert "https://h/p" not in out


def test_sanitize_text_redacts_credential_bearing_url_for_logs() -> None:
    from agent_bom.security import sanitize_text

    out = sanitize_text(Exception("connect failed: postgres://user:supersecretpw@db.internal/app"))
    assert "supersecretpw" not in out
